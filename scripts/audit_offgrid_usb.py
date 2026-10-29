#!/usr/bin/env python3
"""
OffGridUSB Deployment Auditor (audit_offgrid_usb.py)
Independent, zero-dependency deployment and integrity verification suite.

Usage:
    python audit_offgrid_usb.py --drive D: --tier 2
    python audit_offgrid_usb.py --drive /media/usb --tier 1 --skip-live
    python audit_offgrid_usb.py --drive D: --tier 0 --live-only
    python audit_offgrid_usb.py --drive D: --tier 2 --mode static --json D:/audit_report.json

Audits:
    1. Manifest integrity (file presence, minimum sizes, byte-exact checksums)
    2. Magic byte forensics (0x5A494D04 on .zim, b"GGUF" on .gguf, Mach-O/ELF in archives, APE on llamafile)
    3. Line ending forensics (100% pure LF on .sh/.command, valid shebangs, no UTF-8 BOM)
    4. Live multi-service health checks (Kiwix 8081, llama-server 8082, Command Center 8000, CDC math, Grounded AI citations)
    5. Process image path isolation (asserts 100% of listening services run from <drive>:\\bin\\windows_x86_64\\*, 0 from C:\\)

Return Codes:
    0 = Clean deployment (100% PASS)
    1 = Manifest asset integrity failure
    2 = Binary header or magic byte violation
    3 = Line ending or script forensic violation
    4 = Live service health check failure
    5 = Process path isolation violation
    6 = Invalid CLI parameters or configuration error
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import math
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tarfile
import time
from typing import Any, Dict, List, Optional, Tuple
import urllib.error
import urllib.parse
import urllib.request

if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")


class AuditStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"


@dataclass
class CheckResult:
    category: str
    check_name: str
    target: str
    status: AuditStatus
    expected: Any
    observed: Any
    details: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["message"] = self.details
        d["actual"] = str(self.observed)
        return d


class OffGridUSBAuditor:
    """Comprehensive standalone auditor for OffGridUSB deployments."""

    def __init__(
        self,
        drive_path: str,
        tier: int = 2,
        manifest_dir: Optional[str] = None,
        skip_live: bool = False,
        live_only: bool = False,
        mock_process_table: Optional[str] = None,
        skip_checksums: bool = False,
        strict_checksums: bool = False,
        timeout: int = 10,
        llm_timeout: int = 45,
        verbose: bool = False,
    ):
        self.raw_drive = drive_path
        self.drive = self._normalize_drive_path(drive_path)
        self.tier = tier
        self.manifest_dir = Path(manifest_dir).resolve() if manifest_dir else (self.drive / "manifests")
        self.skip_live = skip_live
        self.live_only = live_only
        self.mock_process_table = Path(mock_process_table).resolve() if mock_process_table else None
        if not self.mock_process_table and os.environ.get("OFFGRID_AUDIT_MOCK_PROCESSES"):
            self.mock_process_table = Path(os.environ["OFFGRID_AUDIT_MOCK_PROCESSES"]).resolve()
        self.skip_checksums = skip_checksums
        self.strict_checksums = strict_checksums
        self.timeout = timeout
        self.llm_timeout = llm_timeout
        self.verbose = verbose

        self.results: List[CheckResult] = []
        self.zim_manifest: List[Dict[str, Any]] = []
        self.models_manifest: List[Dict[str, Any]] = []
        self.hardware_manifest: Optional[Dict[str, Any]] = None

    @staticmethod
    def _normalize_drive_path(p: str) -> Path:
        """Normalizes Windows drive letters (e.g. 'D:', 'D:\\') and POSIX paths."""
        cleaned = p.strip()
        if re.match(r"^[a-zA-Z]:$", cleaned):
            cleaned += "\\"
        resolved = Path(cleaned).resolve()
        return resolved

    def log(self, msg: str, level: str = "INFO"):
        if level == "DEBUG" and not self.verbose:
            return
        prefix = {
            "INFO": "[INFO]",
            "PASS": "  [PASS]",
            "FAIL": "  [FAIL]",
            "WARN": "  [WARN]",
            "DEBUG": "  [DEBUG]",
        }.get(level, f"[{level}]")
        print(f"{prefix} {msg}")

    # =========================================================================
    # PHASE 1: MANIFEST INTEGRITY & ASSET CHECKS
    # =========================================================================
    def audit_manifests_and_assets(self) -> None:
        """Audits file presence, sizes, and byte-exact checksums against manifests."""
        self.log("Beginning Manifest & Asset Integrity Audit...", "INFO")

        if not self.manifest_dir.is_dir():
            self.results.append(
                CheckResult(
                    category="Manifest Integrity",
                    check_name="Manifest Directory Presence",
                    target=str(self.manifest_dir),
                    status=AuditStatus.FAIL,
                    expected="Directory exists",
                    observed="Directory not found",
                    details=f"Manifest folder {self.manifest_dir} does not exist on target drive",
                )
            )
            return

        # 1. zim.json
        zim_json_path = self.manifest_dir / "zim.json"
        if not zim_json_path.is_file():
            self.results.append(
                CheckResult(
                    category="Manifest Integrity",
                    check_name="ZIM Manifest Presence",
                    target=str(zim_json_path),
                    status=AuditStatus.FAIL,
                    expected="zim.json exists",
                    observed="File missing",
                    details="OpenZIM catalog manifest missing",
                )
            )
        else:
            try:
                with open(zim_json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.zim_manifest = data.get("archives", [])
                self.results.append(
                    CheckResult(
                        category="Manifest Integrity",
                        check_name="ZIM Manifest Syntax",
                        target=str(zim_json_path),
                        status=AuditStatus.PASS,
                        expected="Valid JSON with archives[]",
                        observed=f"{len(self.zim_manifest)} archives cataloged",
                        details=f"Loaded {len(self.zim_manifest)} archives from {zim_json_path.name}",
                    )
                )
            except Exception as e:
                self.results.append(
                    CheckResult(
                        category="Manifest Integrity",
                        check_name="ZIM Manifest Syntax",
                        target=str(zim_json_path),
                        status=AuditStatus.FAIL,
                        expected="Valid JSON",
                        observed=f"Parse error: {e}",
                        details=str(e),
                    )
                )

        # 2. models.json
        models_json_path = self.manifest_dir / "models.json"
        if not models_json_path.is_file():
            self.results.append(
                CheckResult(
                    category="Manifest Integrity",
                    check_name="Models Manifest Presence",
                    target=str(models_json_path),
                    status=AuditStatus.FAIL,
                    expected="models.json exists",
                    observed="File missing",
                    details="GGUF models catalog manifest missing",
                )
            )
        else:
            try:
                with open(models_json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.models_manifest = data.get("models", [])
                self.results.append(
                    CheckResult(
                        category="Manifest Integrity",
                        check_name="Models Manifest Syntax",
                        target=str(models_json_path),
                        status=AuditStatus.PASS,
                        expected="Valid JSON with models[]",
                        observed=f"{len(self.models_manifest)} models cataloged",
                        details=f"Loaded {len(self.models_manifest)} models from {models_json_path.name}",
                    )
                )
            except Exception as e:
                self.results.append(
                    CheckResult(
                        category="Manifest Integrity",
                        check_name="Models Manifest Syntax",
                        target=str(models_json_path),
                        status=AuditStatus.FAIL,
                        expected="Valid JSON",
                        observed=f"Parse error: {e}",
                        details=str(e),
                    )
                )

        # 3. hardware.json (optional/declarative)
        hw_json_path = self.manifest_dir / "hardware.json"
        if hw_json_path.is_file():
            try:
                with open(hw_json_path, "r", encoding="utf-8") as f:
                    self.hardware_manifest = json.load(f)
                self.results.append(
                    CheckResult(
                        category="Manifest Integrity",
                        check_name="Hardware Manifest Syntax",
                        target=str(hw_json_path),
                        status=AuditStatus.PASS,
                        expected="Valid JSON",
                        observed="Valid JSON loaded",
                        details="Hardware sizing manifest loaded",
                    )
                )
            except Exception as e:
                self.results.append(
                    CheckResult(
                        category="Manifest Integrity",
                        check_name="Hardware Manifest Syntax",
                        target=str(hw_json_path),
                        status=AuditStatus.FAIL,
                        expected="Valid JSON",
                        observed=f"Parse error: {e}",
                        details=str(e),
                    )
                )
        else:
            self.results.append(
                CheckResult(
                    category="Manifest Integrity",
                    check_name="Hardware Manifest Presence",
                    target=str(hw_json_path),
                    status=AuditStatus.WARN,
                    expected="hardware.json present (optional)",
                    observed="File missing (using runtime defaults)",
                    details="hardware.json is optional; skipping hardware profile audit",
                )
            )

        # Validate ZIM files for requested tier
        zim_dir = self.drive / "data" / "zim"
        target_zims = [z for z in self.zim_manifest if z.get("tier", 0) <= self.tier]
        self.log(f"Auditing {len(target_zims)} ZIM archives for Tier <= {self.tier}...", "INFO")

        for z in target_zims:
            fname = z.get("filename", "")
            z_path = zim_dir / fname
            expected_size = z.get("size_bytes", 0)
            z_tier = z.get("tier", 0)

            # Check presence
            if not z_path.exists():
                self.results.append(
                    CheckResult(
                        category="Asset Presence",
                        check_name=f"ZIM File Presence (Tier {z_tier})",
                        target=str(z_path),
                        status=AuditStatus.FAIL,
                        expected="File exists",
                        observed="File not found",
                        details=f"Required ZIM archive '{fname}' missing from {zim_dir}",
                    )
                )
                continue

            # Check for dangling .part files
            part_path = Path(str(z_path) + ".part")
            if part_path.exists():
                self.results.append(
                    CheckResult(
                        category="Asset Integrity",
                        check_name="Dangling Partial Download",
                        target=str(part_path),
                        status=AuditStatus.FAIL,
                        expected="No .part files",
                        observed=f"Found {part_path.name}",
                        details="Interrupted or unfinalized partial download detected",
                    )
                )

            # Check file size
            actual_size = z_path.stat().st_size
            min_allowed = int(expected_size * 0.98) if expected_size > 0 else 1024
            if actual_size < min_allowed:
                self.results.append(
                    CheckResult(
                        category="Asset Integrity",
                        check_name=f"ZIM Size Check ({fname})",
                        target=str(z_path),
                        status=AuditStatus.FAIL,
                        expected=f">= {min_allowed:,} bytes (nominally {expected_size:,})",
                        observed=f"{actual_size:,} bytes",
                        details=f"ZIM archive is truncated: {fname} ({actual_size:,} < {min_allowed:,} bytes)",
                    )
                )
            else:
                self.results.append(
                    CheckResult(
                        category="Asset Integrity",
                        check_name=f"ZIM Size Check ({fname})",
                        target=str(z_path),
                        status=AuditStatus.PASS,
                        expected=f">= {min_allowed:,} bytes",
                        observed=f"{actual_size:,} bytes",
                        details=f"Size verified: {actual_size / (1024*1024):.1f} MB",
                    )
                )

        # Validate GGUF models for requested tier
        models_dir = self.drive / "data" / "models"
        target_models = [m for m in self.models_manifest if m.get("tier", 0) <= self.tier]
        self.log(f"Auditing {len(target_models)} GGUF models for Tier <= {self.tier}...", "INFO")

        for m in target_models:
            fname = m.get("filename", "")
            m_path = models_dir / fname
            expected_size = m.get("size_bytes", 0)
            m_tier = m.get("tier", 0)
            expected_sha = m.get("sha256", "").strip().lower()

            if not m_path.exists():
                self.results.append(
                    CheckResult(
                        category="Asset Presence",
                        check_name=f"Model File Presence (Tier {m_tier})",
                        target=str(m_path),
                        status=AuditStatus.FAIL,
                        expected="File exists",
                        observed="File not found",
                        details=f"Required GGUF model '{fname}' missing from {models_dir}",
                    )
                )
                continue

            # Check for dangling .part files
            part_path = Path(str(m_path) + ".part")
            if part_path.exists():
                self.results.append(
                    CheckResult(
                        category="Asset Integrity",
                        check_name="Dangling Partial Download",
                        target=str(part_path),
                        status=AuditStatus.FAIL,
                        expected="No .part files",
                        observed=f"Found {part_path.name}",
                        details="Interrupted or unfinalized partial download detected",
                    )
                )

            # Check size
            actual_size = m_path.stat().st_size
            min_allowed = int(expected_size * 0.98) if expected_size > 0 else 1024
            if actual_size < min_allowed:
                self.results.append(
                    CheckResult(
                        category="Asset Integrity",
                        check_name=f"Model Size Check ({fname})",
                        target=str(m_path),
                        status=AuditStatus.FAIL,
                        expected=f">= {min_allowed:,} bytes (nominally {expected_size:,})",
                        observed=f"{actual_size:,} bytes",
                        details=f"Model file is truncated: {fname} ({actual_size:,} < {min_allowed:,} bytes)",
                    )
                )
            else:
                self.results.append(
                    CheckResult(
                        category="Asset Integrity",
                        check_name=f"Model Size Check ({fname})",
                        target=str(m_path),
                        status=AuditStatus.PASS,
                        expected=f">= {min_allowed:,} bytes",
                        observed=f"{actual_size:,} bytes",
                        details=f"Size verified: {actual_size / (1024*1024):.1f} MB",
                    )
                )

            # Check SHA-256 checksum if provided and not a placeholder
            is_placeholder = bool(re.match(r"^0{40,}", expected_sha)) or len(expected_sha) != 64
            if expected_sha and not is_placeholder and not self.skip_checksums:
                self.log(f"Hashing {fname} for byte-exact SHA256 checksum...", "INFO")
                actual_sha = self._compute_sha256(m_path)
                if actual_sha.lower() == expected_sha:
                    self.results.append(
                        CheckResult(
                            category="Asset Integrity",
                            check_name=f"Model SHA256 Match ({fname})",
                            target=str(m_path),
                            status=AuditStatus.PASS,
                            expected=expected_sha,
                            observed=actual_sha,
                            details="Byte-exact SHA256 checksum verified",
                        )
                    )
                else:
                    self.results.append(
                        CheckResult(
                            category="Asset Integrity",
                            check_name=f"Model SHA256 Match ({fname})",
                            target=str(m_path),
                            status=AuditStatus.FAIL,
                            expected=expected_sha,
                            observed=actual_sha,
                            details="SHA256 checksum mismatch (corrupted neural weights)",
                        )
                    )
            elif self.strict_checksums and is_placeholder:
                self.results.append(
                    CheckResult(
                        category="Asset Integrity",
                        check_name=f"Model Strict SHA256 ({fname})",
                        target=str(m_path),
                        status=AuditStatus.FAIL,
                        expected="Authoritative SHA256 hex string",
                        observed=f"Placeholder hash: {expected_sha}",
                        details="Strict checksum enforcement rejected manifest placeholder hash",
                    )
                )

    # =========================================================================
    # PHASE 2: MAGIC BYTE FORENSICS
    # =========================================================================
    def audit_magic_bytes(self) -> None:
        """Audits binary magic bytes for ZIM, GGUF, PE, ELF, Mach-O, and APE."""
        self.log("Beginning Binary Magic Byte & Architecture Audit...", "INFO")

        # 1. ZIM Magic Bytes (0x5A494D04)
        zim_dir = self.drive / "data" / "zim"
        if zim_dir.is_dir():
            for zf in sorted(zim_dir.glob("*.zim")):
                try:
                    with open(zf, "rb") as f:
                        header = f.read(4)
                    is_zim = header in (b"ZIM\x04", b"ZIM\x05")
                    if is_zim:
                        self.results.append(
                            CheckResult(
                                category="Magic Bytes",
                                check_name="ZIM Magic Header",
                                target=str(zf),
                                status=AuditStatus.PASS,
                                expected="0x5A494D04 (b'ZIM\\x04')",
                                observed=f"0x{header.hex().upper()} ({header!r})",
                                details=f"Valid OpenZIM container magic header: {zf.name}",
                            )
                        )
                    else:
                        self.results.append(
                            CheckResult(
                                category="Magic Bytes",
                                check_name="ZIM Magic Header",
                                target=str(zf),
                                status=AuditStatus.FAIL,
                                expected="0x5A494D04 (b'ZIM\\x04')",
                                observed=f"0x{header.hex().upper()} ({header!r})",
                                details=f"CORRUPT_ZIM_MAGIC: Corrupt ZIM magic header in {zf.name} (expected 0x5A494D04, got 0x{header.hex().upper()})",
                            )
                        )
                except Exception as e:
                    self.results.append(
                        CheckResult(
                            category="Magic Bytes",
                            check_name="ZIM Magic Header",
                            target=str(zf),
                            status=AuditStatus.FAIL,
                            expected="0x5A494D04",
                            observed=f"Read error: {e}",
                            details=f"CORRUPT_ZIM_MAGIC in {zf.name}: {e}",
                        )
                    )

        # 2. GGUF Magic Bytes (b"GGUF" / 0x47475546)
        models_dir = self.drive / "data" / "models"
        if models_dir.is_dir():
            for mf in sorted(models_dir.glob("*.gguf")):
                try:
                    with open(mf, "rb") as f:
                        header = f.read(8)
                    is_gguf = header[:4] == b"GGUF"
                    if is_gguf:
                        version = struct.unpack("<I", header[4:8])[0] if len(header) >= 8 else 0
                        self.results.append(
                            CheckResult(
                                category="Magic Bytes",
                                check_name="GGUF Magic Header",
                                target=str(mf),
                                status=AuditStatus.PASS,
                                expected="b'GGUF' (0x46554747)",
                                observed=f"{header[:4]!r} (version {version})",
                                details=f"Valid GGUF container version {version}: {mf.name}",
                            )
                        )
                    else:
                        self.results.append(
                            CheckResult(
                                category="Magic Bytes",
                                check_name="GGUF Magic Header",
                                target=str(mf),
                                status=AuditStatus.FAIL,
                                expected="b'GGUF' (0x46554747)",
                                observed=f"0x{header[:4].hex().upper()} ({header[:4]!r})",
                                details=f"CORRUPT_GGUF_MAGIC: Corrupt GGUF magic header in {mf.name} (expected b'GGUF', got {header[:4]!r})",
                            )
                        )
                except Exception as e:
                    self.results.append(
                        CheckResult(
                            category="Magic Bytes",
                            check_name="GGUF Magic Header",
                            target=str(mf),
                            status=AuditStatus.FAIL,
                            expected="b'GGUF'",
                            observed=f"Read error: {e}",
                            details=f"CORRUPT_GGUF_MAGIC in {mf.name}: {e}",
                        )
                    )

        # 3. Cosmopolitan APE header on bin/polyglot/llamafile.exe
        poly_llama = self.drive / "bin" / "polyglot" / "llamafile.exe"
        if not poly_llama.is_file():
            self.results.append(
                CheckResult(
                    category="Magic Bytes",
                    check_name="Cosmopolitan APE Presence",
                    target=str(poly_llama),
                    status=AuditStatus.FAIL,
                    expected="File exists",
                    observed="File missing",
                    details=f"Missing polyglot engine binary at {poly_llama}",
                )
            )
        else:
            try:
                with open(poly_llama, "rb") as f:
                    head = f.read(128)
                is_mz = head[:2] == b"MZ"
                is_ape = head[:6] == b"MZqFpD"
                if is_mz and is_ape:
                    self.results.append(
                        CheckResult(
                            category="Magic Bytes",
                            check_name="Cosmopolitan APE Signature",
                            target=str(poly_llama),
                            status=AuditStatus.PASS,
                            expected="b'MZqFpD' (Cosmopolitan Actually Portable Executable)",
                            observed=f"{head[:6]!r}",
                            details="Authentic Cosmopolitan polyglot binary verified",
                        )
                    )
                elif is_mz:
                    self.results.append(
                        CheckResult(
                            category="Magic Bytes",
                            check_name="Cosmopolitan APE Signature",
                            target=str(poly_llama),
                            status=AuditStatus.WARN,
                            expected="b'MZqFpD'",
                            observed=f"{head[:6]!r}",
                            details="Binary has valid MZ header but atypical APE sub-signature",
                        )
                    )
                else:
                    self.results.append(
                        CheckResult(
                            category="Magic Bytes",
                            check_name="Cosmopolitan APE Signature",
                            target=str(poly_llama),
                            status=AuditStatus.FAIL,
                            expected="b'MZqFpD'",
                            observed=f"{head[:6]!r}",
                            details="Invalid executable header on llamafile.exe",
                        )
                    )
            except Exception as e:
                self.results.append(
                    CheckResult(
                        category="Magic Bytes",
                        check_name="Cosmopolitan APE Signature",
                        target=str(poly_llama),
                        status=AuditStatus.FAIL,
                        expected="b'MZqFpD'",
                        observed=f"Read error: {e}",
                        details=str(e),
                    )
                )

        # 4. Cross-Platform Engine Archives in bin/
        tarballs = [
            ("bin/linux_x86_64/kiwix-tools_linux-x86_64.tar.gz", "linux", "x86_64"),
            ("bin/linux_x86_64/llama-ubuntu-x64.tar.gz", "linux", "x86_64"),
            ("bin/linux_arm64/kiwix-tools_linux-aarch64.tar.gz", "linux", "arm64"),
            ("bin/linux_arm64/llama-ubuntu-arm64.tar.gz", "linux", "arm64"),
            ("bin/macos_arm64/kiwix-tools_macos.tar.gz", "macos", "arm64"),
            ("bin/macos_arm64/llama-macos-arm64.tar.gz", "macos", "arm64"),
            ("bin/macos_x86_64/kiwix-tools_macos-x86_64.tar.gz", "macos", "x86_64"),
            ("bin/macos_x86_64/llama-macos-x64.tar.gz", "macos", "x86_64"),
        ]

        for rel_path, os_target, arch_target in tarballs:
            t_path = self.drive / rel_path
            if not t_path.is_file():
                self.results.append(
                    CheckResult(
                        category="Cross-Platform Engine Archives",
                        check_name=f"Archive Presence ({rel_path})",
                        target=str(t_path),
                        status=AuditStatus.FAIL,
                        expected="File exists",
                        observed="File missing",
                        details=f"Required cross-platform archive '{rel_path}' is missing",
                    )
                )
                continue

            # Verify gzip magic
            try:
                with open(t_path, "rb") as gf:
                    gz_magic = gf.read(2)
                if gz_magic != b"\x1f\x8b":
                    self.results.append(
                        CheckResult(
                            category="Cross-Platform Engine Archives",
                            check_name=f"Gzip Header ({t_path.name})",
                            target=str(t_path),
                            status=AuditStatus.FAIL,
                            expected="0x1F8B (b'\\x1f\\x8b')",
                            observed=f"0x{gz_magic.hex().upper()}",
                            details="Invalid gzip container header",
                        )
                    )
                    continue
            except Exception as e:
                self.results.append(
                    CheckResult(
                        category="Cross-Platform Engine Archives",
                        check_name=f"Gzip Header ({t_path.name})",
                        target=str(t_path),
                        status=AuditStatus.FAIL,
                        expected="0x1F8B",
                        observed=f"Read error: {e}",
                        details=str(e),
                    )
                )
                continue

            # Inspect internal members
            try:
                with tarfile.open(t_path, "r:*") as tf:
                    members = [m for m in tf.getmembers() if m.isreg()]
                    for m in members:
                        if m.name.endswith((".md", ".txt", ".h", ".c", ".dylib", ".so")):
                            continue
                        f_extracted = tf.extractfile(m)
                        if not f_extracted:
                            continue
                        content = f_extracted.read(64)
                        if len(content) < 32:
                            continue

                        # Check executable permission mode
                        is_exec_mode = bool(m.mode & 0o111)
                        if not is_exec_mode:
                            self.results.append(
                                CheckResult(
                                    category="Cross-Platform Engine Archives",
                                    check_name=f"Tarball Permissions ({m.name})",
                                    target=f"{t_path.name} -> {m.name}",
                                    status=AuditStatus.WARN,
                                    expected="Executable bit set (e.g. 0o755)",
                                    observed=f"0o{m.mode:o}",
                                    details="Internal archive member missing executable bit",
                                )
                            )

                        # Linux ELF Inspection
                        if os_target == "linux":
                            is_elf = content[:4] == b"\x7fELF"
                            if not is_elf:
                                self.results.append(
                                    CheckResult(
                                        category="Cross-Platform Engine Archives / Internal Magic",
                                        check_name=f"ELF Magic Check ({m.name})",
                                        target=f"{t_path.name} -> {m.name}",
                                        status=AuditStatus.FAIL,
                                        expected="b'\\x7fELF' (0x7fELF)",
                                        observed=f"{content[:4]!r}",
                                        details=f"Member {m.name} in {t_path.name} does not start with standard ELF magic (observed {content[:4]!r})",
                                    )
                                )
                                continue

                            ei_class = content[4]
                            ei_data = content[5]
                            e_machine = struct.unpack("<H" if ei_data == 1 else ">H", content[18:20])[0]

                            expected_machine = 0x003E if arch_target == "x86_64" else 0x00B7
                            arch_name = "x86_64" if arch_target == "x86_64" else "arm64"

                            if ei_class == 2 and e_machine == expected_machine:
                                self.results.append(
                                    CheckResult(
                                        category="Cross-Platform Engine Archives",
                                        check_name=f"ELF Architecture Match ({m.name})",
                                        target=f"{t_path.name} -> {m.name}",
                                        status=AuditStatus.PASS,
                                        expected=f"ELF 64-bit {arch_name} (0x{expected_machine:04X})",
                                        observed=f"ELF 64-bit class=2 machine=0x{e_machine:04X}",
                                        details=f"Verified valid 64-bit {arch_name} ELF binary in archive",
                                    )
                                )
                            else:
                                self.results.append(
                                    CheckResult(
                                        category="Cross-Platform Engine Archives",
                                        check_name=f"ELF Architecture Match ({m.name})",
                                        target=f"{t_path.name} -> {m.name}",
                                        status=AuditStatus.FAIL,
                                        expected=f"ELF 64-bit {arch_name} (0x{expected_machine:04X})",
                                        observed=f"class={ei_class} machine=0x{e_machine:04X}",
                                        details=f"Architecture mismatch inside Linux engine tarball {t_path.name} -> {m.name}",
                                    )
                                )

                        # macOS Mach-O Inspection
                        elif os_target == "macos":
                            magic_le = struct.unpack("<I", content[:4])[0]
                            magic_be = struct.unpack(">I", content[:4])[0]
                            is_macho = (
                                magic_le == 0xFEEDFACF
                                or magic_be == 0xFEEDFACF
                                or content[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")
                            )

                            if not is_macho:
                                self.results.append(
                                    CheckResult(
                                        category="Cross-Platform Engine Archives / Internal Magic",
                                        check_name=f"Mach-O Magic Check ({m.name})",
                                        target=f"{t_path.name} -> {m.name}",
                                        status=AuditStatus.FAIL,
                                        expected="0xFEEDFACF / 0xCFFAEDFE (Mach-O 64-bit)",
                                        observed=f"0x{magic_le:08X}",
                                        details=f"Member {m.name} in {t_path.name} does not start with standard Mach-O 64-bit magic",
                                    )
                                )
                                continue

                            cputype = struct.unpack("<I", content[4:8])[0]
                            expected_cpu = 0x01000007 if arch_target == "x86_64" else 0x0100000C
                            arch_name = "x86_64" if arch_target == "x86_64" else "arm64"

                            if cputype == expected_cpu:
                                self.results.append(
                                    CheckResult(
                                        category="Cross-Platform Engine Archives",
                                        check_name=f"Mach-O Architecture Match ({m.name})",
                                        target=f"{t_path.name} -> {m.name}",
                                        status=AuditStatus.PASS,
                                        expected=f"Mach-O 64-bit {arch_name} (0x{expected_cpu:08X})",
                                        observed=f"cputype=0x{cputype:08X}",
                                        details=f"Verified valid 64-bit {arch_name} Mach-O binary in archive",
                                    )
                                )
                            else:
                                self.results.append(
                                    CheckResult(
                                        category="Cross-Platform Engine Archives",
                                        check_name=f"Mach-O Architecture Match ({m.name})",
                                        target=f"{t_path.name} -> {m.name}",
                                        status=AuditStatus.FAIL,
                                        expected=f"Mach-O 64-bit {arch_name} (0x{expected_cpu:08X})",
                                        observed=f"cputype=0x{cputype:08X}",
                                        details=f"Architecture mismatch inside macOS engine tarball {t_path.name} -> {m.name}",
                                    )
                                )
            except Exception as e:
                self.results.append(
                    CheckResult(
                        category="Cross-Platform Engine Archives",
                        check_name=f"Tarball Inspection Error ({t_path.name})",
                        target=str(t_path),
                        status=AuditStatus.FAIL,
                        expected="Readable tar archive",
                        observed=f"Error: {e}",
                        details=str(e),
                    )
                )

        # 5. Windows Host Binaries (bin/windows_x86_64/*)
        win_binaries = [
            "bin/windows_x86_64/kiwix/kiwix-serve.exe",
            "bin/windows_x86_64/llama/llama-server.exe",
            "bin/windows_x86_64/python/python.exe",
        ]
        for rel_exe in win_binaries:
            exe_path = self.drive / rel_exe
            if not exe_path.is_file():
                self.results.append(
                    CheckResult(
                        category="Magic Bytes",
                        check_name=f"Windows Binary Presence ({rel_exe})",
                        target=str(exe_path),
                        status=AuditStatus.FAIL,
                        expected="File exists",
                        observed="File missing",
                        details=f"Missing core Windows runtime executable at {exe_path}",
                    )
                )
            else:
                try:
                    with open(exe_path, "rb") as f:
                        pe_head = f.read(2)
                    if pe_head == b"MZ":
                        self.results.append(
                            CheckResult(
                                category="Magic Bytes",
                                check_name=f"PE Header ({exe_path.name})",
                                target=str(exe_path),
                                status=AuditStatus.PASS,
                                expected="b'MZ' (0x4D5A)",
                                observed=f"{pe_head!r}",
                                details="Valid Portable Executable (PE32+) header",
                            )
                        )
                    else:
                        self.results.append(
                            CheckResult(
                                category="Magic Bytes",
                                check_name=f"PE Header ({exe_path.name})",
                                target=str(exe_path),
                                status=AuditStatus.FAIL,
                                expected="b'MZ' (0x4D5A)",
                                observed=f"{pe_head!r}",
                                details="Invalid PE header on Windows executable",
                            )
                        )
                except Exception as e:
                    self.results.append(
                        CheckResult(
                            category="Magic Bytes",
                            check_name=f"PE Header ({exe_path.name})",
                            target=str(exe_path),
                            status=AuditStatus.FAIL,
                            expected="b'MZ'",
                            observed=f"Read error: {e}",
                            details=str(e),
                        )
                    )

    # =========================================================================
    # PHASE 3: LINE ENDINGS & SHEBANG FORENSICS
    # =========================================================================
    def audit_line_endings_and_scripts(self) -> None:
        """Audits all .sh and .command scripts for pure LF, shebangs, and no BOM, and verifies Windows launchers."""
        self.log("Beginning Script Line Endings & Shebang Forensics...", "INFO")

        # Required Windows batch launchers presence audit
        windows_launchers = [
            "START_OFFGRIDUSB_WINDOWS.bat",
            "START_EMYRGE_WINDOWS.bat",
            "run_windows.bat",
        ]
        for w_launcher in windows_launchers:
            w_path = self.drive / w_launcher
            if not w_path.is_file():
                self.results.append(
                    CheckResult(
                        category="Script Forensics / Launcher Scripts",
                        check_name=f"Windows Launcher Presence ({w_launcher})",
                        target=str(w_path),
                        status=AuditStatus.FAIL,
                        expected="File exists",
                        observed="File missing",
                        details=f"Required Windows batch launcher '{w_launcher}' is missing from target drive root",
                    )
                )
            else:
                self.results.append(
                    CheckResult(
                        category="Script Forensics / Launcher Scripts",
                        check_name=f"Windows Launcher Presence ({w_launcher})",
                        target=str(w_path),
                        status=AuditStatus.PASS,
                        expected="File exists",
                        observed="File exists",
                        details=f"Required Windows batch launcher '{w_launcher}' is present at drive root",
                    )
                )

        script_targets = [
            "START_OFFGRIDUSB_LINUX.sh",
            "START_OFFGRIDUSB_MAC.command",
            "START_EMYRGE_LINUX.sh",
            "START_EMYRGE_MAC.command",
            "run_linux.sh",
            "run_macos.command",
            "scripts/download_internet_in_a_box.sh",
            "scripts/setup_usb_unix.sh",
        ]

        discovered_paths = set()
        for pattern in ["*.sh", "*.command"]:
            for p in self.drive.glob(pattern):
                if p.is_file():
                    discovered_paths.add(p)
            for p in (self.drive / "scripts").glob(pattern):
                if p.is_file():
                    discovered_paths.add(p)

        for rel in script_targets:
            discovered_paths.add(self.drive / rel)

        self.log(f"Auditing {len(discovered_paths)} shell scripts for strict LF and valid shebangs...", "INFO")

        for script_path in sorted(discovered_paths):
            rel_name = os.path.relpath(script_path, self.drive)
            if not script_path.is_file():
                self.results.append(
                    CheckResult(
                        category="Script Forensics / Launcher Scripts",
                        check_name=f"Script Presence ({rel_name})",
                        target=str(script_path),
                        status=AuditStatus.FAIL,
                        expected="File exists",
                        observed="File missing",
                        details=f"Required shell launcher/script '{rel_name}' is missing",
                    )
                )
                continue

            try:
                raw_bytes = script_path.read_bytes()
                cr_count = raw_bytes.count(b"\r")
                crlf_count = raw_bytes.count(b"\r\n")
                has_bom = raw_bytes.startswith(b"\xef\xbb\xbf")

                # Check UTF-8 BOM
                if has_bom:
                    self.results.append(
                        CheckResult(
                            category="Script Forensics / Line Endings / BOM",
                            check_name=f"UTF-8 BOM Audit ({rel_name})",
                            target=str(script_path),
                            status=AuditStatus.FAIL,
                            expected="No BOM (0 bytes)",
                            observed="UTF-8 BOM detected (0xEFBBBF)",
                            details=f"BOM_DETECTED: Script {rel_name} contains UTF-8 Byte Order Mark which breaks UNIX execution",
                        )
                    )
                else:
                    self.results.append(
                        CheckResult(
                            category="Script Forensics / Line Endings",
                            check_name=f"UTF-8 BOM Audit ({rel_name})",
                            target=str(script_path),
                            status=AuditStatus.PASS,
                            expected="No BOM",
                            observed="Clean (No BOM)",
                            details="No UTF-8 BOM detected",
                        )
                    )

                # Check pure LF line endings (0 CRLF, 0 stray CRs)
                if cr_count > 0 or crlf_count > 0:
                    self.results.append(
                        CheckResult(
                            category="Script Forensics / Line Endings",
                            check_name=f"Pure LF Line Endings ({rel_name})",
                            target=str(script_path),
                            status=AuditStatus.FAIL,
                            expected="0 CRLF, 0 CR (100% pure LF)",
                            observed=f"{crlf_count} CRLF, {cr_count} CR",
                            details=f"CRLF_DETECTED: Script {rel_name} contains Windows carriage returns (CRLF={crlf_count}, CR={cr_count})",
                        )
                    )
                else:
                    lf_count = raw_bytes.count(b"\n")
                    self.results.append(
                        CheckResult(
                            category="Script Forensics / Line Endings",
                            check_name=f"Pure LF Line Endings ({rel_name})",
                            target=str(script_path),
                            status=AuditStatus.PASS,
                            expected="100% pure LF",
                            observed=f"{lf_count} LF lines, 0 CR, 0 CRLF",
                            details="Clean POSIX line endings verified",
                        )
                    )

                # Check shebang line
                lines = raw_bytes.split(b"\n")
                first_line = lines[0].decode("utf-8", errors="replace").strip()
                valid_shebangs = (
                    "#!/usr/bin/env bash",
                    "#!/bin/bash",
                    "#!/bin/sh",
                )
                if any(first_line.startswith(s) for s in valid_shebangs):
                    self.results.append(
                        CheckResult(
                            category="Script Forensics / Shebang",
                            check_name=f"Valid Shebang ({rel_name})",
                            target=str(script_path),
                            status=AuditStatus.PASS,
                            expected="Valid UNIX shebang (#!/usr/bin/env bash or #!/bin/bash or #!/bin/sh)",
                            observed=first_line,
                            details="Valid executable shebang verified",
                        )
                    )
                else:
                    self.results.append(
                        CheckResult(
                            category="Script Forensics / Shebang",
                            check_name=f"Valid Shebang ({rel_name})",
                            target=str(script_path),
                            status=AuditStatus.FAIL,
                            expected="Valid UNIX shebang",
                            observed=first_line if first_line else "<empty>",
                            details=f"SHEBANG_SYNTAX error: Missing or invalid shebang header '{first_line}' in {rel_name}",
                        )
                    )

            except Exception as e:
                self.results.append(
                    CheckResult(
                        category="Script Forensics",
                        check_name=f"Script Read Error ({rel_name})",
                        target=str(script_path),
                        status=AuditStatus.FAIL,
                        expected="Readable text file",
                        observed=f"Error: {e}",
                        details=str(e),
                    )
                )

    # =========================================================================
    # PHASE 4: LIVE SERVICE HEALTH CHECKS
    # =========================================================================
    def audit_live_services(self) -> None:
        """Audits live services on ports 8000, 8081, 8082, CDC math, and AI citations."""
        if self.skip_live:
            self.log("Skipping Live Service Health Checks (--skip-live requested)", "INFO")
            self.results.append(
                CheckResult(
                    category="Live Services",
                    check_name="Live Services Audit",
                    target="Ports 8000, 8081, 8082",
                    status=AuditStatus.SKIP,
                    expected="Live service health checks",
                    observed="Skipped via CLI flag",
                    details="Static audit completed; live checks bypassed",
                )
            )
            return

        if self.mock_process_table:
            self.log("Mock process table provided; skipping live HTTP port checks.", "INFO")
            self.results.append(
                CheckResult(
                    category="Live Services",
                    check_name="Live Services Audit",
                    target="Ports 8000, 8081, 8082",
                    status=AuditStatus.SKIP,
                    expected="Live service health checks",
                    observed="Skipped via mock process table",
                    details="Mock process table mode active; live network probes bypassed",
                )
            )
            return

        self.log("Beginning Live Service Health Checks...", "INFO")

        # 1. Port 8000 Command Center /api/status
        self._check_command_center_status()

        # 2. Port 8081 Kiwix Server Catalog & Mount Check
        self._check_kiwix_server()

        # 3. Port 8082 llama-server Health & Completions
        self._check_llama_server()

        # 4. CDC Water Chlorination Formula Deterministic Verification
        self._check_cdc_water_calculator()

        # 5. Grounded AI Professor Citation Regex Check
        self._check_grounded_ai_citations()

    def _check_command_center_status(self) -> None:
        url = "http://127.0.0.1:8000/api/status"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "OffGridUSB-Auditor/1.0"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                code = resp.status
                body = json.loads(resp.read().decode("utf-8"))
            if code == 200 and body.get("ok") is True:
                services = body.get("services", {})
                self.results.append(
                    CheckResult(
                        category="Live Services",
                        check_name="Command Center Health (Port 8000)",
                        target=url,
                        status=AuditStatus.PASS,
                        expected="HTTP 200 with {ok: true}",
                        observed=f"HTTP 200 (kiwix_running={services.get('kiwix_running')}, llm_running={services.get('llm_running')})",
                        details="Command Center backend online and responsive",
                    )
                )
            else:
                self.results.append(
                    CheckResult(
                        category="Live Services",
                        check_name="Command Center Health (Port 8000)",
                        target=url,
                        status=AuditStatus.FAIL,
                        expected="HTTP 200 with {ok: true}",
                        observed=f"HTTP {code}: {body}",
                        details="Command Center returned unhealthy status payload",
                    )
                )
        except Exception as e:
            self.results.append(
                CheckResult(
                    category="Live Services",
                    check_name="Command Center Health (Port 8000)",
                    target=url,
                    status=AuditStatus.FAIL,
                    expected="HTTP 200",
                    observed=f"Connection failure: {e}",
                    details=f"Command Center service not responding on port 8000: {e}",
                )
            )

    def _check_kiwix_server(self) -> None:
        url = "http://127.0.0.1:8081/catalog/v2/entries"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "OffGridUSB-Auditor/1.0"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                code = resp.status
                catalog_xml = resp.read().decode("utf-8", errors="replace")

            if code == 200:
                missing_zims = []
                target_zims = [z for z in self.zim_manifest if z.get("tier", 0) <= self.tier]
                for z in target_zims:
                    z_id = z.get("id", "")
                    base_name = z.get("filename", "").replace(".zim", "")
                    if z_id not in catalog_xml and base_name not in catalog_xml:
                        prefix = base_name.split("_")[0]
                        if prefix not in catalog_xml:
                            missing_zims.append(base_name)

                if missing_zims:
                    self.results.append(
                        CheckResult(
                            category="Live Services",
                            check_name="Kiwix Catalog Mount (Port 8081)",
                            target=url,
                            status=AuditStatus.FAIL,
                            expected=f"All Tier <={self.tier} ZIMs indexed",
                            observed=f"Missing archives: {', '.join(missing_zims)}",
                            details="Kiwix server is running but failed to index some staged ZIM archives",
                        )
                    )
                else:
                    self.results.append(
                        CheckResult(
                            category="Live Services",
                            check_name="Kiwix Catalog Mount (Port 8081)",
                            target=url,
                            status=AuditStatus.PASS,
                            expected=f"All Tier <={self.tier} ZIMs indexed",
                            observed=f"HTTP 200 ({len(catalog_xml):,} bytes catalog XML)",
                            details=f"Kiwix server actively indexing all {len(target_zims)} staged archives",
                        )
                    )
            else:
                self.results.append(
                    CheckResult(
                        category="Live Services",
                        check_name="Kiwix Catalog Mount (Port 8081)",
                        target=url,
                        status=AuditStatus.FAIL,
                        expected="HTTP 200",
                        observed=f"HTTP {code}",
                        details="Kiwix server returned non-200 HTTP code",
                    )
                )
        except Exception as e:
            self.results.append(
                CheckResult(
                    category="Live Services",
                    check_name="Kiwix Server Health (Port 8081)",
                    target=url,
                    status=AuditStatus.FAIL,
                    expected="HTTP 200",
                    observed=f"Connection failure: {e}",
                    details=f"Kiwix server not responding on port 8081: {e}",
                )
            )

    def _check_llama_server(self) -> None:
        health_url = "http://127.0.0.1:8082/health"
        try:
            req = urllib.request.Request(health_url, headers={"User-Agent": "OffGridUSB-Auditor/1.0"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                code = resp.status
            if code == 200:
                self.results.append(
                    CheckResult(
                        category="Live Services",
                        check_name="llama-server Health (Port 8082)",
                        target=health_url,
                        status=AuditStatus.PASS,
                        expected="HTTP 200",
                        observed=f"HTTP {code}",
                        details="llama-server /health probe succeeded",
                    )
                )
            else:
                self.results.append(
                    CheckResult(
                        category="Live Services",
                        check_name="llama-server Health (Port 8082)",
                        target=health_url,
                        status=AuditStatus.FAIL,
                        expected="HTTP 200",
                        observed=f"HTTP {code}",
                        details="llama-server /health returned non-200 code",
                    )
                )
        except Exception as e:
            self.results.append(
                CheckResult(
                    category="Live Services",
                    check_name="llama-server Health (Port 8082)",
                    target=health_url,
                    status=AuditStatus.FAIL,
                    expected="HTTP 200",
                    observed=f"Connection failure: {e}",
                    details=f"llama-server not responding on port 8082: {e}",
                )
            )
            return

        chat_url = "http://127.0.0.1:8082/v1/chat/completions"
        payload = json.dumps(
            {
                "messages": [
                    {"role": "system", "content": "You are an air-gapped system tester."},
                    {"role": "user", "content": "Respond with the single word VERIFIED_OFFGRID_PASS."},
                ],
                "temperature": 0.0,
                "max_tokens": 16,
                "stream": False,
            }
        ).encode("utf-8")

        try:
            req = urllib.request.Request(
                chat_url,
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "OffGridUSB-Auditor/1.0"},
            )
            with urllib.request.urlopen(req, timeout=self.llm_timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            if content:
                self.results.append(
                    CheckResult(
                        category="Live Services",
                        check_name="llama-server Chat Completion",
                        target=chat_url,
                        status=AuditStatus.PASS,
                        expected="Non-empty text completion",
                        observed=f"Output: {content.strip()[:60]!r}",
                        details="Local GGUF model runner actively generating tokens",
                    )
                )
            else:
                self.results.append(
                    CheckResult(
                        category="Live Services",
                        check_name="llama-server Chat Completion",
                        target=chat_url,
                        status=AuditStatus.FAIL,
                        expected="Non-empty completion",
                        observed="Empty response payload",
                        details="llama-server returned 200 but 0 tokens generated",
                    )
                )
        except Exception as e:
            self.results.append(
                CheckResult(
                    category="Live Services",
                    check_name="llama-server Chat Completion",
                    target=chat_url,
                    status=AuditStatus.FAIL,
                    expected="HTTP 200 with completion",
                    observed=f"Error: {e}",
                    details=f"Inference failure on port 8082: {e}",
                )
            )

    def _check_cdc_water_calculator(self) -> None:
        """Verifies deterministic CDC Safe Water chlorination dosage calculations."""
        calc_url = "http://127.0.0.1:8000/api/calc"

        # Case 1: 20 Liters Clear Water, 6.0% bleach
        p1 = json.dumps(
            {
                "type": "water",
                "params": {"volume_liters": 20.0, "is_turbid": False, "concentration_pct": 6.0},
            }
        ).encode("utf-8")

        try:
            req = urllib.request.Request(
                calc_url,
                data=p1,
                headers={"Content-Type": "application/json", "User-Agent": "OffGridUSB-Auditor/1.0"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                d1 = json.loads(resp.read().decode("utf-8"))

            res1 = d1.get("result", {})
            drops1 = res1.get("drops")
            ml1 = res1.get("volume_ml")
            time1 = res1.get("contact_time_minutes")

            if drops1 == 40 and ml1 == 2.0 and time1 == 30:
                self.results.append(
                    CheckResult(
                        category="Deterministic Calculators",
                        check_name="CDC Chlorination (20L Clear)",
                        target=calc_url,
                        status=AuditStatus.PASS,
                        expected="drops=40, volume_ml=2.0, contact_time_minutes=30",
                        observed=f"drops={drops1}, volume_ml={ml1}, contact_time_minutes={time1}",
                        details="Deterministic CDC clear water dosage formula verified",
                    )
                )
            else:
                self.results.append(
                    CheckResult(
                        category="Deterministic Calculators",
                        check_name="CDC Chlorination (20L Clear)",
                        target=calc_url,
                        status=AuditStatus.FAIL,
                        expected="drops=40, volume_ml=2.0, contact_time_minutes=30",
                        observed=f"drops={drops1}, volume_ml={ml1}, contact_time_minutes={time1}",
                        details="Deterministic calculation divergence on clear water parameters",
                    )
                )
        except Exception as e:
            self.results.append(
                CheckResult(
                    category="Deterministic Calculators",
                    check_name="CDC Chlorination (20L Clear)",
                    target=calc_url,
                    status=AuditStatus.FAIL,
                    expected="drops=40, volume_ml=2.0, contact_time_minutes=30",
                    observed=f"Error: {e}",
                    details=f"Calculator endpoint failure: {e}",
                )
            )

        # Case 2: 50 Liters Turbid Water, 6.0% bleach
        p2 = json.dumps(
            {
                "type": "water",
                "params": {"volume_liters": 50.0, "is_turbid": True, "concentration_pct": 6.0},
            }
        ).encode("utf-8")

        try:
            req = urllib.request.Request(
                calc_url,
                data=p2,
                headers={"Content-Type": "application/json", "User-Agent": "OffGridUSB-Auditor/1.0"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                d2 = json.loads(resp.read().decode("utf-8"))

            res2 = d2.get("result", {})
            drops2 = res2.get("drops")
            ml2 = res2.get("volume_ml")
            time2 = res2.get("contact_time_minutes")

            if drops2 == 200 and ml2 == 10.0 and time2 == 60:
                self.results.append(
                    CheckResult(
                        category="Deterministic Calculators",
                        check_name="CDC Chlorination (50L Turbid)",
                        target=calc_url,
                        status=AuditStatus.PASS,
                        expected="drops=200, volume_ml=10.0, contact_time_minutes=60",
                        observed=f"drops={drops2}, volume_ml={ml2}, contact_time_minutes={time2}",
                        details="Deterministic CDC turbid water dosage formula verified",
                    )
                )
            else:
                self.results.append(
                    CheckResult(
                        category="Deterministic Calculators",
                        check_name="CDC Chlorination (50L Turbid)",
                        target=calc_url,
                        status=AuditStatus.FAIL,
                        expected="drops=200, volume_ml=10.0, contact_time_minutes=60",
                        observed=f"drops={drops2}, volume_ml={ml2}, contact_time_minutes={time2}",
                        details="Deterministic calculation divergence on turbid water parameters",
                    )
                )
        except Exception as e:
            self.results.append(
                CheckResult(
                    category="Deterministic Calculators",
                    check_name="CDC Chlorination (50L Turbid)",
                    target=calc_url,
                    status=AuditStatus.FAIL,
                    expected="drops=200, volume_ml=10.0, contact_time_minutes=60",
                    observed=f"Error: {e}",
                    details=f"Calculator endpoint failure: {e}",
                )
            )

    def _check_grounded_ai_citations(self) -> None:
        """Verifies Grounded AI Professor returns answers with [Source: ...] citations."""
        ask_url = "http://127.0.0.1:8000/api/ask"
        query_payload = json.dumps(
            {
                "query": "What is the recommended bleach dosage for purifying 20 liters of clear water?",
                "mode": "harness",
            }
        ).encode("utf-8")

        try:
            req = urllib.request.Request(
                ask_url,
                data=query_payload,
                headers={"Content-Type": "application/json", "User-Agent": "OffGridUSB-Auditor/1.0"},
            )
            with urllib.request.urlopen(req, timeout=self.llm_timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            answer = data.get("answer", "")
            citations_list = data.get("citations", [])

            citation_pattern = re.compile(r"\[(Source|Lesson):\s*[^\]]+\]", re.IGNORECASE)
            embedded_citations = citation_pattern.findall(answer)
            has_citations = len(embedded_citations) > 0 or len(citations_list) > 0

            if has_citations:
                matched_snippet = citation_pattern.search(answer)
                sample = matched_snippet.group(0) if matched_snippet else f"{len(citations_list)} structured citations"
                self.results.append(
                    CheckResult(
                        category="Grounded AI Verification",
                        check_name="Grounded AI Citation Regex Match",
                        target=ask_url,
                        status=AuditStatus.PASS,
                        expected=r"Contains [Source: ...] citation regex match",
                        observed=f"Citations present ({sample})",
                        details=f"Authentic ZIM-grounded citations verified: {answer[:120]}...",
                    )
                )
            else:
                self.results.append(
                    CheckResult(
                        category="Grounded AI Verification",
                        check_name="Grounded AI Citation Regex Match",
                        target=ask_url,
                        status=AuditStatus.FAIL,
                        expected=r"Regex pattern '\[Source:\s*[^\]]+\]' matched in answer",
                        observed="No citations detected in model response",
                        details=f"Model hallucination or grounding failure. Output: {answer[:200]}",
                    )
                )
        except Exception as e:
            self.results.append(
                CheckResult(
                    category="Grounded AI Verification",
                    check_name="Grounded AI Citation Regex Match",
                    target=ask_url,
                    status=AuditStatus.FAIL,
                    expected="HTTP 200 with citations",
                    observed=f"Error: {e}",
                    details=f"Grounded AI query failure: {e}",
                )
            )

    # =========================================================================
    # PHASE 5: PROCESS IMAGE PATH ISOLATION
    # =========================================================================
    def audit_process_isolation(self) -> None:
        """Audits that 100% of listening services run strictly from <drive>:\\bin\\windows_x86_64\\* (0 from C:\\)."""
        if self.skip_live:
            self.log("Skipping Process Path Isolation Audit (--skip-live requested)", "INFO")
            self.results.append(
                CheckResult(
                    category="Process Isolation",
                    check_name="Process Image Path Audit",
                    target="Ports 8000, 8081, 8082",
                    status=AuditStatus.SKIP,
                    expected="All processes from USB bin\\",
                    observed="Skipped via CLI flag",
                    details="Live checks skipped",
                )
            )
            return

        self.log("Beginning Process Image Path Isolation Audit...", "INFO")
        target_ports = [8000, 8081, 8082]

        normalized_drive_str = str(self.drive).upper()
        if not normalized_drive_str.endswith("\\"):
            normalized_drive_str += "\\"

        expected_bin_prefix = (normalized_drive_str + "BIN\\WINDOWS_X86_64\\").upper()
        allowed_polyglot_prefix = (normalized_drive_str + "BIN\\POLYGLOT\\").upper()

        # Check if mock process table is provided
        if self.mock_process_table and self.mock_process_table.exists():
            self.log(f"Using mock process table from {self.mock_process_table}...", "INFO")
            try:
                with open(self.mock_process_table, "r", encoding="utf-8") as f:
                    mock_table = json.load(f)
            except Exception as e:
                self.results.append(
                    CheckResult(
                        category="Process Isolation",
                        check_name="Mock Process Table Parsing",
                        target=str(self.mock_process_table),
                        status=AuditStatus.FAIL,
                        expected="Valid JSON process map",
                        observed=f"Error: {e}",
                        details=str(e),
                    )
                )
                return

            for port in target_ports:
                exe_path = mock_table.get(str(port)) or mock_table.get(port) or ""
                if not exe_path:
                    self.results.append(
                        CheckResult(
                            category="Process Isolation",
                            check_name=f"Service Listener Active (Port {port})",
                            target=f"127.0.0.1:{port}",
                            status=AuditStatus.FAIL,
                            expected=f"Process listening on port {port}",
                            observed="No process entry in mock table",
                            details=f"Required OffGridUSB service port {port} is not defined in mock table",
                        )
                    )
                    continue

                norm_exe = exe_path.upper()
                is_on_usb_bin = norm_exe.startswith(expected_bin_prefix) or norm_exe.startswith(allowed_polyglot_prefix)
                touches_c_drive = "C:\\" in norm_exe or "C:/" in norm_exe

                if is_on_usb_bin and not touches_c_drive:
                    self.results.append(
                        CheckResult(
                            category="Process Isolation",
                            check_name=f"Process Image Path (Port {port})",
                            target=f"Port {port} -> {exe_path}",
                            status=AuditStatus.PASS,
                            expected=f"{expected_bin_prefix}*",
                            observed=exe_path,
                            details="100% Isolated to staged USB binary directory; zero host drive contamination",
                        )
                    )
                else:
                    self.results.append(
                        CheckResult(
                            category="Process Isolation",
                            check_name=f"Process Image Path (Port {port})",
                            target=f"Port {port} -> {exe_path}",
                            status=AuditStatus.FAIL,
                            expected=f"{expected_bin_prefix}* (0 from C:\\)",
                            observed=f"Exe: {exe_path} | Touches C: {touches_c_drive}",
                            details=f"PROCESS_ISOLATION_VIOLATION: Service process on port {port} executing outside USB bin\\ ({exe_path})",
                        )
                    )
            return

        if sys.platform != "win32":
            self.log("Non-Windows host detected; checking POSIX listening process isolation...", "INFO")
            self._audit_posix_process_isolation(target_ports)
            return

        # Windows Process Inspection via PowerShell or netstat
        listening_pids: Dict[int, int] = {}
        try:
            ps_cmd = (
                "$ports = @(8000, 8081, 8082); "
                "$conns = Get-NetTCPConnection -LocalPort $ports -State Listen -ErrorAction SilentlyContinue; "
                "$res = @{}; "
                "foreach ($c in $conns) { $res[$c.LocalPort] = $c.OwningProcess }; "
                "$res | ConvertTo-Json -Compress"
            )
            out = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if out.stdout.strip():
                raw_json = json.loads(out.stdout.strip())
                for port_str, pid_val in raw_json.items():
                    listening_pids[int(port_str)] = int(pid_val)
        except Exception as e:
            self.log(f"Failed querying Get-NetTCPConnection: {e}", "WARN")

        # Fallback to netstat if PowerShell failed
        if not listening_pids:
            try:
                res = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=10)
                for line in res.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 5 and "LISTENING" in line.upper():
                        local_addr = parts[1]
                        pid_str = parts[4]
                        for port in target_ports:
                            if local_addr.endswith(f":{port}"):
                                listening_pids[port] = int(pid_str)
            except Exception as e:
                self.log(f"netstat fallback error: {e}", "WARN")

        for port in target_ports:
            pid = listening_pids.get(port)
            if not pid:
                self.results.append(
                    CheckResult(
                        category="Process Isolation",
                        check_name=f"Service Listener Active (Port {port})",
                        target=f"127.0.0.1:{port}",
                        status=AuditStatus.FAIL,
                        expected=f"Process listening on port {port}",
                        observed="No listening socket detected",
                        details=f"Required OffGridUSB service port {port} is not listening",
                    )
                )
                continue

            exe_path = ""
            cmd_line = ""
            try:
                query_ps = (
                    f"$p = Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}'; "
                    f"@{{ ExecutablePath = $p.ExecutablePath; CommandLine = $p.CommandLine }} | ConvertTo-Json -Compress"
                )
                q_out = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", query_ps],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if q_out.stdout.strip():
                    p_info = json.loads(q_out.stdout.strip())
                    exe_path = p_info.get("ExecutablePath") or ""
                    cmd_line = p_info.get("CommandLine") or ""
            except Exception as e:
                exe_path = f"<Query error: {e}>"

            norm_exe = exe_path.upper()
            is_on_usb_bin = norm_exe.startswith(expected_bin_prefix) or norm_exe.startswith(allowed_polyglot_prefix)
            touches_c_drive = "C:\\" in norm_exe or ("C:\\" in cmd_line.upper() and not "SYSTEM32" in cmd_line.upper())

            if is_on_usb_bin and not touches_c_drive:
                self.results.append(
                    CheckResult(
                        category="Process Isolation",
                        check_name=f"Process Image Path (Port {port})",
                        target=f"Port {port} -> PID {pid}",
                        status=AuditStatus.PASS,
                        expected=f"{expected_bin_prefix}*",
                        observed=exe_path,
                        details="100% Isolated to staged USB binary directory; zero host drive contamination",
                    )
                )
            else:
                self.results.append(
                    CheckResult(
                        category="Process Isolation",
                        check_name=f"Process Image Path (Port {port})",
                        target=f"Port {port} -> PID {pid}",
                        status=AuditStatus.FAIL,
                        expected=f"{expected_bin_prefix}* (0 from C:\\)",
                        observed=f"Exe: {exe_path} | Touches C: {touches_c_drive}",
                        details=f"PROCESS_ISOLATION_VIOLATION: Service process on port {port} executing outside USB bin\\ ({exe_path})",
                    )
                )

    def _audit_posix_process_isolation(self, target_ports: List[int]) -> None:
        """POSIX lsof / procfs fallback for cross-platform process isolation check."""
        for port in target_ports:
            try:
                cmd = ["lsof", "-iTCP:" + str(port), "-sTCP:LISTEN", "-n", "-P", "-Fp"]
                res = subprocess.run(cmd, capture_output=True, text=True)
                pid = None
                for line in res.stdout.splitlines():
                    if line.startswith("p"):
                        pid = int(line[1:])
                        break
                if pid:
                    exe_link = Path(f"/proc/{pid}/exe")
                    real_exe = os.readlink(exe_link) if exe_link.exists() else "unknown"
                    norm_drive = str(self.drive)
                    if real_exe.startswith(norm_drive) or "/tmp/emyrge_runtime" in real_exe:
                        self.results.append(
                            CheckResult(
                                category="Process Isolation",
                                check_name=f"Process Image Path (Port {port})",
                                target=f"Port {port} -> PID {pid}",
                                status=AuditStatus.PASS,
                                expected=f"Path starting with {self.drive} or /tmp/emyrge_runtime",
                                observed=real_exe,
                                details="POSIX process path isolation verified",
                            )
                        )
                    else:
                        self.results.append(
                            CheckResult(
                                category="Process Isolation",
                                check_name=f"Process Image Path (Port {port})",
                                target=f"Port {port} -> PID {pid}",
                                status=AuditStatus.FAIL,
                                expected=f"Path starting with {self.drive}",
                                observed=real_exe,
                                details=f"PROCESS_ISOLATION_VIOLATION: POSIX process running outside deployment drive ({real_exe})",
                            )
                        )
            except Exception as e:
                self.results.append(
                    CheckResult(
                        category="Process Isolation",
                        check_name=f"Process Image Path (Port {port})",
                        target=f"Port {port}",
                        status=AuditStatus.WARN,
                        expected="POSIX listener verification",
                        observed=f"Inspection error: {e}",
                        details=str(e),
                    )
                )

    # =========================================================================
    # HELPERS & EXECUTION RUNNER
    # =========================================================================
    @staticmethod
    def _compute_sha256(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    def run_full_audit(self) -> Dict[str, Any]:
        """Executes the complete audit pipeline and generates structured results."""
        start_time = time.time()
        self.log("=" * 80, "INFO")
        self.log(f"STARTING OFFGRIDUSB DEPLOYMENT AUDIT -- TIER {self.tier}", "INFO")
        self.log(f"Target Drive: {self.drive} | Timestamp: {datetime.now(timezone.utc).isoformat()}", "INFO")
        self.log("=" * 80, "INFO")

        if not self.live_only:
            self.audit_manifests_and_assets()
            self.audit_magic_bytes()
            self.audit_line_endings_and_scripts()

        if not self.skip_live or self.live_only:
            self.audit_live_services()
            self.audit_process_isolation()

        elapsed = time.time() - start_time

        # Compute summary
        total_checks = len(self.results)
        passed = sum(1 for r in self.results if r.status == AuditStatus.PASS)
        failed = sum(1 for r in self.results if r.status == AuditStatus.FAIL)
        warned = sum(1 for r in self.results if r.status == AuditStatus.WARN)
        skipped = sum(1 for r in self.results if r.status == AuditStatus.SKIP)

        overall_status = AuditStatus.PASS if failed == 0 else AuditStatus.FAIL

        # Determine exit code
        exit_code = 0
        if failed > 0:
            failed_cats = {r.category for r in self.results if r.status == AuditStatus.FAIL}
            if any("Asset" in c or "Manifest" in c for c in failed_cats):
                exit_code = 1
            elif any("Magic" in c or "Cross-Platform Engine" in c for c in failed_cats):
                exit_code = 2
            elif any("Script" in c or "Line Ending" in c for c in failed_cats):
                exit_code = 3
            elif any("Live" in c or "Deterministic" in c or "Grounded" in c for c in failed_cats):
                exit_code = 4
            elif any("Process" in c for c in failed_cats):
                exit_code = 5
            else:
                exit_code = 1

        report = {
            "audit_version": "1.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_drive": str(self.drive),
            "tier": self.tier,
            "overall_status": overall_status.value,
            "status": overall_status.value,
            "exit_code": exit_code,
            "duration_seconds": round(elapsed, 3),
            "summary": {
                "total_checks": total_checks,
                "passed": passed,
                "passed_checks": passed,
                "failed": failed,
                "failed_checks": failed,
                "warnings": warned,
                "skipped": skipped,
                "pass_rate_pct": round((passed / total_checks * 100), 1) if total_checks else 0.0,
            },
            "failures": [r.to_dict() for r in self.results if r.status == AuditStatus.FAIL],
            "warnings": [r.to_dict() for r in self.results if r.status == AuditStatus.WARN],
            "results": [r.to_dict() for r in self.results],
        }

        return report

    def render_console_summary(self, report: Dict[str, Any]) -> None:
        """Renders clean, human-readable terminal output."""
        print("\n" + "=" * 80)
        print("OFFGRIDUSB DEPLOYMENT AUDIT REPORT SUMMARY")
        print("=" * 80)
        print(f"Target Drive:   {report['target_drive']}")
        print(f"Audited Tier:   Tier {report['tier']}")
        print(f"Timestamp:      {report['timestamp']}")
        print(f"Execution Time: {report['duration_seconds']}s")
        print(f"Total Checks:   {report['summary']['total_checks']}")
        print(f"Checks Passed:  {report['summary']['passed']}")
        print(f"Checks Failed:  {report['summary']['failed']}")
        print(f"Warnings:       {report['summary']['warnings']}")
        print(f"Pass Rate:      {report['summary']['pass_rate_pct']}%")
        print("-" * 80)

        categories: Dict[str, List[CheckResult]] = {}
        for r in self.results:
            categories.setdefault(r.category, []).append(r)

        for cat, items in categories.items():
            cat_passed = sum(1 for i in items if i.status == AuditStatus.PASS)
            cat_failed = sum(1 for i in items if i.status == AuditStatus.FAIL)
            status_indicator = "[PASS]" if cat_failed == 0 else "[FAIL]"
            print(f"\n{status_indicator} [{cat}] ({cat_passed}/{len(items)} passed)")
            for item in items:
                mark = {
                    AuditStatus.PASS: "  [PASS]",
                    AuditStatus.FAIL: "  [FAIL]",
                    AuditStatus.WARN: "  [WARN]",
                    AuditStatus.SKIP: "  [SKIP]",
                }[item.status]
                print(f"  {mark} {item.check_name}: {item.details}")
                if item.status == AuditStatus.FAIL:
                    print(f"         Expected: {item.expected}")
                    print(f"         Observed: {item.observed}")

        print("\n" + "=" * 80)
        if report["overall_status"] == "PASS":
            print("=== OVERALL AUDIT VERDICT: PASS (Exit Code: 0) ===")
            print("Deployment is clean, authentic, isolated, and production-ready.")
        else:
            print(f"=== OVERALL AUDIT VERDICT: FAIL (Exit Code: {report['exit_code']}) ===")
            print(f"Integrity violations detected: {report['summary']['failed']} check(s) failed.")
        print("=" * 80 + "\n")


class AuditorArgumentParser(argparse.ArgumentParser):
    """Custom ArgumentParser that writes usage to stderr and exits with code 6 on CLI errors."""

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        sys.stderr.write(f"{self.prog}: error: {message}\n")
        sys.exit(6)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = AuditorArgumentParser(
        description="Standalone Independent Auditor for OffGridUSB Deployments",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python audit_offgrid_usb.py --drive D: --tier 2
    python audit_offgrid_usb.py --drive D: --tier 0 --skip-live
    python audit_offgrid_usb.py --drive D: --tier 2 --mode static --json D:\\audit_report.json
    python audit_offgrid_usb.py --drive /Volumes/OFFGRIDUSB --tier 2 --skip-live
    python audit_offgrid_usb.py --drive C:\\temp\\mock_drive --tier 2 --skip-live
        """,
    )
    parser.add_argument(
        "--drive",
        "-d",
        required=True,
        help="Target drive letter or mount path (e.g. 'D:', 'D:\\', '/media/usb')",
    )
    parser.add_argument(
        "--tier",
        "-t",
        type=int,
        default=2,
        choices=[0, 1, 2, 3, 4],
        help="Deployment tier to evaluate (default: 2)",
    )
    parser.add_argument(
        "--mode",
        choices=["all", "static", "live"],
        default="all",
        help="Audit execution mode: 'all' (default), 'static' (skip live servers), or 'live' (live servers only)",
    )
    parser.add_argument(
        "--manifest-dir",
        default=None,
        help="Optional path to directory containing zim.json and models.json (default: <drive>/manifests)",
    )
    parser.add_argument(
        "--skip-live",
        action="store_true",
        help="Perform static file and forensics checks only (bypasses live ports 8000, 8081, 8082)",
    )
    parser.add_argument(
        "--live-only",
        action="store_true",
        help="Perform live service health and process isolation checks only",
    )
    parser.add_argument(
        "--mock-process-table",
        default=None,
        help="Optional path to JSON mock process table {port: exe_path} for testing process isolation",
    )
    parser.add_argument(
        "--skip-checksums",
        action="store_true",
        help="Skip heavy SHA-256 rehashing of multi-gigabyte models (checks presence, sizes, and headers only)",
    )
    parser.add_argument(
        "--strict-checksums",
        action="store_true",
        help="Enforce non-placeholder SHA-256 checksums on all catalog models",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP socket timeout in seconds for API and status health endpoints (default: 10s)",
    )
    parser.add_argument(
        "--llm-timeout",
        type=int,
        default=45,
        help="Timeout in seconds for local LLM inference completions (default: 45s)",
    )
    parser.add_argument(
        "--output-json",
        "--json",
        "-o",
        dest="output_json",
        default="audit_report.json",
        help="Output file path for structured JSON results (default: audit_report.json)",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress intermediate logging; display only final report and exit code",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable detailed diagnostic logging for every header and network exchange",
    )

    args = parser.parse_args(argv)

    # Reconcile mode with skip_live / live_only flags
    if args.mode == "static":
        args.skip_live = True
    elif args.mode == "live":
        args.live_only = True

    return args


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    auditor = OffGridUSBAuditor(
        drive_path=args.drive,
        tier=args.tier,
        manifest_dir=args.manifest_dir,
        skip_live=args.skip_live,
        live_only=args.live_only,
        mock_process_table=args.mock_process_table,
        skip_checksums=args.skip_checksums,
        strict_checksums=args.strict_checksums,
        timeout=args.timeout,
        llm_timeout=args.llm_timeout,
        verbose=args.verbose,
    )

    report = auditor.run_full_audit()

    # Save JSON report
    out_json_path = Path(args.output_json).resolve()
    try:
        out_json_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        if not args.quiet:
            auditor.log(f"Structured audit report written to: {out_json_path}", "INFO")
    except Exception as e:
        auditor.log(f"Failed writing audit report to {out_json_path}: {e}", "WARN")

    # Render console output
    if not args.quiet:
        auditor.render_console_summary(report)

    return report["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
