#!/usr/bin/env python3
r"""
Adversarial Mutation & Negative Verification Test Suite for audit_offgrid_usb.py.

Verifies Acceptance Criteria R5:
1. Asserts PASS and exit code 0 on a clean, valid deployment.
2. Introduces controlled mutations one by one, asserting non-zero exit code
   and structured FAIL details:
   - Mutation A1: Missing ZIM archive
   - Mutation A2: Truncated ZIM archive (<4 bytes or undersized)
   - Mutation B:  Corrupted magic bytes in .zim (0x00000000 vs 0x5A494D04)
   - Mutation C:  Corrupted magic bytes in .gguf (b"FAKE" vs b"GGUF")
   - Mutation D:  Injected CRLF (\r\n) in POSIX shell launcher
   - Mutation E1: Missing root launcher script (.bat, .sh, .command)
   - Mutation E2: Missing cross-platform runtime engine tarball (.tar.gz)
   - Mutation F:  Simulated process path violation (service running from C:\)
   - Mutation G:  Invalid shebang line in POSIX launcher
   - Mutation H:  Corrupted ELF magic (\x00ELF) inside compressed tarball
   - Mutation I:  Injected UTF-8 Byte Order Mark (BOM) in POSIX script

Zero external pip dependencies: 100% Python 3 standard library.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple
import unittest


# ==============================================================================
# Binary Signatures & Standards Constants
# ==============================================================================

ZIM_MAGIC_LE = b"\x5a\x49\x4d\x04"       # 'ZIM\x04' in little-endian uint32 (0x044D495A)
ZIM_MAGIC_INT_LE = 0x044D495A
ZIM_MAGIC_INT_BE = 0x5A494D04

GGUF_MAGIC = b"GGUF"                     # GGUF model container header
GZIP_MAGIC = b"\x1f\x8b"                 # POSIX gzip archive header
ELF_IDENT_64_LE = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8  # 16-byte ELF e_ident
MACHO_64_MAGIC_LE = b"\xcf\xfa\xed\xfe"  # Mach-O 64-bit Little-Endian (0xCFFAEDFE)
APE_MAGIC = b"MZqFpD\n\x00"              # Cosmopolitan Actually Portable Executable

PE_EXE_MAGIC = b"MZ\x90\x00"


# ==============================================================================
# Mock Drive Generator
# ==============================================================================

class MockOffGridDriveGenerator:
    """Constructs a lightweight, fully conformant mock OffGridUSB deployment root."""

    def __init__(self, tier: int = 0):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="mock_offgrid_drive_")
        self.root = Path(self.temp_dir.name).resolve()
        self.tier = tier
        self.build_mock_deployment()

    def build_mock_deployment(self):
        """Constructs directory tree, manifests, launchers, binaries, and assets."""
        # 1. Directories
        dirs = [
            "bin/windows_x86_64/python",
            "bin/windows_x86_64/kiwix",
            "bin/windows_x86_64/llama",
            "bin/windows_arm64/llama",
            "bin/linux_x86_64",
            "bin/linux_arm64",
            "bin/macos_x86_64",
            "bin/macos_arm64",
            "bin/polyglot",
            "data/zim",
            "data/models",
            "data/vault",
            "data/uploads",
            "manifests",
            "scripts",
            "docs",
            "src/emyrge/calculators",
            "src/emyrge/web",
            "src/emyrge/ai",
            "web/static",
        ]
        for d in dirs:
            (self.root / d).mkdir(parents=True, exist_ok=True)

        # 2. Manifests
        self._write_manifests()

        # 3. Root Launchers
        self._write_launchers()

        # 4. Windows Binaries
        self._write_windows_binaries()

        # 5. Cross-Platform Tarballs (with valid embedded ELF and Mach-O binaries)
        self._write_posix_tarballs()

        # 6. Polyglot llamafile
        (self.root / "bin/polyglot/llamafile.exe").write_bytes(APE_MAGIC + b"\x00" * 1024)

        # 7. Knowledge Assets (ZIM archives)
        self._write_zim_archives()

        # 8. Model Assets (GGUF models)
        self._write_gguf_models()

        # 9. Readme & Docs
        (self.root / "README.md").write_text("# OffGridUSB Mock Deployment\n", encoding="utf-8")
        (self.root / "CONTRIBUTING.md").write_text("# Contributing Guide\n", encoding="utf-8")

    def _write_manifests(self):
        zim_manifest = {
            "schema_version": "1.0",
            "archives": [
                {
                    "id": "zimgit-water",
                    "filename": "zimgit-water_en_2024-08.zim",
                    "tier": 0,
                    "size_bytes": 102400,
                },
                {
                    "id": "zimgit-medicine",
                    "filename": "zimgit-medicine_en_2024-08.zim",
                    "tier": 0,
                    "size_bytes": 102400,
                },
                {
                    "id": "wikipedia-medicine-mini",
                    "filename": "wikipedia_en_medicine_mini_2026-10.zim",
                    "tier": 0,
                    "size_bytes": 102400,
                },
                {
                    "id": "wikipedia-top-mini",
                    "filename": "wikipedia_en_top_mini_2026-09.zim",
                    "tier": 0,
                    "size_bytes": 102400,
                },
            ],
        }
        (self.root / "manifests/zim.json").write_text(json.dumps(zim_manifest, indent=2), encoding="utf-8")

        models_manifest = {
            "schema_version": "1.0",
            "models": [
                {
                    "id": "smollm2-135m-q4",
                    "filename": "smollm2-135m-instruct-q4_k_m.gguf",
                    "tier": 0,
                    "size_bytes": 204800,
                },
                {
                    "id": "qwen2.5-0.5b-q4",
                    "filename": "qwen2.5-0.5b-instruct-q4_k_m.gguf",
                    "tier": 0,
                    "size_bytes": 204800,
                },
            ],
        }
        (self.root / "manifests/models.json").write_text(json.dumps(models_manifest, indent=2), encoding="utf-8")

        hardware_manifest = {
            "schema_version": "1.0",
            "supported_architectures": ["windows_x86_64", "linux_x86_64", "linux_arm64", "macos_x86_64", "macos_arm64"],
        }
        (self.root / "manifests/hardware.json").write_text(json.dumps(hardware_manifest, indent=2), encoding="utf-8")

    def _write_launchers(self):
        # Windows batch scripts: CRLF permitted
        bat_files = [
            "START_OFFGRIDUSB_WINDOWS.bat",
            "START_EMYRGE_WINDOWS.bat",
            "run_windows.bat",
            "FORMAT_AND_SETUP_USB.bat",
            "DOWNLOAD_INTERNET_IN_A_BOX.bat",
            "MAKE_USB_DRIVES.bat",
        ]
        for bat in bat_files:
            content = f"@echo off\r\nrem OffGridUSB Launcher: {bat}\r\nset EMYRGE_PORT=8000\r\n"
            (self.root / bat).write_bytes(content.encode("ascii"))

        # POSIX shell scripts: Strict LF line endings (0 CRLF), valid shebang
        sh_files = [
            "START_OFFGRIDUSB_LINUX.sh",
            "START_EMYRGE_LINUX.sh",
            "run_linux.sh",
            "START_OFFGRIDUSB_MAC.command",
            "START_EMYRGE_MAC.command",
            "run_macos.command",
            "scripts/download_internet_in_a_box.sh",
            "scripts/setup_usb_unix.sh",
        ]
        for sh in sh_files:
            content = f"#!/usr/bin/env bash\n# OffGridUSB Script: {sh}\nset -euo pipefail\nexport EMYRGE_PORT=8000\n"
            (self.root / sh).write_bytes(content.encode("ascii"))

    def _write_windows_binaries(self):
        for p in [
            "bin/windows_x86_64/python/python.exe",
            "bin/windows_x86_64/kiwix/kiwix-serve.exe",
            "bin/windows_x86_64/llama/llama-server.exe",
        ]:
            (self.root / p).write_bytes(PE_EXE_MAGIC + b"\x00" * 4096)
        (self.root / "bin/windows_x86_64/python/python312._pth").write_text("..\\..\\..\\src\n.\n", encoding="utf-8")

    def _create_tarball(self, dest_path: Path, member_name: str, payload: bytes):
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        bio = io.BytesIO()
        with tarfile.open(fileobj=bio, mode="w:gz") as tar:
            ti = tarfile.TarInfo(name=member_name)
            ti.size = len(payload)
            ti.mode = 0o755
            ti.mtime = int(time.time())
            tar.addfile(ti, io.BytesIO(payload))
        dest_path.write_bytes(bio.getvalue())

    def _write_posix_tarballs(self):
        # 1. Linux x86_64: Standard ELF 64-bit LE:
        # e_ident: 16 bytes (0..15)
        # e_type: 2 bytes uint16 = 2 (ET_EXEC) at offset 16..17
        # e_machine: 2 bytes uint16 = 0x003E (AMD x86-64) at offset 18..19
        elf_x64 = ELF_IDENT_64_LE + struct.pack("<H", 2) + struct.pack("<H", 0x003E) + b"\x00" * 512
        self._create_tarball(
            self.root / "bin/linux_x86_64/kiwix-tools_linux-x86_64.tar.gz",
            "kiwix-tools_linux-x86_64/kiwix-serve",
            elf_x64,
        )
        self._create_tarball(
            self.root / "bin/linux_x86_64/llama-ubuntu-x64.tar.gz",
            "llama-server",
            elf_x64,
        )

        # 2. Linux arm64: Standard ELF 64-bit LE, machine 0x00B7 (AArch64) at offset 18..19
        elf_arm64 = ELF_IDENT_64_LE + struct.pack("<H", 2) + struct.pack("<H", 0x00B7) + b"\x00" * 512
        self._create_tarball(
            self.root / "bin/linux_arm64/kiwix-tools_linux-aarch64.tar.gz",
            "kiwix-tools_linux-aarch64/kiwix-serve",
            elf_arm64,
        )
        self._create_tarball(
            self.root / "bin/linux_arm64/llama-ubuntu-arm64.tar.gz",
            "llama-server",
            elf_arm64,
        )

        # 3. macOS x86_64: Mach-O 64-bit LE, CPU type 0x01000007 at offset 4..7
        macho_x64 = MACHO_64_MAGIC_LE + struct.pack("<I", 0x01000007) + b"\x00" * 512
        self._create_tarball(
            self.root / "bin/macos_x86_64/kiwix-tools_macos-x86_64.tar.gz",
            "kiwix-tools_macos-x86_64/kiwix-serve",
            macho_x64,
        )
        self._create_tarball(
            self.root / "bin/macos_x86_64/llama-macos-x64.tar.gz",
            "llama-server",
            macho_x64,
        )

        # 4. macOS arm64: Mach-O 64-bit LE, CPU type 0x0100000C at offset 4..7
        macho_arm64 = MACHO_64_MAGIC_LE + struct.pack("<I", 0x0100000C) + b"\x00" * 512
        self._create_tarball(
            self.root / "bin/macos_arm64/kiwix-tools_macos.tar.gz",
            "kiwix-tools_macos-arm64/kiwix-serve",
            macho_arm64,
        )
        self._create_tarball(
            self.root / "bin/macos_arm64/llama-macos-arm64.tar.gz",
            "llama-server",
            macho_arm64,
        )

    def _write_zim_archives(self):
        zims = [
            "zimgit-water_en_2024-08.zim",
            "zimgit-medicine_en_2024-08.zim",
            "wikipedia_en_medicine_mini_2026-10.zim",
            "wikipedia_en_top_mini_2026-09.zim",
        ]
        for z in zims:
            payload = ZIM_MAGIC_LE + b"\x00" * (100 * 1024)
            (self.root / "data/zim" / z).write_bytes(payload)

    def _write_gguf_models(self):
        models = [
            "smollm2-135m-instruct-q4_k_m.gguf",
            "qwen2.5-0.5b-instruct-q4_k_m.gguf",
        ]
        for m in models:
            payload = GGUF_MAGIC + struct.pack("<I", 3) + b"\x00" * (200 * 1024)
            (self.root / "data/models" / m).write_bytes(payload)

    def cleanup(self):
        self.temp_dir.cleanup()


# ==============================================================================
# Auditor Subprocess Runner
# ==============================================================================

@dataclass
class AuditRunResult:
    exit_code: int
    stdout: str
    stderr: str
    report_data: Optional[Dict[str, Any]]
    report_file: Optional[Path]


class AuditorSubprocessRunner:
    """Executes audit_offgrid_usb.py in a dedicated subprocess and parses results."""

    def __init__(self, script_path: Optional[Path] = None):
        self.script_path = script_path or self._resolve_auditor_script()

    def _resolve_auditor_script(self) -> Path:
        """Finds audit_offgrid_usb.py in standard repository and agent locations."""
        candidates = [
            Path("audit_offgrid_usb.py"),
            Path("scripts/audit_offgrid_usb.py"),
            Path(__file__).resolve().parent.parent.parent / "scripts/audit_offgrid_usb.py",
            Path(__file__).resolve().parent.parent.parent / "audit_offgrid_usb.py",
            Path("C:/Users/ndoki/Desktop/offgridusb/offgridUSB.com/audit_offgrid_usb.py"),
            Path("C:/Users/ndoki/Desktop/offgridusb/offgridUSB.com/scripts/audit_offgrid_usb.py"),
            Path("D:/audit_offgrid_usb.py"),
            Path("D:/scripts/audit_offgrid_usb.py"),
        ]
        for c in candidates:
            if c.exists():
                return c.resolve()
        return Path("audit_offgrid_usb.py").resolve()

    def run(
        self,
        drive_path: Path,
        tier: int = 0,
        mode: str = "static",
        mock_process_table: Optional[Path] = None,
        extra_args: Optional[List[str]] = None,
    ) -> AuditRunResult:
        with tempfile.NamedTemporaryFile(prefix="audit_out_", suffix=".json", delete=False) as tf:
            report_path = Path(tf.name)

        cmd = [
            sys.executable,
            str(self.script_path),
            "--drive", str(drive_path),
            "--tier", str(tier),
            "--mode", mode,
            "--json", str(report_path),
        ]
        if mock_process_table and mock_process_table.exists():
            cmd.extend(["--mock-process-table", str(mock_process_table)])
        if extra_args:
            cmd.extend(extra_args)

        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )

        report_data = None
        if report_path.exists() and report_path.stat().st_size > 0:
            try:
                with open(report_path, "r", encoding="utf-8") as f:
                    report_data = json.load(f)
            except Exception:
                pass

        try:
            report_path.unlink(missing_ok=True)
        except Exception:
            pass

        return AuditRunResult(
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            report_data=report_data,
            report_file=report_path,
        )


# ==============================================================================
# Adversarial Mutation & Negative Verification Test Suite
# ==============================================================================

class TestAuditMutations(unittest.TestCase):
    """Adversarial negative mutation test harness for audit_offgrid_usb.py."""

    auditor_runner: AuditorSubprocessRunner

    @classmethod
    def setUpClass(cls):
        auditor_arg = getattr(cls, "_custom_auditor_path", None)
        cls.auditor_runner = AuditorSubprocessRunner(auditor_arg)

    def setUp(self):
        self.mock_drive = MockOffGridDriveGenerator(tier=0)
        self.root = self.mock_drive.root

    def tearDown(self):
        self.mock_drive.cleanup()

    # --------------------------------------------------------------------------
    # Test 0: Baseline Zero-Defect Deployment
    # --------------------------------------------------------------------------
    def test_00_baseline_valid_deployment_passes(self):
        """Baseline check: A clean, complete deployment must return exit code 0 and PASS."""
        res = self.auditor_runner.run(self.root, tier=0, mode="static")
        self.assertEqual(res.exit_code, 0, f"Baseline deployment failed with stderr: {res.stderr}\nstdout: {res.stdout}")
        self.assertIsNotNone(res.report_data, "Auditor failed to write structured JSON report")
        self.assertEqual(res.report_data.get("status"), "PASS")
        self.assertEqual(len(res.report_data.get("failures", [])), 0)
        self.assertEqual(res.report_data.get("summary", {}).get("failed_checks"), 0)

    # --------------------------------------------------------------------------
    # Mutation A: Truncated or Missing ZIM File
    # --------------------------------------------------------------------------
    def test_01_mutation_a1_missing_zim_fails(self):
        """Mutation A1: Deleting a required ZIM archive must trigger exit code non-zero and FAIL."""
        target_zim = self.root / "data/zim/zimgit-water_en_2024-08.zim"
        self.assertTrue(target_zim.exists())
        target_zim.unlink()

        res = self.auditor_runner.run(self.root, tier=0, mode="static")
        self.assertNotEqual(res.exit_code, 0, "Auditor returned 0 despite missing ZIM archive")
        self.assertIsNotNone(res.report_data)
        self.assertEqual(res.report_data.get("status"), "FAIL")

        failures = res.report_data.get("failures", [])
        self.assertGreaterEqual(len(failures), 1)
        found_finding = any(
            "zimgit-water_en_2024-08.zim" in (f.get("target", "") or f.get("message", ""))
            for f in failures
        )
        self.assertTrue(found_finding, f"Expected failure finding for missing ZIM, got: {failures}")

    def test_02_mutation_a2_truncated_zim_fails(self):
        """Mutation A2: Truncating a ZIM archive below header length (2 bytes) must fail."""
        target_zim = self.root / "data/zim/zimgit-medicine_en_2024-08.zim"
        target_zim.write_bytes(b"\x5a\x49")

        res = self.auditor_runner.run(self.root, tier=0, mode="static")
        self.assertNotEqual(res.exit_code, 0, "Auditor returned 0 on truncated ZIM archive")
        self.assertIsNotNone(res.report_data)
        self.assertEqual(res.report_data.get("status"), "FAIL")

        failures = res.report_data.get("failures", [])
        found_finding = any(
            "zimgit-medicine_en_2024-08.zim" in (f.get("target", "") or f.get("message", ""))
            for f in failures
        )
        self.assertTrue(found_finding, f"Expected truncation failure finding, got: {failures}")

    # --------------------------------------------------------------------------
    # Mutation B: Corrupted Magic Bytes in .zim
    # --------------------------------------------------------------------------
    def test_03_mutation_b_corrupt_zim_magic_fails(self):
        """Mutation B: Corrupting .zim magic header (0x00000000 vs 0x5A494D04) must fail."""
        target_zim = self.root / "data/zim/wikipedia_en_medicine_mini_2026-10.zim"
        with open(target_zim, "r+b") as f:
            f.seek(0)
            f.write(b"\x00\x00\x00\x00")

        res = self.auditor_runner.run(self.root, tier=0, mode="static")
        self.assertNotEqual(res.exit_code, 0, "Auditor returned 0 on corrupted ZIM magic bytes")
        self.assertIsNotNone(res.report_data)
        self.assertEqual(res.report_data.get("status"), "FAIL")

        failures = res.report_data.get("failures", [])
        found_magic_err = any(
            "wikipedia_en_medicine_mini_2026-10.zim" in (f.get("target", "") or f.get("message", "")) and
            ("MAGIC" in f.get("category", "").upper() or "0x00000000" in f.get("message", "") or "0x5A494D04" in f.get("expected", ""))
            for f in failures
        )
        self.assertTrue(found_magic_err, f"Expected ZIM magic byte error, got: {failures}")

    # --------------------------------------------------------------------------
    # Mutation C: Corrupted Magic Bytes in GGUF
    # --------------------------------------------------------------------------
    def test_04_mutation_c_corrupt_gguf_magic_fails(self):
        """Mutation C: Corrupting GGUF magic bytes (b'FAKE' vs b'GGUF') must fail."""
        target_model = self.root / "data/models/smollm2-135m-instruct-q4_k_m.gguf"
        with open(target_model, "r+b") as f:
            f.seek(0)
            f.write(b"FAKE")

        res = self.auditor_runner.run(self.root, tier=0, mode="static")
        self.assertNotEqual(res.exit_code, 0, "Auditor returned 0 on corrupted GGUF magic bytes")
        self.assertIsNotNone(res.report_data)
        self.assertEqual(res.report_data.get("status"), "FAIL")

        failures = res.report_data.get("failures", [])
        found_model_err = any(
            "smollm2-135m-instruct-q4_k_m.gguf" in (f.get("target", "") or f.get("message", "")) and
            ("MAGIC" in f.get("category", "").upper() or "FAKE" in f.get("actual", "") or "GGUF" in f.get("expected", "") or "GGUF" in f.get("message", ""))
            for f in failures
        )
        self.assertTrue(found_model_err, f"Expected GGUF magic byte failure, got: {failures}")

    # --------------------------------------------------------------------------
    # Mutation D: Injected CRLF in Shell Script
    # --------------------------------------------------------------------------
    def test_05_mutation_d_injected_crlf_fails(self):
        """Mutation D: Injecting \\r\\n in POSIX launcher (START_OFFGRIDUSB_LINUX.sh) must fail."""
        target_sh = self.root / "START_OFFGRIDUSB_LINUX.sh"
        content = target_sh.read_bytes()
        mutated = content.replace(b"\n", b"\r\n")
        target_sh.write_bytes(mutated)

        res = self.auditor_runner.run(self.root, tier=0, mode="static")
        self.assertNotEqual(res.exit_code, 0, "Auditor returned 0 on shell script with injected CRLF")
        self.assertIsNotNone(res.report_data)
        self.assertEqual(res.report_data.get("status"), "FAIL")

        failures = res.report_data.get("failures", [])
        found_crlf_err = any(
            "START_OFFGRIDUSB_LINUX.sh" in (f.get("target", "") or f.get("message", "")) and
            ("CRLF" in f.get("category", "").upper() or "CRLF" in f.get("message", "").upper() or "LINE_ENDING" in f.get("category", "").upper())
            for f in failures
        )
        self.assertTrue(found_crlf_err, f"Expected CRLF detection finding, got: {failures}")

    # --------------------------------------------------------------------------
    # Mutation E: Missing Launcher Script or Missing Cross-Platform Tarball
    # --------------------------------------------------------------------------
    def test_06_mutation_e1_missing_launcher_fails(self):
        """Mutation E1: Removing START_OFFGRIDUSB_MAC.command must trigger audit FAIL."""
        target_launcher = self.root / "START_OFFGRIDUSB_MAC.command"
        self.assertTrue(target_launcher.exists())
        target_launcher.unlink()

        res = self.auditor_runner.run(self.root, tier=0, mode="static")
        self.assertNotEqual(res.exit_code, 0, "Auditor returned 0 when root launcher is missing")
        self.assertIsNotNone(res.report_data)
        self.assertEqual(res.report_data.get("status"), "FAIL")

        failures = res.report_data.get("failures", [])
        found_launcher_err = any(
            "START_OFFGRIDUSB_MAC.command" in (f.get("target", "") or f.get("message", ""))
            for f in failures
        )
        self.assertTrue(found_launcher_err, f"Expected missing launcher finding, got: {failures}")

    def test_07_mutation_e2_missing_tarball_fails(self):
        """Mutation E2: Removing bin/linux_x86_64/kiwix-tools_linux-x86_64.tar.gz must fail."""
        target_tarball = self.root / "bin/linux_x86_64/kiwix-tools_linux-x86_64.tar.gz"
        self.assertTrue(target_tarball.exists())
        target_tarball.unlink()

        res = self.auditor_runner.run(self.root, tier=0, mode="static")
        self.assertNotEqual(res.exit_code, 0, "Auditor returned 0 when cross-platform tarball is missing")
        self.assertIsNotNone(res.report_data)
        self.assertEqual(res.report_data.get("status"), "FAIL")

        failures = res.report_data.get("failures", [])
        found_tarball_err = any(
            "kiwix-tools_linux-x86_64.tar.gz" in (f.get("target", "") or f.get("message", ""))
            for f in failures
        )
        self.assertTrue(found_tarball_err, f"Expected missing tarball finding, got: {failures}")

    # --------------------------------------------------------------------------
    # Mutation F: Simulated Process Path Violation
    # --------------------------------------------------------------------------
    def test_08_mutation_f_process_path_violation_fails(self):
        """Mutation F: Simulating a daemon listening from C:\\ must trigger boundary FAIL."""
        proc_table_path = self.root / "mock_process_table.json"
        mock_proc_data = {
            "8000": f"{self.root}\\bin\\windows_x86_64\\python\\python.exe",
            "8081": "C:\\Program Files\\Kiwix\\kiwix-serve.exe",  # VIOLATION: Host C: drive
            "8082": f"{self.root}\\bin\\windows_x86_64\\llama\\llama-server.exe",
        }
        proc_table_path.write_text(json.dumps(mock_proc_data, indent=2), encoding="utf-8")

        res = self.auditor_runner.run(
            self.root,
            tier=0,
            mode="live",
            mock_process_table=proc_table_path,
        )
        self.assertNotEqual(res.exit_code, 0, "Auditor returned 0 despite process running from C:\\")
        self.assertIsNotNone(res.report_data)
        self.assertEqual(res.report_data.get("status"), "FAIL")

        failures = res.report_data.get("failures", [])
        found_proc_err = any(
            "8081" in (f.get("target", "") or f.get("message", "")) or
            "C:\\Program Files" in f.get("message", "") or
            "PROCESS_ISOLATION" in f.get("category", "").upper()
            for f in failures
        )
        self.assertTrue(found_proc_err, f"Expected process path isolation finding, got: {failures}")

    # --------------------------------------------------------------------------
    # Mutation G: Invalid Shebang
    # --------------------------------------------------------------------------
    def test_09_mutation_g_invalid_shebang_fails(self):
        """Mutation G: Non-portable or corrupted shebang line must trigger audit FAIL."""
        target_sh = self.root / "run_linux.sh"
        target_sh.write_text("#!/bin/broken_custom_shell_path\nexit 0\n", encoding="ascii")

        res = self.auditor_runner.run(self.root, tier=0, mode="static")
        self.assertNotEqual(res.exit_code, 0, "Auditor returned 0 on invalid shebang")
        self.assertIsNotNone(res.report_data)
        self.assertEqual(res.report_data.get("status"), "FAIL")

        failures = res.report_data.get("failures", [])
        found_shebang_err = any(
            "run_linux.sh" in (f.get("target", "") or f.get("message", "")) and
            ("SHEBANG" in f.get("category", "").upper() or "SHEBANG" in f.get("message", "").upper())
            for f in failures
        )
        self.assertTrue(found_shebang_err, f"Expected shebang syntax finding, got: {failures}")

    # --------------------------------------------------------------------------
    # Mutation H: Corrupted Internal ELF Member in Tarball
    # --------------------------------------------------------------------------
    def test_10_mutation_h_corrupted_tarball_member_fails(self):
        """Mutation H: Corrupting ELF header inside a .tar.gz archive must fail."""
        tarball = self.root / "bin/linux_x86_64/llama-ubuntu-x64.tar.gz"
        corrupted_elf = b"\x00ELF\x02\x01\x01\x00" + b"\x00" * 8 + struct.pack("<H", 2) + struct.pack("<H", 0x003E) + b"\x00" * 512
        bio = io.BytesIO()
        with tarfile.open(fileobj=bio, mode="w:gz") as tar:
            ti = tarfile.TarInfo(name="llama-server")
            ti.size = len(corrupted_elf)
            ti.mode = 0o755
            tar.addfile(ti, io.BytesIO(corrupted_elf))
        tarball.write_bytes(bio.getvalue())

        res = self.auditor_runner.run(self.root, tier=0, mode="static")
        self.assertNotEqual(res.exit_code, 0, "Auditor returned 0 on corrupted internal tarball ELF member")
        self.assertIsNotNone(res.report_data)
        self.assertEqual(res.report_data.get("status"), "FAIL")

        failures = res.report_data.get("failures", [])
        found_elf_err = any(
            "llama-ubuntu-x64.tar.gz" in (f.get("target", "") or f.get("message", ""))
            for f in failures
        )
        self.assertTrue(found_elf_err, f"Expected tarball member header failure, got: {failures}")

    # --------------------------------------------------------------------------
    # Mutation I: Injected UTF-8 Byte Order Mark (BOM) in POSIX Script
    # --------------------------------------------------------------------------
    def test_11_mutation_i_injected_bom_fails(self):
        """Mutation I: Prepending UTF-8 BOM (\\xef\\xbb\\xbf) to a POSIX shell script must fail."""
        target_sh = self.root / "START_EMYRGE_LINUX.sh"
        content = target_sh.read_bytes()
        target_sh.write_bytes(b"\xef\xbb\xbf" + content)

        res = self.auditor_runner.run(self.root, tier=0, mode="static")
        self.assertNotEqual(res.exit_code, 0, "Auditor returned 0 on POSIX script with UTF-8 BOM")
        self.assertIsNotNone(res.report_data)
        self.assertEqual(res.report_data.get("status"), "FAIL")

        failures = res.report_data.get("failures", [])
        found_bom_err = any(
            "START_EMYRGE_LINUX.sh" in (f.get("target", "") or f.get("message", "")) and
            ("BOM" in f.get("category", "").upper() or "BOM" in f.get("message", "").upper() or "SHEBANG" in f.get("category", "").upper())
            for f in failures
        )
        self.assertTrue(found_bom_err, f"Expected UTF-8 BOM finding, got: {failures}")


# ==============================================================================
# CLI Entry Point & Runner
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="Run Adversarial Mutation Tests for audit_offgrid_usb.py")
    parser.add_argument(
        "--auditor",
        default="",
        help="Path to audit_offgrid_usb.py (auto-detected if omitted)",
    )
    parser.add_argument(
        "--json",
        default="",
        help="Save structured test results to this JSON file path",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose test output",
    )
    args = parser.parse_args()

    if args.auditor:
        TestAuditMutations._custom_auditor_path = Path(args.auditor).resolve()

    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestAuditMutations)

    print("=" * 80)
    print("  OFFGRIDUSB AUDITOR MUTATION & NEGATIVE VERIFICATION TEST HARNESS")
    print(f"  Target Auditor: {args.auditor or 'Auto-Detected'}")
    print(f"  Total Mutations to Execute: {suite.countTestCases()}")
    print("=" * 80)

    start_time = time.time()
    runner = unittest.TextTestRunner(verbosity=2 if args.verbose else 1)
    result = runner.run(suite)
    elapsed = round(time.time() - start_time, 3)

    passed_count = result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped)

    print("\n" + "=" * 80)
    print("  MUTATION TEST SUMMARY")
    print("-" * 80)
    print(f"  Mutations Executed: {result.testsRun}")
    print(f"  Verified (Passed):  {passed_count}")
    print(f"  Failures:           {len(result.failures)}")
    print(f"  Errors:             {len(result.errors)}")
    print(f"  Elapsed Time:       {elapsed}s")
    print("=" * 80)

    if args.json:
        summary_payload = {
            "auditor": str(args.auditor),
            "total_mutations": result.testsRun,
            "passed": passed_count,
            "failures": len(result.failures),
            "errors": len(result.errors),
            "elapsed_seconds": elapsed,
            "was_successful": result.wasSuccessful(),
            "failure_details": [{"test": str(t), "trace": trace} for t, trace in result.failures],
            "error_details": [{"test": str(t), "trace": trace} for t, trace in result.errors],
        }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(summary_payload, f, indent=2)
        print(f"  Structured results written to: {args.json}")

    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
