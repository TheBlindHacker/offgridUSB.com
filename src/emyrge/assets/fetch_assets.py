"""Controlled Offline Asset Provisioner & Verifier (F-42, F-43).

100% Pure Python Standard Library.
Downloads and verifies Internet-in-a-Box (.zim) encyclopedias and GGUF AI models
defined in `manifests/zim.json` and `manifests/models.json`.

Usage:
    python -m emyrge.assets.fetch_assets --list
    python -m emyrge.assets.fetch_assets --dry-run --tier 2
    python -m emyrge.assets.fetch_assets --verify
    python -m emyrge.assets.fetch_assets --tier 0
    python -m emyrge.assets.fetch_assets --zim-only --tier 2
    python -m emyrge.assets.fetch_assets --id wikipedia-medicine-mini
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional
import urllib.error
import urllib.request

ZIM_MAGICS = (0x044D495A, 0x5A494D04)
USER_AGENT = "OffGridUSB-Provisioner/0.1 (+https://offgridusb.com)"


def _default_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent.parent


def load_manifests(project_root: Optional[Path] = None) -> Dict[str, Any]:
    root = project_root or _default_root()
    models_path = root / "manifests" / "models.json"
    zim_path = root / "manifests" / "zim.json"

    models_data = json.loads(models_path.read_text(encoding="utf-8")) if models_path.is_file() else {"models": []}
    zim_data = json.loads(zim_path.read_text(encoding="utf-8")) if zim_path.is_file() else {"archives": []}
    return {
        "models": models_data.get("models", []),
        "archives": zim_data.get("archives", []),
    }


def _check_magic_header(path: Path) -> bool:
    """Validates binary magic header for .gguf ('GGUF') or .zim ('ZIM\\x04')."""
    if not path.is_file() or path.stat().st_size < 16:
        return False
    suffix = path.suffix.lower()
    try:
        with open(path, "rb") as f:
            hdr = f.read(4)
        if len(hdr) < 4:
            return False
        if suffix == ".gguf":
            return hdr == b"GGUF"
        if suffix == ".zim":
            magic = struct.unpack("<I", hdr)[0]
            return magic in ZIM_MAGICS
        return True
    except OSError:
        return False


def verify_assets(project_root: Optional[Path] = None) -> Dict[str, Any]:
    root = project_root or _default_root()
    manifests = load_manifests(root)
    models_dir = root / "data" / "models"
    zim_dir = root / "data" / "zim"

    found_models: List[Dict[str, Any]] = []
    if models_dir.is_dir():
        for p in sorted(models_dir.glob("*.gguf")):
            found_models.append(
                {
                    "filename": p.name,
                    "size_mb": round(p.stat().st_size / (1024 * 1024), 2),
                    "header_valid": _check_magic_header(p),
                }
            )

    found_zims: List[Dict[str, Any]] = []
    if zim_dir.is_dir():
        for p in sorted(zim_dir.glob("*.zim")):
            found_zims.append(
                {
                    "filename": p.name,
                    "size_mb": round(p.stat().st_size / (1024 * 1024), 2),
                    "header_valid": _check_magic_header(p),
                }
            )

    return {
        "ok": True,
        "catalog_models_count": len(manifests["models"]),
        "catalog_zim_count": len(manifests["archives"]),
        "staged_models": found_models,
        "staged_zims": found_zims,
    }


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _stream_download(url: str, dest: Path) -> None:
    """Streams a remote file to `dest.part` with progress logging and renames atomically."""
    part_path = dest.with_suffix(dest.suffix + ".part")
    existing_bytes = part_path.stat().st_size if part_path.is_file() else 0

    curl_bin = shutil.which("curl")
    if curl_bin:
        curl_cmd = [
            curl_bin,
            "-L",
            "-f",
            "--retry", "5",
            "--retry-connrefused",
            "--retry-delay", "2",
            "--connect-timeout", "30",
            "-A", USER_AGENT,
        ]
        if existing_bytes > 0:
            curl_cmd.extend(["-C", "-"])
        curl_cmd.extend(["-o", str(part_path), url])
        proc = subprocess.run(curl_cmd)
        if proc.returncode != 0:
            if proc.returncode == 33 and existing_bytes > 0:
                print(f"    [WARN] Server rejected byte range (curl exit code 33). Retrying clean: {url}", flush=True)
                if part_path.is_file():
                    part_path.unlink()
                clean_cmd = [
                    curl_bin,
                    "-L",
                    "-f",
                    "--retry", "5",
                    "--retry-connrefused",
                    "--retry-delay", "2",
                    "--connect-timeout", "30",
                    "-A", USER_AGENT,
                    "-o", str(part_path),
                    url,
                ]
                proc = subprocess.run(clean_cmd)
            if proc.returncode != 0:
                raise RuntimeError(
                    f"Download failed for {url} (curl exit code {proc.returncode}). "
                    f"Partial file preserved at: {part_path}"
                )
        part_path.replace(dest)
        return

    headers = {"User-Agent": USER_AGENT}
    if existing_bytes > 0:
        headers["Range"] = f"bytes={existing_bytes}-"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            status = getattr(resp, "status", 200)
            mode = "ab" if (existing_bytes > 0 and status == 206) else "wb"
            if mode == "wb":
                existing_bytes = 0

            content_len = resp.headers.get("Content-Length")
            total_bytes = (int(content_len) + existing_bytes) if content_len and content_len.isdigit() else 0

            downloaded = existing_bytes
            last_print = 0.0
            with open(part_path, mode) as out:
                while True:
                    chunk = resp.read(1024 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
                    downloaded += len(chunk)
                    now = time.monotonic()
                    if now - last_print >= 1.0:
                        mb_done = downloaded / (1024 * 1024)
                        if total_bytes > 0:
                            pct = min(100.0, (downloaded / total_bytes) * 100.0)
                            mb_total = total_bytes / (1024 * 1024)
                            print(f"    ... {mb_done:,.1f} / {mb_total:,.1f} MB ({pct:.1f}%)", flush=True)
                        else:
                            print(f"    ... {mb_done:,.1f} MB downloaded", flush=True)
                        last_print = now
    except urllib.error.HTTPError as exc:
        # Only discard partial download if the server explicitly rejected the Range header (HTTP 416)
        if exc.code == 416 and existing_bytes > 0:
            if part_path.is_file():
                part_path.unlink()
            print(f"    [WARN] Server rejected byte range (HTTP 416). Restarting clean: {url}", flush=True)
            _stream_download(url, dest)
            return
        raise
    except Exception as exc:
        # Preserve .part file on all other transient network failures
        print(f"    [WARN] Download interrupted ({exc}). Partial file preserved at: {part_path}", flush=True)
        raise

    part_path.replace(dest)


def _print_catalog(manifests: Dict[str, Any]) -> None:
    print("=" * 80)
    print("OffGridUSB (offgridusb.com) -- Internet-in-a-Box (.zim) & AI Model (.gguf) Catalog")
    print("=" * 80)
    print("\n[Internet-in-a-Box OpenZIM Knowledge Packs -- manifests/zim.json]")
    for z in manifests["archives"]:
        print(f"  Tier {z.get('tier', 0)} | {z['id']:<26} | {z.get('size_mb', 0):>8.1f} MB | {z['name']}")
    print("\n[Elastic Offline GGUF AI Models -- manifests/models.json]")
    for m in manifests["models"]:
        print(f"  Tier {m.get('tier', 0)} | {m['id']:<26} | {m.get('size_mb', 0):>8.1f} MB | {m['name']}")
    print("=" * 80)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="OffGridUSB (offgridusb.com) Offline Asset Provisioner")
    parser.add_argument("--list", action="store_true", help="List all available Internet-in-a-Box ZIMs and GGUF models")
    parser.add_argument("--dry-run", action="store_true", help="Print planned downloads without fetching")
    parser.add_argument("--verify", action="store_true", help="Verify staged models and ZIM files on disk")
    parser.add_argument("--tier", type=int, default=0, help="Maximum hardware tier assets to fetch (0 to 4, default: 0)")
    parser.add_argument("--zim-only", action="store_true", help="Download only Internet-in-a-Box (.zim) archives")
    parser.add_argument("--models-only", action="store_true", help="Download only GGUF (.gguf) AI models")
    parser.add_argument("--id", dest="asset_ids", action="append", default=[], help="Download specific asset ID(s) by manifest id")
    args = parser.parse_args(argv)

    root = _default_root()
    manifests = load_manifests(root)

    if args.list:
        _print_catalog(manifests)
        return 0

    if args.verify:
        report = verify_assets(root)
        print(json.dumps(report, indent=2))
        return 0

    requested_ids = {aid.strip() for aid in args.asset_ids if aid.strip()}
    if requested_ids:
        selected_models = [m for m in manifests["models"] if m.get("id") in requested_ids]
        selected_zims = [z for z in manifests["archives"] if z.get("id") in requested_ids]
    else:
        selected_models = [] if args.zim_only else [m for m in manifests["models"] if int(m.get("tier", 0)) <= args.tier]
        selected_zims = [] if args.models_only else [z for z in manifests["archives"] if int(z.get("tier", 0)) <= args.tier]

    if args.dry_run:
        print(
            json.dumps(
                {
                    "dry_run": True,
                    "max_tier": args.tier,
                    "planned_models": selected_models,
                    "planned_zims": selected_zims,
                },
                indent=2,
            )
        )
        return 0

    models_dir = root / "data" / "models"
    zim_dir = root / "data" / "zim"
    models_dir.mkdir(parents=True, exist_ok=True)
    zim_dir.mkdir(parents=True, exist_ok=True)

    for item in selected_models:
        dest = models_dir / item["filename"]
        if dest.exists() and dest.stat().st_size > 1024 * 1024 and _check_magic_header(dest):
            print(f"[SKIP] Model already staged & valid: {dest.name}")
            continue
        print(f"[FETCH] Downloading AI Model: {item['name']} -> {dest}")
        _stream_download(item["url"], dest)
        if not _check_magic_header(dest):
            print(f"[WARN] Downloaded file {dest.name} did not pass GGUF magic-byte check.", file=sys.stderr)
        else:
            print(f"[OK] Verified GGUF header: {dest.name} ({dest.stat().st_size / (1024 * 1024):.1f} MB)")

    for item in selected_zims:
        dest = zim_dir / item["filename"]
        if dest.exists() and dest.stat().st_size > 1024 and _check_magic_header(dest):
            print(f"[SKIP] ZIM archive already staged & valid: {dest.name}")
            continue
        print(f"[FETCH] Downloading Internet-in-a-Box ZIM: {item['name']} -> {dest}")
        _stream_download(item["url"], dest)
        if not _check_magic_header(dest):
            print(f"[WARN] Downloaded file {dest.name} did not pass OpenZIM magic-byte check.", file=sys.stderr)
        else:
            print(f"[OK] Verified OpenZIM header: {dest.name} ({dest.stat().st_size / (1024 * 1024):.1f} MB)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
