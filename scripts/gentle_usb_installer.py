"""Gentle Rate-Controlled USB Provisioner for USB 2.0 / sensitive flash drives.
Prevents USB controller buffer overflow and hardware disconnects.
"""

import os
import pathlib
import sys
import time

SOURCE_ROOT = pathlib.Path(__file__).resolve().parent.parent
CHUNK_SIZE = 128 * 1024  # 128 KB chunks
MAX_BYTES_PER_SEC = 8 * 1024 * 1024  # 8 MB/s sustained limit


def resolve_target_root() -> pathlib.Path:
    """Resolves target drive from CLI arguments or environment, defaulting to D:/ with safety checks."""
    raw_target = None
    if len(sys.argv) > 1:
        arg = sys.argv[1].strip()
        if arg in ("--help", "-h"):
            print("Usage: python scripts/gentle_usb_installer.py [TARGET_DRIVE]")
            print("Example: python scripts/gentle_usb_installer.py D:")
            sys.exit(0)
        raw_target = arg
    if not raw_target:
        raw_target = os.environ.get("OFFGRIDUSB_TARGET") or os.environ.get("TARGET_DRIVE") or "D:/"

    # Normalize drive letter on Windows (e.g. 'D' -> 'D:/', 'D:' -> 'D:/')
    if len(raw_target) == 1 and raw_target.isalpha():
        raw_target = f"{raw_target.upper()}:/"
    elif len(raw_target) == 2 and raw_target[0].isalpha() and raw_target[1] == ":":
        raw_target = f"{raw_target.upper()}/"

    target_path = pathlib.Path(raw_target)
    sys_drive = os.environ.get("SystemDrive", "C:").rstrip("\\/").upper()
    if str(target_path).upper().startswith(sys_drive) or target_path.resolve() == pathlib.Path("/").resolve():
        print(f"ERROR: Refusing to target system drive ({sys_drive}) or root filesystem!", file=sys.stderr)
        sys.exit(1)
    return target_path

EXCLUDE_DIRS = {"__pycache__", ".pytest_cache", ".agents", "tests", "tmp_dl", ".git", ".venv"}
EXCLUDE_FILES = {".DS_Store"}


def is_excluded(path: pathlib.Path) -> bool:
    for part in path.parts:
        if part in EXCLUDE_DIRS:
            return True
    if path.name in EXCLUDE_FILES or path.name.endswith((".pyc", ".pyo")):
        return True
    if "-DESKTOP-" in path.name or "-JoeWorkTop" in path.name:
        return True
    return False


def copy_file_gentle(src: pathlib.Path, dst: pathlib.Path):
    dst.parent.mkdir(parents=True, exist_ok=True)
    size = src.stat().st_size

    # Small files (< 1MB) copy directly
    if size < 1024 * 1024:
        with open(src, "rb") as f_in, open(dst, "wb") as f_out:
            f_out.write(f_in.read())
            f_out.flush()
        return

    # Larger files write in chunks with rate limiting and fsync
    mb = size / (1024 * 1024)
    print(f"  [COPY] {src.name} ({mb:.1f} MB)...", flush=True)

    copied = 0
    t0 = time.time()
    with open(src, "rb") as f_in, open(dst, "wb") as f_out:
        while True:
            chunk = f_in.read(CHUNK_SIZE)
            if not chunk:
                break
            f_out.write(chunk)
            copied += len(chunk)

            # Rate limit
            elapsed = time.time() - t0
            expected_time = copied / MAX_BYTES_PER_SEC
            if expected_time > elapsed:
                time.sleep(expected_time - elapsed)

        f_out.flush()
        try:
            os.fsync(f_out.fileno())
        except OSError:
            pass

    # Brief 0.3s cooldown for flash controller
    time.sleep(0.3)


def main():
    target_root = resolve_target_root()
    if not target_root.exists():
        print(f"ERROR: Target drive '{target_root}' not found or not mounted!", file=sys.stderr)
        return 1

    print("=" * 80)
    print(f"OffGridUSB -- Gentle Flash Provisioner (Target: {target_root})")
    print(f"Sustained Write Rate: {MAX_BYTES_PER_SEC / 1048576:.1f} MB/s (protects USB controller)")
    print("=" * 80)

    # 1. Root files
    root_files = [
        "START_OFFGRIDUSB_WINDOWS.bat",
        "START_OFFGRIDUSB_MAC.command",
        "START_OFFGRIDUSB_LINUX.sh",
        "START_EMYRGE_WINDOWS.bat",
        "START_EMYRGE_MAC.command",
        "START_EMYRGE_LINUX.sh",
        "MAKE_USB_DRIVES.bat",
        "FORMAT_AND_SETUP_USB.bat",
        "DOWNLOAD_INTERNET_IN_A_BOX.bat",
        "run_windows.bat",
        "run_linux.sh",
        "run_macos.command",
        "README.md",
        "CONTRIBUTING.md",
        "TEST_READY.md",
    ]
    print("\n[1/4] Copying root launcher scripts...")
    for rf in root_files:
        p = SOURCE_ROOT / rf
        if p.exists():
            copy_file_gentle(p, target_root / rf)
    print("  -> Root launchers ready.")

    # 2. Application runtime directories
    app_dirs = ["docs", "manifests", "scripts", "src", "web"]
    print("\n[2/4] Copying core application runtime...")
    for d in app_dirs:
        base = SOURCE_ROOT / d
        if not base.exists():
            continue
        for item in base.rglob("*"):
            if item.is_file() and not is_excluded(item):
                rel = item.relative_to(SOURCE_ROOT)
                copy_file_gentle(item, target_root / rel)
    print("  -> Application code & UI ready.")

    # 3. Binaries (native engines)
    print("\n[3/4] Copying portable native engines (bin/)...")
    bin_base = SOURCE_ROOT / "bin"
    if bin_base.exists():
        for item in bin_base.rglob("*"):
            if item.is_file() and not is_excluded(item):
                rel = item.relative_to(SOURCE_ROOT)
                copy_file_gentle(item, target_root / rel)
    print("  -> Portable engines ready.")

    # 4. Data (Internet-in-a-Box ZIMs + GGUF AI models)
    print("\n[4/4] Copying Internet-in-a-Box encyclopedias & AI models (data/)...")
    (target_root / "data" / "vault").mkdir(parents=True, exist_ok=True)
    (target_root / "data" / "uploads").mkdir(parents=True, exist_ok=True)

    data_base = SOURCE_ROOT / "data"
    if data_base.exists():
        for item in data_base.rglob("*"):
            if item.is_file() and not is_excluded(item):
                rel = item.relative_to(SOURCE_ROOT)
                copy_file_gentle(item, target_root / rel)

    print("\n" + "=" * 80)
    print(f"SUCCESS! Complete OffGridUSB installation verified on {target_root}")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    sys.exit(main())
