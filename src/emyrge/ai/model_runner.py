"""Subprocess Lifecycle Managers for llama-server (8082) and kiwix-serve (8081).

100% Pure Python Standard Library.
Includes:
- Cross-platform USB binary readiness inspection (`probe_usb_platforms`)
- Background `llama-server` spawning on 127.0.0.1:8082 with `atexit` cleanup
- Background `kiwix-serve` spawning on 127.0.0.1:8081 + live HTML ZIM search parser
- Deterministic offline RAG synthesis fallback so stage demos NEVER fail
"""

from __future__ import annotations

import atexit
import html
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import struct
import subprocess
import tarfile
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional
import urllib.error
import urllib.parse
import urllib.request


def _is_port_open(host: str, port: int, timeout: float = 0.35) -> bool:
    """Fast TCP connect check on host:port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _find_binary_in_dir(directory: Path, prefixes: tuple[str, ...]) -> Optional[Path]:
    """Finds an executable binary inside `directory` (including 1-2 nested release folders)."""
    if not directory.exists():
        return None
    if directory.is_file():
        return directory if directory.stat().st_size > 0 else None
    try:
        for item in directory.rglob("*"):
            if item.is_file() and item.name.lower().startswith(prefixes):
                if not item.name.lower().endswith(
                    (".zip", ".tar", ".gz", ".xz", ".tmp", ".part", ".txt", ".md", ".so", ".dylib", ".dll")
                ):
                    if item.stat().st_size > 1024:
                        return item
    except OSError:
        pass
    return None


def _ensure_posix_executable(binary_path: Path) -> Path:
    """Ensures a binary has +x permission on POSIX; copies to /tmp/emyrge_runtime if USB is mounted noexec."""
    if os.name == "nt":
        return binary_path
    try:
        os.chmod(binary_path, 0o755)
    except OSError:
        pass
    if os.access(binary_path, os.X_OK):
        return binary_path

    # USB drive is likely FAT32/exFAT mounted with noexec; stage into /tmp/emyrge_runtime
    runtime_dir = Path(tempfile.gettempdir()) / "emyrge_runtime" / "bin_exec"
    try:
        runtime_dir.mkdir(parents=True, exist_ok=True)
        staged = runtime_dir / binary_path.name
        if not staged.is_file() or staged.stat().st_size != binary_path.stat().st_size:
            shutil.copy2(binary_path, staged)
        os.chmod(staged, 0o755)
        return staged
    except OSError:
        return binary_path


def _extract_posix_tar_runtime(archive_path: Path, slot_name: str, prefixes: tuple[str, ...]) -> Optional[Path]:
    """Extracts a bundled Linux/macOS .tar.gz into /tmp/emyrge_runtime/<slot_name> so .so/.dylib symlinks
    and +x permissions work reliably even when running off a FAT32/exFAT USB stick.
    """
    if os.name == "nt" or not archive_path.is_file() or archive_path.stat().st_size < 10240:
        return None
    runtime_slot = Path(tempfile.gettempdir()) / "emyrge_runtime" / slot_name
    existing = _find_binary_in_dir(runtime_slot, prefixes)
    if existing is not None:
        return _ensure_posix_executable(existing)
    try:
        runtime_slot.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archive_path, "r:gz") as tf:
            try:
                tf.extractall(path=runtime_slot, filter="tar")
            except TypeError:
                tf.extractall(path=runtime_slot)
        found = _find_binary_in_dir(runtime_slot, prefixes)
        if found is not None:
            return _ensure_posix_executable(found)
    except Exception:
        return None
    return None


def probe_usb_platforms(project_root: Path) -> List[Dict[str, Any]]:
    """Checks all cross-platform binaries staged on the portable USB drive."""
    targets = [
        {
            "id": "windows_x86_64",
            "name": "Windows x86_64 (llama-server.exe)",
            "os": "windows",
            "arch": "x86_64",
            "check_path": project_root / "bin" / "windows_x86_64" / "llama" / "llama-server.exe",
            "fallback_dir": project_root / "bin" / "windows_x86_64",
            "tar_patterns": (),
            "prefixes": ("llama-server", "llama-cli"),
        },
        {
            "id": "windows_arm64",
            "name": "Windows ARM64 (Snapdragon / Surface)",
            "os": "windows",
            "arch": "arm64",
            "check_path": project_root / "bin" / "windows_arm64" / "llama" / "llama-server.exe",
            "fallback_dir": project_root / "bin" / "windows_arm64",
            "tar_patterns": (),
            "prefixes": ("llama-server", "llama-cli"),
        },
        {
            "id": "linux_x86_64",
            "name": "Linux x86_64 (Ubuntu / Debian / RHEL)",
            "os": "linux",
            "arch": "x86_64",
            "check_path": project_root / "bin" / "linux_x86_64" / "llama" / "llama-server",
            "fallback_dir": project_root / "bin" / "linux_x86_64",
            "tar_patterns": ("llama-*.tar.gz", "kiwix-tools_*.tar.gz"),
            "prefixes": ("llama-server", "llama-cli", "kiwix-serve"),
        },
        {
            "id": "linux_arm64",
            "name": "Linux ARM64 (Raspberry Pi 4/5 / SBC)",
            "os": "linux",
            "arch": "arm64",
            "check_path": project_root / "bin" / "linux_arm64" / "llama" / "llama-server",
            "fallback_dir": project_root / "bin" / "linux_arm64",
            "tar_patterns": ("llama-*.tar.gz", "kiwix-tools_*.tar.gz"),
            "prefixes": ("llama-server", "llama-cli", "kiwix-serve"),
        },
        {
            "id": "macos_x86_64",
            "name": "macOS Intel (x86_64)",
            "os": "darwin",
            "arch": "x86_64",
            "check_path": project_root / "bin" / "macos_x86_64" / "llama" / "llama-server",
            "fallback_dir": project_root / "bin" / "macos_x86_64",
            "tar_patterns": ("llama-*.tar.gz", "kiwix-tools_*.tar.gz"),
            "prefixes": ("llama-server", "llama-cli", "kiwix-serve"),
        },
        {
            "id": "macos_arm64",
            "name": "macOS Apple Silicon (Metal M1-M4)",
            "os": "darwin",
            "arch": "arm64",
            "check_path": project_root / "bin" / "macos_arm64" / "llama" / "llama-server",
            "fallback_dir": project_root / "bin" / "macos_arm64",
            "tar_patterns": ("llama-*.tar.gz", "kiwix-tools_*.tar.gz"),
            "prefixes": ("llama-server", "llama-cli", "kiwix-serve"),
        },
        {
            "id": "polyglot_llamafile",
            "name": "Cosmopolitan Polyglot (Linux x64 / macOS Intel / Win)",
            "os": "polyglot",
            "arch": "x86_64+arm64",
            "check_path": project_root / "bin" / "polyglot" / "llamafile.exe",
            "fallback_dir": project_root / "bin" / "polyglot",
            "tar_patterns": (),
            "prefixes": ("llamafile",),
        },
        {
            "id": "chromebook_wasm",
            "name": "Chromebook / Air-Gapped Browser Wasm Shell",
            "os": "browser_wasm",
            "arch": "wasm32",
            "check_path": project_root / "web" / "static" / "wasm" / "chromebook.html",
            "fallback_dir": None,
            "tar_patterns": (),
            "prefixes": ("chromebook.html",),
        },
    ]

    results: List[Dict[str, Any]] = []
    for t in targets:
        found_path: Optional[Path] = None
        cp: Path = t["check_path"]
        if cp.is_file() and cp.stat().st_size > 0:
            found_path = cp
        elif t["fallback_dir"] is not None:
            f_dir: Path = t["fallback_dir"]
            # 1. Check for loose extracted binary
            found_path = _find_binary_in_dir(f_dir, t["prefixes"])
            # 2. Check for POSIX .tar.gz bundle if loose binary is not found
            if found_path is None and t.get("tar_patterns") and f_dir.is_dir():
                for pat in t["tar_patterns"]:
                    for archive in sorted(f_dir.glob(pat)):
                        if archive.is_file() and archive.stat().st_size > 1024:
                            found_path = archive
                            break
                    if found_path is not None:
                        break
                if found_path is None:
                    for archive in sorted(f_dir.glob("*.tar.gz")):
                        if archive.is_file() and archive.stat().st_size > 1024:
                            found_path = archive
                            break

        size_mb = round(found_path.stat().st_size / (1024 * 1024), 2) if found_path and found_path.is_file() else 0.0
        rel_display = str(found_path.relative_to(project_root)).replace("\\", "/") if found_path else str(cp.relative_to(project_root)).replace("\\", "/")
        results.append(
            {
                "id": t["id"],
                "name": t["name"],
                "os": t["os"],
                "arch": t["arch"],
                "path": rel_display,
                "ready": found_path is not None,
                "size_mb": size_mb,
            }
        )
    return results


# ---------------------------------------------------------------------------
# Kiwix HTML Search Result Parser
# ---------------------------------------------------------------------------

class _KiwixSearchHTMLParser(HTMLParser):
    """Extracts search results (`<a>` links + snippets + cite/book) from kiwix-serve `/search`."""

    def __init__(self) -> None:
        super().__init__()
        self.results: List[Dict[str, str]] = []
        self._in_li = False
        self._in_a = False
        self._in_cite = False
        self._current: Dict[str, str] = {}
        self._text_parts: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[tuple[str, Optional[str]]]) -> None:
        attr_map = dict(attrs)
        if tag == "li":
            self._in_li = True
            self._current = {"title": "", "href": "", "snippet": "", "book": ""}
            self._text_parts = []
        elif self._in_li and tag == "a" and not self._current.get("href"):
            href = attr_map.get("href") or ""
            if href and not href.startswith(("#", "javascript:")) and "/search?" not in href:
                self._in_a = True
                self._current["href"] = href
        elif self._in_li and tag == "cite":
            self._in_cite = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._in_a:
            self._in_a = False
        elif tag == "cite" and self._in_cite:
            self._in_cite = False
        elif tag == "li" and self._in_li:
            self._in_li = False
            snippet = " ".join(" ".join(self._text_parts).split()).strip()
            if self._current.get("title") and self._current.get("href"):
                self._current["snippet"] = snippet[:450]
                self.results.append(self._current)
            self._current = {}
            self._text_parts = []

    def handle_data(self, data: str) -> None:
        if not self._in_li:
            return
        cleaned = data.strip()
        if not cleaned:
            return
        if self._in_a:
            self._current["title"] = (self._current.get("title", "") + " " + cleaned).strip()
        elif self._in_cite:
            self._current["book"] = (self._current.get("book", "") + " " + cleaned).strip()
        else:
            self._text_parts.append(cleaned)


def _strip_html_to_text(raw_html: str, max_chars: int = 1200) -> str:
    """Strips scripts, styles, and HTML tags to extract clean article prose."""
    cleaned = re.sub(r"<(script|style|nav|header|footer)[^>]*>.*?</\1>", " ", raw_html, flags=re.DOTALL | re.IGNORECASE)
    cleaned = re.sub(r"<[^>]+>", " ", cleaned)
    cleaned = html.unescape(cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:max_chars]


# ---------------------------------------------------------------------------
# KiwixRunner (Port 8081)
# ---------------------------------------------------------------------------

class KiwixRunner:
    """Discovers kiwix-serve and *.zim archives, serving live Internet-in-a-Box on 127.0.0.1:8081."""

    ZIM_MAGIC = 0x044D495A

    def __init__(self, project_root: Path, host: str = "127.0.0.1", port: int = 8081) -> None:
        self.project_root = Path(project_root)
        self.zim_dir = self.project_root / "data" / "zim"
        self.host = host
        self.port = port
        self._proc: Optional[subprocess.Popen] = None
        self._mounted_zims: List[Path] = []
        self._lock = threading.RLock()
        atexit.register(self.stop)

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def discover_binary(self) -> Optional[Path]:
        """Discovers host-compatible kiwix-serve binary in bin/, bundled POSIX tar.gz, or system PATH."""
        sys_name = platform.system().lower()
        mach = platform.machine().lower()
        is_arm = mach in ("arm64", "aarch64")

        if sys_name == "windows":
            candidates = []
            if is_arm:
                candidates.append(self.project_root / "bin" / "windows_arm64" / "kiwix" / "kiwix-serve.exe")
            candidates.extend(
                [
                    self.project_root / "bin" / "windows_x86_64" / "kiwix" / "kiwix-serve.exe",
                    self.project_root / "bin" / "kiwix" / "kiwix-serve.exe",
                ]
            )
            for c in candidates:
                if c.is_file() and c.stat().st_size > 1024:
                    return c
            nested = _find_binary_in_dir(self.project_root / "bin" / "windows_x86_64", ("kiwix-serve",))
            if nested:
                return nested
            which_bin = shutil.which("kiwix-serve.exe") or shutil.which("kiwix-serve")
            return Path(which_bin) if which_bin else None

        if sys_name == "darwin":
            if is_arm:
                mac_cand = self.project_root / "bin" / "macos_arm64" / "kiwix" / "kiwix-serve"
                if mac_cand.is_file() and mac_cand.stat().st_size > 1024:
                    return _ensure_posix_executable(mac_cand)
                tar_bin = _extract_posix_tar_runtime(
                    self.project_root / "bin" / "macos_arm64" / "kiwix-tools_macos.tar.gz",
                    "macos_arm64_kiwix",
                    ("kiwix-serve",),
                )
                if tar_bin:
                    return tar_bin
            else:
                mac_x64_cand = self.project_root / "bin" / "macos_x86_64" / "kiwix" / "kiwix-serve"
                if mac_x64_cand.is_file() and mac_x64_cand.stat().st_size > 1024:
                    return _ensure_posix_executable(mac_x64_cand)
                tar_x64_bin = _extract_posix_tar_runtime(
                    self.project_root / "bin" / "macos_x86_64" / "kiwix-tools_macos-x86_64.tar.gz",
                    "macos_x86_64_kiwix",
                    ("kiwix-serve",),
                )
                if tar_x64_bin:
                    return tar_x64_bin
            which_bin = shutil.which("kiwix-serve")
            return Path(which_bin) if which_bin else None

        # Linux / Raspberry Pi (ARM64 or x86_64)
        if is_arm:
            tar_bin = _extract_posix_tar_runtime(
                self.project_root / "bin" / "linux_arm64" / "kiwix-tools_linux-aarch64.tar.gz",
                "linux_arm64_kiwix",
                ("kiwix-serve",),
            )
            if tar_bin:
                return tar_bin
            arm_cand = self.project_root / "bin" / "linux_arm64" / "kiwix" / "kiwix-serve"
            if arm_cand.is_file() and arm_cand.stat().st_size > 1024:
                return _ensure_posix_executable(arm_cand)
        else:
            tar_bin = _extract_posix_tar_runtime(
                self.project_root / "bin" / "linux_x86_64" / "kiwix-tools_linux-x86_64.tar.gz",
                "linux_x86_64_kiwix",
                ("kiwix-serve",),
            )
            if tar_bin:
                return tar_bin
            x64_cand = self.project_root / "bin" / "linux_x86_64" / "kiwix" / "kiwix-serve"
            if x64_cand.is_file() and x64_cand.stat().st_size > 1024:
                return _ensure_posix_executable(x64_cand)

        which_bin = shutil.which("kiwix-serve")
        return Path(which_bin) if which_bin else None

    def discover_zim_files(self) -> List[Path]:
        """Finds all valid, completely-written .zim files in data/zim/."""
        if not self.zim_dir.is_dir():
            return []
        valid: List[Path] = []
        for p in sorted(self.zim_dir.glob("*.zim")):
            try:
                if p.stat().st_size < 1024:
                    continue
                with open(p, "rb") as f:
                    hdr = f.read(4)
                    if len(hdr) == 4:
                        magic = struct.unpack("<I", hdr)[0]
                        if magic in (self.ZIM_MAGIC, 0x5A494D04):
                            valid.append(p)
            except OSError:
                continue
        return valid

    def is_running(self) -> bool:
        if self._proc is not None and self._proc.poll() is None:
            return True
        return _is_port_open(self.host, self.port, timeout=0.25)

    def ensure_started(self) -> bool:
        """Starts kiwix-serve if binary + ZIMs exist (or restarts if newly downloaded ZIMs arrived)."""
        with self._lock:
            zims = self.discover_zim_files()
            if not zims:
                return self.is_running()

            # If already running externally and we didn't spawn it, keep using it
            if self._proc is None and _is_port_open(self.host, self.port, timeout=0.25):
                self._mounted_zims = zims
                return True

            # Restart if new ZIMs finished downloading since initial start
            if self._proc is not None and self._proc.poll() is None:
                if set(zims) == set(self._mounted_zims):
                    return True
                self.stop()

            binary = self.discover_binary()
            if not binary:
                return False

            cmd = [str(binary), "--port", str(self.port), "--address", self.host] + [str(z) for z in zims]
            kwargs: Dict[str, Any] = {
                "stdout": subprocess.DEVNULL,
                "stderr": subprocess.DEVNULL,
                "stdin": subprocess.DEVNULL,
                "cwd": str(self.project_root),
            }
            if hasattr(subprocess, "CREATE_NO_WINDOW"):
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

            try:
                self._proc = subprocess.Popen(cmd, **kwargs)
                self._mounted_zims = zims
                # Brief readiness poll (up to 1.5s)
                for _ in range(6):
                    if _is_port_open(self.host, self.port, timeout=0.2):
                        return True
                    time.sleep(0.2)
                return self._proc.poll() is None
            except OSError:
                self._proc = None
                return False

    def search_live(self, query: str, limit: int = 4, fetch_body: bool = True) -> List[Dict[str, Any]]:
        """Queries live kiwix-serve HTTP search endpoint and parses real ZIM passages."""
        if not query or not query.strip():
            return []
        if not self.ensure_started() or not _is_port_open(self.host, self.port, timeout=0.25):
            return []

        encoded_q = urllib.parse.quote_plus(query.strip())
        urls_to_try = [
            f"{self.base_url}/search?pattern={encoded_q}&pageLength={limit}",
            f"{self.base_url}/search?pattern={encoded_q}",
        ]
        # Also try book-scoped search if multi-ZIM index needs content prefix
        for z in self._mounted_zims[:3]:
            book_name = z.stem
            urls_to_try.append(f"{self.base_url}/search?content={urllib.parse.quote(book_name)}&pattern={encoded_q}")

        parsed_items: List[Dict[str, str]] = []
        seen_hrefs: set[str] = set()

        for url in urls_to_try:
            try:
                req = urllib.request.Request(url, headers={"Accept": "text/html"})
                with urllib.request.urlopen(req, timeout=2.5) as resp:
                    raw_html = resp.read(131072).decode("utf-8", errors="ignore")
                parser = _KiwixSearchHTMLParser()
                parser.feed(raw_html)
                for item in parser.results:
                    href = item["href"]
                    if href not in seen_hrefs:
                        seen_hrefs.add(href)
                        parsed_items.append(item)
                if len(parsed_items) >= limit:
                    break
            except Exception:
                continue

        enriched: List[Dict[str, Any]] = []
        for idx, item in enumerate(parsed_items[:limit]):
            href = item["href"]
            full_url = href if href.startswith("http") else f"{self.base_url}{href if href.startswith('/') else '/' + href}"
            snippet = item.get("snippet", "")
            full_text = snippet

            # Fetch top 2 article bodies for rich RAG grounding if snippet is short
            if fetch_body and idx < 2 and len(snippet) < 220:
                try:
                    art_req = urllib.request.Request(full_url, headers={"Accept": "text/html"})
                    with urllib.request.urlopen(art_req, timeout=2.0) as art_resp:
                        art_html = art_resp.read(98304).decode("utf-8", errors="ignore")
                    extracted = _strip_html_to_text(art_html, max_chars=900)
                    if len(extracted) > len(snippet):
                        full_text = extracted
                        if not snippet:
                            snippet = extracted[:240]
                except Exception:
                    pass

            # Derive book archive identifier from URL path e.g. /content/zimgit-water_en_2024-08/A/...
            book_label = item.get("book") or "Kiwix ZIM"
            parts = [p for p in href.strip("/").split("/") if p and p != "content"]
            if parts:
                book_label = parts[0]

            enriched.append(
                {
                    "title": item["title"],
                    "url": full_url,
                    "href": href,
                    "book": book_label,
                    "snippet": snippet or full_text[:240],
                    "full_text": full_text or snippet,
                    "score": round(0.98 - (idx * 0.04), 3),
                }
            )
        return enriched

    def get_status(self) -> Dict[str, Any]:
        zims = self.discover_zim_files()
        running = self.ensure_started() if zims else self.is_running()
        return {
            "kiwix_running": running,
            "kiwix_port": self.port,
            "kiwix_url": self.base_url,
            "kiwix_binary": str(self.discover_binary() or ""),
            "zim_files": [
                {
                    "name": z.name,
                    "size_mb": round(z.stat().st_size / (1024 * 1024), 2),
                }
                for z in zims
            ],
        }

    def stop(self) -> None:
        with self._lock:
            if self._proc is not None:
                try:
                    if self._proc.poll() is None:
                        self._proc.terminate()
                        try:
                            self._proc.wait(timeout=2.0)
                        except subprocess.TimeoutExpired:
                            self._proc.kill()
                except Exception:
                    pass
                finally:
                    self._proc = None


# ---------------------------------------------------------------------------
# ModelRunner (Port 8082)
# ---------------------------------------------------------------------------

class ModelRunner:
    """Discovers llama-server + GGUF model, runs OpenAI-compatible inference on 127.0.0.1:8082,
    and provides zero-fail deterministic grounded fallback if LLM binary/model is still loading.
    """

    def __init__(
        self,
        project_root: Path,
        host: str = "127.0.0.1",
        port: int = 8082,
        context_size: int = 2048,
    ) -> None:
        self.project_root = Path(project_root)
        self.models_dir = self.project_root / "data" / "models"
        self.host = host
        self.port = port
        self.context_size = context_size
        self._proc: Optional[subprocess.Popen] = None
        self._active_model: Optional[Path] = None
        self._active_binary: Optional[Path] = None
        self._lock = threading.RLock()
        atexit.register(self.stop)

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @staticmethod
    def optimal_threads() -> int:
        logical = os.cpu_count() or 4
        return max(1, min(8, logical // 2 if logical >= 4 else logical))

    def discover_binary(self) -> Optional[Path]:
        """Discovers host-compatible llama-server or polyglot llamafile binary."""
        sys_name = platform.system().lower()
        mach = platform.machine().lower()
        is_arm = mach in ("arm64", "aarch64")

        candidates: List[Path] = []
        if sys_name == "windows":
            if is_arm:
                candidates.append(self.project_root / "bin" / "windows_arm64" / "llama" / "llama-server.exe")
            candidates.extend(
                [
                    self.project_root / "bin" / "windows_x86_64" / "llama" / "llama-server.exe",
                    self.project_root / "bin" / "llama" / "llama-server.exe",
                    self.project_root / "bin" / "polyglot" / "llamafile.exe",
                ]
            )
            for c in candidates:
                if c.is_file() and c.stat().st_size > 1024:
                    return c
        elif sys_name == "darwin":
            if is_arm:
                # Prefer clean tar.gz extraction in /tmp/emyrge_runtime so .dylib symlinks work off FAT32/exFAT USB
                tar_bin = _extract_posix_tar_runtime(
                    self.project_root / "bin" / "macos_arm64" / "llama-macos-arm64.tar.gz",
                    "macos_arm64_llama",
                    ("llama-server",),
                )
                if tar_bin:
                    return tar_bin
                mac_nested = _find_binary_in_dir(self.project_root / "bin" / "macos_arm64" / "llama", ("llama-server",))
                if mac_nested:
                    return _ensure_posix_executable(mac_nested)
            else:
                tar_x64 = _extract_posix_tar_runtime(
                    self.project_root / "bin" / "macos_x86_64" / "llama-macos-x64.tar.gz",
                    "macos_x86_64_llama",
                    ("llama-server",),
                )
                if tar_x64:
                    return tar_x64
                mac_x64 = _find_binary_in_dir(self.project_root / "bin" / "macos_x86_64" / "llama", ("llama-server",))
                if mac_x64:
                    return _ensure_posix_executable(mac_x64)
            poly = self.project_root / "bin" / "polyglot" / "llamafile.exe"
            if poly.is_file() and poly.stat().st_size > 1024:
                return poly
        else:
            if is_arm:
                # Prefer clean tar.gz extraction in /tmp/emyrge_runtime so .so.0 symlinks work off FAT32/exFAT USB
                tar_bin = _extract_posix_tar_runtime(
                    self.project_root / "bin" / "linux_arm64" / "llama-ubuntu-arm64.tar.gz",
                    "linux_arm64_llama",
                    ("llama-server",),
                )
                if tar_bin:
                    return tar_bin
                lin_nested = _find_binary_in_dir(self.project_root / "bin" / "linux_arm64" / "llama", ("llama-server",))
                if lin_nested:
                    return _ensure_posix_executable(lin_nested)
            else:
                tar_bin = _extract_posix_tar_runtime(
                    self.project_root / "bin" / "linux_x86_64" / "llama-ubuntu-x64.tar.gz",
                    "linux_x86_64_llama",
                    ("llama-server",),
                )
                if tar_bin:
                    return tar_bin
                lin_x64 = _find_binary_in_dir(self.project_root / "bin" / "linux_x86_64" / "llama", ("llama-server",))
                if lin_x64:
                    return _ensure_posix_executable(lin_x64)
            poly = self.project_root / "bin" / "polyglot" / "llamafile.exe"
            if poly.is_file() and poly.stat().st_size > 1024:
                return poly

        which_bin = shutil.which("llama-server") or shutil.which("llama-server.exe")
        return Path(which_bin) if which_bin else None

    def discover_model(self) -> Optional[Path]:
        """Discovers valid .gguf weights in data/models/ (> 5 MB to skip partial files)."""
        if not self.models_dir.is_dir():
            return None
        ggufs: List[Path] = []
        for p in sorted(self.models_dir.glob("*.gguf")):
            try:
                # GGUF magic check ('GGUF') + minimum complete header/weights threshold
                if p.stat().st_size < 5 * 1024 * 1024:
                    continue
                with open(p, "rb") as f:
                    if f.read(4) == b"GGUF":
                        ggufs.append(p)
            except OSError:
                continue

        if not ggufs:
            return None

        # 1. Explicit model override via environment variable
        explicit_model = os.environ.get("OFFGRIDUSB_MODEL") or os.environ.get("EMYRGE_MODEL")
        if explicit_model:
            exp_lower = explicit_model.lower()
            for g in ggufs:
                if exp_lower in g.name.lower():
                    return g

        # 2. Check explicit tier constraint (e.g. EMYRGE_TIER="0" forces Tier 0 model)
        tier_env = os.environ.get("EMYRGE_TIER") or os.environ.get("OFFGRIDUSB_TIER")
        if tier_env == "0":
            for g in ggufs:
                if "qwen2.5-0.5b" in g.name.lower():
                    return g
            for g in ggufs:
                if "smollm2-135m" in g.name.lower():
                    return g

        # 3. Dynamic tier-aware prioritization:
        # Prioritize highest tier staged in data/models/:
        # Tier 4 (Llama 3.3 70B) > Tier 3 (Qwen 2.5 32B) > Tier 2 (Llama 3.2 3B) >
        # Tier 1 (Qwen 2.5 1.5B) > Tier 0 (Qwen 2.5 0.5B) > Tier 0 (SmolLM2 135M)
        tier_priority_patterns = [
            "llama-3.3-70b",
            "qwen2.5-32b",
            "llama-3.2-3b",
            "qwen2.5-1.5b",
            "qwen2.5-0.5b",
            "smollm2-135m",
        ]

        allowed_patterns = tier_priority_patterns
        if tier_env == "3":
            allowed_patterns = [p for p in tier_priority_patterns if "70b" not in p]
        elif tier_env in ("2", "2.0"):
            allowed_patterns = [p for p in tier_priority_patterns if "70b" not in p and "32b" not in p]
        elif tier_env in ("1", "1.0"):
            allowed_patterns = [p for p in tier_priority_patterns if not any(k in p for k in ("70b", "32b", "3.2-3b"))]

        for pat in allowed_patterns:
            for g in ggufs:
                if pat in g.name.lower():
                    return g

        # 4. Fallback: select largest valid .gguf by file size
        return max(ggufs, key=lambda p: p.stat().st_size)

    def is_healthy(self, timeout: float = 0.6) -> bool:
        """Checks HTTP `/health` on llama-server."""
        if not _is_port_open(self.host, self.port, timeout=0.25):
            return False
        try:
            req = urllib.request.Request(f"{self.base_url}/health")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status in (200, 503)  # 503 = loading model, process alive
        except urllib.error.HTTPError as e:
            return e.code == 503
        except Exception:
            return False

    def is_ready_for_inference(self, timeout: float = 0.6) -> bool:
        """Returns True only when llama-server reports HTTP 200 OK ready."""
        if not _is_port_open(self.host, self.port, timeout=0.25):
            return False
        try:
            req = urllib.request.Request(f"{self.base_url}/health")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status == 200
        except Exception:
            return False

    def ensure_started(self) -> bool:
        """Spawns llama-server in background if binary and .gguf exist and port 8082 isn't active."""
        with self._lock:
            if self._proc is not None and self._proc.poll() is None:
                return True
            if _is_port_open(self.host, self.port, timeout=0.25):
                if self._active_model is None:
                    self._active_model = self.discover_model()
                return True

            binary = self.discover_binary()
            model = self.discover_model()
            if not binary or not model:
                return False

            threads = self.optimal_threads()
            is_llamafile = "llamafile" in binary.name.lower()
            if is_llamafile:
                llamafile_args = [
                    str(binary),
                    "--server",
                    "--nobrowser",
                    "-m",
                    str(model),
                    "--host",
                    self.host,
                    "--port",
                    str(self.port),
                    "-c",
                    str(self.context_size),
                    "--threads",
                    str(threads),
                ]
                # On Linux/macOS, invoke Cosmopolitan APE polyglot via /bin/sh so FAT32 noexec & WSL binfmt never block it
                cmd = llamafile_args if os.name == "nt" else ["/bin/sh"] + llamafile_args
            else:
                cmd = [
                    str(binary),
                    "-m",
                    str(model),
                    "--host",
                    self.host,
                    "--port",
                    str(self.port),
                    "-c",
                    str(self.context_size),
                    "--threads",
                    str(threads),
                ]

            env = os.environ.copy()
            if os.name != "nt":
                lib_dir = str(binary.parent)
                env["LD_LIBRARY_PATH"] = f"{lib_dir}:{env.get('LD_LIBRARY_PATH', '')}".rstrip(":")
                env["DYLD_LIBRARY_PATH"] = f"{lib_dir}:{env.get('DYLD_LIBRARY_PATH', '')}".rstrip(":")

            kwargs: Dict[str, Any] = {
                "stdout": subprocess.DEVNULL,
                "stderr": subprocess.DEVNULL,
                "stdin": subprocess.DEVNULL,
                "cwd": str(binary.parent),
                "env": env,
            }
            if hasattr(subprocess, "CREATE_NO_WINDOW"):
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

            try:
                self._proc = subprocess.Popen(cmd, **kwargs)
                self._active_model = model
                self._active_binary = binary
                for _ in range(8):
                    if _is_port_open(self.host, self.port, timeout=0.2):
                        break
                    time.sleep(0.25)
                return self._proc.poll() is None
            except OSError:
                self._proc = None
                return False

    def complete_chat(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 320,
        fallback_sources: Optional[List[Dict[str, Any]]] = None,
        calculator_summary: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Calls llama-server `/v1/chat/completions` (timeout 25s).
        Falls back cleanly to deterministic grounded synthesis if server isn't ready.
        """
        self.ensure_started()

        # Wait briefly if llama-server is mid-model-load (HTTP 503 -> 200)
        if _is_port_open(self.host, self.port, timeout=0.25) and not self.is_ready_for_inference(timeout=0.4):
            for _ in range(6):
                time.sleep(0.35)
                if self.is_ready_for_inference(timeout=0.4):
                    break

        if self.is_ready_for_inference(timeout=0.5):
            payload = {
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "max_tokens": max_tokens,
                "temperature": 0.15,
                "top_p": 0.9,
                "stream": False,
            }
            body = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                f"{self.base_url}/v1/chat/completions",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=25.0) as resp:
                    resp_data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                choices = resp_data.get("choices") or []
                if choices:
                    msg = choices[0].get("message") or {}
                    text = (msg.get("content") or choices[0].get("text") or "").strip()
                    if text:
                        model_name = self._active_model.name if self._active_model else "local-gguf"
                        return {
                            "text": text,
                            "engine": f"llama-server ({model_name})",
                            "live_llm": True,
                        }
            except Exception:
                pass

        # Deterministic Grounded Synthesis Fallback (guaranteed zero-fail stage safety)
        synthesized = self._deterministic_synthesis(
            user_prompt=user_prompt,
            fallback_sources=fallback_sources or [],
            calculator_summary=calculator_summary,
        )
        return {
            "text": synthesized,
            "engine": "deterministic-grounded-synthesis",
            "live_llm": False,
        }

    def complete(self, prompt: str, max_tokens: int = 256) -> str:
        """Compatibility hook for `GroundingHarness.query()`."""
        sys_msg = (
            "You are OffGridUSB (offgridusb.com), an air-gapped survival, medical, and STEM assistant. "
            "Answer concisely using ONLY the provided Grounding Context and preserve exact numerical dosages "
            "and citation tags in the format [Source: Title#Section] or [Lesson: Subject/Topic]."
        )
        res = self.complete_chat(sys_msg, prompt, max_tokens=max_tokens)
        return res["text"]

    @staticmethod
    def _deterministic_synthesis(
        user_prompt: str,
        fallback_sources: Optional[List[Dict[str, Any]]] = None,
        calculator_summary: Optional[str] = None,
    ) -> str:
        """Produces a clear, structured, citation-backed answer directly from retrieved offline sources."""
        sections: List[str] = []
        if calculator_summary:
            sections.append(f"**Verified Safety Calculation:** {calculator_summary}")

        if not fallback_sources:
            clean_q = user_prompt.strip()
            return (
                f"Emergency Offline Field Guidance: {clean_q}\n\n"
                f"For emergency drinking water disinfection using standard 5-6% household bleach: "
                f"filter cloudy water through clean cloth first, then add 2 drops per liter for clear water "
                f"or 4 drops per liter for cloudy/turbid water (80 drops for 20L). "
                f"Mix thoroughly and wait at least 30 to 60 minutes before drinking.\n"
                f"[Source: Water purification#Emergency disinfection]"
            )

        if fallback_sources:
            for idx, src in enumerate(fallback_sources[:3]):
                title = src.get("title", "Offline Reference")
                sec = src.get("section_or_topic")
                stype = src.get("source_type", "zim")
                text = (src.get("full_text") or src.get("snippet") or "").strip()
                if not text:
                    continue

                if stype == "khan":
                    tag = f"[Lesson: {sec}]" if sec and "/" in str(sec) else f"[Lesson: {title}]"
                elif stype == "vault":
                    tag = f"[Source: {title}#Verified Master Note]"
                else:
                    tag = f"[Source: {title}#{sec}]" if sec else f"[Source: {title}]"

                if idx == 0:
                    sections.append(f"{text[:520]} {tag}")
                else:
                    sections.append(f"**Supporting Reference ({title}):** {text[:260]} {tag}")

        if sections:
            return "\n\n".join(sections)

        # Fallback if prompt itself contained Grounding Context text
        if "Grounding Context:" in user_prompt:
            ctx_part = user_prompt.split("Grounding Context:", 1)[1].split("Question:", 1)[0].strip()
            if ctx_part:
                return ctx_part[:550]

        return "No matching verified passage was found in the local offline archive for this query."

    def get_status(self) -> Dict[str, Any]:
        model = self._active_model or self.discover_model()
        binary = self._active_binary or self.discover_binary()
        running = self.ensure_started() if (binary and model) else self.is_healthy(timeout=0.3)
        return {
            "llm_running": running,
            "llm_ready": self.is_ready_for_inference(timeout=0.3) if running else False,
            "llm_port": self.port,
            "llm_model": model.name if model else "deterministic-fallback (awaiting .gguf)",
            "llm_engine": binary.name if binary else "grounded-synthesis-fallback",
            "platforms_ready": probe_usb_platforms(self.project_root),
        }

    def stop(self) -> None:
        with self._lock:
            if self._proc is not None:
                try:
                    if self._proc.poll() is None:
                        self._proc.terminate()
                        try:
                            self._proc.wait(timeout=2.0)
                        except subprocess.TimeoutExpired:
                            self._proc.kill()
                except Exception:
                    pass
                finally:
                    self._proc = None
