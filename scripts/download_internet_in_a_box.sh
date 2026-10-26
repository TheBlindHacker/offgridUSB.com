#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# OffGridUSB (offgridusb.com) — Cross-Platform Internet-in-a-Box & AI Downloader
# Works on Linux (x86_64 & ARM64 / Raspberry Pi) and macOS (Apple Silicon & Intel)
#
# Usage:
#   ./scripts/download_internet_in_a_box.sh                 # Interactive or Tier 0
#   ./scripts/download_internet_in_a_box.sh --tier 0        # Survival Core (~850 MB)
#   ./scripts/download_internet_in_a_box.sh --tier 2        # Khan + 50GB Wikipedia
#   ./scripts/download_internet_in_a_box.sh --zim-only      # Only OpenZIM archives
#   ./scripts/download_internet_in_a_box.sh --engines-only  # Only Kiwix + llama.cpp
#   ./scripts/download_internet_in_a_box.sh --verify        # Verify staged files
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

TIER=0
ENGINES_ONLY=0
ZIM_ONLY=0
MODELS_ONLY=0
CURRENT_OS_ONLY=0
VERIFY_ONLY=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)
            echo "================================================================================"
            echo "OffGridUSB (offgridusb.com) — Internet-in-a-Box & AI Provisioning Script"
            echo "================================================================================"
            echo "Usage: ./scripts/download_internet_in_a_box.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --tier <0-4>       Maximum hardware/knowledge tier to stage (default: 0)"
            echo "                       0 = Pocket Survival Pack (~850 MB: Water/Med ZIMs + 0.5B AI)"
            echo "                       1 = Legacy Laptop / Pi 4-5 (~2 GB: adds 135M + 1.5B AI)"
            echo "                       2 = Full School & Wiki (~59 GB: Khan Academy + 50GB Wikipedia)"
            echo "                       3 = Scavenged Swarm (~78 GB: adds Qwen2.5-32B AI)"
            echo "                       4 = Settlement Hub (~230 GB: 110GB Illustrated Wiki + 70B AI)"
            echo "  --engines-only     Download only portable Kiwix-Serve, llama.cpp & Python engines"
            echo "  --zim-only         Download only Internet-in-a-Box (.zim) knowledge packs"
            echo "  --models-only      Download only offline GGUF (.gguf) AI models"
            echo "  --current-os-only  Stage binaries only for the current OS/CPU instead of universal USB"
            echo "  --verify           Verify staged engines, .zim headers, and .gguf headers"
            echo "  --help, -h         Show this help message"
            echo "================================================================================"
            exit 0
            ;;
        --tier)
            TIER="$2"
            shift 2
            ;;
        --engines-only)
            ENGINES_ONLY=1
            shift
            ;;
        --zim-only)
            ZIM_ONLY=1
            shift
            ;;
        --models-only)
            MODELS_ONLY=1
            shift
            ;;
        --current-os-only)
            CURRENT_OS_ONLY=1
            shift
            ;;
        --verify)
            VERIFY_ONLY=1
            shift
            ;;
        *)
            echo "[WARN] Ignoring unknown flag: $1"
            shift
            ;;
    esac
done

PYTHON_BIN=""
for cand in python3 python; do
    if command -v "${cand}" >/dev/null 2>&1; then
        PYTHON_BIN="${cand}"
        break
    fi
done

if [[ -z "${PYTHON_BIN}" ]]; then
    echo "[ERROR] python3 is required to parse manifests and verify binary headers." >&2
    exit 1
fi

if [[ "${VERIFY_ONLY}" -eq 1 ]]; then
    PYTHONPATH="${ROOT_DIR}/src" "${PYTHON_BIN}" -m emyrge.assets.fetch_assets --verify
    exit 0
fi

fetch_url() {
    local url="$1"
    local dest="$2"
    local min_bytes="${3:-65536}"

    mkdir -p "$(dirname "${dest}")"

    if [[ -f "${dest}" ]]; then
        local sz
        sz="$(wc -c < "${dest}" | tr -d ' ')"
        if [[ "${sz}" -ge "${min_bytes}" ]]; then
            echo "  [SKIP] Already staged: ${dest} ($(( sz / 1048576 )) MB)"
            return 0
        fi
    fi

    local part="${dest}.part"
    echo "  [DL]   ${url} -> ${dest}"
    if command -v curl >/dev/null 2>&1; then
        local curl_args=("-L" "-f" "--retry" "5" "--retry-connrefused" "--retry-delay" "2" "--connect-timeout" "30" "-A" "OffGridUSB-Provisioner/0.1")
        if [[ -f "${part}" ]]; then
            curl "${curl_args[@]}" -C - -o "${part}" "${url}"
            local rc=$?
            if [[ ${rc} -eq 33 ]]; then
                echo "  [WARN] Server rejected byte-range resume (exit code 33 / HTTP 416). Retrying clean..."
                rm -f "${part}"
                curl "${curl_args[@]}" -o "${part}" "${url}" || {
                    echo "[ERROR] Download failed for ${url} (curl exit code $?)" >&2
                    return 1
                }
            elif [[ ${rc} -ne 0 ]]; then
                echo "[ERROR] Download failed for ${url} (curl exit code ${rc}). Partial file preserved at ${part}." >&2
                return ${rc}
            fi
        else
            curl "${curl_args[@]}" -o "${part}" "${url}" || {
                echo "[ERROR] Download failed for ${url} (curl exit code $?). Partial file preserved at ${part}." >&2
                return $?
            }
        fi
    elif command -v wget >/dev/null 2>&1; then
        wget -c -U "OffGridUSB-Provisioner/0.1" -O "${part}" "${url}"
    else
        echo "[ERROR] Neither curl nor wget found. Please install curl or wget." >&2
        exit 1
    fi

    mv -f "${part}" "${dest}"
    echo "  [OK]   Saved ${dest}"
}

extract_zip_flat() {
    local zip_path="$1"
    local target_dir="$2"
    "${PYTHON_BIN}" - "${zip_path}" "${target_dir}" <<'PY'
import pathlib, shutil, sys, tempfile, zipfile
zip_path = pathlib.Path(sys.argv[1])
target_dir = pathlib.Path(sys.argv[2])
target_dir.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory() as tmp:
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(tmp)
    for item in pathlib.Path(tmp).rglob("*"):
        if item.is_file():
            shutil.copy2(item, target_dir / item.name)
PY
}

mkdir -p \
    bin/windows_x86_64/python \
    bin/windows_x86_64/kiwix \
    bin/windows_x86_64/llama \
    bin/windows_arm64/llama \
    bin/linux_x86_64 \
    bin/linux_arm64 \
    bin/macos_arm64 \
    bin/macos_x86_64 \
    bin/polyglot \
    data/models \
    data/zim \
    data/vault \
    data/uploads \
    tmp_dl

OS_NAME="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH_NAME="$(uname -m)"

# ------------------------------------------------------------------------------
# 1. Portable Cross-Platform Engines
# ------------------------------------------------------------------------------
if [[ "${ZIM_ONLY}" -eq 0 && "${MODELS_ONLY}" -eq 0 ]]; then
    echo "================================================================================"
    echo "[1/3] Staging Portable Engines (Kiwix-Serve + llama.cpp + Zero-Install Python)"
    echo "================================================================================"

    if [[ "${CURRENT_OS_ONLY}" -eq 0 ]]; then
        # Windows x64 Portable Python + Kiwix + llama-server (so the USB boots on Windows too!)
        if [[ ! -f "bin/windows_x86_64/python/python.exe" ]]; then
            fetch_url "https://www.python.org/ftp/python/3.12.8/python-3.12.8-embed-amd64.zip" "tmp_dl/py_embed.zip"
            "${PYTHON_BIN}" -c "import zipfile; zipfile.ZipFile('tmp_dl/py_embed.zip').extractall('bin/windows_x86_64/python')"
            printf "python312.zip\r\n.\r\n..\\..\\..\\src\r\nimport site\r\n" > "bin/windows_x86_64/python/python312._pth"
        fi
        if [[ ! -f "bin/windows_x86_64/kiwix/kiwix-serve.exe" ]]; then
            fetch_url "https://download.kiwix.org/release/kiwix-tools/kiwix-tools_win-x86_64-3.8.1.zip" "tmp_dl/kiwix_win.zip"
            extract_zip_flat "tmp_dl/kiwix_win.zip" "bin/windows_x86_64/kiwix"
        fi
        if [[ ! -f "bin/windows_x86_64/llama/llama-server.exe" ]]; then
            fetch_url "https://github.com/ggml-org/llama.cpp/releases/download/b11867/llama-b11867-bin-win-cpu-x64.zip" "tmp_dl/llama_win_x64.zip"
            extract_zip_flat "tmp_dl/llama_win_x64.zip" "bin/windows_x86_64/llama"
        fi
        if [[ ! -f "bin/windows_arm64/llama/llama-server.exe" ]]; then
            fetch_url "https://github.com/ggml-org/llama.cpp/releases/download/b11867/llama-b11867-bin-win-cpu-arm64.zip" "tmp_dl/llama_win_arm64.zip"
            extract_zip_flat "tmp_dl/llama_win_arm64.zip" "bin/windows_arm64/llama"
        fi
    fi

    # Linux x86_64
    if [[ "${CURRENT_OS_ONLY}" -eq 0 ]] || [[ "${OS_NAME}" == "linux" && "${ARCH_NAME}" == "x86_64" ]]; then
        fetch_url "https://download.kiwix.org/release/kiwix-tools/kiwix-tools_linux-x86_64-3.8.1.tar.gz" "bin/linux_x86_64/kiwix-tools_linux-x86_64.tar.gz"
        fetch_url "https://github.com/ggml-org/llama.cpp/releases/download/b11867/llama-b11867-bin-ubuntu-x64.tar.gz" "bin/linux_x86_64/llama-ubuntu-x64.tar.gz"
    fi

    # Linux ARM64 (Raspberry Pi 4/5 & ARM SBCs)
    if [[ "${CURRENT_OS_ONLY}" -eq 0 ]] || [[ "${OS_NAME}" == "linux" && ( "${ARCH_NAME}" == "aarch64" || "${ARCH_NAME}" == "arm64" ) ]]; then
        fetch_url "https://download.kiwix.org/release/kiwix-tools/kiwix-tools_linux-aarch64-3.8.1.tar.gz" "bin/linux_arm64/kiwix-tools_linux-aarch64.tar.gz"
        fetch_url "https://github.com/ggml-org/llama.cpp/releases/download/b11867/llama-b11867-bin-ubuntu-arm64.tar.gz" "bin/linux_arm64/llama-ubuntu-arm64.tar.gz"
    fi

    # macOS Apple Silicon (ARM64)
    if [[ "${CURRENT_OS_ONLY}" -eq 0 ]] || [[ "${OS_NAME}" == "darwin" && "${ARCH_NAME}" == "arm64" ]]; then
        fetch_url "https://download.kiwix.org/release/kiwix-tools/kiwix-tools_macos-arm64-3.8.1.tar.gz" "bin/macos_arm64/kiwix-tools_macos.tar.gz"
        fetch_url "https://github.com/ggml-org/llama.cpp/releases/download/b11867/llama-b11867-bin-macos-arm64.tar.gz" "bin/macos_arm64/llama-macos-arm64.tar.gz"
    fi

    # macOS Intel (x86_64)
    if [[ "${CURRENT_OS_ONLY}" -eq 0 ]] || [[ "${OS_NAME}" == "darwin" && "${ARCH_NAME}" == "x86_64" ]]; then
        fetch_url "https://download.kiwix.org/release/kiwix-tools/kiwix-tools_macos-x86_64-3.8.1.tar.gz" "bin/macos_x86_64/kiwix-tools_macos-x86_64.tar.gz"
        fetch_url "https://github.com/ggml-org/llama.cpp/releases/download/b11867/llama-b11867-bin-macos-x64.tar.gz" "bin/macos_x86_64/llama-macos-x64.tar.gz"
    fi

    # Polyglot llamafile fallback
    if [[ "${CURRENT_OS_ONLY}" -eq 0 ]]; then
        fetch_url "https://github.com/mozilla-ai/llamafile/releases/download/0.10.6/llamafile-0.10.6-thin" "bin/polyglot/llamafile.exe"
        chmod +x "bin/polyglot/llamafile.exe" 2>/dev/null || true
    fi
fi

# ------------------------------------------------------------------------------
# 2 & 3. Internet-in-a-Box (.zim) & Offline GGUF Models (.gguf)
# ------------------------------------------------------------------------------
if [[ "${ENGINES_ONLY}" -eq 0 ]]; then
    echo "================================================================================"
    echo "[2/3] Fetching Internet-in-a-Box ZIMs & GGUF Models (Tier <= ${TIER})"
    echo "================================================================================"

    FETCH_ARGS=("--tier" "${TIER}")
    if [[ "${ZIM_ONLY}" -eq 1 ]]; then
        FETCH_ARGS+=("--zim-only")
    elif [[ "${MODELS_ONLY}" -eq 1 ]]; then
        FETCH_ARGS+=("--models-only")
    fi

    PYTHONPATH="${ROOT_DIR}/src" "${PYTHON_BIN}" -m emyrge.assets.fetch_assets "${FETCH_ARGS[@]}"
fi

rm -rf tmp_dl
chmod +x run_linux.sh run_macos.command START_EMYRGE_LINUX.sh START_EMYRGE_MAC.command 2>/dev/null || true

echo "================================================================================"
echo "[3/3] Verification Summary"
echo "================================================================================"
PYTHONPATH="${ROOT_DIR}/src" "${PYTHON_BIN}" -m emyrge.assets.fetch_assets --verify
echo ""
echo "[OK] Ready! Next step: Run ./scripts/setup_usb_unix.sh --list to format/provision your USB."
