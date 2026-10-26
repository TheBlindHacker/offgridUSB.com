<#
.SYNOPSIS
    OffGridUSB (offgridusb.com) -- Internet-in-a-Box, Portable Engine & AI Model Downloader
.DESCRIPTION
    Downloads and verifies all air-gapped runtime components needed to build a universal
    OffGridUSB flash drive:
      1. Portable Cross-Platform Binaries (Python 3.12 Embeddable, Kiwix-Serve 3.8.1,
         llama.cpp b11867 for Windows/Linux/Raspberry Pi/macOS, and Mozilla llamafile)
      2. Internet-in-a-Box OpenZIM Encyclopedias (manifests/zim.json: Water, Austere Medicine,
         Wikipedia Medicine Mini, Khan Academy STEM, Full English Wikipedia 50GB / 110GB)
      3. Elastic GGUF AI Weights (manifests/models.json: Tier 0 0.5B through Tier 4 70B)
.EXAMPLE
    .\scripts\download_internet_in_a_box.ps1
    .\scripts\download_internet_in_a_box.ps1 -Tier 0 -NonInteractive
    .\scripts\download_internet_in_a_box.ps1 -Tier 2 -NonInteractive
    .\scripts\download_internet_in_a_box.ps1 -Verify
#>

param(
    [ValidateRange(0, 4)]
    [int]$Tier = 0,
    [switch]$NonInteractive,
    [switch]$EnginesOnly,
    [switch]$ZimOnly,
    [switch]$ModelsOnly,
    [switch]$CurrentOsOnly,
    [switch]$IncludeUltraMicro,
    [switch]$Verify
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $Root
[System.IO.Directory]::SetCurrentDirectory($Root)

function Test-FileMagicHeader {
    param(
        [string]$FilePath,
        [ValidateSet("ZIM", "GGUF", "ANY")]
        [string]$Expected = "ANY"
    )
    if (-not (Test-Path $FilePath)) { return $false }
    $item = Get-Item $FilePath
    if ($item.Length -lt 1024) { return $false }
    if ($Expected -eq "ANY") { return $true }

    $fs = [System.IO.File]::OpenRead($item.FullName)
    try {
        $buf = New-Object byte[] 4
        $read = $fs.Read($buf, 0, 4)
        if ($read -lt 4) { return $false }
        if ($Expected -eq "GGUF") {
            return ($buf[0] -eq 0x47 -and $buf[1] -eq 0x47 -and $buf[2] -eq 0x55 -and $buf[3] -eq 0x46)
        }
        if ($Expected -eq "ZIM") {
            # Little-endian ZIM\x04: 0x5A 0x49 0x4D 0x04
            return ($buf[0] -eq 0x5A -and $buf[1] -eq 0x49 -and $buf[2] -eq 0x4D -and $buf[3] -eq 0x04)
        }
        return $true
    } finally {
        $fs.Close()
    }
}

function Invoke-ResumableDownload {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$Dest,
        [ValidateSet("ZIM", "GGUF", "ANY")]
        [string]$MagicCheck = "ANY",
        [long]$MinBytes = 65536
    )

    $parentDir = Split-Path -Parent $Dest
    if ($parentDir -and -not (Test-Path $parentDir)) {
        New-Item -ItemType Directory -Force -Path $parentDir | Out-Null
    }

    if (Test-Path $Dest) {
        $existingLen = (Get-Item $Dest).Length
        if ($existingLen -ge $MinBytes -and (Test-FileMagicHeader -FilePath $Dest -Expected $MagicCheck)) {
            $mb = [math]::Round($existingLen / 1MB, 1)
            Write-Host "  [SKIP] Verified & staged: $Dest ($mb MB)" -ForegroundColor DarkGreen
            return
        }
    }

    $partFile = "$Dest.part"
    Write-Host "  [DL]   Fetching: $Url" -ForegroundColor Cyan
    Write-Host "         Target  : $Dest" -ForegroundColor Gray

    if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
        $curlArgs = @(
            "-L", "-f",
            "--retry", "5",
            "--retry-connrefused",
            "--retry-delay", "2",
            "--connect-timeout", "30",
            "-A", "OffGridUSB-Provisioner/0.1"
        )
        if (Test-Path $partFile) {
            $curlArgs += @("-C", "-")
        }
        $curlArgs += @("-o", $partFile, $Url)
        & curl.exe @curlArgs
        if ($LASTEXITCODE -ne 0) {
            # Only remove partFile if server rejected byte-range resume (curl exit code 33 = HTTP 416 Range Not Satisfiable)
            if ($LASTEXITCODE -eq 33) {
                Write-Warning "Server rejected byte-range resume (curl exit code 33 / HTTP 416). Retrying clean download..."
                Remove-Item $partFile -Force -ErrorAction SilentlyContinue
                & curl.exe -L -f --retry 5 --retry-connrefused --retry-delay 2 --connect-timeout 30 -A "OffGridUSB-Provisioner/0.1" -o $partFile $Url
            }
            if ($LASTEXITCODE -ne 0) {
                throw "Download failed for $Url (curl exit code $LASTEXITCODE). Partial file preserved at $partFile for resumption."
            }
        }
    } else {
        Invoke-WebRequest -Uri $Url -OutFile $partFile -UseBasicParsing -UserAgent "OffGridUSB-Provisioner/0.1"
    }

    Move-Item -Path $partFile -Destination $Dest -Force
    $finalLen = (Get-Item $Dest).Length
    if ($finalLen -lt $MinBytes -or -not (Test-FileMagicHeader -FilePath $Dest -Expected $MagicCheck)) {
        throw "Integrity check failed for $Dest ($finalLen bytes, expected header: $MagicCheck)"
    }
    $finalMb = [math]::Round($finalLen / 1MB, 1)
    Write-Host "  [OK]   Ready: $Dest ($finalMb MB)" -ForegroundColor Green
}

function Show-VerifyReport {
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "  OffGridUSB (offgridusb.com) -- Offline Asset & Engine Verification Report" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan

    $engineChecks = @(
        @{ Name = "Windows x64 Portable Python 3.12"; Path = "bin\windows_x86_64\python\python.exe" },
        @{ Name = "Windows x64 Kiwix ZIM Server";     Path = "bin\windows_x86_64\kiwix\kiwix-serve.exe" },
        @{ Name = "Windows x64 llama-server";         Path = "bin\windows_x86_64\llama\llama-server.exe" },
        @{ Name = "Windows ARM64 llama-server";       Path = "bin\windows_arm64\llama\llama-server.exe" },
        @{ Name = "Linux x64 Kiwix Bundle";           Path = "bin\linux_x86_64\kiwix-tools_linux-x86_64.tar.gz" },
        @{ Name = "Linux x64 llama-server Bundle";    Path = "bin\linux_x86_64\llama-ubuntu-x64.tar.gz" },
        @{ Name = "Linux ARM64 (Pi) Kiwix Bundle";    Path = "bin\linux_arm64\kiwix-tools_linux-aarch64.tar.gz" },
        @{ Name = "Linux ARM64 (Pi) llama Bundle";    Path = "bin\linux_arm64\llama-ubuntu-arm64.tar.gz" },
        @{ Name = "macOS Apple Silicon Kiwix Bundle"; Path = "bin\macos_arm64\kiwix-tools_macos.tar.gz" },
        @{ Name = "macOS Apple Silicon llama Bundle"; Path = "bin\macos_arm64\llama-macos-arm64.tar.gz" },
        @{ Name = "Polyglot Cosmopolitan llamafile";  Path = "bin\polyglot\llamafile.exe" }
    )

    Write-Host "`n  [Portable Cross-Platform Engines]" -ForegroundColor Yellow
    foreach ($ec in $engineChecks) {
        $exists = Test-Path $ec.Path
        $status = if ($exists) { "[READY]" } else { "[MISSING]" }
        $color  = if ($exists) { "Green" } else { "DarkYellow" }
        Write-Host ("    {0,-10} {1,-36} ({2})" -f $status, $ec.Name, $ec.Path) -ForegroundColor $color
    }

    Write-Host "`n  [Staged Internet-in-a-Box OpenZIM Archives (data\zim)]" -ForegroundColor Yellow
    $zims = if (Test-Path "data\zim") { Get-ChildItem "data\zim\*.zim" -ErrorAction SilentlyContinue } else { @() }
    if (-not $zims -or $zims.Count -eq 0) {
        Write-Host "    [NONE] No .zim files found in data\zim yet." -ForegroundColor DarkYellow
    } else {
        foreach ($z in $zims) {
            $valid = Test-FileMagicHeader -FilePath $z.FullName -Expected "ZIM"
            $tag = if ($valid) { "[VALID ZIM]" } else { "[BAD HEADER]" }
            $col = if ($valid) { "Green" } else { "Red" }
            Write-Host ("    {0,-13} {1,-44} ({2,8:N1} MB)" -f $tag, $z.Name, ($z.Length / 1MB)) -ForegroundColor $col
        }
    }

    Write-Host "`n  [Staged Offline GGUF AI Models (data\models)]" -ForegroundColor Yellow
    $models = if (Test-Path "data\models") { Get-ChildItem "data\models\*.gguf" -ErrorAction SilentlyContinue } else { @() }
    if (-not $models -or $models.Count -eq 0) {
        Write-Host "    [NONE] No .gguf models found in data\models yet." -ForegroundColor DarkYellow
    } else {
        foreach ($m in $models) {
            $valid = Test-FileMagicHeader -FilePath $m.FullName -Expected "GGUF"
            $tag = if ($valid) { "[VALID GGUF]" } else { "[BAD HEADER]" }
            $col = if ($valid) { "Green" } else { "Red" }
            Write-Host ("    {0,-13} {1,-44} ({2,8:N1} MB)" -f $tag, $m.Name, ($m.Length / 1MB)) -ForegroundColor $col
        }
    }
    Write-Host ""
}

if ($Verify) {
    Show-VerifyReport
    exit 0
}

# Interactive pack selector when launched via double-click without flags
if (-not $NonInteractive -and -not $PSBoundParameters.ContainsKey("Tier") -and -not $EnginesOnly -and -not $ZimOnly -and -not $ModelsOnly) {
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "  OffGridUSB (offgridusb.com) // Internet-in-a-Box & AI Provisioning Wizard" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Choose the Offline Knowledge & AI Pack size for your target USB drive:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    [0] Tier 0 -- Pocket Survival Pack (~850 MB total | Fits ANY 4GB-16GB+ USB)" -ForegroundColor Green
    Write-Host "        * Cross-OS Portable Engines (Win/Mac/Linux/Pi Python + Kiwix + llama.cpp)"
    Write-Host "        * Safe Water Manual + Austere Field Medicine + Wikipedia Medicine Mini ZIMs"
    Write-Host "        * Qwen2.5-0.5B-Instruct Q4_K_M Universal AI Model (~380 MB)"
    Write-Host ""
    Write-Host "    [1] Tier 1 -- Legacy Laptop & Raspberry Pi 4/5 Pack (~2.0 GB | 8GB+ USB)" -ForegroundColor Cyan
    Write-Host "        * Everything in Tier 0 + SmolLM2-135M + Qwen2.5-1.5B-Instruct GGUF"
    Write-Host ""
    Write-Host "    [2] Tier 2 -- Full Civilization & School-in-a-Box (~59 GB | 64GB-128GB exFAT USB)" -ForegroundColor Cyan
    Write-Host "        * Everything in Tier 1 + Llama-3.2-3B-Instruct GGUF"
    Write-Host "        * Khan Academy Complete STEM & K-12 ZIM (~4.6 GB)"
    Write-Host "        * Full Compact English Wikipedia ZIM (~50 GB)"
    Write-Host ""
    Write-Host "    [3] Tier 3 -- Scavenged Swarm 32B Pack (~78 GB | 128GB+ exFAT USB)" -ForegroundColor Cyan
    Write-Host "        * Everything in Tier 2 + Qwen2.5-32B-Instruct GGUF (~19 GB)"
    Write-Host ""
    Write-Host "    [4] Tier 4 -- Settlement Hub Master Archive (~230 GB | 256GB-512GB USB SSD)" -ForegroundColor Cyan
    Write-Host "        * Full Illustrated English Wikipedia Maxi ZIM (~110 GB) + Llama-3.3-70B GGUF"
    Write-Host ""
    Write-Host "    [V] Verify currently downloaded files only" -ForegroundColor Gray
    Write-Host "    [Q] Quit" -ForegroundColor Gray
    Write-Host ""

    $choice = Read-Host "  Select option [0-4, V, Q] (Press Enter for [0] Recommended)"
    $c = if ($null -eq $choice) { "0" } else { $choice.Trim().ToUpper() }
    if ($c -eq "" -or $c -eq "0") { $Tier = 0 }
    elseif ($c -eq "1") { $Tier = 1; $IncludeUltraMicro = $true }
    elseif ($c -eq "2") { $Tier = 2; $IncludeUltraMicro = $true }
    elseif ($c -eq "3") { $Tier = 3; $IncludeUltraMicro = $true }
    elseif ($c -eq "4") { $Tier = 4; $IncludeUltraMicro = $true }
    elseif ($c -eq "V") { Show-VerifyReport; exit 0 }
    elseif ($c -eq "Q") { exit 0 }
    else {
        Write-Host "  [WARN] Unrecognized input '$c' -- defaulting to Tier 0." -ForegroundColor Yellow
        $Tier = 0
    }
}

# Create standard USB runtime directories
$dirs = @(
    "bin\windows_x86_64\python",
    "bin\windows_x86_64\kiwix",
    "bin\windows_x86_64\llama",
    "bin\windows_arm64\llama",
    "bin\linux_x86_64",
    "bin\linux_arm64",
    "bin\macos_arm64",
    "bin\macos_x86_64",
    "bin\polyglot",
    "data\models",
    "data\zim",
    "data\vault",
    "data\uploads",
    "tmp_dl"
)
foreach ($d in $dirs) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}

# ------------------------------------------------------------------------------
# STEP 1: Portable Zero-Install Engines (Python + Kiwix-Serve + llama.cpp)
# ------------------------------------------------------------------------------
if (-not $ZimOnly -and -not $ModelsOnly) {
    Write-Host ""
    Write-Host "=== [1/3] Staging Portable Cross-Platform Engines ===" -ForegroundColor Cyan

    # 1A. Portable Python 3.12.8 Embeddable for Windows x86_64 (Zero-Install)
    if (-not (Test-Path "bin\windows_x86_64\python\python.exe")) {
        Invoke-ResumableDownload `
            -Url "https://www.python.org/ftp/python/3.12.8/python-3.12.8-embed-amd64.zip" `
            -Dest "tmp_dl\py_embed.zip"
        Expand-Archive -Path "tmp_dl\py_embed.zip" -DestinationPath "bin\windows_x86_64\python" -Force
        $pth = @"
python312.zip
.
..\..\..\src
import site
"@
        Set-Content -Path "bin\windows_x86_64\python\python312._pth" -Value $pth -Encoding ASCII
        Write-Host "  [OK]   Configured zero-install Python 3.12.8 (bin\windows_x86_64\python)" -ForegroundColor Green
    } else {
        Write-Host "  [SKIP] Portable Python 3.12.8 already staged" -ForegroundColor DarkGreen
    }

    # 1B. Portable Kiwix Tools (kiwix-serve.exe -- Internet-in-a-Box ZIM Server)
    if (-not (Test-Path "bin\windows_x86_64\kiwix\kiwix-serve.exe")) {
        Invoke-ResumableDownload `
            -Url "https://download.kiwix.org/release/kiwix-tools/kiwix-tools_win-x86_64-3.8.1.zip" `
            -Dest "tmp_dl\kiwix_win.zip"
        Expand-Archive -Path "tmp_dl\kiwix_win.zip" -DestinationPath "tmp_dl\kiwix_win_ext" -Force
        Get-ChildItem -Path "tmp_dl\kiwix_win_ext" -Recurse -File | Copy-Item -Destination "bin\windows_x86_64\kiwix" -Force
        Write-Host "  [OK]   Extracted Windows kiwix-serve.exe" -ForegroundColor Green
    } else {
        Write-Host "  [SKIP] Windows kiwix-serve.exe already staged" -ForegroundColor DarkGreen
    }

    # 1C. Windows x86_64 & ARM64 llama.cpp (llama-server.exe)
    if (-not (Test-Path "bin\windows_x86_64\llama\llama-server.exe")) {
        Invoke-ResumableDownload `
            -Url "https://github.com/ggml-org/llama.cpp/releases/download/b11867/llama-b11867-bin-win-cpu-x64.zip" `
            -Dest "tmp_dl\llama_win_x64.zip"
        Expand-Archive -Path "tmp_dl\llama_win_x64.zip" -DestinationPath "tmp_dl\llama_win_x64_ext" -Force
        Get-ChildItem -Path "tmp_dl\llama_win_x64_ext" -Recurse -File | Copy-Item -Destination "bin\windows_x86_64\llama" -Force
        Write-Host "  [OK]   Extracted Windows x64 llama-server.exe" -ForegroundColor Green
    } else {
        Write-Host "  [SKIP] Windows x64 llama-server.exe already staged" -ForegroundColor DarkGreen
    }

    if (-not $CurrentOsOnly) {
        if (-not (Test-Path "bin\windows_arm64\llama\llama-server.exe")) {
            Invoke-ResumableDownload `
                -Url "https://github.com/ggml-org/llama.cpp/releases/download/b11867/llama-b11867-bin-win-cpu-arm64.zip" `
                -Dest "tmp_dl\llama_win_arm64.zip"
            Expand-Archive -Path "tmp_dl\llama_win_arm64.zip" -DestinationPath "tmp_dl\llama_win_arm64_ext" -Force
            Get-ChildItem -Path "tmp_dl\llama_win_arm64_ext" -Recurse -File | Copy-Item -Destination "bin\windows_arm64\llama" -Force
            Write-Host "  [OK]   Extracted Windows ARM64 llama-server.exe" -ForegroundColor Green
        }

        # Keep POSIX .tar.gz archives intact on USB so Linux, Raspberry Pi & macOS preserve .so/.dylib symlinks off exFAT/FAT32!
        Invoke-ResumableDownload `
            -Url "https://download.kiwix.org/release/kiwix-tools/kiwix-tools_linux-x86_64-3.8.1.tar.gz" `
            -Dest "bin\linux_x86_64\kiwix-tools_linux-x86_64.tar.gz"
        Invoke-ResumableDownload `
            -Url "https://github.com/ggml-org/llama.cpp/releases/download/b11867/llama-b11867-bin-ubuntu-x64.tar.gz" `
            -Dest "bin\linux_x86_64\llama-ubuntu-x64.tar.gz"

        Invoke-ResumableDownload `
            -Url "https://download.kiwix.org/release/kiwix-tools/kiwix-tools_linux-aarch64-3.8.1.tar.gz" `
            -Dest "bin\linux_arm64\kiwix-tools_linux-aarch64.tar.gz"
        Invoke-ResumableDownload `
            -Url "https://github.com/ggml-org/llama.cpp/releases/download/b11867/llama-b11867-bin-ubuntu-arm64.tar.gz" `
            -Dest "bin\linux_arm64\llama-ubuntu-arm64.tar.gz"

        Invoke-ResumableDownload `
            -Url "https://download.kiwix.org/release/kiwix-tools/kiwix-tools_macos-arm64-3.8.1.tar.gz" `
            -Dest "bin\macos_arm64\kiwix-tools_macos.tar.gz"
        Invoke-ResumableDownload `
            -Url "https://github.com/ggml-org/llama.cpp/releases/download/b11867/llama-b11867-bin-macos-arm64.tar.gz" `
            -Dest "bin\macos_arm64\llama-macos-arm64.tar.gz"

        Invoke-ResumableDownload `
            -Url "https://download.kiwix.org/release/kiwix-tools/kiwix-tools_macos-x86_64-3.8.1.tar.gz" `
            -Dest "bin\macos_x86_64\kiwix-tools_macos-x86_64.tar.gz"
        Invoke-ResumableDownload `
            -Url "https://github.com/ggml-org/llama.cpp/releases/download/b11867/llama-b11867-bin-macos-x64.tar.gz" `
            -Dest "bin\macos_x86_64\llama-macos-x64.tar.gz"

        Invoke-ResumableDownload `
            -Url "https://github.com/mozilla-ai/llamafile/releases/download/0.10.6/llamafile-0.10.6-thin" `
            -Dest "bin\polyglot\llamafile.exe"
    }
}

# ------------------------------------------------------------------------------
# STEP 2: Internet-in-a-Box OpenZIM Knowledge Packs (manifests/zim.json)
# ------------------------------------------------------------------------------
if (-not $EnginesOnly -and -not $ModelsOnly) {
    Write-Host ""
    Write-Host "=== [2/3] Downloading Internet-in-a-Box OpenZIM Archives (Tier <= $Tier) ===" -ForegroundColor Cyan

    $zimManifestPath = Join-Path $Root "manifests\zim.json"
    $zimManifest = Get-Content $zimManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($z in $zimManifest.archives) {
        if ([int]$z.tier -le $Tier) {
            $destPath = Join-Path $Root (Join-Path "data\zim" $z.filename)
            Invoke-ResumableDownload -Url $z.url -Dest $destPath -MagicCheck "ZIM" -MinBytes 102400
        }
    }
}

# ------------------------------------------------------------------------------
# STEP 3: Elastic GGUF Offline AI Models (manifests/models.json)
# ------------------------------------------------------------------------------
if (-not $EnginesOnly -and -not $ZimOnly) {
    Write-Host ""
    Write-Host "=== [3/3] Downloading Offline GGUF AI Models (Tier <= $Tier) ===" -ForegroundColor Cyan

    $modelsManifestPath = Join-Path $Root "manifests\models.json"
    $modelsManifest = Get-Content $modelsManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($m in $modelsManifest.models) {
        if ([int]$m.tier -le $Tier) {
            # At Tier 0 default, skip the optional 135M Wasm model unless requested so default download stays fast (~380 MB)
            if ($Tier -eq 0 -and -not $IncludeUltraMicro -and $m.id -eq "smollm2-135m-q4") {
                continue
            }
            $destPath = Join-Path $Root (Join-Path "data\models" $m.filename)
            Invoke-ResumableDownload -Url $m.url -Dest $destPath -MagicCheck "GGUF" -MinBytes 1048576
        }
    }
}

Remove-Item -Recurse -Force "tmp_dl" -ErrorAction SilentlyContinue

Show-VerifyReport
Write-Host "================================================================================" -ForegroundColor Green
Write-Host "  [READY] All selected Internet-in-a-Box & AI assets are staged!" -ForegroundColor Green
Write-Host "  Next step: Run FORMAT_AND_SETUP_USB.bat or MAKE_USB_DRIVES.bat to build your USB!" -ForegroundColor White
Write-Host "================================================================================" -ForegroundColor Green
