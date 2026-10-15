<#
.SYNOPSIS
    Build (and optionally flash) the MoneroCarrot firmware with arduino-cli.

.DESCRIPTION
    Downloads arduino-cli if it is not installed, installs the esp32 Arduino
    core, compiles the sketch for ESP32-S3-DevKitC-1 and, with -Port, flashes it.
    Results: dist\<usb>\MoneroCarrot.ino.merged.bin (whole flash image) and
    the separate bootloader / partitions / app images.

    Before the first build copy secrets.example.h to secrets.h and put your
    wallet keys there (see README.md).

.EXAMPLE
    .\build.ps1
    USB-OTG (Serial + HID), OPI PSRAM, 8 MB flash (ESP32-S3-DevKitC-1-N8R8).

.EXAMPLE
    .\build.ps1 -Port COM5
    Build and flash through COM5.

.EXAMPLE
    .\build.ps1 -Usb hwcdc -Psram qspi -Flash 8M
    Serial only (Hardware CDC), quad PSRAM (DevKitC-1-N8R2).
#>
[CmdletBinding()]
param(
    # otg   = USB Mode "USB-OTG (TinyUSB)": Serial + vendor HID (recommended)
    # hwcdc = USB Mode "Hardware CDC and JTAG": Serial only
    [ValidateSet('otg', 'hwcdc')] [string] $Usb = 'otg',
    # opi = N8R8 / N16R8 / N32R8V modules, qspi = N8R2
    [ValidateSet('opi', 'qspi')] [string] $Psram = 'opi',
    [ValidateSet('8M', '16M', '32M')] [string] $Flash = '8M',
    # COM port to flash after a successful build (optional)
    [string] $Port = '',
    # esp32 Arduino core version the firmware is tested with
    [string] $Core = '3.3.12',
    [string] $CliVersion = '1.1.1'
)

$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
$IndexUrl = 'https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json'

function Step($text) { Write-Host "==> $text" -ForegroundColor Cyan }

# --- keys ---------------------------------------------------------------------
if (-not (Test-Path (Join-Path $Root 'secrets.h'))) {
    throw "secrets.h not found. Copy secrets.example.h to secrets.h and put your wallet keys there."
}

# --- arduino-cli ----------------------------------------------------------------
$cmd = Get-Command arduino-cli -ErrorAction SilentlyContinue
if ($cmd) {
    $Cli = $cmd.Source
} else {
    $ToolDir = Join-Path $Root 'build\tools'
    $Cli = Join-Path $ToolDir 'arduino-cli.exe'
    if (-not (Test-Path $Cli)) {
        Step "downloading arduino-cli $CliVersion"
        New-Item -ItemType Directory -Force -Path $ToolDir | Out-Null
        $zip = Join-Path $ToolDir 'arduino-cli.zip'
        $url = "https://github.com/arduino/arduino-cli/releases/download/v$CliVersion/arduino-cli_${CliVersion}_Windows_64bit.zip"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
        Expand-Archive -Path $zip -DestinationPath $ToolDir -Force
        Remove-Item $zip
    }
}
Step "arduino-cli: $Cli"

# --- esp32 core -------------------------------------------------------------------
$installed = (& $Cli core list 2>$null | Out-String)
if ($installed -notmatch "esp32:esp32\s+$([regex]::Escape($Core))\b") {
    Step "installing esp32 core $Core (first run downloads ~1 GB of toolchains)"
    & $Cli core update-index --additional-urls $IndexUrl
    if ($LASTEXITCODE -ne 0) { throw "arduino-cli core update-index failed" }
    & $Cli core install "esp32:esp32@$Core" --additional-urls $IndexUrl
    if ($LASTEXITCODE -ne 0) { throw "arduino-cli core install failed" }
}

# --- sketch copy (the folder name must match the .ino, whatever the repo is called) ---
$Stage = Join-Path $Root 'build\sketch\MoneroCarrot'
if (Test-Path $Stage) { Remove-Item -Recurse -Force $Stage }
New-Item -ItemType Directory -Force -Path $Stage | Out-Null
Get-ChildItem -Path $Root -File |
    Where-Object { $_.Extension -in '.ino', '.c', '.cpp', '.h', '.csv' -and $_.Name -ne 'secrets.example.h' } |
    Copy-Item -Destination $Stage

# --- board options -------------------------------------------------------------------
$usbMode = if ($Usb -eq 'otg') { 'default' } else { 'hwcdc' }
$psramOpt = if ($Psram -eq 'opi') { 'opi' } else { 'enabled' }
$Fqbn = "esp32:esp32:esp32s3:USBMode=$usbMode,CDCOnBoot=cdc,PSRAM=$psramOpt,FlashSize=$Flash,DebugLevel=none"
$Out = Join-Path $Root "dist\$Usb"
$BuildPath = Join-Path $Root "build\out-$Usb"

Step "compiling ($Fqbn)"
& $Cli compile --fqbn $Fqbn --build-path $BuildPath --output-dir $Out $Stage
if ($LASTEXITCODE -ne 0) { throw "compilation failed" }
Step "firmware: $Out"

# --- flashing ---------------------------------------------------------------------------
if ($Port) {
    Step "flashing through $Port"
    & $Cli upload -p $Port --fqbn $Fqbn --input-dir $Out $Stage
    if ($LASTEXITCODE -ne 0) {
        throw "upload failed: hold BOOT, press and release RESET, release BOOT, then run again"
    }
    Step "done: press RESET (or replug the cable) to start the new firmware"
}
