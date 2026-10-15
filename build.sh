#!/usr/bin/env bash
# Build (and optionally flash) the MoneroCarrot firmware with arduino-cli.
# Linux / macOS counterpart of build.ps1.
#
#   ./build.sh                          USB-OTG (Serial + HID), OPI PSRAM, 8 MB flash
#   ./build.sh --port /dev/ttyACM0      build and flash
#   ./build.sh --usb hwcdc --psram qspi Serial only, quad PSRAM (DevKitC-1-N8R2)
#
# Options: --usb otg|hwcdc  --psram opi|qspi  --flash 8M|16M|32M  --port PORT
#          --core VERSION (esp32 Arduino core, default 3.3.12)
# Results: dist/<usb>/MoneroCarrot.ino.merged.bin and the separate images.
# The image contains your keys from secrets.h: never publish it.
set -euo pipefail

USB=otg PSRAM=opi FLASH=8M PORT="" CORE=3.3.12 CLI_VERSION=1.1.1
while [ $# -gt 0 ]; do
    case "$1" in
        --usb) USB="$2"; shift 2 ;;
        --psram) PSRAM="$2"; shift 2 ;;
        --flash) FLASH="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --core) CORE="$2"; shift 2 ;;
        -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done
case "$USB" in otg) USBMODE=default ;; hwcdc) USBMODE=hwcdc ;; *) echo "--usb otg|hwcdc" >&2; exit 2 ;; esac
case "$PSRAM" in opi) PSRAMOPT=opi ;; qspi) PSRAMOPT=enabled ;; *) echo "--psram opi|qspi" >&2; exit 2 ;; esac
case "$FLASH" in 8M|16M|32M) ;; *) echo "--flash 8M|16M|32M" >&2; exit 2 ;; esac

ROOT="$(cd "$(dirname "$0")" && pwd)"
INDEX_URL=https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
step() { printf '==> %s\n' "$*"; }

[ -f "$ROOT/secrets.h" ] || {
    echo "secrets.h not found. Copy secrets.example.h to secrets.h and put your wallet keys there." >&2
    exit 1
}

# arduino-cli: from PATH or downloaded into build/tools
if command -v arduino-cli >/dev/null 2>&1; then
    CLI="$(command -v arduino-cli)"
else
    CLI="$ROOT/build/tools/arduino-cli"
    if [ ! -x "$CLI" ]; then
        case "$(uname -s)-$(uname -m)" in
            Linux-x86_64) PKG=Linux_64bit ;;
            Linux-aarch64) PKG=Linux_ARM64 ;;
            Darwin-arm64) PKG=macOS_ARM64 ;;
            Darwin-x86_64) PKG=macOS_64bit ;;
            *) echo "install arduino-cli manually: https://arduino.github.io/arduino-cli/" >&2; exit 1 ;;
        esac
        step "downloading arduino-cli $CLI_VERSION"
        mkdir -p "$ROOT/build/tools"
        curl -fsSL "https://github.com/arduino/arduino-cli/releases/download/v$CLI_VERSION/arduino-cli_${CLI_VERSION}_$PKG.tar.gz" |
            tar -xz -C "$ROOT/build/tools" arduino-cli
    fi
fi
step "arduino-cli: $CLI"

# esp32 core
if ! "$CLI" core list 2>/dev/null | grep -Eq "^esp32:esp32[[:space:]]+$CORE([[:space:]]|$)"; then
    step "installing esp32 core $CORE (first run downloads ~1 GB of toolchains)"
    "$CLI" core update-index --additional-urls "$INDEX_URL"
    "$CLI" core install "esp32:esp32@$CORE" --additional-urls "$INDEX_URL"
fi

# sketch copy: the folder name must match the .ino, whatever the repo is called
STAGE="$ROOT/build/sketch/MoneroCarrot"
rm -rf "$STAGE"; mkdir -p "$STAGE"
for f in "$ROOT"/*.ino "$ROOT"/*.c "$ROOT"/*.cpp "$ROOT"/*.h "$ROOT"/*.csv; do
    [ "$(basename "$f")" = secrets.example.h ] || cp "$f" "$STAGE/"
done

FQBN="esp32:esp32:esp32s3:USBMode=$USBMODE,CDCOnBoot=cdc,PSRAM=$PSRAMOPT,FlashSize=$FLASH,DebugLevel=none"
OUT="$ROOT/dist/$USB"
step "compiling ($FQBN)"
"$CLI" compile --fqbn "$FQBN" --build-path "$ROOT/build/out-$USB" --output-dir "$OUT" "$STAGE"
step "firmware: $OUT"

if [ -n "$PORT" ]; then
    step "flashing through $PORT"
    "$CLI" upload -p "$PORT" --fqbn "$FQBN" --input-dir "$OUT" "$STAGE" || {
        echo "upload failed: hold BOOT, press and release RESET, release BOOT, then run again" >&2
        exit 1
    }
    step "done: press RESET (or replug the cable) to start the new firmware"
fi
