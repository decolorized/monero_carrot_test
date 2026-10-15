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
# Self-contained: arduino-cli, the esp32 core and all caches are downloaded into
# build/ of this project; nothing goes into the system or the home folder.
# Delete build/ and dist/ to remove everything.
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
        -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
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

# arduino-cli: own copy in build/tools (ARDUINO_CLI=/path overrides)
CLI="${ARDUINO_CLI:-$ROOT/build/tools/arduino-cli}"
if [ ! -x "$CLI" ]; then
    case "$(uname -s)-$(uname -m)" in
        Linux-x86_64) PKG=Linux_64bit ;;
        Linux-aarch64) PKG=Linux_ARM64 ;;
        Darwin-arm64) PKG=macOS_ARM64 ;;
        Darwin-x86_64) PKG=macOS_64bit ;;
        *) echo "unsupported system: set ARDUINO_CLI to an arduino-cli binary" >&2; exit 1 ;;
    esac
    step "downloading arduino-cli $CLI_VERSION into build/tools"
    mkdir -p "$ROOT/build/tools"
    curl -fsSL "https://github.com/arduino/arduino-cli/releases/download/v$CLI_VERSION/arduino-cli_${CLI_VERSION}_$PKG.tar.gz" |
        tar -xz -C "$ROOT/build/tools" arduino-cli
fi

# arduino-cli settings: all its folders inside build/arduino
A="$ROOT/build/arduino"
mkdir -p "$A"
CONFIG="$A/arduino-cli.yaml"
printf '%s\n' \
    "directories:" \
    "  data: '$A/data'" \
    "  downloads: '$A/staging'" \
    "  user: '$A/user'" \
    "build_cache:" \
    "  path: '$A/cache'" \
    "board_manager:" \
    "  additional_urls:" \
    "    - '$INDEX_URL'" \
    "updater:" \
    "  enable_notification: false" > "$CONFIG"
cli() { "$CLI" --config-file "$CONFIG" "$@"; }

# esp32 core
if ! cli core list 2>/dev/null | grep -Eq "^esp32:esp32[[:space:]]+$CORE([[:space:]]|$)"; then
    step "installing esp32 core $CORE into build/arduino (first run downloads ~1 GB)"
    cli core update-index
    cli core install "esp32:esp32@$CORE" --skip-post-install
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
cli compile --fqbn "$FQBN" --build-path "$ROOT/build/out-$USB" --output-dir "$OUT" "$STAGE"
step "firmware: $OUT"

if [ -n "$PORT" ]; then
    step "flashing through $PORT"
    cli upload -p "$PORT" --fqbn "$FQBN" --input-dir "$OUT" "$STAGE" || {
        echo "upload failed: hold BOOT, press and release RESET, release BOOT, then run again" >&2
        exit 1
    }
    step "done: press RESET (or replug the cable) to start the new firmware"
fi
