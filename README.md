# MoneroCarrot

A cold signer for Monero's **FCMP++ / Carrot** transaction format, running
on an **ESP32-S3-DevKitC-1**. The spend key lives only on the device. A PC
with a view-only monero-wallet-gui wallet prepares the transaction, the
device signs it, and the wallet broadcasts it.

> **Status: experimental.** FCMP++ and Carrot currently run only on test
> networks (branch `fcmp++-beta-stressnet-v3` of
> [seraphis-migration/monero](https://github.com/seraphis-migration/monero),
> testnet / stressnet, RPC port 28081). Do not use it with real money: the
> keys are stored in the firmware in plain text, and the device signs without
> asking for confirmation (see [Security](#security)).

## Contents

- [How it works](#how-it-works)
- [What you need](#what-you-need)
- [Quick start](#quick-start)
- [1. Keys: secrets.h](#1-keys-secretsh)
- [2. Building and flashing](#2-building-and-flashing)
- [3. PC program (mwlink)](#3-pc-program-mwlink)
- [4. Using it with monero-wallet-gui](#4-using-it-with-monero-wallet-gui)
- [Troubleshooting](#troubleshooting)
- [Testing on a PC and CI](#testing-on-a-pc-and-ci)
- [Project layout](#project-layout)
- [Security](#security)
- [Licenses](#licenses)

## How it works

```
 PC (online)                                     ESP32-S3 (spend key)
 ┌────────────────────────┐   files   ┌──────────┐   USB    ┌──────────────┐
 │ monero-wallet-gui      │ ────────► │  mwlink  │ ───────► │ MoneroCarrot │
 │ (view-only wallet)     │ ◄──────── │ (Python) │ ◄─────── │ SA/L signing │
 └────────────────────────┘           └──────────┘          └──────────────┘
```

| The device takes | The device returns |
|---|---|
| `Monero unsigned tx set` v6 (unsigned transaction) | `Monero signed tx set` v6 + a `<signed>_keyImages` file |
| `Monero output export` v5/v4 (wallet outputs) | `Monero key image export` v4/v3 |

With FCMP++ the cold wallet no longer builds the whole transaction. The hot
wallet sends a compact proposal: a random seed, the one-time addresses of the
inputs, the recipients and the fee. The device:

1. opens the inputs: legacy outputs with the view key; Carrot outputs are
   fully recomputed (X25519, Blake2b, Janus anchors);
2. computes the key images;
3. expands the recipient and change outputs and the input re-randomization
   from the seed, and checks that inputs balance outputs plus fee;
4. computes the transaction's signable hash and attaches an SA/L proof
   (384 bytes) to every input;
5. adds the key images of the wallet's other outputs, so the hot wallet
   knows which of them are spent.

The membership proof (FCMP) and Bulletproofs+ are completed by
monero-wallet-gui when it submits the signed file.

## What you need

### Board

An **ESP32-S3-DevKitC-1 with PSRAM**. Without PSRAM the firmware cannot load
the keys (cn_slow_hash needs 2 MB of RAM). The variant is printed on the
module and on the box:

| Module | Flash | PSRAM | Supported | Build options |
|---|---|---|---|---|
| ESP32-S3-WROOM-1-**N8R8** | 8 MB | 8 MB octal | yes | `-Psram opi -Flash 8M` (default) |
| ESP32-S3-WROOM-1-**N16R8** | 16 MB | 8 MB octal | yes | `-Psram opi -Flash 16M` |
| ESP32-S3-WROOM-2-**N32R8V** | 32 MB | 8 MB octal | yes | `-Psram opi -Flash 32M` |
| ESP32-S3-WROOM-1-**N8R2** | 8 MB | 2 MB quad | yes | `-Psram qspi -Flash 8M` |
| ESP32-S3-WROOM-1-**N8** | 8 MB | none | **no** | — |

The board has two USB connectors:

- **USB** (native USB, GPIO19/20): the PC program talks to the device here;
- **UART** (CP210x or CH343 bridge): handy for flashing, because it puts the
  board into the bootloader by itself.

Use a cable with data lines, not a charge-only one.

### Software

- **Windows 10/11**, Linux or macOS;
- **Python 3.9+** for the PC program;
- **arduino-cli** (the build script downloads it) or **Arduino IDE 2.x**,
  with the **esp32 by Espressif 3.3.12** core (the tested version);
- **monero-wallet-gui** and **monerod** built from the FCMP++ branch
  (`fcmp++-beta-stressnet-v3`). Wallets from regular Monero releases do not
  understand the new files.

## Quick start

```powershell
git clone <repository url> MoneroCarrot
cd MoneroCarrot
copy secrets.example.h secrets.h        # put your keys into secrets.h
.\build.cmd -Port COM5                  # build and flash (the board's COM port)
py -m venv .venv                        # Python environment inside the project
.venv\Scripts\pip install --no-cache-dir -r tools\mwlink\requirements.txt
.venv\Scripts\python tools\mwlink\mwlink_gui.py     # Connect -> device ready
```

Then in monero-wallet-gui: **Create** → file to the device → **Submit**
(section 4).

## 1. Keys: secrets.h

The device signs with the keys from `secrets.h`. The file is listed in
`.gitignore`; the repository contains only a template.

1. Copy `secrets.example.h` to `secrets.h` (in the project root).
2. Open the full wallet in monero-wallet-gui: **Settings → Wallet → Show
   seed & keys**.
3. Fill in:

| Field in secrets.h | Where to get it | Required |
|---|---|---|
| `SPEND_SECRET_KEY_HEX` | Secret spend key | yes |
| `VIEW_SECRET_KEY_HEX` | Secret view key | yes |
| `SPEND_PUBLIC_KEY_HEX` | Public spend key | no, catches typos |
| `VIEW_PUBLIC_KEY_HEX` | Public view key | no, catches typos |
| `WALLET_NETWORK` | 0 mainnet, 1 testnet, 2 stagenet | display only |
| `WALLET_NAME` | name shown in the PC program | display only |

Keys are 64 hex characters. If the public keys are given, the device checks
them against the private keys at startup and refuses to work on a mismatch.

A regular Monero wallet (25-word seed or polyseed) works: the two keys cover
both legacy and Carrot outputs. monero-wallet-gui on this branch does not yet
create wallets with the new Carrot key hierarchy.

**The built firmware contains your keys.** Never publish the files in
`dist/` or `build/`.

## 2. Building and flashing

### Option A: build script (recommended)

The script downloads arduino-cli, installs the esp32 core, builds with the
right settings and flashes. The first run downloads about 1 GB of tools.

Everything stays inside the project folder; nothing is installed into the
system or your user profile, and no administrator rights are needed:

| Folder | Contents |
|---|---|
| `build/tools/` | the script's own copy of arduino-cli (pinned version) |
| `build/arduino/` | esp32 core and toolchains, download cache, build cache, arduino-cli settings |
| `build/out-<usb>/`, `build/sketch/` | intermediate build files |
| `dist/<usb>/` | firmware images |

An Arduino IDE or arduino-cli already installed on the PC is neither used nor
changed. To remove everything, delete `build/` and `dist/`; if Explorer
complains about long paths inside `build/arduino`, use `rmdir /s /q build`
in a console.

**Windows** (double-click `build.cmd` or run it from a console):

```powershell
.\build.cmd                         # build only (N8R8, Serial + HID)
.\build.cmd -Port COM5              # build and flash
.\build.cmd -Psram qspi             # N8R2
.\build.cmd -Flash 16M -Port COM5   # N16R8
.\build.cmd -Usb hwcdc              # no HID, Serial only (Hardware CDC)
```

`build.cmd` runs `build.ps1` with the PowerShell execution policy bypassed.
You can also run `build.ps1` directly:
`powershell -ExecutionPolicy Bypass -File build.ps1 -Port COM5`.

**Linux / macOS:**

```bash
./build.sh                          # build
./build.sh --port /dev/ttyUSB0      # build and flash
./build.sh --psram qspi --flash 8M --usb hwcdc
```

The output goes to `dist/otg/` (or `dist/hwcdc/`):

- `MoneroCarrot.ino.merged.bin` — the whole flash image, written at `0x0`;
- `*.bootloader.bin`, `*.partitions.bin`, `*.bin` — the same parts
  separately.

Find the port in *Device Manager → Ports (COM & LPT)*. Flashing is easiest
through the **UART** connector. If flashing through the **USB** connector
fails ("Failed to connect"): hold **BOOT**, press and release **RST**,
release **BOOT** and try again. After flashing, press **RST** or replug the
cable.

### Option B: Arduino IDE 2.x

1. **Folder.** The project folder must be named `MoneroCarrot`, like
   `MoneroCarrot.ino`. A GitHub ZIP unpacks into `MoneroCarrot-main`: rename
   it.
2. **ESP32 core.** *File → Preferences → Additional boards manager URLs*:
   `https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json`.
   Then *Tools → Board → Boards Manager*: find **esp32 by Espressif
   Systems** and install version **3.3.12**.
3. **Board.** *Tools → Board → esp32 → **ESP32S3 Dev Module***.
4. **Settings** in the *Tools* menu:

| Item | Value | Why |
|---|---|---|
| USB Mode | **USB-OTG (TinyUSB)** | Serial + HID; or *Hardware CDC and JTAG* for Serial only |
| USB CDC On Boot | **Enabled** | the PC program uses the native USB port |
| PSRAM | **OPI PSRAM** (N8R8, N16R8) / **QSPI PSRAM** (N8R2) | the keys do not load without PSRAM |
| Flash Size | **8MB** (N8R8, N8R2) / **16MB** (N16R8) | room for the output store |
| Partition Scheme | any | `partitions.csv` in the project folder overrides this item |
| Core Debug Level | **None** | stray text on the port breaks the protocol |
| Erase All Flash Before Sketch Upload | **Disabled** | otherwise the device forgets the wallet's outputs |
| Upload Mode | UART0 / Hardware CDC | default |
| CPU Frequency | 240MHz | default |

5. *Tools → Port* — the board's port; **Upload**.
6. Close the **Serial Monitor**: while it is open the COM port is busy. The
   PC program can still connect over HID if it is enabled.

### Flash layout

Arduino uses `partitions.csv` from the project folder instead of the
*Partition Scheme* menu:

| Partition | Offset | Size | Contents |
|---|---|---|---|
| `app0` | 0x10000 | 4 MB | firmware (~620 KB) |
| `storage` | 0x410000 | ~3.9 MB | LittleFS: wallet outputs the device has seen |

It needs a board with at least 8 MB of flash. The device finds the LittleFS
partition by type, so a standard "with spiffs" scheme works too. Without such
a partition the device logs `no LittleFS partition` and forgets outputs on
restart.

### First check

```powershell
.venv\Scripts\python tools\mwlink\mwlink.py info
```

```
firmware    carrot-1.0
board       ESP32-S3
protocol    3
caps        serial, hid, auto-kind
state       wallet open 'MoneroCarrot'
wallets     1, network testnet
```

After power-up the device spends a few seconds loading the keys (state
`busy`), then switches to `wallet open`. If the keys in `secrets.h` are
wrong, the log says why (`secrets.h: ...`).

## 3. PC program (mwlink)

The program moves files between a folder on the PC and the device and shows
the device log. Details: [tools/mwlink/README.md](tools/mwlink/README.md).

```powershell
py -m venv .venv
.venv\Scripts\pip install --no-cache-dir -r tools\mwlink\requirements.txt   # pyserial, hidapi
.venv\Scripts\python tools\mwlink\mwlink_gui.py
```

The `.venv` folder in the project keeps the Python packages away from your
system Python; `--no-cache-dir` stops pip from caching downloads in your
profile. On Linux/macOS: `python3 -m venv .venv`,
`.venv/bin/pip install --no-cache-dir -r tools/mwlink/requirements.txt`,
`.venv/bin/python tools/mwlink/mwlink_gui.py`.

1. **Connect.** The device is found automatically: HID first, then the COM
   port.
2. **Send file...** — pick a file from monero-wallet-gui. The result is saved
   next to it.
3. Or enable **Watch the folder** and save the wallet's files into the
   exchange folder (default `tools/mwlink/exchange`): they are sent
   automatically.

For a signed transaction the program saves **two** files:
`<name>_signed_monero_tx` and `<name>_signed_monero_tx_keyImages`.
monero-wallet-gui reads the second one when it submits the first, so keep
them in the same folder.

On Linux you need access to the port: `sudo usermod -aG dialout $USER`
(then log in again). For HID, add a udev rule, for example
`/etc/udev/rules.d/99-monerocarrot.rules`:

```
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="303a", MODE="0660", GROUP="plugdev"
```

## 4. Using it with monero-wallet-gui

### 4.1. View-only wallet (once)

1. Start `monerod` from the FCMP++ branch (testnet/stressnet, RPC 28081) and
   monero-wallet-gui in **Advanced** mode.
2. **Restore wallet from keys or mnemonic seed → Restore from keys**:
   - *Account address (public)* — the wallet's primary address;
   - *View key (private)* — the secret view key;
   - *Spend key (private)* — **leave empty** to get a view-only wallet;
   - *Restore height* — a block height before the wallet's first output.
3. Wait for the sync to finish.
4. The node must be **trusted**: on submit the wallet imports key images,
   which is allowed only with a trusted daemon. A local node is trusted
   automatically; for a remote node enable **Mark as Trusted Daemon** in the
   node settings.

### 4.2. Sending

1. **Send**: enter the address and amount. Enable **Advanced options** at the
   bottom of the page.
2. **Offline transaction signing → Create**: save the file, for example
   `tx1_unsigned_monero_tx`.
3. Send the file to the device (**Send file...** or the exchange folder). The
   device signs right away and logs the recipients and amounts:

   ```
   [I] tx 0: 2 inputs, 1 payments, 1 self-sends, fee 1292925
   [I]   pay 5.000000000000 XMR to subaddr ea597d36d1a12655...
   [I] done: 5200 bytes
   saved tx1_signed_monero_tx
   saved tx1_signed_monero_tx_keyImages
   ```

   **Check the address and amount in the log.**
4. **Offline transaction signing → Submit**: pick `tx1_signed_monero_tx`. The
   wallet completes the FCMP++ proofs and broadcasts the transaction. This can
   take tens of seconds.

No separate key image sync is needed: every unsigned file contains all
outputs whose key images the wallet does not know yet. The device remembers
them in flash and returns their key images together with the signature.

### 4.3. When an outputs file is needed

Only in one case: the hot wallet already knows the key images of some
outputs that the device has never seen. This happens if the wallet used to
work with another signer (for example a cold monero-wallet-gui), or if the
device's flash was erased. The device then answers:

```
[E] refused: input 0 is unknown to the device: send the outputs file first
```

What to do, once:

1. **Advanced options → Outputs → Export** — save the file.
2. Send it to the device. The device remembers all outputs and returns a
   `..._keyImages` file; importing it into the wallet is optional.
3. Send the same unsigned file again.

## Troubleshooting

| Message | Cause and fix |
|---|---|
| `input N is unknown to the device: send the outputs file first` | The device has not seen this output. Send an outputs file (section 4.3). |
| `no LittleFS partition: ...` | No partition for the output store: build with the project's `partitions.csv` and a Flash Size of at least 8 MB. |
| `cannot decrypt: file is not for this wallet or is damaged` | The file belongs to another wallet: check the keys in `secrets.h`. |
| `outputs file is meant for another wallet` | The same for an outputs file. |
| `pre-Carrot unsigned tx set ... is not supported` | The file comes from an old monero-wallet-gui: use the FCMP++ branch. |
| `not a Monero exchange file` | Wrong file; the device takes `unsigned_monero_tx` files and binary outputs exports. |
| `inputs do not balance outputs + fee`, `SA/L ... failed` | The file is damaged or inconsistent. Create the transaction again; if it repeats, open an issue with the log. |
| `secrets.h: ...` | A problem with the keys: fix `secrets.h` and reflash. |
| `secrets.h not found` while building | Copy `secrets.example.h` to `secrets.h`. |
| monero-wallet-gui: `Failed to import key images: failed to read file ..._keyImages` | The `_keyImages` file is missing next to the signed file. Sign again with the current PC program and keep both files in one folder. |
| monero-wallet-gui: `Key images can only be imported with a trusted daemon` | Mark the node as trusted (section 4.1). |
| monero-wallet-gui closes or stops responding on **Submit** | A problem in the FCMP++ branch of the GUI itself, not in the device. Retrying after the wallet finishes syncing usually works. |
| The PC program does not find the device | Is the cable in the **USB** connector (not UART)? Is the Serial Monitor closed? In *Hardware CDC* mode there is no HID: pick the port by hand. |
| Flashing: `Failed to connect to ESP32-S3` | BOOT + RST (section 2) or flash through the UART connector. |
| Arduino IDE: `main file missing from sketch` | The project folder is not named `MoneroCarrot`. |

## Testing on a PC and CI

The signing code builds unchanged on a PC (Linux, gcc):

```bash
test/smoke.sh       # random keys, device simulator + mwlink
```

`test/host.mk` builds:

- `cwtool` — signs and verifies files from the command line;
- `cwsim` — a device simulator on a pseudo-terminal that the PC program can
  talk to;
- `test_hotcold` — signs monero-wallet-gui files and compares the result with
  the GUI's own signatures. Needs your test files and `secrets.h`.

`refharness.cpp` (cross-check against the monero reference code) and
`test_sal.c` (SA/L cross-check against monero-oxide) need external
repositories built first; see the comments at the top of each file.

GitHub Actions (`.github/workflows/build.yml`) builds the firmware in both
USB modes with empty keys and runs `test/smoke.sh` on every push.

What has been verified:

- SA/L proofs made by monero-wallet-gui itself verify against the device's
  expansion of the same transaction;
- the device's key images match the wallet's;
- the monero reference code accepts signed sets from the device in 5
  scenarios: legacy and Carrot outputs, subaddresses, integrated addresses,
  2 and more outputs;
- SA/L matches the monero-oxide Rust implementation in both directions;
- transactions signed by the device have been broadcast through
  monero-wallet-gui.

## Project layout

| File | What it is |
|---|---|
| `MoneroCarrot.ino` | Arduino entry point: `setup()` / `loop()` |
| `cw_esp32.cpp` | platform: USB Serial/HID, worker task, LittleFS, RNG |
| `cw_config.h` | version, board name, HID on/off, worker stack size |
| `secrets.example.h` | template for `secrets.h` with the keys |
| `partitions.csv` | flash layout |
| `cw_link.c/.h` | mwlink protocol 3: framing, PING/INFO/PUT/GET/STATUS/CLEAR |
| `cw_hotcold.c/.h` | exchange files: parsing, transaction expansion, signing, key images |
| `cw_carrot.c/.h` | addresses, Carrot outputs, opening inputs, key images |
| `cw_sal.c/.h` | input re-randomization and SA/L (port of monero-oxide) |
| `cw_crypto.c/.h` | Blake2b, hash-to-point, generators T/U/V, signatures |
| `x25519.c`, `x25519_fe.h` | X25519 without clamping (from mx25519) |
| `crypto-ops*`, `keccak.*`, `blake2b.*`, `slow-hash.c`, `hash*`, `aesb.c`, `oaes_lib.*`, `groestl*`, `jh.*`, `skein*`, `blake256.*`, `chacha20.*` | monero cryptography (stressnet branch) |
| `build.ps1`, `build.cmd`, `build.sh` | building and flashing with arduino-cli |
| `tools/mwlink/` | PC program |
| `test/` | PC build of the signing code, simulator, tests |

mwlink protocol 3: frame magic `"MWPK" C7 3A 5E 91`, version 3, CRC32 of the
header and of the frame. Over Serial: COBS with a `0x00` delimiter; over HID:
64-byte reports. Commands: PING 1, INFO 2, PUT 3, GET 4, STATUS 5, CLEAR 6.
File kinds: outputs 0, keyimages 1, unsigned 2, signed 3. Details in
`cw_link.h`.

## Security

- **The keys are in the firmware in plain text.** Anyone holding the board
  can read the flash. Real funds would need ESP32-S3 Flash Encryption and
  Secure Boot; this project does not enable them.
- **Signing without confirmation.** A compromised PC can swap the recipient
  and the device will sign. Check the address and amount in the device log
  (`[I] pay ...`) before pressing **Submit**.
- **Variable-time arithmetic** (`crypto-ops.c`): in theory open to timing and
  power analysis by someone with physical access.
- Signature nonces are derived from the secret, the context and the hardware
  RNG (hedged). At startup the device tests the RNG and does not sign without
  it.
- Private keys never leave the device: the protocol has no way to send them.

## Licenses

Code taken from other projects keeps its license:

- monero cryptography (`crypto-ops*`, `keccak*`, `hash*`, `slow-hash.c`,
  `blake2b*`, `oaes_lib*`, `aesb.c`, `groestl*`, `jh*`, `skein*`,
  `blake256*`, `chacha20*`) — BSD-3-Clause, © The Monero Project and the
  authors named in the files;
- `x25519.c`, `x25519_fe.h` — based on [tevador/mx25519](https://github.com/tevador/mx25519),
  LGPLv3;
- `cw_sal.c` — port of SA/L from [monero-oxide](https://github.com/monero-oxide/monero-oxide),
  MIT.
