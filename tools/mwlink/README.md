# mwlink — PC program for MoneroCarrot

Moves files between monero-wallet-gui and the device over USB (Serial or HID,
mwlink protocol 3) and shows the device log. The program never sees keys: the
files are encrypted by the wallets, and every conversion happens on the
device.

```
pip install -r requirements.txt     # pyserial, hidapi
python mwlink_gui.py                # window
python mwlink.py --help             # command line
```

`hidapi` is needed only for HID; without it the program uses the COM port.

## Window (`mwlink_gui.py`)

1. **Connect** — the device is found automatically (VID 0x303A): HID first,
   then the COM port. The port and transport can also be picked by hand.
   After the device restarts, the window reconnects by itself.
2. **Folder** — the exchange folder (default: `exchange` next to the
   program).
3. **Watch the folder** — outputs files and unsigned transactions saved into
   this folder are sent to the device automatically; a sent file is moved to
   `sent/`.
4. **Send file...** — send any file: the device recognizes it by content and
   explains when a file does not fit.
5. Results are saved next to the file that was sent:

   | Sent | Received |
   | :--- | :--- |
   | `wallet_1789637203_outputs` | `wallet_<time>_keyImages` |
   | `tx6_1791997265_unsigned_monero_tx` | `tx6_<time>_signed_monero_tx` and `tx6_<time>_signed_monero_tx_keyImages` |
   | `tx1_unsigned_monero_tx` | `tx1_signed_monero_tx` and `tx1_signed_monero_tx_keyImages` |

   monero-wallet-gui reads the second file (`..._keyImages`) when it submits
   the signed transaction, so keep the two together.

The "Request address / view-only" buttons are not used by this firmware and
stay disabled.

## Command line (`mwlink.py`)

```
python mwlink.py info                          # which device, in which state
python mwlink.py send FILE [--out DIR]         # send a file and save the result
python mwlink.py exchange [DIR]                # watch a folder, like the window
python mwlink.py console                       # device log until Ctrl-C
python mwlink.py --serial COM5 info            # use this port
python mwlink.py --hid info                    # HID only
```

## Device messages

- `[P]` — progress, `[I]` — information (recipients and amounts),
  `[E]` — error or refusal.
- `refused: <reason>` — the device declined to process the file and returned
  nothing. The common reasons are in the Troubleshooting section of the main
  README.
