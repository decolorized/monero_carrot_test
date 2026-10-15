#!/usr/bin/env python3
#
# middleware.py — отправляет outputs.bin на ESP32-S3, получает keyimages.bin.
#
# Особенности:
#   - OUTPUTS_BIN шлётся чанками по 128 байт с паузой 5 мс, чтобы ESP
#     успевала вычитывать USB-CDC (иначе host пишет 1922 байта разом и
#     ESP теряет большую часть).
#   - Перед отправкой OUTPUTS_BIN — пауза 0.5 с, чтобы ESP закончила
#     писать свои LOG-и от предыдущих команд.
#   - LOG-фреймы печатаются сразу.
#   - Watchdog: если от ESP нет байт N секунд, пишем предупреждение.
#

import argparse
import struct
import sys
import time
import threading

import serial

FRAME_START = 0xAA

TYPE_OUTPUTS_BIN        = 0x01
TYPE_KEYIMAGES_OUT      = 0x02
TYPE_LOG                = 0x03
TYPE_GET_SPEND_PUBKEY   = 0x04
TYPE_SPEND_PUBKEY_OUT   = 0x05
TYPE_PING               = 0x06
TYPE_PONG               = 0x07
TYPE_ERROR              = 0xFF

TYPE_NAMES = {
    TYPE_OUTPUTS_BIN:      "OUTPUTS_BIN",
    TYPE_KEYIMAGES_OUT:    "KEYIMAGES_OUT",
    TYPE_LOG:              "LOG",
    TYPE_GET_SPEND_PUBKEY: "GET_SPEND_PUBKEY",
    TYPE_SPEND_PUBKEY_OUT: "SPEND_PUBKEY_OUT",
    TYPE_PING:             "PING",
    TYPE_PONG:             "PONG",
    TYPE_ERROR:            "ERROR",
}

PRINT_RAW_HEX = False

_LOG_FP = None
_LOG_LOCK = threading.Lock()

def open_log(path: str) -> None:
    global _LOG_FP
    _LOG_FP = open(path, "a", buffering=1, encoding="utf-8")

def close_log() -> None:
    global _LOG_FP
    if _LOG_FP:
        try:
            _LOG_FP.flush()
            _LOG_FP.close()
        except Exception:
            pass
        _LOG_FP = None

def log_write(line: str) -> None:
    with _LOG_LOCK:
        if _LOG_FP:
            try:
                _LOG_FP.write(line + "\n")
            except Exception:
                pass

def _ts() -> str:
    return time.strftime("%H:%M:%S")

def log_host(msg: str) -> None:
    line = f"[{_ts()}] [HOST] {msg}"
    print(line, flush=True); log_write(line)

def log_esp(msg: str) -> None:
    line = f"[{_ts()}] [ESP ] {msg}"
    print(line, flush=True); log_write(line)

def log_sys(msg: str) -> None:
    line = f"[{_ts()}] [SYS ] {msg}"
    print(line, flush=True); log_write(line)

def log_frm(msg: str) -> None:
    line = f"[{_ts()}] [FRM] {msg}"
    print(line, flush=True); log_write(line)

def log_raw(tag: str, data: bytes) -> None:
    ts = _ts()
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(16 * 3 - 1)
        asc = "".join(chr(b) if 0x20 <= b <= 0x7e else "." for b in chunk)
        line = f"[{ts}] [{tag}] {off:06x}  {hexpart}  |{asc}|"
        log_write(line)
        if PRINT_RAW_HEX:
            print(line, flush=True)

class LoggedSerial:
    def __init__(self, ser: serial.Serial):
        self._ser = ser
        self._last_rx_time = time.time()

    def write(self, data: bytes) -> int:
        if data:
            log_raw("TX", data[:256])
            if len(data) > 256:
                log_write(f"[{_ts()}] [TX] ... ({len(data)} bytes total)")
        return self._ser.write(data)

    def flush(self):
        try: self._ser.flush()
        except Exception: pass

    def read(self, size: int = 1) -> bytes:
        b = self._ser.read(size)
        if b:
            self._last_rx_time = time.time()
        return b

    def reset_input_buffer(self):
        try: self._ser.reset_input_buffer()
        except Exception: pass

    def close(self):
        try: self._ser.close()
        except Exception: pass

    @property
    def last_rx_time(self) -> float:
        return self._last_rx_time

def crc16_ccitt(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc

def build_frame(type_: int, payload: bytes) -> bytes:
    crc = crc16_ccitt(payload)
    return (bytes([FRAME_START, type_])
            + struct.pack("<H", len(payload))
            + payload
            + struct.pack("<H", crc))

def read_frame(ser, timeout: float):
    deadline = time.time() + timeout
    state = "start"
    t = None
    plen = 0
    buf = bytearray()
    crc_recv = 0

    while time.time() < deadline:
        b = ser.read(1)
        if not b:
            continue
        x = b[0]

        if state == "start":
            if x == FRAME_START:
                state = "type"
            else:
                log_frm(f"stray byte 0x{x:02x}")
        elif state == "type":
            t = x; state = "len0"
        elif state == "len0":
            plen = x; state = "len1"
        elif state == "len1":
            plen |= x << 8
            buf = bytearray()
            state = "payload" if plen > 0 else "crc0"
        elif state == "payload":
            buf.append(x)
            if len(buf) == plen:
                state = "crc0"
        elif state == "crc0":
            crc_recv = x; state = "crc1"
        elif state == "crc1":
            crc_recv |= x << 8
            expected = crc16_ccitt(bytes(buf))
            tname = TYPE_NAMES.get(t, f"0x{t:02x}")
            if crc_recv != expected:
                log_frm(f"type={tname} len={plen} crc={crc_recv:04x}/{expected:04x} BAD")
                return None, None, None
            log_frm(f"type={tname} len={plen} crc={crc_recv:04x} OK")
            return t, bytes(buf), None

    return None, None, None

def wait_for_response(ser, timeout, progress_every=5.0, silent_warn=20.0):
    deadline = time.time() + timeout
    last_progress = time.time()
    last_warn = time.time()
    log_host(f"waiting for response (timeout {timeout:.0f}s)...")

    while time.time() < deadline:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        t, p, _ = read_frame(ser, timeout=min(remaining, 1.0))
        now = time.time()

        if t is None:
            if now - last_progress >= progress_every:
                elapsed = int(now - (deadline - timeout))
                log_host(f"... still waiting ({elapsed}s)")
                last_progress = now
            if now - last_warn >= silent_warn:
                silent = now - ser.last_rx_time
                log_sys(f"WATCHDOG: no RX bytes from ESP for {silent:.1f}s")
                last_warn = now
            continue

        if t == TYPE_LOG:
            log_esp(p.decode(errors='replace'))
            continue
        if t == TYPE_ERROR:
            log_esp(f"[ERROR] {p.decode(errors='replace')}")
            return t, p
        return t, p
    return None, None

def ping(ser) -> None:
    log_host("PING...")
    ser.write(build_frame(TYPE_PING, b""))
    t, p = wait_for_response(ser, timeout=15.0)
    if t is None:
        raise RuntimeError("timeout waiting for PONG")
    if t != TYPE_PONG:
        raise RuntimeError(f"expected PONG, got {TYPE_NAMES.get(t, t)}")
    log_host("PONG")

def get_spend_pubkey(ser) -> bytes:
    log_host("GET_SPEND_PUBKEY...")
    ser.write(build_frame(TYPE_GET_SPEND_PUBKEY, b""))
    t, p = wait_for_response(ser, timeout=15.0)
    if t is None:
        raise RuntimeError("timeout waiting for SPEND_PUBKEY_OUT")
    if t != TYPE_SPEND_PUBKEY_OUT:
        raise RuntimeError(f"expected SPEND_PUBKEY_OUT, got {TYPE_NAMES.get(t, t)}")
    pubkey = bytes.fromhex(p.decode())
    if len(pubkey) != 32:
        raise RuntimeError(f"spend pubkey wrong length: {len(pubkey)}")
    log_host(f"spend pubkey: {pubkey.hex()}")
    return pubkey

def send_outputs_and_get_keyimages(ser, outputs_bin: bytes, timeout: float) -> bytes:
    log_host(f"sending OUTPUTS_BIN ({len(outputs_bin)} bytes)...")
    payload = outputs_bin.hex().encode("ascii")
    frame = build_frame(TYPE_OUTPUTS_BIN, payload)
    log_host(f"frame: {len(frame)} bytes, sending in chunks of 128 with 5ms delay...")

    # Дать ESP закончить писать LOG-и от предыдущей команды.
    time.sleep(0.5)

    CHUNK = 128
    t0 = time.time()
    for off in range(0, len(frame), CHUNK):
        ser.write(frame[off:off + CHUNK])
        ser.flush()
        time.sleep(0.005)
    log_host(f"frame fully sent in {time.time()-t0:.2f}s")

    t, p = wait_for_response(ser, timeout=timeout)
    if t is None:
        raise RuntimeError("timeout waiting for KEYIMAGES_OUT")
    if t == TYPE_ERROR:
        raise RuntimeError(f"device error: {p.decode(errors='replace')}")
    if t != TYPE_KEYIMAGES_OUT:
        raise RuntimeError(f"expected KEYIMAGES_OUT, got {TYPE_NAMES.get(t, t)}")

    keyimages = bytes.fromhex(p.decode())
    log_host(f"got keyimages.bin ({len(keyimages)} bytes)")
    if keyimages:
        log_host(f"  head: {keyimages[:32].hex()}")
        log_host(f"  tail: ...{keyimages[-16:].hex()}")
    return keyimages

def main() -> int:
    global PRINT_RAW_HEX
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", required=True)
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--in", dest="in_path", default="outputs.bin")
    ap.add_argument("--out", dest="out_path", default="keyimages.bin")
    ap.add_argument("--timeout", type=float, default=600.0)
    ap.add_argument("--log", dest="log_path", default="esp.log")
    ap.add_argument("--raw-hex", action="store_true")
    ap.add_argument("--no-ping", action="store_true")
    ap.add_argument("--expected-pubkey", default=None)
    ap.add_argument("--retries", type=int, default=1)
    args = ap.parse_args()

    PRINT_RAW_HEX = args.raw_hex

    open_log(args.log_path)
    log_sys(f"=== middleware.py started, log -> {args.log_path} ===")

    try:
        with open(args.in_path, "rb") as f:
            outputs_bin = f.read()
        if not outputs_bin:
            log_host(f"[!] {args.in_path} is empty")
            return 1
        log_host(f"loaded {args.in_path}: {len(outputs_bin)} bytes")

        log_host(f"opening {args.port} @ {args.baud}...")
        raw_ser = serial.Serial(args.port, args.baud, timeout=0.05)
        time.sleep(0.3)

        ser = LoggedSerial(raw_ser)
        try: ser.reset_input_buffer()
        except Exception: pass

        try:
            if not args.no_ping:
                ping(ser)
                pubkey = get_spend_pubkey(ser)
                if args.expected_pubkey is not None:
                    expected = args.expected_pubkey.lower()
                    got = pubkey.hex().lower()
                    if got != expected:
                        log_host("[!] spend pubkey mismatch!")
                        log_host(f"    expected: {expected}")
                        log_host(f"    got:      {got}")
                        return 2
                    log_host("spend pubkey matches expected")

            last_error = None
            keyimages = None
            for attempt in range(1, args.retries + 1):
                if args.retries > 1:
                    log_host(f"attempt {attempt}/{args.retries}")
                try:
                    keyimages = send_outputs_and_get_keyimages(
                        ser, outputs_bin, args.timeout)
                    break
                except Exception as e:
                    last_error = e
                    log_host(f"[!] attempt {attempt} failed: {e}")
                    if attempt < args.retries:
                        time.sleep(2.0)

            if keyimages is None:
                raise last_error if last_error else RuntimeError("all retries failed")

            with open(args.out_path, "wb") as f:
                f.write(keyimages)
            log_host(f"wrote {args.out_path} ({len(keyimages)} bytes)")

        except KeyboardInterrupt:
            log_host("[!] interrupted by user")
            return 130
        except Exception as e:
            log_host(f"[!] error: {e}")
            return 1
        finally:
            ser.close()
        return 0
    finally:
        log_sys("=== middleware.py finished ===")
        close_log()

if __name__ == "__main__":
    sys.exit(main())