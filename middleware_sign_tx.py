#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
middleware_sign_tx.py
Host-side middleware for Monero cold wallet on ESP32-S3.
"""

import os
import sys
import time
import argparse
import serial

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------
FRAME_START = 0xAA

TYPE_OUTPUTS_BIN      = 0x01
TYPE_KEYIMAGES_OUT    = 0x02
TYPE_LOG              = 0x03
TYPE_GET_SPEND_PUBKEY = 0x04
TYPE_SPEND_PUBKEY_OUT = 0x05
TYPE_PING             = 0x06
TYPE_PONG             = 0x07
TYPE_TX_BIN           = 0x10
TYPE_TX_SIGNED        = 0x11
TYPE_PT_DUMP          = 0x20
TYPE_ERROR            = 0xFF

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_FILE = None


def log(msg, *, to_stdout=True, to_file=True):
    ts = time.strftime("[%H:%M:%S]")
    line = f"{ts} {msg}"
    if to_stdout:
        print(line, flush=True)
    if to_file and LOG_FILE:
        LOG_FILE.write(line + "\n")
        LOG_FILE.flush()


def hex_dump_short(data, max_len=16):
    if data is None:
        return "<none>"
    n = min(len(data), max_len)
    return " ".join(f"{b:02x}" for b in data[:n]) + (" ..." if len(data) > n else "")


# ---------------------------------------------------------------------------
# CRC16-CCITT
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Frame I/O
# ---------------------------------------------------------------------------
def read_exact(ser, n, timeout=1.0):
    deadline = time.time() + timeout
    buf = bytearray()
    while len(buf) < n:
        if time.time() > deadline:
            raise TimeoutError(f"read_exact({n}): got only {len(buf)} bytes")
        chunk = ser.read(n - len(buf))
        if chunk:
            buf.extend(chunk)
    return bytes(buf)


def send_frame(ser, ftype, payload: bytes, *, chunk_size=128, chunk_delay=0.005):
    crc = crc16_ccitt(payload)
    hdr = bytes([FRAME_START, ftype, len(payload) & 0xFF, (len(payload) >> 8) & 0xFF])
    tail = bytes([crc & 0xFF, (crc >> 8) & 0xFF])
    frame = hdr + payload + tail

    log(f"[TX] frame type=0x{ftype:02x} len={len(payload)} total={len(frame)}")
    for i in range(0, len(frame), chunk_size):
        ser.write(frame[i:i + chunk_size])
        ser.flush()
        if chunk_delay > 0 and i + chunk_size < len(frame):
            time.sleep(chunk_delay)


def recv_frame(ser, timeout=15.0):
    deadline = time.time() + timeout
    while True:
        if time.time() > deadline:
            raise TimeoutError("recv_frame: timeout waiting for start")
        b = ser.read(1)
        if not b:
            continue
        if b[0] == FRAME_START:
            break

    hdr = read_exact(ser, 3, timeout=1.0)
    ftype = hdr[0]
    plen = hdr[1] | (hdr[2] << 8)

    payload = read_exact(ser, plen, timeout=5.0) if plen else b""
    tail = read_exact(ser, 2, timeout=1.0)
    crc_recv = tail[0] | (tail[1] << 8)
    crc_calc = crc16_ccitt(payload)

    if crc_recv != crc_calc:
        log(f"[FRM] CRC BAD type=0x{ftype:02x} len={plen} "
            f"got=0x{crc_recv:04x} calc=0x{crc_calc:04x}")

    return ftype, payload, crc_recv == crc_calc


# ---------------------------------------------------------------------------
# High-level operations
# ---------------------------------------------------------------------------
def _drain_logs(ser, stop_types, timeout=15.0, max_log_lines=500):
    """
    Читает фреймы, логирует LOG, ERROR.
    Возвращает первый фрейм, тип которого в stop_types.
    Иначе None (timeout).
    """
    deadline = time.time() + timeout
    lines = 0
    while time.time() < deadline and lines < max_log_lines:
        try:
            t, p, ok = recv_frame(ser, timeout=2.0)
        except TimeoutError:
            continue
        if not ok:
            continue

        if t == TYPE_LOG:
            lines += 1
            try:
                log(f"[ESP ] {p.decode(errors='replace')}")
            except Exception:
                log(f"[ESP ] <log bytes: {hex_dump_short(p)}>")
            continue

        if t == TYPE_ERROR:
            log(f"[ESP ] [ERROR] {p.decode(errors='replace')}")
            return (t, p)

        if t in stop_types:
            return (t, p)

        log(f"[HOST] skip unexpected frame type=0x{t:02x} len={len(p)}")

    return None


def ping(ser, timeout=15.0):
    log("[HOST] PING...")
    send_frame(ser, TYPE_PING, b"")
    r = _drain_logs(ser, stop_types={TYPE_PONG}, timeout=timeout)
    if r is None:
        log("[HOST] PING timeout")
        return False
    t, p = r
    if t == TYPE_PONG:
        log(f"[HOST] PONG ({p.decode(errors='replace')})")
        return True
    return False


def get_spend_pubkey(ser, timeout=15.0):
    log("[HOST] GET_SPEND_PUBKEY...")
    send_frame(ser, TYPE_GET_SPEND_PUBKEY, b"")
    r = _drain_logs(ser, stop_types={TYPE_SPEND_PUBKEY_OUT}, timeout=timeout)
    if r is None:
        log("[HOST] GET_SPEND_PUBKEY timeout")
        return None
    t, p = r
    try:
        pk = bytes.fromhex(p.decode("ascii"))
        log(f"[HOST] spend pubkey: {pk.hex()}")
        return pk
    except Exception as e:
        log(f"[HOST] cannot parse pubkey: {e}")
        return None


def send_tx_and_get_signed(ser, tx_bytes: bytes, timeout=600.0, pt_file=None):
    log(f"[HOST] sending TX_BIN ({len(tx_bytes)} bytes)...")
    payload = tx_bytes.hex().encode("ascii")
    send_frame(ser, TYPE_TX_BIN, payload, chunk_size=128, chunk_delay=0.005)
    log(f"[HOST] waiting for response (timeout {int(timeout)}s)...")

    signed = None
    deadline = time.time() + timeout
    pt_total = 0

    while time.time() < deadline:
        try:
            t, p, ok = recv_frame(ser, timeout=5.0)
        except TimeoutError:
            continue
        if not ok:
            log("[HOST] frame with bad CRC, ignored")
            continue

        if t == TYPE_LOG:
            try:
                log(f"[ESP ] {p.decode(errors='replace')}")
            except Exception:
                log(f"[ESP ] <log bytes: {hex_dump_short(p)}>")

        elif t == TYPE_ERROR:
            msg = p.decode(errors="replace")
            log(f"[ESP ] [ERROR] {msg}")
            raise RuntimeError(f"device error: {msg}")

        elif t == TYPE_TX_SIGNED:
            log(f"[HOST] got TX_SIGNED ({len(p)} hex chars)")
            try:
                signed = bytes.fromhex(p.decode("ascii"))
            except Exception as e:
                log(f"[HOST] cannot parse signed tx: {e}")
                signed = None
            break

        elif t == TYPE_PT_DUMP:
            if pt_file is not None:
                pt_file.write(p)
                pt_file.flush()
                pt_total += len(p)
                if pt_total % 4096 < len(p):
                    log(f"[HOST] [PT ] received {pt_total} bytes so far")
            else:
                log(f"[HOST] [PT ] dump frame {len(p)} bytes (no file)")

        else:
            log(f"[HOST] unknown frame type=0x{t:02x} len={len(p)}")

    if pt_file is not None:
        log(f"[HOST] [PT ] total plaintext received: {pt_total} bytes")

    return signed


def send_outputs_and_get_keyimages(ser, outputs_bytes: bytes, timeout=600.0):
    log(f"[HOST] sending OUTPUTS_BIN ({len(outputs_bytes)} bytes)...")
    payload = outputs_bytes.hex().encode("ascii")
    send_frame(ser, TYPE_OUTPUTS_BIN, payload, chunk_size=128, chunk_delay=0.005)
    log(f"[HOST] waiting for KEYIMAGES_OUT (timeout {int(timeout)}s)...")

    keyimages = None
    deadline = time.time() + timeout

    while time.time() < deadline:
        try:
            t, p, ok = recv_frame(ser, timeout=5.0)
        except TimeoutError:
            continue
        if not ok:
            continue

        if t == TYPE_LOG:
            try:
                log(f"[ESP ] {p.decode(errors='replace')}")
            except Exception:
                log(f"[ESP ] <log bytes: {hex_dump_short(p)}>")
        elif t == TYPE_ERROR:
            msg = p.decode(errors="replace")
            log(f"[ESP ] [ERROR] {msg}")
            raise RuntimeError(f"device error: {msg}")
        elif t == TYPE_KEYIMAGES_OUT:
            log(f"[HOST] got KEYIMAGES_OUT ({len(p)} hex chars)")
            try:
                keyimages = bytes.fromhex(p.decode("ascii"))
            except Exception as e:
                log(f"[HOST] cannot parse keyimages: {e}")
            break
        else:
            log(f"[HOST] unexpected frame type=0x{t:02x} len={len(p)}")

    return keyimages


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Sign Monero tx on ESP32-S3")
    ap.add_argument("--port", required=True, help="Serial port (COM3, /dev/ttyUSB0)")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--tx", default="tx.bin", help="Path to unsigned tx.bin")
    ap.add_argument("--out", default="tx-signed.bin", help="Path for signed tx")
    ap.add_argument("--log", default="esp_sign.log", help="Path for host+device log")
    ap.add_argument("--pt-dump", default=None, help="Save raw plaintext to this file (debug)")
    ap.add_argument("--timeout", type=float, default=600.0)
    args = ap.parse_args()

    global LOG_FILE
    LOG_FILE = open(args.log, "w", encoding="utf-8")

    log(f"[SYS ] === sign_tx.py started, log -> {args.log} ===")

    if not os.path.exists(args.tx):
        log(f"[SYS ] FATAL: tx file not found: {args.tx}")
        return 1

    with open(args.tx, "rb") as f:
        tx_bytes = f.read()
    log(f"[HOST] loaded tx: {len(tx_bytes)} bytes")

    log("[HOST] opening port...")
    ser = serial.Serial(args.port, args.baud, timeout=0.1)
    time.sleep(0.5)
    ser.reset_input_buffer()
    ser.reset_output_buffer()

    try:
        if not ping(ser):
            log("[SYS ] PING failed")
            return 2

        # Опционально: получить spend pubkey
        spk = get_spend_pubkey(ser)
        if spk is not None:
            log(f"[HOST] device spend pubkey: {spk.hex()}")

        # === Основная операция: подпись транзакции ===
        pt_file = None
        try:
            if args.pt_dump:
                pt_file = open(args.pt_dump, "wb")
                log(f"[HOST] plaintext dump -> {args.pt_dump}")

            signed = send_tx_and_get_signed(ser, tx_bytes, args.timeout, pt_file=pt_file)
        finally:
            if pt_file is not None:
                pt_file.close()
                if os.path.exists(args.pt_dump):
                    log(f"[HOST] plaintext saved: "
                        f"{os.path.getsize(args.pt_dump)} bytes -> {args.pt_dump}")

        if signed is None:
            log("[SYS ] no signed tx received")
            return 3

        with open(args.out, "wb") as f:
            f.write(signed)
        log(f"[SYS ] signed tx saved: {len(signed)} bytes -> {args.out}")

        return 0

    except Exception as e:
        log(f"[SYS ] FATAL: {e}")
        return 4
    finally:
        ser.close()
        log("[SYS ] === sign_tx.py finished ===")
        if LOG_FILE:
            LOG_FILE.close()


if __name__ == "__main__":
    sys.exit(main())