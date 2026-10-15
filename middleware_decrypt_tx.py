#!/usr/bin/env python3
# middleware_decrypt_tx.py
#
# Расшифровка signed/unsigned tx set на ESP32.
# Пишет всё в esp_decrypt.log.
#
# Использование:
#   middleware_decrypt_tx.py <tx_file> [COM_PORT]
# Пример:
#   middleware_decrypt_tx.py tx-signed-orig.bin COM12

import sys
import time
import serial

FRAME_START = 0xAA

# ---------------------------------------------------------------------------
# Типы фреймов (совпадают с .ino)
# ---------------------------------------------------------------------------
TYPE_LOG             = 0x03
TYPE_PING            = 0x06
TYPE_PONG            = 0x07
TYPE_DECRYPT_TX_SET  = 0x30
TYPE_DECRYPT_TX_OUT  = 0x31
TYPE_DECRYPT_TX_END  = 0x32
TYPE_ERROR           = 0xFF

# ---------------------------------------------------------------------------
# Файловый лог
# ---------------------------------------------------------------------------
LOG_FILE = "esp_decrypt.log"
_log_fp = None

def log_open():
    global _log_fp
    try:
        _log_fp = open(LOG_FILE, "w", encoding="utf-8")
    except Exception as e:
        print(f"[HOST] WARNING: cannot open log file {LOG_FILE}: {e}")
        _log_fp = None

def log_close():
    global _log_fp
    if _log_fp:
        try:
            _log_fp.flush()
            _log_fp.close()
        except Exception:
            pass
        _log_fp = None

def log_write_raw(text):
    """Пишет строку и в консоль, и в файл."""
    print(text, flush=True)
    if _log_fp:
        try:
            _log_fp.write(text + "\n")
            _log_fp.flush()
        except Exception:
            pass

def log(fmt, *args):
    ts = time.strftime("%H:%M:%S")
    msg = fmt % args if args else fmt
    log_write_raw(f"[{ts}] [HOST] {msg}")

def log_esp(payload):
    ts = time.strftime("%H:%M:%S")
    text = payload.decode("utf-8", errors="replace")
    log_write_raw(f"[{ts}] [ESP ] {text}")

# ---------------------------------------------------------------------------
# CRC16-CCITT
# ---------------------------------------------------------------------------
def crc16_ccitt(data):
    crc = 0xFFFF
    for b in data:
        crc ^= (b << 8) & 0xFFFF
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc

# ---------------------------------------------------------------------------
# Отправка фрейма
# ---------------------------------------------------------------------------
def send_frame(ser, ftype, payload):
    crc = crc16_ccitt(payload)
    hdr = bytes([FRAME_START, ftype, len(payload) & 0xFF, (len(payload) >> 8) & 0xFF])
    tail = bytes([crc & 0xFF, (crc >> 8) & 0xFF])
    ser.write(hdr + payload + tail)
    ser.flush()

# ---------------------------------------------------------------------------
# Чтение фрейма
# ---------------------------------------------------------------------------
def read_frame(ser, timeout=0.3):
    state = "start"
    ftype = 0
    length = 0
    payload = bytearray()
    rx_crc = 0
    t0 = time.time()

    while time.time() - t0 < timeout:
        b = ser.read(1)
        if not b:
            if state == "start":
                return None, None
            continue
        b = b[0]
        if state == "start":
            if b == FRAME_START:
                state = "type"
        elif state == "type":
            ftype = b
            state = "len0"
        elif state == "len0":
            length = b
            state = "len1"
        elif state == "len1":
            length |= b << 8
            payload = bytearray()
            state = "payload" if length > 0 else "crc0"
        elif state == "payload":
            payload.append(b)
            if len(payload) == length:
                state = "crc0"
        elif state == "crc0":
            rx_crc = b
            state = "crc1"
        elif state == "crc1":
            rx_crc |= b << 8
            if rx_crc == crc16_ccitt(bytes(payload)):
                return ftype, bytes(payload)
            else:
                log("CRC fail: got 0x%04x", rx_crc)
                state = "start"
    return None, None

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: middleware_decrypt_tx.py <tx_file> [COM_PORT]")
        sys.exit(1)

    tx_file  = sys.argv[1]
    com_port = sys.argv[2] if len(sys.argv) > 2 else "COM12"

    log_open()

    log("=== middleware_decrypt_tx.py started ===")
    log("tx_file=%s", tx_file)
    log("com_port=%s", com_port)
    log("log_file=%s", LOG_FILE)

    # --- Чтение файла ---
    try:
        with open(tx_file, "rb") as f:
            raw = f.read()
    except Exception as e:
        log("ERROR: cannot read file: %s", e)
        log_close()
        sys.exit(1)

    log("file loaded: %u bytes", len(raw))

    # Автоопределение hex/binary
    is_hex = True
    if len(raw) % 2 != 0:
        is_hex = False
    else:
        for b in raw[:64]:
            if b not in b"0123456789abcdefABCDEF":
                is_hex = False
                break
        if is_hex:
            for b in raw[-64:]:
                if b not in b"0123456789abcdefABCDEF":
                    is_hex = False
                    break

    if is_hex:
        log("detected: hex text")
        tx_hex_bytes = raw.decode("ascii").strip().encode("ascii")
    else:
        log("detected: binary")
        if raw.startswith(b"Monero signed tx set"):
            log("magic: 'Monero signed tx set'")
        elif raw.startswith(b"Monero unsigned tx set"):
            log("magic: 'Monero unsigned tx set'")
        else:
            log("WARNING: unknown magic: %s", raw[:30].hex())
        tx_hex_bytes = raw.hex().encode("ascii")

    log("will send %u hex chars (%u binary bytes)",
        len(tx_hex_bytes), len(raw))

    # --- Открытие порта ---
    log("opening port %s @ 115200...", com_port)
    ser = serial.Serial()
    ser.port = com_port
    ser.baudrate = 115200
    ser.timeout = 0.05
    ser.dtr = False
    ser.rts = False
    try:
        ser.open()
    except Exception as e:
        log("ERROR: cannot open port: %s", e)
        log_close()
        sys.exit(1)
    log("port opened OK")

    log("waiting 2s for ESP32...")
    time.sleep(2.0)
    ser.reset_input_buffer()
    ser.reset_output_buffer()
    log("buffers flushed")

    # --- PING ---
    log("--- PING ---")
    send_frame(ser, TYPE_PING, b"")

    got_pong = False
    t0 = time.time()
    while time.time() - t0 < 10.0 and not got_pong:
        ftype, payload = read_frame(ser, timeout=0.5)
        if ftype is None:
            continue
        if ftype == TYPE_PONG:
            log(">>> got PONG, ESP32 ready <<<")
            got_pong = True
        elif ftype == TYPE_LOG:
            log_esp(payload)
        else:
            log("pre-pong frame: type=0x%02x len=%u", ftype, len(payload))

    if not got_pong:
        log("ERROR: no PONG, aborting")
        ser.close()
        log_close()
        sys.exit(1)

    time.sleep(0.3)

    # --- Отправка tx set одним фреймом ---
    log("--- SENDING TX SET ---")
    log("frame: type=0x%02x len=%u", TYPE_DECRYPT_TX_SET, len(tx_hex_bytes))
    send_frame(ser, TYPE_DECRYPT_TX_SET, tx_hex_bytes)
    log("frame sent, waiting for response...")

    # --- Чтение ответа ---
    pt_chunks = []
    t0 = time.time()
    last_recv = time.time()
    done_marker = False

    while time.time() - t0 < 600.0:
        ftype, payload = read_frame(ser, timeout=0.5)
        if ftype is None:
            # Если получили данные и 5 секунд тишины — завершаем
            if pt_chunks and (time.time() - last_recv > 5.0):
                log("no frames for 5s, finishing (got %u chunks)",
                    len(pt_chunks))
                break
            if time.time() - last_recv > 30.0:
                log("no frames for 30s, giving up")
                break
            continue

        last_recv = time.time()

        if ftype == TYPE_LOG:
            log_esp(payload)
        elif ftype == TYPE_ERROR:
            log_esp(payload)
            log("ERROR frame received, aborting")
            break
        elif ftype == TYPE_DECRYPT_TX_OUT:
            pt_chunks.append(payload)
            log(">>> plaintext chunk: %u bytes (total %u) <<<",
                len(payload), sum(len(c) for c in pt_chunks))
        elif ftype == TYPE_DECRYPT_TX_END:
            log(">>> DONE marker received <<<")
            done_marker = True
            break
        elif ftype == TYPE_PONG:
            log("late PONG")
        else:
            log("unknown frame type=0x%02x len=%u", ftype, len(payload))

    if not pt_chunks:
        log("no plaintext received")
        ser.close()
        log_close()
        sys.exit(1)

    pt = b"".join(pt_chunks)
    log("=== total plaintext: %u bytes (done_marker=%s) ===",
        len(pt), done_marker)

    out_name = tx_file + ".pt"
    try:
        with open(out_name, "wb") as f:
            f.write(pt)
        log("saved: %s", out_name)
    except Exception as e:
        log("ERROR saving .pt: %s", e)

    out_hex_name = tx_file + ".pt.hex"
    try:
        with open(out_hex_name, "w") as f:
            f.write(pt.hex())
        log("saved: %s", out_hex_name)
    except Exception as e:
        log("ERROR saving .hex: %s", e)

    ser.close()
    log("=== DONE ===")
    log_close()

if __name__ == "__main__":
    main()