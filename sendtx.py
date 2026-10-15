#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sendtx.py — отправка подписанной Monero-транзакции в monerod через RPC.

По умолчанию:
    file = tx-signed.bin
    host = 127.0.0.1
    port = 18081 (mainnet)

Использование:
    python sendtx.py
    python sendtx.py --stagenet
    python sendtx.py --file my_tx.bin
"""

import sys
import json
import argparse
import urllib.request
import urllib.error
from pathlib import Path


DEFAULT_FILE = "tx-signed.bin"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 18081   # mainnet


def load_tx_hex(path: str) -> str:
    data = Path(path).read_bytes()
    if len(data) == 0:
        raise ValueError(f"Файл пустой: {path}")
    hex_str = data.hex()
    print(f"[sendtx] loaded {len(data)} bytes from {path}")
    print(f"[sendtx] hex length = {len(hex_str)} chars")
    print(f"[sendtx] first 32 bytes = {data[:32].hex()}")
    print(f"[sendtx] version = {data[0]}")
    return hex_str


def send_raw_transaction(hex_str: str, host: str, port: int,
                         user: str = None, password: str = None) -> dict:
    url = f"http://{host}:{port}/send_raw_transaction"
    payload = {"tx_as_hex": hex_str}
    body = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")

    if user is not None:
        import base64
        creds = base64.b64encode(f"{user}:{password}".encode()).decode()
        req.add_header("Authorization", f"Basic {creds}")

    print(f"[sendtx] POST {url}")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            status = resp.status
            data = resp.read().decode("utf-8", errors="replace")
            print(f"[sendtx] HTTP {status}")
            try:
                return json.loads(data)
            except json.JSONDecodeError:
                print(f"[sendtx] raw response (not JSON):\n{data}")
                return {"raw": data}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"[sendtx] HTTP error {e.code}")
        print(f"[sendtx] body: {body}")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return {"raw": body, "http_error": e.code}
    except urllib.error.URLError as e:
        print(f"[sendtx] connection error: {e.reason}")
        return {"connection_error": str(e.reason)}


def print_result(result: dict):
    print("[sendtx] === response ===")
    print(json.dumps(result, indent=2))

    if "result" in result:
        r = result["result"]
        status = r.get("status", "")
        if status == "OK":
            print()
            print("=" * 60)
            print("[sendtx] SUCCESS! Transaction submitted.")
            print(f"[sendtx] tx_hash = {r.get('tx_hash', '<none>')}")
            print("=" * 60)
        elif status == "Failed":
            print()
            print("=" * 60)
            print(f"[sendtx] FAILED: {r.get('reason', '<no reason>')}")
            flags = [k for k, v in r.items()
                     if isinstance(v, bool) and v and k != "untrusted"]
            if flags:
                print(f"[sendtx] flags: {', '.join(flags)}")
            print("=" * 60)


def main():
    ap = argparse.ArgumentParser(
        description="Send signed Monero tx via RPC",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("--file", default=DEFAULT_FILE,
                    help="Binary file with signed transaction")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT,
                    help="18081 mainnet / 38081 stagenet / 28081 testnet")
    ap.add_argument("--stagenet", action="store_true",
                    help="shortcut: use stagenet port 38081")
    ap.add_argument("--testnet", action="store_true",
                    help="shortcut: use testnet port 28081")
    ap.add_argument("--user", default=None)
    ap.add_argument("--password", default=None)
    args = ap.parse_args()

    if args.stagenet:
        args.port = 38081
    elif args.testnet:
        args.port = 28081

    print(f"[sendtx] file = {args.file}")
    print(f"[sendtx] host = {args.host}")
    print(f"[sendtx] port = {args.port}")

    try:
        hex_str = load_tx_hex(args.file)
    except Exception as e:
        print(f"[sendtx] FATAL: {e}")
        return 1

    result = send_raw_transaction(hex_str, args.host, args.port,
                                  args.user, args.password)
    print_result(result)

    if result.get("result", {}).get("status") == "OK":
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())