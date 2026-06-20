#!/usr/bin/env python3
"""Extract B-Hyve GATT frames from a tshark JSON export (-T json, raw bytes).

The official-app capture maps the fe32 characteristics to these handles:
    0x000d = 6c71 (AES init: WriteReq + ReadResp)
    0x000f = 6c72 (TX, host->device encrypted writes)
    0x0011 = 6c73 (RX, device->host notifications)

Usage:
    python extract_capture.py [capture.json]   # defaults to the bundled app capture
Prints the init handshake, ordered TX frames, and ordered RX frames as hex.
"""
import json
import sys
from pathlib import Path

H_INIT, H_TX, H_RX = "0x000d", "0x000f", "0x0011"
DEFAULT_CAP = Path(__file__).resolve().parent / "captures" / "20260619_app_single_station.json"


def _first(d, k):
    v = d.get(k)
    return v[0] if isinstance(v, list) else v


def _hex(val):
    return val.replace(":", "").replace(" ", "") if val else ""


def load(path):
    data = json.load(open(path))
    init_tx = init_rx = None
    tx, rx = [], []
    for p in data:
        l = p["_source"]["layers"]
        b = l.get("btatt")
        if not b:
            continue
        op = _first(b, "btatt.opcode")
        h = _first(b, "btatt.handle")
        val = _hex(_first(b, "btatt.value"))
        fn = l["frame"]["frame.number"]
        t = l["frame"]["frame.time_relative"]
        if h == H_INIT and op == "0x12" and val:      # WriteReq
            init_tx = val
        elif h == H_INIT and op == "0x0b" and val:    # ReadResp
            init_rx = val
        elif h == H_TX and op in ("0x12", "0x52") and val:
            tx.append((fn, t, val))
        elif h == H_RX and op == "0x1b" and val:      # Notification
            rx.append((fn, t, val))
    return init_tx, init_rx, tx, rx


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else str(DEFAULT_CAP)
    init_tx, init_rx, tx, rx = load(path)
    print(f"init_tx (6c71 write): {init_tx}")
    print(f"init_rx (6c71 resp):  {init_rx}")
    print(f"\nTX frames ({len(tx)}) on 6c72:")
    for fn, t, v in tx:
        print(f"  #{fn} t={t} ({len(v)//2}B) {v}")
    print(f"\nRX frames ({len(rx)}) on 6c73:")
    for fn, t, v in rx:
        print(f"  #{fn} t={t} ({len(v)//2}B) {v}")


if __name__ == "__main__":
    main()
