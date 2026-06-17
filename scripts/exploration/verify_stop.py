#!/usr/bin/env python3
"""
B-Hyve Stop Verification Probe — start, then STOP within the SAME session.

Why a dedicated probe (vs. two retest_live.py runs):
  - The device maintains a running CTR counter within a session (see
    bhyve.py `ble_command`: aes_encrypt returns the advanced counter and the
    multi-zone path reuses it). A stop sent in a *fresh* session re-inits the
    counter at base; sending it in the *same* session as the start exercises
    the real counter-continuation path the shipping CLI uses.
  - It proves stop *works* unambiguously: we start with a long auto-timer
    (default 120s) but send stop after a short observation window (default
    15s). If the valve closes at ~15s rather than ~120s, the STOP command
    closed it — not the on-device safety timer.

Ground truth is physical: this script cannot see the valve. Watch the spigot.
  expected: OPENS at ~t=0, CLOSES at ~t=<hold>s  (well before <duration>s).

Captures every RX notification (with timestamps) across both commands and
decodes the TX frames, so the data also feeds the RX-keystream work.

Usage:
    python3 verify_stop.py --device 4                 # zone 1, hold 15s, timer 120s
    python3 verify_stop.py --device 4 --hold 20 --duration 180
    python3 verify_stop.py --mac <MAC> --key <32hex>

WARNING: real water on a real spigot. Keep --duration modest; the device
enforces it on-device as the safety auto-close.
"""
import argparse
import asyncio
import os
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import bhyve as bh          # noqa: E402
import decode_frame as dec  # noqa: E402


def resolve_device(args):
    if args.mac and args.key:
        return ("<cli-override>", args.mac, args.key)
    config = bh.load_config()
    devices = config.get("devices") or []
    if not devices:
        sys.exit("No devices configured (run `bhyve.py setup`) and no --mac/--key given.")
    idx = (args.device or 1) - 1
    if idx < 0 or idx >= len(devices):
        sys.exit(f"--device {args.device} out of range (have {len(devices)}).")
    dev = devices[idx]
    return (dev.get("name", f"device{idx + 1}"),
            args.mac or dev["mac"], args.key or dev["network_key"])


async def run(name, mac, key_hex, zone, duration, hold):
    from bleak import BleakClient, BleakScanner

    key = bytes.fromhex(key_hex)
    print(f"B-Hyve stop verify — {name}  ({mac})")
    print(f"Scanning for {mac} (press the device button to wake it)...")
    device = await BleakScanner.find_device_by_address(mac, timeout=25.0)
    if device is None:
        sys.exit(f"{mac} not found — is it awake and in range?")
    print("Found. Connecting...")

    async with BleakClient(device, timeout=15.0) as client:
        acquire_mtu = getattr(client._backend, "_acquire_mtu", None)
        if acquire_mtu is not None:
            await acquire_mtu()
        print(f"Connected (MTU={client.mtu_size})")

        rx_frames = []
        t0 = time.monotonic()
        await client.start_notify(
            bh.READ_CHAR,
            lambda _s, d: rx_frames.append((time.monotonic() - t0, bytes(d))),
        )

        # AES session init (identical to bhyve.py)
        init_tx = bytearray(os.urandom(20))
        init_tx[11] = 0x00
        init_tx = bytes(init_tx)
        await client.write_gatt_char(bh.AES_CHAR, init_tx)
        rx = await client.read_gatt_char(bh.AES_CHAR)

        iv = rx[:4] + init_tx[4:12]
        counter = struct.unpack("<I", init_tx[12:16])[0]
        base = counter
        print(f"Session init: iv={iv.hex()} base_counter={base}")
        print(f"  init_tx={init_tx.hex()}")
        print(f"  6c71 rx={bytes(rx).hex()}")

        def send(protobuf, ctr):
            message = bh.build_message(protobuf)
            ct, new_ctr = bh.aes_encrypt(key, iv, ctr, message)
            frame = bh.build_ble_frame(ct, bh.compute_trailer(message))
            return frame, new_ctr, ctr

        # ── START ──
        frame, counter, used = send(bh.build_start_protobuf(zone - 1, duration), counter)
        print(f"\n=== TX START (zone {zone}, {duration}s) @ counter={used} ===")
        dec.dump_frame(frame, key, iv, used)
        await client.write_gatt_char(bh.WRITE_CHAR, frame, response=False)
        print(f"\n>>> Sent START. VALVE SHOULD OPEN NOW. Holding {hold}s before STOP...")
        await asyncio.sleep(hold)

        # ── STOP (continued counter) ──
        frame, counter, used = send(bh.build_stop_protobuf(), counter)
        print(f"\n=== TX STOP @ counter={used} (continued from base) ===")
        dec.dump_frame(frame, key, iv, used)
        await client.write_gatt_char(bh.WRITE_CHAR, frame, response=False)
        print("\n>>> Sent STOP. VALVE SHOULD CLOSE NOW. Watching 6s for RX...")
        await asyncio.sleep(6.0)
        await client.stop_notify(bh.READ_CHAR)

        # ── Report ──
        print(f"\n=== RX ({len(rx_frames)} notification(s)) ===")
        for i, (dt, raw) in enumerate(rx_frames):
            print(f"\n[{i}] +{dt:.2f}s")
            dec.dump_frame(raw, key, iv, base)

        print("\n=== Verdict (physical observation required) ===")
        print(f"  Did the valve OPEN shortly after START (~t=0)?")
        print(f"  Did it CLOSE shortly after STOP (~t={hold}s), well before {duration}s?")
        print("  CLOSE-at-hold = stop command works. CLOSE-at-duration = only the")
        print("  on-device timer fired (stop had no effect).")


def main():
    ap = argparse.ArgumentParser(
        description="Verify the B-Hyve stop command closes the valve early.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--device", "-d", type=int, help="Device index in config (1-based)")
    ap.add_argument("--mac", help="Override MAC (requires --key)")
    ap.add_argument("--key", help="Override network key, hex (requires --mac)")
    ap.add_argument("--zone", "-z", type=int, default=1, help="Zone/station (1-based)")
    ap.add_argument("--duration", type=int, default=120,
                    help="On-device run timer / safety auto-close (default 120s)")
    ap.add_argument("--hold", type=int, default=15,
                    help="Seconds to keep the valve open before sending STOP (default 15)")
    args = ap.parse_args()

    name, mac, key = resolve_device(args)
    asyncio.run(run(name, mac, key, args.zone, args.duration, args.hold))


if __name__ == "__main__":
    main()
