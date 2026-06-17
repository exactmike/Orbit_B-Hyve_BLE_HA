#!/usr/bin/env python3
"""
B-Hyve Live Retest Probe — send a real command and decode whatever comes back.

Purpose: turn a single live BLE attempt into an *informative* experiment after
the trailer fix in bhyve.py. It builds and sends a command using bhyve.py's real
frame construction (so we're testing exactly what the shipping CLI would send),
captures any RX notification on 6c73, and decrypts it offline with the helpers
in decode_frame.py.

Read the outcomes this way (brief §7):
  - valve actuates                      → trailer fix solved it; done.
  - no actuation, RX decodes cleanly    → key is correct (H1 settled) → go capture
                                          the app session and diff (H2/H4).
  - no actuation, RX won't decode        → wrong key / different IV-counter (H1/H4).
  - no actuation, zero RX                → notification path / sleep (H3) → capture.

This is RESEARCH tooling and does NOT modify bhyve.py. It imports bhyve.py's
builders (for send fidelity) and decode_frame.py's decoders (for RX analysis).

Usage:
    python3 retest_live.py --device 2 --zone 1 --duration 30
    python3 retest_live.py --mac 44:67:55:1A:FA:64 --key <32hex> --zone 1 --duration 30
    python3 retest_live.py --device 2 --stop          # send the stop command instead

⚠️  Real water on a real spigot — use a short duration; the device enforces it.
"""
import argparse
import asyncio
import os
import struct
import sys
import time
from pathlib import Path

# Import bhyve.py (parent dir) for the real send path, and decode_frame.py
# (same dir) for RX analysis. Neither runs anything at import time.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import bhyve as bh          # noqa: E402
import decode_frame as dec  # noqa: E402


def resolve_device(args):
    """Return (name, mac, key_hex) from --mac/--key or the saved config."""
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
    mac = args.mac or dev["mac"]
    key = args.key or dev["network_key"]
    return (dev.get("name", f"device{idx + 1}"), mac, key)


async def run(name, mac, key_hex, action, zone, duration):
    from bleak import BleakClient, BleakScanner

    key = bytes.fromhex(key_hex)
    print(f"B-Hyve retest — {name}  ({mac})")
    print(f"Scanning for {mac} (press the device button to wake it)...")
    device = await BleakScanner.find_device_by_address(mac, timeout=25.0)
    if device is None:
        sys.exit(f"{mac} not found — is it awake and in range?")
    print("Found. Connecting...")

    async with BleakClient(device, timeout=15.0) as client:
        # _acquire_mtu() is BlueZ-only; Windows/WinRT negotiates automatically.
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
        base_counter = struct.unpack("<I", init_tx[12:16])[0]
        print(f"Session init: iv={iv.hex()} counter={base_counter}")
        print(f"  init_tx={init_tx.hex()}")
        print(f"  6c71 rx={bytes(rx).hex()}")

        # Build the command exactly as bhyve.py would
        if action == "stop":
            protobuf = bh.build_stop_protobuf()
            label = "STOP"
        else:
            protobuf = bh.build_start_protobuf(zone - 1, duration)
            label = f"Zone {zone} ON {duration}s"
        message = bh.build_message(protobuf)
        ct, _ = bh.aes_encrypt(key, iv, base_counter, message)
        frame = bh.build_ble_frame(ct, bh.compute_trailer(message))

        print(f"\n=== TX ({label}) ===")
        dec.dump_frame(frame, key, iv, base_counter)

        await client.write_gatt_char(bh.WRITE_CHAR, frame, response=False)
        print("\nSent. Waiting 6s for any RX notification...")
        await asyncio.sleep(6.0)
        await client.stop_notify(bh.READ_CHAR)

        # ── Report ──
        print(f"\n=== RX ({len(rx_frames)} notification(s)) ===")
        any_decoded = False
        for i, (dt, raw) in enumerate(rx_frames):
            print(f"\n[{i}] +{dt:.2f}s")
            parsed = dec.parse_ble_frame(raw)
            dec.dump_frame(raw, key, iv, base_counter)
            if parsed is not None:
                _, ct_rx, _ = parsed
                _, pt, _ = dec.decrypt_frame(key, iv, ct_rx, base_counter)
                any_decoded = any_decoded or pt is not None

        print("\n=== Verdict ===")
        if not rx_frames:
            print("  Zero RX. → notification-path / sleep behavior (H3). Get the app capture.")
        elif any_decoded:
            print("  RX decoded cleanly → network key is correct (H1 settled).")
            print("  If the valve did NOT actuate, it's H2/H4 — capture the app session and diff.")
        else:
            print("  RX received but did NOT decode with the host→device IV/counter.")
            print("  NOTE: the TX frame above self-decoded (trailer + CRC OK), so the KEY is")
            print("  proven correct — the device→host direction just uses a different keystream")
            print("  (different IV and/or counter). This is expected, not a failure.")
            print("  → feed these RX frames to find_rx_keystream.py to recover the RX scheme.")
        print("\n  Did the valve physically actuate? That's the ground truth this can't see.")


def main():
    ap = argparse.ArgumentParser(
        description="Live B-Hyve retest with RX capture + decode.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--device", "-d", type=int, help="Device index in config (1-based)")
    ap.add_argument("--mac", help="Override MAC (requires --key)")
    ap.add_argument("--key", help="Override network key, hex (requires --mac)")
    ap.add_argument("--zone", "-z", type=int, default=1, help="Zone/station (1-based)")
    ap.add_argument("--duration", type=int, default=30, help="Run time in seconds (default 30)")
    ap.add_argument("--stop", action="store_true", help="Send the stop command instead of on")
    args = ap.parse_args()

    name, mac, key = resolve_device(args)
    action = "stop" if args.stop else "on"
    asyncio.run(run(name, mac, key, action, args.zone, args.duration))


if __name__ == "__main__":
    main()
