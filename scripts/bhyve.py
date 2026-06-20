#!/usr/bin/env python3
"""
Orbit B-Hyve XD Bluetooth Valve Controller

Direct BLE control of the B-Hyve XD hose timer — no cloud, no app, no Wi-Fi hub.

Setup (first time):
    python3 bhyve.py setup                          # Interactive setup wizard
    python3 bhyve.py setup --email you@email.com     # Auto-extract via Orbit API

Control:
    python3 bhyve.py on 1 300        # Zone 1 on for 5 minutes
    python3 bhyve.py on 2 600        # Zone 2 on for 10 minutes
    python3 bhyve.py off              # Stop all watering

Requirements:
    pip install bleak cryptography requests

⚠️  WARNING: Do NOT update your B-Hyve device firmware!
    This controller was reverse-engineered against firmware version 0107.
    A firmware update could change the encryption protocol and break
    compatibility. If the B-Hyve app prompts you to update, decline it.

Protocol reverse-engineered against firmware 0107.
See the project README for the full reverse-engineering documentation.
"""

import asyncio
import argparse
import struct
import json
import os
import sys
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ─── Configuration ───────────────────────────────────────────────────────

# Config location: $BHYVE_CONFIG overrides; otherwise the legacy in-repo path.
# Keeping secrets out of the repo tree is the documented setup (point
# $BHYVE_CONFIG at a file outside the checkout); the in-repo path stays as a
# backwards-compatible fallback for existing users.
CONFIG_FILE = Path(os.environ.get("BHYVE_CONFIG") or (Path(__file__).parent / ".bhyve_config.json"))

ORBIT_API_BASE = "https://api.orbitbhyve.com/v1"
ORBIT_APP_ID = "Bhyve-App"

# GATT characteristic UUIDs
AES_CHAR   = "00006c71-fe32-4f58-8b78-98e42b2c047f"
WRITE_CHAR = "00006c72-fe32-4f58-8b78-98e42b2c047f"
READ_CHAR  = "00006c73-fe32-4f58-8b78-98e42b2c047f"

# Inner message constants
MSG_HEADER = bytes([0xAA, 0x77, 0x5A, 0x0F])

FIRMWARE_WARNING = """
╔══════════════════════════════════════════════════════════════════╗
║  ⚠️  WARNING: Do NOT update your B-Hyve device firmware!        ║
║                                                                  ║
║  This controller was reverse-engineered against firmware v0107.  ║
║  A firmware update may change the encryption protocol and break  ║
║  this tool. If the B-Hyve app asks you to update, DECLINE.       ║
╚══════════════════════════════════════════════════════════════════╝
"""


# ─── Config Management ──────────────────────────────────────────────────

def load_config():
    if CONFIG_FILE.exists():
        return json.loads(CONFIG_FILE.read_text())
    return {}


def save_config(config):
    CONFIG_FILE.write_text(json.dumps(config, indent=2) + "\n")
    print(f"Config saved to {CONFIG_FILE}")


# ─── Orbit Cloud API ────────────────────────────────────────────────────

def orbit_login(email, password):
    import requests
    resp = requests.post(
        f"{ORBIT_API_BASE}/session",
        json={"session": {"email": email, "password": password}},
        headers={"orbit-app-id": ORBIT_APP_ID, "Content-Type": "application/json"},
    )
    resp.raise_for_status()
    data = resp.json()
    return data.get("orbit_api_key"), data.get("user_id")


def orbit_get_devices(token):
    import requests
    resp = requests.get(
        f"{ORBIT_API_BASE}/devices",
        headers={"orbit-api-key": token, "orbit-app-id": ORBIT_APP_ID},
    )
    resp.raise_for_status()
    return resp.json()


def orbit_get_network_key(token, topology_id):
    # Orbit renamed the endpoint and the response field on accounts migrated
    # to the newer schema. Try legacy paths first so behavior is unchanged
    # for accounts still on the old schema; fall through to current names.
    import requests
    headers = {"orbit-api-key": token, "orbit-app-id": ORBIT_APP_ID}
    candidate_paths = [
        f"/network_topologies/{topology_id}",
        f"/meshes/{topology_id}",
        f"/networks/{topology_id}",
    ]
    last_error = None
    for path in candidate_paths:
        url = f"{ORBIT_API_BASE}{path}"
        try:
            resp = requests.get(url, headers=headers)
            if resp.status_code == 404:
                continue
            resp.raise_for_status()
            body = resp.json()
            key = body.get("network_key") or body.get("ble_network_key")
            if key:
                return key
        except Exception as e:
            last_error = e
    if last_error:
        raise last_error
    raise RuntimeError("No candidate endpoint returned a network_key")


# ─── Crypto ──────────────────────────────────────────────────────────────

def crc16_ccitt(data, init=0):
    crc = init
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def aes_encrypt(key, iv, counter, plaintext):
    result = bytearray()
    for offset in range(0, len(plaintext), 16):
        chunk = plaintext[offset:offset + 16]
        block = iv + struct.pack("<I", counter)
        keystream = Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(block)
        result.extend(b ^ k for b, k in zip(chunk, keystream[:len(chunk)]))
        counter = (counter + 1) % 0x100000000  # 2^32, per-block counter wrap
    return bytes(result), counter


def compute_trailer(plaintext):
    """2-byte outer-frame trailer: uint16_LE(sum(plaintext) + 0x11 + len).

    Matches custom_components/orbit_bhyve_ble/bhyve_device.py and docs/encryption.md.
    The 0x11 is the BLE frame magic header byte; `len` is the frame length byte.
    """
    total = sum(plaintext) + 0x11 + len(plaintext)
    return struct.pack("<H", total & 0xFFFF)


# ─── Message Building ────────────────────────────────────────────────────

def build_message(protobuf):
    payload_len = len(protobuf) + 2
    msg = MSG_HEADER + bytes([payload_len, 0x00]) + protobuf
    crc = struct.pack("<H", crc16_ccitt(msg, 0))
    return msg + crc


def build_ble_frame(ciphertext, trailer):
    return bytes([0x11, len(ciphertext)]) + ciphertext + trailer


def pb_varint(val):
    r = bytearray()
    while val > 0x7F:
        r.append((val & 0x7F) | 0x80)
        val >>= 7
    r.append(val & 0x7F)
    return bytes(r)


def pb_field_varint(f, v):
    return pb_varint((f << 3) | 0) + pb_varint(v)


def pb_field_bytes(f, d):
    return pb_varint((f << 3) | 2) + pb_varint(len(d)) + d


def build_start_protobuf(station_id, duration_sec):
    station_info = pb_field_varint(1, station_id) + pb_field_varint(2, duration_sec)
    manual_params = pb_field_bytes(3, station_info)
    timer_mode = pb_field_varint(1, 2) + pb_field_bytes(2, manual_params)
    return pb_field_bytes(14, timer_mode)


def build_stop_protobuf():
    return bytes.fromhex("720408021200")


# ─── Setup Wizard ────────────────────────────────────────────────────────

def cmd_setup(args):
    print(FIRMWARE_WARNING)
    print("B-Hyve Controller Setup")
    print("=" * 40)
    print()

    email = args.email
    password = args.password

    if not email:
        print("This wizard extracts your device's encryption key from the")
        print("Orbit B-Hyve cloud. You need the email and password from the")
        print("B-Hyve app (created when you first paired your sprinkler).")
        print()
        email = input("Orbit B-Hyve email: ").strip()

    if not password:
        import getpass
        password = getpass.getpass("Orbit B-Hyve password: ")

    # Login
    print(f"\nLogging in as {email}...")
    try:
        token, user_id = orbit_login(email, password)
        print(f"  Authenticated! (user_id: {user_id})")
    except Exception as e:
        print(f"  Login failed: {e}")
        print("  Check your email/password. You can reset it at:")
        print("  https://techsupport.orbitbhyve.com")
        sys.exit(1)

    # Get devices
    print("\nFetching devices...")
    try:
        devices = orbit_get_devices(token)
    except Exception as e:
        print(f"  Failed to fetch devices: {e}")
        sys.exit(1)

    if not devices:
        print("  No devices found on this account.")
        sys.exit(1)

    print(f"  Found {len(devices)} device(s):\n")

    config = {"devices": []}

    for i, dev in enumerate(devices):
        mac = dev.get("mac_address", "unknown")
        name = dev.get("name", "Unknown")
        fw = dev.get("firmware_version", "?")
        hw = dev.get("hardware_version", "?")
        stations = dev.get("num_stations", "?")
        topology_id = dev.get("network_topology_id") or dev.get("mesh_id", "")
        device_id = dev.get("id", "")

        print(f"  [{i+1}] {name}")
        print(f"      MAC: {mac}")
        print(f"      Firmware: {fw}  Hardware: {hw}")
        print(f"      Stations: {stations}")

        # Get network key
        if topology_id:
            try:
                network_key_b64 = orbit_get_network_key(token, topology_id)
                import base64
                network_key_hex = base64.b64decode(network_key_b64).hex()
                print(f"      Network Key: {network_key_b64}")
                print(f"      Key (hex): {network_key_hex}")

                # Format MAC with colons
                mac_formatted = ":".join(mac[j:j+2].upper() for j in range(0, len(mac), 2))

                config["devices"].append({
                    "name": name,
                    "mac": mac_formatted,
                    "network_key": network_key_hex,
                    "network_key_b64": network_key_b64,
                    "stations": stations,
                    "firmware": fw,
                    "device_id": device_id,
                })
                print(f"      Status: Ready!")
            except Exception as e:
                print(f"      Failed to get network key: {e}")
        else:
            print(f"      No network topology — device may need pairing first")
        print()

    if config["devices"]:
        save_config(config)
        print("\nSetup complete! You can now control your sprinkler:")
        dev = config["devices"][0]
        print(f"\n  python3 bhyve.py on 1 300    # Zone 1 for 5 minutes")
        print(f"  python3 bhyve.py off          # Stop watering")
        if len(config["devices"]) > 1:
            print(f"\n  Use --device N to select a specific device (1-{len(config['devices'])})")

    print(FIRMWARE_WARNING)


# ─── BLE Control ─────────────────────────────────────────────────────────

async def ble_command(mac, network_key, command, zones=None, duration=600):
    from bleak import BleakClient, BleakScanner

    key = bytes.fromhex(network_key)
    print(f"Scanning for {mac}...")
    device = await BleakScanner.find_device_by_address(mac, timeout=25.0)
    if device is None:
        print(f"{mac} not found — is it awake (press the button) and in range?")
        return
    print("Found. Connecting...")

    async with BleakClient(device, timeout=15.0) as client:
        # _acquire_mtu() exists only on the BlueZ (Linux) backend; Windows
        # negotiates MTU automatically, so call it only if present.
        acquire_mtu = getattr(client._backend, "_acquire_mtu", None)
        if acquire_mtu is not None:
            await acquire_mtu()
        print(f"Connected (MTU={client.mtu_size})")

        notifications = []
        await client.start_notify(READ_CHAR, lambda s, d: notifications.append(d))

        # AES session init
        init_tx = bytearray(os.urandom(20))
        init_tx[11] = 0x00
        init_tx = bytes(init_tx)
        await client.write_gatt_char(AES_CHAR, init_tx)
        rx = await client.read_gatt_char(AES_CHAR)

        iv = rx[:4] + init_tx[4:12]
        counter = struct.unpack("<I", init_tx[12:16])[0]
        print("Session established")

        if command == "on":
            for zone in zones:
                protobuf = build_start_protobuf(zone - 1, duration)
                message = build_message(protobuf)
                ct, counter = aes_encrypt(key, iv, counter, message)
                frame = build_ble_frame(ct, compute_trailer(message))
                await client.write_gatt_char(WRITE_CHAR, frame, response=False)
                mins, secs = duration // 60, duration % 60
                time_str = f"{mins}m{secs}s" if secs else f"{mins}m"
                print(f"Zone {zone} ON for {time_str} — sent!")

        elif command == "off":
            protobuf = build_stop_protobuf()
            message = build_message(protobuf)
            ct, counter = aes_encrypt(key, iv, counter, message)
            frame = build_ble_frame(ct, compute_trailer(message))
            await client.write_gatt_char(WRITE_CHAR, frame, response=False)
            print("All zones STOPPED — sent!")

        await asyncio.sleep(3)
        if notifications:
            print(f"Device confirmed ({len(notifications)} response(s))")
        else:
            print("No confirmation notification received.")
        await client.stop_notify(READ_CHAR)
        print("Done.")

def cmd_control(args):
    config = load_config()

    # Get device config
    if not config.get("devices"):
        print("No devices configured. Run setup first:")
        print("  python3 bhyve.py setup")
        sys.exit(1)

    dev_idx = (args.device or 1) - 1
    if dev_idx >= len(config["devices"]):
        print(f"Device {dev_idx+1} not found. You have {len(config['devices'])} device(s).")
        sys.exit(1)

    dev = config["devices"][dev_idx]
    mac = args.mac or dev["mac"]
    network_key = dev["network_key"]

    print(f"B-Hyve Controller — {dev['name']}")

    if args.command == "on":
        if not args.zones:
            print("Error: 'on' requires a zone number (1-4)")
            sys.exit(1)
        zones = [int(z.strip()) for z in args.zones.split(",")]
        max_stations = dev.get("stations", 4)
        for z in zones:
            if z < 1 or z > max_stations:
                print(f"Error: Zone {z} out of range (1-{max_stations})")
                sys.exit(1)
        asyncio.run(ble_command(mac, network_key, "on", zones, args.duration))

    elif args.command == "off":
        asyncio.run(ble_command(mac, network_key, "off"))


# ─── CLI ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Orbit B-Hyve XD Bluetooth Valve Controller",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Setup (first time):
  %(prog)s setup                         Interactive setup wizard
  %(prog)s setup --email you@email.com   Non-interactive with email

Control:
  %(prog)s on 1 300          Zone 1 on for 5 minutes
  %(prog)s on 1 600          Zone 1 on for 10 minutes (default)
  %(prog)s on 2 60           Zone 2 on for 1 minute
  %(prog)s off               Stop all watering

⚠️  Do NOT update your B-Hyve firmware — it may break this tool!
        """,
    )

    sub = parser.add_subparsers(dest="action")

    # Setup
    setup_p = sub.add_parser("setup", help="First-time setup wizard")
    setup_p.add_argument("--email", "-e", help="Orbit B-Hyve account email")
    setup_p.add_argument("--password", "-p", help="Orbit B-Hyve account password")

    # On
    on_p = sub.add_parser("on", help="Turn on a zone")
    on_p.add_argument("zones", help="Zone number (1-4)")
    on_p.add_argument("duration", nargs="?", type=int, default=600,
                       help="Duration in seconds (default: 600)")
    on_p.add_argument("--device", "-d", type=int, help="Device number (if multiple)")
    on_p.add_argument("--mac", help="Override MAC address")

    # Off
    off_p = sub.add_parser("off", help="Stop all watering")
    off_p.add_argument("--device", "-d", type=int, help="Device number (if multiple)")
    off_p.add_argument("--mac", help="Override MAC address")

    args = parser.parse_args()

    if args.action == "setup":
        cmd_setup(args)
    elif args.action in ("on", "off"):
        args.command = args.action
        cmd_control(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
