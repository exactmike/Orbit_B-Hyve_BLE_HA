#!/usr/bin/env python3
"""
Shared research helpers for the B-Hyve BLE reverse-engineering tools.

This is the single home for everything the exploration tools share: the offline
decode path (frame/inner parsing, a protobuf reader), session derivation for
*both* directions, device resolution, and a live-session helper. The *encode*
primitives (AES-CTR, CRC-16, trailer, frame/message builders, protobuf writers)
are reused from the shipping CLI `scripts/bhyve.py` rather than duplicated.

Dependency direction: research tools import the shipping CLI; the CLI must never
import this module. (See the brief's "Upstream PR Priorities".)

Protocol reference: ../../docs/encryption.md and ../../docs/ble_protocol.md.
    outer:  0x11 | len | ciphertext(len) | trailer(2, LE)
    inner:  AA 77 5A 0F | payload_len | 00 | protobuf | CRC16-CCITT(2, LE)
    cipher: AES-128-ECB used as CTR; keystream = AES-ECB(key, IV || ctr_LE)
    IV          = rx_response[:4] || init_tx[4:12]   (same for both directions)
    counter_TX  = uint32_LE(init_tx[12:16])
    counter_RX  = uint32_LE(init_tx[16:20])
"""
import struct
import sys
from pathlib import Path

# Frame dumps print Unicode (→, ✓, ✗); Windows consoles default to cp1252 and
# raise UnicodeEncodeError mid-report. Force UTF-8 so a live run never dies after
# the command was already sent. Idempotent/best-effort; importing this module
# (every tool does) installs the guard once for all of them.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

# Import the shipping CLI for the canonical ENCODE primitives, config loader, and
# GATT constants. bhyve.py imports bleak/requests lazily, so this stays offline.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import bhyve as bh  # noqa: E402

MSG_HEADER = bh.MSG_HEADER
AES_CHAR, WRITE_CHAR, READ_CHAR = bh.AES_CHAR, bh.WRITE_CHAR, bh.READ_CHAR

# Re-export the shipping encode primitives so tools have one import surface.
crc16_ccitt = bh.crc16_ccitt
compute_trailer = bh.compute_trailer
build_message = bh.build_message
build_ble_frame = bh.build_ble_frame
load_config = bh.load_config


def aes_ctr(key, iv, counter, data):
    """AES-128 ECB-as-CTR. Returns (out, next_counter). Symmetric (enc == dec)."""
    return bh.aes_encrypt(key, iv, counter, data)


# ─── Session derivation (both directions) ─────────────────────────────────

def derive_session(init_tx, rx_resp):
    """From the 20-byte 6c71 write + read response, return (iv, tx_ctr, rx_ctr)."""
    if len(init_tx) < 20 or len(rx_resp) < 4:
        raise ValueError("need >=20-byte init_tx and >=4-byte rx_resp")
    iv = rx_resp[:4] + init_tx[4:12]
    tx_counter = struct.unpack("<I", init_tx[12:16])[0]
    rx_counter = struct.unpack("<I", init_tx[16:20])[0]
    return iv, tx_counter, rx_counter


# ─── Frame / inner-message parsing ────────────────────────────────────────

def parse_ble_frame(raw):
    """Split `0x11 | len | ciphertext | trailer(2)`; None if not a 0x11 frame."""
    if len(raw) < 4 or raw[0] != 0x11:
        return None
    length = raw[1]
    ct = raw[2:2 + length]
    trailer = raw[2 + length:2 + length + 2]
    if len(ct) != length:
        return None
    return length, ct, trailer


def decode_inner(pt):
    """Parse a decrypted inner message and validate its CRC; None if no header."""
    if len(pt) < 6 or pt[:4] != MSG_HEADER:
        return None
    payload_len = pt[4]
    pb_end = 4 + payload_len            # protobuf occupies pt[6:pb_end]
    if payload_len < 2 or pb_end + 2 > len(pt):
        return None
    protobuf = pt[6:pb_end]
    crc_rx = struct.unpack("<H", pt[pb_end:pb_end + 2])[0]
    crc_calc = crc16_ccitt(pt[:pb_end], 0)
    return {
        "protobuf": protobuf,
        "crc_ok": crc_rx == crc_calc,
        "crc_rx": crc_rx,
        "crc_calc": crc_calc,
    }


def decrypt_frame(key, iv, ct, base_counter, lo=-8, hi=1024):
    """Decrypt, sweeping the counter to find one yielding a valid inner frame.

    With both counters now known, callers should pass the correct base
    (tx_counter or rx_counter); the small window still absorbs per-frame counter
    advance across a notification burst. Returns (counter, plaintext, inner) for
    the first CRC-valid decode, else the first header-only match, else Nones.
    """
    fallback = None
    for d in range(lo, hi):
        c = (base_counter + d) % 0x100000000
        pt, _ = aes_ctr(key, iv, c, ct)
        if pt[:4] != MSG_HEADER:
            continue
        inner = decode_inner(pt)
        if inner and inner["crc_ok"]:
            return c, pt, inner
        if fallback is None:
            fallback = (c, pt, inner)
    return fallback if fallback else (None, None, None)


def build_command_frame(key, iv, counter, protobuf):
    """Encode a protobuf into a full on-wire frame. Returns (frame, next_counter)."""
    message = build_message(protobuf)
    ct, next_counter = aes_ctr(key, iv, counter, message)
    return build_ble_frame(ct, compute_trailer(message)), next_counter


# ─── Minimal protobuf reader ──────────────────────────────────────────────

def _read_varint(data, i):
    result = shift = 0
    while i < len(data):
        b = data[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, i
        shift += 7
        if shift > 63:
            break
    return None, i


def pb_parse(data):
    """Parse protobuf to a list of (field, wire, value), or None if malformed."""
    fields = []
    i = 0
    while i < len(data):
        tag, i = _read_varint(data, i)
        if tag is None:
            return None
        field, wire = tag >> 3, tag & 7
        if wire == 0:
            val, i = _read_varint(data, i)
            if val is None:
                return None
            fields.append((field, wire, val))
        elif wire == 2:
            ln, i = _read_varint(data, i)
            if ln is None or i + ln > len(data):
                return None
            fields.append((field, wire, data[i:i + ln]))
            i += ln
        elif wire == 5:
            if i + 4 > len(data):
                return None
            fields.append((field, wire, data[i:i + 4]))
            i += 4
        elif wire == 1:
            if i + 8 > len(data):
                return None
            fields.append((field, wire, data[i:i + 8]))
            i += 8
        else:
            return None  # groups / unknown wire types
    return fields


def pb_format(data, indent=1):
    fields = pb_parse(data)
    pad = "    " * indent
    if fields is None:
        return f"{pad}<not protobuf> {data.hex()}"
    lines = []
    for field, wire, val in fields:
        if wire == 0:
            lines.append(f"{pad}#{field} varint = {val}")
        elif wire == 2:
            if val and pb_parse(val) is not None:
                lines.append(f"{pad}#{field} ({len(val)}B) {{")
                lines.append(pb_format(val, indent + 1))
                lines.append(f"{pad}}}")
            else:
                lines.append(f"{pad}#{field} bytes({len(val)}) = {val.hex()}")
        elif wire == 5:
            lines.append(f"{pad}#{field} i32 = {val.hex()}")
        elif wire == 1:
            lines.append(f"{pad}#{field} i64 = {val.hex()}")
    return "\n".join(lines)


# ─── Device resolution (from saved config or --mac/--key) ─────────────────

def resolve_device(args):
    """Return (name, mac, key_hex) from --mac/--key overrides or saved config."""
    if getattr(args, "mac", None) and getattr(args, "key", None):
        return ("<cli-override>", args.mac, args.key)
    config = load_config()
    devices = config.get("devices") or []
    if not devices:
        sys.exit("No devices configured (run `bhyve.py setup`) and no --mac/--key given.")
    idx = (getattr(args, "device", None) or 1) - 1
    if idx < 0 or idx >= len(devices):
        sys.exit(f"--device {args.device} out of range (have {len(devices)}).")
    dev = devices[idx]
    mac = getattr(args, "mac", None) or dev["mac"]
    key = getattr(args, "key", None) or dev["network_key"]
    return (dev.get("name", f"device{idx + 1}"), mac, key)


# ─── Live BLE session helper ──────────────────────────────────────────────

class LiveSession:
    """Async context manager: scan → connect → MTU → AES init → notify.

    Exposes iv / tx_counter / rx_counter (derived for both directions), a
    timestamped `rx_frames` buffer, `send(protobuf)` (advances the TX counter),
    and `decode_rx(raw)` (decodes with the RX counter). Mirrors the session-init
    quirks of the shipping CLI exactly (init_tx[11] = 0x00, write-without-response).
    """

    def __init__(self, mac, key_hex, scan_timeout=25.0, connect_timeout=15.0):
        self.mac = mac
        self.key = bytes.fromhex(key_hex)
        self.scan_timeout = scan_timeout
        self.connect_timeout = connect_timeout
        self.rx_frames = []   # list of (t_relative, raw_bytes)

    async def __aenter__(self):
        import os
        import time
        from bleak import BleakClient, BleakScanner

        device = await BleakScanner.find_device_by_address(self.mac, timeout=self.scan_timeout)
        if device is None:
            sys.exit(f"{self.mac} not found — is it awake and in range?")
        self.client = BleakClient(device, timeout=self.connect_timeout)
        await self.client.__aenter__()

        # _acquire_mtu() is BlueZ-only; Windows/WinRT negotiates automatically.
        acquire_mtu = getattr(self.client._backend, "_acquire_mtu", None)
        if acquire_mtu is not None:
            await acquire_mtu()
        self.mtu = self.client.mtu_size

        self._t0 = time.monotonic()
        await self.client.start_notify(
            READ_CHAR,
            lambda _s, d: self.rx_frames.append((time.monotonic() - self._t0, bytes(d))),
        )

        # AES session init — identical to bhyve.py (init_tx[11] forced to 0x00).
        init_tx = bytearray(os.urandom(20))
        init_tx[11] = 0x00
        self.init_tx = bytes(init_tx)
        await self.client.write_gatt_char(AES_CHAR, self.init_tx)
        self.init_rx = bytes(await self.client.read_gatt_char(AES_CHAR))
        self.iv, self.tx_counter, self.rx_counter = derive_session(self.init_tx, self.init_rx)
        return self

    async def __aexit__(self, *exc):
        try:
            await self.client.stop_notify(READ_CHAR)
        except Exception:
            pass
        await self.client.__aexit__(*exc)

    async def send(self, protobuf):
        """Build + write a command frame on 6c72, advancing the TX counter."""
        frame, self.tx_counter = build_command_frame(self.key, self.iv, self.tx_counter, protobuf)
        await self.client.write_gatt_char(WRITE_CHAR, frame, response=False)
        return frame

    def decode_rx(self, raw):
        """Decode an RX notification with the RX counter. Returns (ctr, pt, inner)."""
        parsed = parse_ble_frame(raw)
        if parsed is None:
            return None, None, None
        _, ct, _ = parsed
        return decrypt_frame(self.key, self.iv, ct, self.rx_counter)
