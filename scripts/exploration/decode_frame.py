#!/usr/bin/env python3
"""
B-Hyve BLE Frame Decoder (offline analysis tool)

Decrypts and pretty-prints a captured on-wire BLE frame so we can:
  - verify the network key is correct (a clean decode == right key; brief §7/H1),
  - inspect the inner message + protobuf, and
  - diff our generated frames against frames captured from the official app
    (brief §8) to settle whether single-station / fw 111 differs (H2/H4).

This is a RESEARCH tool: it does no Bluetooth I/O. It takes hex you've already
captured — from Wireshark (Android HCI snoop log) or from the official app — and
turns it back into protobuf. It deliberately duplicates the handful of crypto
primitives it needs so it has no dependency on the shipping CLI.

Frame format (see ../../docs/encryption.md):
    outer:  0x11 | len | ciphertext(len) | trailer(2, LE)
    inner:  AA 77 5A 0F | payload_len | 00 | protobuf | CRC16-CCITT(2, LE)
    cipher: AES-128-ECB used as CTR; keystream = AES-ECB(key, IV || ctr_LE)

You must supply the session IV and the session-init counter. Either pass them
directly (--iv / --counter), or let the tool derive them the way the protocol
does, from the 20-byte 6c71 init write and the 20-byte 6c71 read response:
    IV      = rx_response[:4] || init_tx[4:12]
    counter = uint32_LE(init_tx[12:16])

Examples:
    # Derive IV/counter from the captured init exchange, then decode a data frame:
    python3 decode_frame.py --key <32hex> \\
        --init <20-byte 6c71 write hex> --rx <20-byte 6c71 response hex> \\
        11 2e <...ciphertext...> 80 04

    # IV/counter already known:
    python3 decode_frame.py --key <32hex> --iv <24hex> --counter 12345 <frame hex>
"""
import argparse
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MSG_HEADER = bytes([0xAA, 0x77, 0x5A, 0x0F])


# ─── Crypto primitives (self-contained; mirror docs/encryption.md) ────────

def crc16_ccitt(data, init=0):
    crc = init
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def aes_decrypt(key, iv, counter, ciphertext):
    """AES-128 ECB-as-CTR. XOR is symmetric, so this also encrypts."""
    out = bytearray()
    for off in range(0, len(ciphertext), 16):
        chunk = ciphertext[off:off + 16]
        block = iv + struct.pack("<I", counter)
        keystream = Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(block)
        out.extend(b ^ k for b, k in zip(chunk, keystream[:len(chunk)]))
        counter = (counter + 1) % 0x100000000
    return bytes(out)


def compute_trailer(plaintext):
    total = sum(plaintext) + 0x11 + len(plaintext)
    return struct.pack("<H", total & 0xFFFF)


# ─── Frame / message parsing ──────────────────────────────────────────────

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

    The device→host counter isn't known a priori, so we search a window around
    `base_counter`. Returns (counter, plaintext, inner) for the first CRC-valid
    decode, else the first header-only match (right key, wrong CRC), else Nones.
    """
    fallback = None
    for d in range(lo, hi):
        c = (base_counter + d) % 0x100000000
        pt = aes_decrypt(key, iv, c, ct)
        if pt[:4] != MSG_HEADER:
            continue
        inner = decode_inner(pt)
        if inner and inner["crc_ok"]:
            return c, pt, inner
        if fallback is None:
            fallback = (c, pt, inner)
    return fallback if fallback else (None, None, None)


# ─── Minimal protobuf walker ──────────────────────────────────────────────

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


# ─── Top-level decode + CLI ───────────────────────────────────────────────

def dump_frame(raw, key, iv, base_counter):
    print(f"raw frame ({len(raw)}B): {raw.hex()}")
    parsed = parse_ble_frame(raw)
    if parsed is None:
        print("  not a 0x11 BLE frame — nothing to decode")
        return
    length, ct, trailer = parsed
    print(f"  len={length}  trailer={trailer.hex()}")
    counter, pt, inner = decrypt_frame(key, iv, ct, base_counter)
    if pt is None:
        print("  decrypt: NO counter in the search window produced the AA775A0F header")
        print("           → wrong network key, or a different IV/counter scheme")
        return
    print(f"  decrypted (@counter={counter}): {pt.hex()}")
    exp = compute_trailer(pt)
    print(f"  trailer: got {trailer.hex()} expected {exp.hex()} "
          f"[{'OK' if exp == trailer else 'MISMATCH'}]")
    if inner is None:
        print("  inner: header matched but the message was truncated/unparseable")
        return
    print(f"  inner CRC: {'OK' if inner['crc_ok'] else 'BAD'} "
          f"(rx={inner['crc_rx']:#06x} calc={inner['crc_calc']:#06x})")
    print(f"  protobuf ({len(inner['protobuf'])}B): {inner['protobuf'].hex()}")
    print(pb_format(inner["protobuf"]))


def _hex(s):
    return bytes.fromhex(s.replace(":", "").replace(" ", ""))


def main():
    ap = argparse.ArgumentParser(
        description="Decode a captured B-Hyve BLE frame (offline).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("frame", nargs="+",
                    help="Outer frame hex (spaces allowed, e.g. '11 2e ... 80 04')")
    ap.add_argument("--key", required=True, help="16-byte network key (hex)")
    ap.add_argument("--iv", help="12-byte session IV (hex)")
    ap.add_argument("--counter", type=int, help="Session-init counter (uint32)")
    ap.add_argument("--init", help="20-byte 6c71 init write (hex) — to derive IV/counter")
    ap.add_argument("--rx", help="20-byte 6c71 read response (hex) — to derive IV")
    args = ap.parse_args()

    key = _hex(args.key)
    if len(key) != 16:
        ap.error(f"--key must be 16 bytes, got {len(key)}")

    if args.iv is not None and args.counter is not None:
        iv = _hex(args.iv)
        counter = args.counter
    elif args.init and args.rx:
        init_tx, rx = _hex(args.init), _hex(args.rx)
        if len(init_tx) < 16 or len(rx) < 4:
            ap.error("--init must be >=16 bytes and --rx >=4 bytes")
        iv = rx[:4] + init_tx[4:12]
        counter = struct.unpack("<I", init_tx[12:16])[0]
        print(f"derived IV={iv.hex()} counter={counter}\n")
    else:
        ap.error("provide either (--iv and --counter) or (--init and --rx)")

    if len(iv) != 12:
        ap.error(f"IV must be 12 bytes, got {len(iv)}")

    raw = _hex(" ".join(args.frame))
    dump_frame(raw, key, iv, counter)


if __name__ == "__main__":
    sys.exit(main())
