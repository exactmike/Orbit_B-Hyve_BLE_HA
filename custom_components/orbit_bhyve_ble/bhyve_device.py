"""B-Hyve BLE device communication layer.

Uses HA's Bluetooth manager for device access (same pattern as SensorPush).
Handles AES-ECB CTR encryption, session init, and GATT writes.
"""

import asyncio
import logging
import os
import struct

from bleak import BleakClient
from bleak_retry_connector import establish_connection
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .const import AES_CHAR, WRITE_CHAR, READ_CHAR, MSG_HEADER

_LOGGER = logging.getLogger(__name__)


# ─── Crypto helpers ──────────────────────────────────────────────────────

def _crc16_ccitt(data: bytes, init: int = 0) -> int:
    crc = init
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def _pb_varint(val: int) -> bytes:
    r = bytearray()
    while val > 0x7F:
        r.append((val & 0x7F) | 0x80)
        val >>= 7
    r.append(val & 0x7F)
    return bytes(r)


def _pb_field_varint(f: int, v: int) -> bytes:
    return _pb_varint((f << 3) | 0) + _pb_varint(v)


def _pb_field_bytes(f: int, d: bytes) -> bytes:
    return _pb_varint((f << 3) | 2) + _pb_varint(len(d)) + d


# ─── Device class ────────────────────────────────────────────────────────

class BHyveDevice:
    """Represents a B-Hyve BLE sprinkler device."""

    def __init__(self, hass, address: str, network_key: str, num_zones: int = 4):
        self.hass = hass
        self.address = address
        self.network_key = bytes.fromhex(network_key)
        self.num_zones = num_zones
        self._lock = asyncio.Lock()

    def _aes_encrypt(self, iv: bytes, counter: int, plaintext: bytes) -> tuple[bytes, int]:
        result = bytearray()
        for offset in range(0, len(plaintext), 16):
            chunk = plaintext[offset:offset + 16]
            block = iv + struct.pack("<I", counter)
            keystream = Cipher(
                algorithms.AES(self.network_key), modes.ECB()
            ).encryptor().update(block)
            result.extend(b ^ k for b, k in zip(chunk, keystream[:len(chunk)]))
            counter = (counter + 1) % 0x100000000  # 2^32, per-block counter wrap
        return bytes(result), counter

    def _build_message(self, protobuf: bytes) -> bytes:
        payload_len = len(protobuf) + 2
        msg = MSG_HEADER + bytes([payload_len, 0x00]) + protobuf
        crc = struct.pack("<H", _crc16_ccitt(msg, 0))
        return msg + crc

    @staticmethod
    def _compute_trailer(plaintext: bytes) -> bytes:
        """Compute the 2-byte frame trailer (checksum validated by device).

        Formula: uint16_LE(sum(plaintext_bytes) + 0x11 + len(plaintext))
        The 0x11 is the BLE frame magic header byte.
        """
        total = sum(plaintext) + 0x11 + len(plaintext)
        return struct.pack("<H", total & 0xFFFF)

    async def _send_command(self, protobuf: bytes) -> bool:
        """Connect via HA's Bluetooth manager and send an encrypted command."""
        from homeassistant.components.bluetooth import async_ble_device_from_address

        _LOGGER.info("B-Hyve %s: looking up BLE device...", self.address)

        ble_device = async_ble_device_from_address(
            self.hass, self.address, connectable=True
        )
        if ble_device is None:
            _LOGGER.error("B-Hyve %s not connectable — is it in range?", self.address)
            return False

        _LOGGER.info("B-Hyve %s: found, connecting via HA Bluetooth manager...", self.address)
        client = None
        try:
            client = await establish_connection(
                BleakClient,
                ble_device,
                self.address,
                max_attempts=3,
            )
            _LOGGER.info("B-Hyve %s: connected!", self.address)
            await asyncio.sleep(0.5)

            # Init AES session: write 20 random bytes (byte[11]=0x00) to 6c71
            init_tx = bytearray(os.urandom(20))
            init_tx[11] = 0x00
            init_tx = bytes(init_tx)
            await client.write_gatt_char(AES_CHAR, init_tx)
            rx = await client.read_gatt_char(AES_CHAR)
            _LOGGER.debug("B-Hyve %s: AES session init done", self.address)

            # Derive session IV and counter
            iv = rx[:4] + init_tx[4:12]
            counter = struct.unpack("<I", init_tx[12:16])[0]

            # Build, encrypt, and frame the message
            message = self._build_message(protobuf)
            trailer = self._compute_trailer(message)
            ciphertext, _ = self._aes_encrypt(iv, counter, message)
            frame = bytes([0x11, len(ciphertext)]) + ciphertext + trailer
            _LOGGER.debug("B-Hyve %s: frame=%d bytes, trailer=%s", self.address, len(frame), trailer.hex())

            # Send via write-without-response (Write Command)
            await client.write_gatt_char(WRITE_CHAR, frame, response=False)
            _LOGGER.info("B-Hyve %s: command sent (%dB)", self.address, len(frame))

            await asyncio.sleep(2)
            return True

        except Exception as err:
            _LOGGER.error("B-Hyve %s: BLE command failed: %s", self.address, err)
            return False

        finally:
            if client is not None:
                try:
                    await client.disconnect()
                except Exception:
                    pass

    async def turn_on(self, zone: int, duration: int = 600) -> bool:
        """Turn on a zone (1-indexed). Duration in seconds."""
        async with self._lock:
            _LOGGER.info("Zone %d ON for %ds on %s", zone, duration, self.address)
            station_info = _pb_field_varint(1, zone - 1) + _pb_field_varint(2, duration)
            manual_params = _pb_field_bytes(3, station_info)
            timer_mode = _pb_field_varint(1, 2) + _pb_field_bytes(2, manual_params)
            protobuf = _pb_field_bytes(14, timer_mode)
            return await self._send_command(protobuf)

    async def turn_off(self) -> bool:
        """Stop all watering."""
        async with self._lock:
            _LOGGER.info("Stopping all zones on %s", self.address)
            protobuf = bytes.fromhex("720408021200")
            return await self._send_command(protobuf)
