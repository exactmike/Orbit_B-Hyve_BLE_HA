# Orbit B-Hyve Bluetooth Sprinkler Controller

**Local BLE control for Orbit B-Hyve Bluetooth hose timers — no cloud, no app, no Wi-Fi hub.**

> **STATUS:** All zones controllable from Home Assistant. Custom AES encryption decoded, frame trailer checksum algorithm reverse-engineered. Verified on the XD 4-port timer and on single-station hose valves — start/stop are hardware-verified on both.

### Supported devices

The BLE control protocol (framing, AES cipher, CRC, and trailer checksum) is **identical**
across these models — single-station valves speak the same protocol as the XD 4-port, just
with one zone (`stationId = 0`).

| | XD 4-Port (reference) | Single-station valve |
|---|---|---|
| Device | B-Hyve XD Bluetooth Hose Faucet Timer | B-Hyve single-port Bluetooth hose timer |
| Part Number | 24634 | 21205 |
| FCC ID | ML6-HT34BT | ML6-HT25G2 |
| MCU | — | Nordic nRF52833 |
| Firmware Tested | 0107 | 111 |
| Hardware | HT34A-0001 | HT25G2 |
| Zones | 4 | 1 |

Protocol: BLE GATT, AES-128 (custom CTR mode), CRC-16 CCITT inner, 16-bit sum trailer.

When adding a single-station valve in Home Assistant, set **Number of zones = 1**.

> ⚠️ **DO NOT UPDATE YOUR B-HYVE DEVICE FIRMWARE.** This integration was reverse-engineered against firmware 0107 (XD 4-port) and 111 (single-station valves). A firmware update could change the encryption protocol or trailer algorithm and break compatibility. If the official B-Hyve app prompts you to update, **decline it.**

---

## What This Project Provides

- **Home Assistant custom integration** (`custom_components/orbit_bhyve_ble/`) — auto-discovers B-Hyve devices via Bluetooth, exposes one HA switch entity per zone, supports configurable per-zone watering durations.
- **Standalone Python CLI** (`scripts/bhyve.py`) — interactive setup wizard, network key extraction (via Orbit cloud API), and direct zone on/off control without HA.
- **MQTT bridge** (`scripts/bhyve_mqtt_bridge.py`) — for setups that prefer to expose B-Hyve as MQTT switches rather than via the HA integration.
- **Reverse-engineering documentation** — the full BLE protocol, AES algorithm, frame format, trailer checksum derivation, and protobuf schema, in `docs/`.
- **Exploration scripts** (`scripts/exploration/`) — the probes and tests that were used to discover the protocol.

---

## Installation

You can install the Home Assistant integration two ways. Pick the one that matches your setup.

### Option A: HACS (recommended)

1. In HACS, go to **Integrations → ⋮ menu → Custom repositories**.
2. Add this repository's URL with category **Integration**.
3. Click **Install** on **Orbit B-Hyve BLE Sprinkler**.
4. Restart Home Assistant.
5. **Settings → Devices & Services → Add Integration → "Orbit B-Hyve BLE Sprinkler"**.

### Option B: Manual ZIP install

1. Download `orbit_bhyve_ble-X.Y.Z.zip` from the [Releases page](../../releases).
2. Unzip into your Home Assistant config directory so that the path is:
   ```
   <config>/custom_components/orbit_bhyve_ble/__init__.py
   ```
3. Restart Home Assistant.
4. **Settings → Devices & Services → Add Integration → "Orbit B-Hyve BLE Sprinkler"**.

### Configuration

The integration prompts for:

- **BLE MAC address** — populated automatically if HA's Bluetooth integration has already discovered the device.
- **Network key** — 32 hex characters (16 bytes). To extract this from your account, run the included setup wizard:
  ```bash
  cd scripts
  pip install -r ../requirements.txt
  python3 bhyve.py setup
  ```
  See [`docs/network_key_extraction.md`](docs/network_key_extraction.md) for alternative extraction methods (ADB / MMKV).
- **Number of zones** — 1, 2, or 4 (the XD comes in 1, 2, and 4-port variants).

---

## Quick Start (CLI, no Home Assistant)

```bash
pip install bleak cryptography requests
python3 scripts/bhyve.py setup            # Interactive setup wizard
python3 scripts/bhyve.py on 1 300         # Zone 1 on for 5 minutes
python3 scripts/bhyve.py on 3 600         # Zone 3 on for 10 minutes
python3 scripts/bhyve.py off              # Stop all watering
```

---

## Documentation

The repository ships with the technical reference under `docs/`. The full reverse-engineering journey, screenshots, schematics, and exploration logs live in the **[project wiki](../../wiki)**.

| Topic | Where |
|---|---|
| Step-by-step reverse engineering chronicle | Wiki: *Journey* |
| BLE GATT handle map, frame format | [`docs/ble_protocol.md`](docs/ble_protocol.md) |
| Custom AES algorithm + trailer checksum | [`docs/encryption.md`](docs/encryption.md) |
| Reconstructed protobuf schema | [`protobuf/orbit_ble.proto`](protobuf/orbit_ble.proto) |
| How to extract your network key | [`docs/network_key_extraction.md`](docs/network_key_extraction.md) |
| Frida instrumentation scripts | [`tools/frida/`](tools/frida/) |
| MQTT bridge setup | [`docker/`](docker/) |

---

## Legal & Ethical Notice

This project documents the protocol of a device the project authors lawfully purchased and own. Reverse engineering for the purpose of interoperability with hardware you own is protected in the United States under 17 U.S.C. §1201(f). This repository does **not** redistribute proprietary firmware, application source code, or decompiled vendor binaries. The protobuf schema and protocol descriptions in this repository were reconstructed from observation of the device's wire-level BLE traffic and from analysis techniques applied to the publicly distributed companion mobile application.

The project is provided **as-is, with no warranty, for educational and interoperability purposes**. Using this software with a B-Hyve device may void your warranty. The authors are not affiliated with Orbit Irrigation Products Inc.

---

## License

[MIT](LICENSE) — see `LICENSE` for full text.
