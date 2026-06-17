# B‑Hyve BLE — Single‑Station Valve Support (Claude Code Working Brief)

> **Purpose:** orient a Claude Code session (and the human working alongside it) on
> what we're doing, what's now **solved**, what's still **open**, and the order to
> tackle it. Read top to bottom before changing code.
>
> **Last updated:** 2026‑06‑17.

---

## 0. State at a glance (read this first)

- ✅ **Core problem SOLVED — single‑station valves actuate over local BLE.** The
  blocker was a **hardcoded outer‑frame trailer** in `scripts/bhyve.py`; computing
  it from the message fixed it. **Verified on real hardware** (valve `BTValve03`,
  `zone 1 ON 30s` physically actuated).
- ✅ **Single‑station (fw `111`) speaks the SAME BLE protocol as the XD 4‑port
  (fw `0107`) for control.** Same framing, same cipher, same `timerMode` protobuf,
  `stationId = 0` for the single station. No per‑firmware protocol profile is needed
  for start/stop. (This collapses most of the old §7 hypotheses.)
- ✅ **Network key is correct** (H1 settled): our TX frame self‑decrypts to a valid
  inner message and the valve obeys it.
- ✅ **Fix committed & pushed:** branch `fix/ble-trailer-winrt`, commit `888da05`
  (`scripts/bhyve.py` only), on the fork. Pending an upstream PR. Fork workflow and
  branch roles are in §9.1.
- 🔎 **Main open thread:** device→host (RX) notifications on `6c73` use a **different
  keystream** than host→device (TX). The valve is *talkative* (5 notifications within
  0.28 s of a start command — almost certainly status/battery/time). Decoding RX gives
  Home Assistant real battery/state. Tooling + captured data are ready (see §8, §10).
- 🎯 **Standing priority across all work: keep changes upstream‑PR‑acceptable** (§9).

---

## 1. Goal

Extend local Bluetooth (no cloud, no app, no Wi‑Fi hub) control of Orbit B‑Hyve
irrigation devices to a **set of single‑station Bluetooth valves** that mesh with a
Wi‑Fi hub. We build on an existing project that already worked for the **XD 4‑port**
timer (upstream: `wxfield/Orbit_B-Hyve_4Port_Controller`; reference device: XD 4‑port,
part **24634**, FCC **ML6‑HT34BT**, hardware **HT34A‑0001**, firmware **0107**).

End state:
1. ✅ A CLI that starts/stops watering on each single‑station valve. *(start **and stop**
   hardware‑verified on `BTValve03`; cross‑device on/off still TODO — see §11.)*
2. A Home Assistant integration exposing each valve, with battery/state **if** we crack
   the RX path (§8).
3. **Backwards‑compatible** changes structured as a clean fork and, ideally, an upstream
   PR adding multi‑device / multi‑model support without breaking existing XD users (§9).

---

## 2. Our Hardware (differs from upstream's reference device)

- Reported model: **B‑Hyve 21205** (single‑port BT hose timer). Label ids:
  FCC `ML6-HT25G2`, IC `3330A-HT25G2`, HVIN `HT25G2`.
- MCU: **Nordic nRF52833** (BLE + 802.15.4).
- Power: **2× AA** driving a **latching (bistable) solenoid** via boost converter + H‑bridge.
- Account topology (from `setup`): **1 Wi‑Fi hub + 4 single‑station valves**.
  - Hub: firmware `0096`, `stations: 0`.
  - Valves `BTValve01..04`: firmware **`111`**, `stations: 1` each, MAC OUI `44:67:55`.
- Test unit used this session: **`BTValve03`**, MAC `44:67:55:1A:FA:64`, config `--device 4`.

**Key difference vs upstream:** upstream is *one device with 4 stations*; we have *four
separate one‑station devices* (plus a hub). Firmware string differs (`111` vs `0107`),
but — now confirmed — the **control protocol is identical** (§0).

---

## 3. Current Status

### ✅ Solved / confirmed working this session
- **Start watering actuates the valve.** The original "sent, no actuation, no
  confirmation" symptom was the wrong outer‑frame trailer; see §6.
- **Stop closes the valve (hardware‑verified 2026‑06‑17, `BTValve03`).** A single‑session
  start→hold(15 s)→stop closed the valve at ~15 s, well before the 120 s on‑device timer,
  so the *stop command* (not the auto‑close) shut it. Stop used the **continued** session
  counter (start consumed 2 blocks). The device emitted a fresh RX burst at the moment of
  stop (state‑change report). Tool: `scripts/exploration/verify_stop.py`.
- GATT service `fe32` + chars `6c71` (AES init) / `6c72` (TX) / `6c73` (RX notify) present.
- CLI connects, negotiates MTU (247), AES session‑init round‑trips, sends a command, and
  the valve **physically actuates**.
- Our **TX frame self‑decrypts** to a valid inner message: `AA77 5A0F` header, matching
  CRC‑16, matching trailer — proving key + framing + cipher + protobuf are all correct.
- Decoded TX protobuf (start): field `14` `timerMode { 1: mode=2 (manual),
  2: manualParams { 3: stationInfo { 1: stationId=0, 2: runTimeSec=30 } } }`.

### 🔎 Open
- **RX notifications do not decrypt with the TX keystream.** Outer framing is identical
  (`0x11 | len | ciphertext | trailer`, length bytes valid), but neither the TX IV nor a
  ±counter window decodes them → device→host uses a different IV and/or counter (§7, §8).
- **Cross‑device on/off** — start+stop proven on `BTValve03` only; not yet on a second
  valve (§11 step 2). **Blocked by range (2026‑06‑17):** a full BLE scan from the desktop
  adapter sees **only `BTValve03`** (`44:67:55:1A:FA:64`, rssi ≈ −79); `BTValve01`
  (`…:FA:38`) and the other two never appear even after a button press. The desktop adapter
  can't reach the installed valves ⇒ cross‑device verification needs a valve moved into
  range or an **ESP32 BT proxy** (the planned HA end‑state, §12).
- **Sleep/advertising (partial):** `BTValve03` keeps advertising for **many minutes** after
  its last command with no re‑wake needed, so repeated tests "just work" without a button
  press. A cold valve out of range can't be distinguished from a sleeping one here (§11.3).
- Valve **sleep/advertising** behavior still uncharacterized (matters for HA on‑demand
  connect / scheduled watering).

---

## 4. Repo Layout (relevant files)

```
custom_components/orbit_bhyve_ble/   # HA integration (one switch per zone)
  bhyve_device.py                    #   canonical send path (correct trailer/cipher)
scripts/bhyve.py                     # standalone CLI (FIXED this session; committed)
scripts/exploration/                 # research probes (RE tooling lives here)
  decode_frame.py                    #   NEW: offline frame decrypt + protobuf dump
  retest_live.py                     #   NEW: live send + RX capture + decode
  find_rx_keystream.py               #   NEW: offline brute to recover the RX keystream
docs/encryption.md                   # cipher + trailer + CRC (source of truth)
docs/ble_protocol.md                 # GATT map + frame format
protobuf/orbit_ble.proto             # partial reconstructed schema (NOT the start msg)
```

`docs/encryption.md`, `protobuf/orbit_ble.proto`, and
`custom_components/orbit_bhyve_ble/bhyve_device.py` (`_send_command`) are the source of
truth — read them before changing the protocol layer.

---

## 5. Protocol Summary (now confirmed against fw `111` and fw `0107`)

- **Transport:** custom GATT service `fe32`. Init on `6c71` (20‑byte writes), encrypted
  TX on `6c72`, encrypted RX via notifications on `6c73`.
- **No BLE bonding / no source‑MAC enforcement.** Security is app‑layer (network key +
  per‑session IV/counter).
- **Outer frame:** `0x11 | len | ciphertext(len) | trailer(2, LE)` where
  `trailer = (sum(plaintext) + 0x11 + len) mod 65536`. **The trailer is computed from the
  plaintext — it is NOT a constant.** (This was the bug; see §6.)
- **Inner (decrypted) message:** `AA 77 5A 0F | payload_len | 00 | protobuf | CRC16‑CCITT`
  (poly `0x1021`, init `0`, no reflection/XOR‑out; CRC over header+len+protobuf).
  `payload_len = len(protobuf) + 2`.
- **Cipher:** AES‑128 ECB used as CTR. Keystream block = `AES‑ECB(networkKey, IV || ctr_LE)`;
  XOR with plaintext; counter increments per 16‑byte block; **wraps at 2³²**.
- **Host→device (TX) session params:** `IV = rx_response[:4] || init_tx[4:12]` (12 bytes);
  `counter = uint32_LE(init_tx[12:16])`. Init write quirk: `init_tx[11] = 0x00`.
- **Device→host (RX) session params:** **UNKNOWN / different from TX.** This is the open
  problem (§7/§8). Outer framing is the same; only the keystream derivation differs.

---

## 6. The Fix (committed — `888da05` on `fix/ble-trailer-winrt`)

`scripts/bhyve.py`, the standalone CLI, was sending a **hardcoded** trailer
(`b"\x80\x04"` for on, `b"\x80\x03"` for off). The device **silently rejects** any frame
whose trailer ≠ `sum(plaintext)+0x11+len` (write‑without‑response → no error surfaced),
so commands were transmitted but never actuated. The HA integration
(`bhyve_device.py._compute_trailer`) and `docs/encryption.md` already did this correctly;
the CLI did not.

Changes in the commit:
1. **Compute the trailer from the message** (`compute_trailer()`), at both send sites.
   (Note: even the §‑old "zone 1 / 60 s" repro was wrong — our builder yields trailer
   `0x9403`, not the docs' illustrative `0x8004`, because our protobuf omits the extra
   fields the docs sample carried.)
2. **Counter wrap `% 0x100000000`** (2³²), was `% 0xFFFFFFFF`.
3. **WinRT/Windows handling** (pre‑existing local mods, now landed behind guards so they
   don't regress Linux/BlueZ): scan‑before‑connect via
   `BleakScanner.find_device_by_address`, a `getattr` guard around the BlueZ‑only
   `_acquire_mtu()`, and write‑without‑response (`response=False`) to match the HA path.

Kept as one commit because the trailer fix and the `response=False`/connect changes are
intertwined in the same hunks and were validated together by the live actuation.

---

## 7. Hypotheses — status

- **H1 (wrong key): ✅ DISPROVEN.** Key is correct — TX self‑decodes, valve actuates.
- **H2 (single‑station protobuf differs): ✅ DISPROVEN for control.** Same `timerMode`
  message works on fw `111`.
- **H4 (TX counter/IV handshake differs): ✅ DISPROVEN for TX.** Standard derivation works.
- **H‑trailer (NEW, was the real cause): ✅ CONFIRMED & FIXED.**
- **H‑RX (NEW, still open): device→host uses a different keystream.** Prime suspect is a
  **seed swap** — RX IV leads with the *host* seed (`init_tx[:4]`) instead of the *device*
  seed (`rx[:4]`), i.e. candidate `B+C+D` vs the TX `A+C+D`. Other possibilities: an
  RX‑specific counter base (incl. flash‑stored/arbitrary), or a derived RX key. See §8.

---

## 8. Tools Built This Session (`scripts/exploration/`, untracked)

All three reuse the same primitives and the **key‑independent trailer oracle**
(`sum(pt)+0x11+len` doesn't depend on the key or the inner header, so it confirms a
correct decrypt without assuming RX structure).

- **`decode_frame.py`** — offline: give it a captured frame hex + key + (IV/counter, or
  the `6c71` init+response to derive them); it decrypts, checks trailer/CRC, and prints a
  protobuf tree. Works on both our frames and Wireshark captures.
- **`retest_live.py`** — live: sends a command using `bhyve.py`'s real builders, captures
  RX on `6c73`, decodes everything, prints a Verdict. Use `--device N`, `--zone`,
  `--duration`, `--stop`. (This is what confirmed actuation.)
- **`find_rx_keystream.py`** — offline brute to recover the RX keystream. Tries 120
  structured IV constructions (ordered arrangements of the handshake's 4‑byte chunks)
  × a counter window, against the captured RX frames, using the trailer oracle. The real
  session's handshake + 5 RX frames are **embedded** as defaults.
  - **RAN 2026‑06‑17 — INCONCLUSIVE (no RX scheme found).** TX self‑check `PASS`, but the
    per‑frame "hits" are **16‑bit‑oracle noise, not a real scheme**: 120 IVs × 1088
    counters ≈ 130 k candidates/frame vs. a 16‑bit trailer ⇒ ~2 random collisions/frame
    expected. The hits used *different* IV constructions (`A+Z+E`, `D+E+C`, `B+D+E`) at
    *unrelated* counter offsets, none had a recognizable header, and the two long frames
    (0, 4) matched nothing. A **strengthened joint test** (one IV, counter advancing by
    block‑count across all 5 frames = ~80‑bit oracle, ±8192 window) found **nothing**; no
    single handshake‑derived IV decodes all frames at base. ⇒ **RX is NOT a rearrangement
    of handshake chunks with a near‑base counter.** Remaining: derived RX key, or
    arbitrary flash‑stored counter (only reliably searchable *jointly*, too slow in pure
    Python) → **best next move is a real app capture** (§10), now feasible.
- **`verify_stop.py`** — live: single‑session start→hold→stop on the **continued** counter,
  with RX capture across both commands. Used to hardware‑verify stop (§3). `--device N`,
  `--zone`, `--duration` (safety auto‑close), `--hold` (seconds open before stop).

These are **research tooling and deliberately self‑contained**; they must not become a
dependency of the shipping CLI (see §9).

---

## 9. Upstream PR Priorities (HARD REQUIREMENTS — apply to every change)

The goal is a fork that can become an **accepted upstream PR**. Optimize for a maintainer
saying "yes" with minimal friction:

1. **Backwards compatibility is non‑negotiable.** Existing XD 4‑port behavior must keep
   working unchanged. New device support must be **additive** (gate on station count /
   model / firmware), never a rewrite of the working path. The trailer fix is universally
   correct (it reproduces the XD's values), so it's safe; build on that posture.
2. **Keep shipping files minimal and obviously correct.** `bhyve.py` carries only
   bug/compat fixes. **Research code stays in `scripts/exploration/`** (matches upstream's
   existing structure). Do not bloat the CLI/HA modules with diagnostics.
3. **Platform changes behind guards.** WinRT/Windows fixes use `getattr`/feature checks so
   Linux/BlueZ is not regressed — a maintainer won't accept a Windows fix that breaks Linux.
4. **Commit in logical, reviewable steps**; keep upstream's layout; document new device
   support in `docs/`. Don't redistribute any vendor firmware/app code or reconstructed
   schema beyond what's behaviorally validated.
5. **Secrets never get committed.** `.bhyve_config*.json` hold per‑device network keys.
   The real file is git‑ignored (`/scripts/.bhyve_config.json`); the stray
   `*_redacted.json` was deleted. Redact keys in any shared logs.
6. **Keep the firmware‑update warning prominent.** RE'd against specific firmware
   (`0107` / `111`); updates may break it.
7. **Deferred (candidate future PRs, intentionally NOT done yet):**
   - *Config outside the repo* (`$BHYVE_CONFIG` → `~/.bhyve/config.json` → legacy
     in‑repo fallback). Discussed; deferred by request.
   - *Shared protocol module* — factor `crc16` / AES / `compute_trailer` / frame
     build+parse into one module imported by the CLI, HA integration, and diagnostics.
     This is the right §‑structural cleanup, but do it **only after** the RX protocol is
     settled, and as its own reviewable step (it touches multiple files).
   - *Device‑vs‑station model* — the CLI conflates "zone index" with "device"; the config
     already has per‑device MAC+key+station‑count, but the control path needs typed
     devices (and the **hub off‑by‑one** fixed: hub sits in config slot 1, so valves are
     `--device 2..5`). Do this for true multi‑device support, additively.

---

## 9.1 Branch Strategy & Remotes (fork workflow)

**Remotes:**
- `origin` → **your fork**, `https://github.com/exactmike/Orbit_B-Hyve_BTLE_HA.git`
  (note the fork is renamed vs upstream). Push here.
- `upstream` → **original**, `https://github.com/wxfield/Orbit_B-Hyve_4Port_Controller.git`.
  Fetch updates / target PRs here.

**Long-lived branches:**
- **`main`** — kept **pristine, in sync with `upstream/main`**. Never commit feature
  work directly here; it's the clean base for upstream PRs.
  Sync: `git fetch upstream && git merge --ff-only upstream/main && git push`.
- **`production`** — **your private integration line** (pushed to the fork). Carries the
  fix + fork-internal RE tooling + merged features. **This is what you run from.** Never
  PR'd upstream.

**Topic branches — base depends on destination:**
- **Upstream-bound** fix/feature (`fix/*`, `feat/*`) → branch off **`main`** (clean, no
  tooling cruft). Merge into `production` for your own use **and** open a PR to `upstream`
  from the branch. Keep PRs surgical (if a branch has drifted, cherry-pick just the
  feature's commits onto a fresh branch off `upstream/main`).
- **Research/dev** (`research/*`) — needs the RE tools, not upstreamed as-is → branch off
  **`production`** (so the tools in `scripts/exploration/` are present). Merge findings
  back to `production`.

**Rule of thumb:** *branch off `main` to propose upstream; branch off `production` to do
research/dev.*

**Current branches:**
- `fix/ble-trailer-winrt` (`888da05`) — pushed; pending upstream PR.
- `production` (`78017da`) — pushed; integration line (fix + dev tooling).
- `research/rx-keystream` — **active** research branch off `production` for the RX keystream
  work (§8/§10). New session should start here.

---

## 10. Captured Reference Data (this session)

Embedded as defaults in `scripts/exploration/find_rx_keystream.py` (handshake + 5 RX
frames are not secret; only the key is). Key facts:
- Device `BTValve03` / `--device 4`. `base_counter = uint32_LE(init_tx[12:16]) = 4199198414`.
- TX IV (works) = `rx[:4] || init_tx[4:12]`. The 6c71 response was `<4 seed bytes> || zeros`.
- RX frames: 5 notifications, ciphertext lengths 74 / 27 / 27 / 25 / 104, arriving
  +0.06 … +0.28 s after the start command. None decode with the TX keystream.
- A real Wireshark capture of the **official app** driving a valve (hub unplugged) is no
  longer on the critical path for control, but would still help confirm the RX scheme and
  any state/battery message shapes if the offline brute stalls.

---

## 11. Next Steps (suggested order)

1. **Crack RX:** run `find_rx_keystream.py --device 4`; if it hits, decode the RX protobuf
   to identify status/battery/time fields. If it stalls, widen `--span` or reconsider a
   derived RX key / arbitrary counter (then a real app capture, §10).
2. **Hardware‑verify `stop`** — ✅ DONE on `BTValve03` via `verify_stop.py --device 4`
   (start→hold→stop, closed early). **Still TODO:** run on at least one other valve
   (e.g. `verify_stop.py --device 2` = `BTValve01`) so on/off across devices is proven.
   *Blocked from the desktop by range (only `BTValve03` is reachable).* **Next session is
   planned from a laptop** that can be moved into range of the other valves — this also
   re‑tests from a **different control endpoint/BT adapter** (confirms the protocol isn't
   host‑specific). Run `verify_stop.py --device 2` (and `--hold 30`) there.
3. **Characterize sleep/advertising** (interval/duration after a button press, hub
   unplugged) — determines whether HA can connect on demand or needs an always‑on BT proxy.
4. **Then** do the §9 additive refactor (typed devices, hub off‑by‑one) and wire the HA
   integration; consider committing the `exploration/` tools as their own tracked commit.
5. **Open the upstream PR** for `fix/ble-trailer-winrt` (already pushed) when ready.

---

## 12. Environment & Safety

- OS: **Windows 11**, Bleak **WinRT** backend (no BlueZ private APIs). Python **3.14**.
- Deps: `bleak`, `cryptography`, `requests`.
- Config: resolved from `scripts/.bhyve_config.json` (git‑ignored; contains secret
  per‑device `network_key`).
- **Do not update B‑Hyve firmware** on any valve — decline app prompts. Known‑good
  baseline: hub `0096`, valves `111`.
- Valves **sleep** — press the button to wake before scanning. Keep the **Wi‑Fi hub
  unplugged** during local BLE work. End‑state likely retires the Orbit hub (HA owns the
  valves, ESP32 BT proxy for range + always‑on scanning).
- Real water on a real spigot: test with short durations; the device enforces the run
  timer on‑device (that's also the safety auto‑close).
