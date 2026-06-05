# Rev Conquer Observer — Protocol & Architecture Notes

What we learned about Rev's wire protocol on `139.99.125.223` (ports 9959/5817)
and how this proxy is built to observe it. Treat this as the load-bearing
knowledge: if everything else is lost, this is what you need to rebuild the
observer.

---

## Topology

Three programs on the Windows box:

1. **Conquer.exe** — the real game client, started by Rev's launcher. We never
   spawn it directly because the launcher does integrity work that the server
   checks for.
2. **Proxy** ([src/Proxy/ProxyMain.cs](../src/Proxy/ProxyMain.cs)) — SOCKS5
   server on `0.0.0.0:1080`. Proxifier routes `Conquer.exe` through it. The
   proxy connects upstream to the real Rev server and bridges bytes both ways.
   It is **observe-only**: it never re-encrypts, never injects, never modifies.
3. **Frida capture script** ([tools/frida_key_capture.py](../tools/frida_key_capture.py))
   — attaches to `Conquer.exe` during login, snapshots the post-DH Blowfish
   key schedules, writes them to a JSON file, detaches.

The proxy reads that JSON to decrypt the rest of the session.

```
launcher → spawns → Conquer.exe ──→ Proxifier ──→ proxy:1080 ──→ rev:5817
                          │                            │
                          ▼                            ▼
                    Frida key_capture            captures/keys/session_*.json
                          │                            │
                          └──── writes file ───────────┘
```

---

## Why hybrid (Frida + proxy) instead of pure MitM

The proxy *can* do a MitM-DH on port 5817 — it has `ServerKeyExchange` and
`ClientKeyExchange` and the DH math. But Rev's `BF_set_key` doesn't produce
an OpenSSL-compatible schedule. Even if we know the DH-derived shared secret,
running it through OpenSSL's standard key schedule gives the wrong P/S boxes,
so decryption fails. We tried; it doesn't work.

Frida sidesteps this entirely: we let the real client run its own
`BF_set_key`, then read the resulting 4168-byte `BF_KEY` struct directly out
of process memory. No reversing required.

Frida's downside is anti-cheat detection. Rev's SecurePlay/AnticheatLibrary
notices Frida and kicks within ~10–20 seconds. The capture script is designed
to minimize that window: hook only `BF_set_key`, grab both schedules in the
first second after they're set, detach immediately. By the time the AC
notices, we already have what we need (and the proxy is what continues to
observe — Frida is gone).

---

## Rev's wire protocol on 5817 — key facts

### Two BF_KEY schedules per session

The client maintains two distinct `BF_KEY` structs, identified by pointer:

| Pointer       | Key length | Source           | Purpose                                     |
| ------------- | ---------- | ---------------- | ------------------------------------------- |
| `~0x1ab1f8`   | 16 bytes   | `DR654dt34trg4UI6` (static) | Login (port 9959) AND the first c→s auth packet on 5817 |
| `~0x101716x0` | 64 bytes   | DH-derived       | Steady-state encryption on 5817 (both directions) |

Pointers vary per process (we observed `0x10171360`, `0x10176640`, `0x0ecd2a38`, etc.).
Key lengths are stable: 16 = static DR654, 64 = DH-derived game key.

### 5817 stream layout

```
client → server (c→s):  [ ONE auth packet, DR654-encrypted ][ everything else, game-key-encrypted ]
server → client (s→c):  [ everything game-key-encrypted, starting at byte 0 ]
```

Concretely, on a fresh 5817 connection:

- **c→s**: client sends ONE encrypted packet using the static DR654 key. It's
  a ~167-byte login/auth blob that does NOT use standard `[u16-len][u16-type]`
  TQ packet framing — its body is an opaque token/hash blob — but it always
  ends with the ASCII trailer `TQClient` (8 bytes). After that trailer, every
  subsequent c→s byte is encrypted with the 64-byte game key.
- **s→c**: the server's very first byte on 5817 is already game-key-encrypted.
  No DR654 phase, no plaintext greeting. IV starts at 0.

### Where the game key comes from

The 64-byte game key is derived during the **login flow on 9959**, not via DH
on 5817 (this is different from stock TQ/5065). By the time 5817 opens, the
client already has the schedule loaded — that's why we see `BF_set_key`
called with `keylen=64` on the game-key pointer once, mid-login, and never
again for that pointer.

We do not know how the client derives the 64-byte material from the login
response. We don't need to — Frida snapshots the resulting schedule, so the
derivation algorithm is irrelevant to us.

### CFB-64 details

- OpenSSL's `BF_cfb64_encrypt` with `enc=1` for encrypt, `enc=0` for decrypt.
- IV is **caller-maintained**; `BF_set_key` does not touch it.
- First cfb64 call after `BF_set_key` always sees IV = `00 00 00 00 00 00 00 00`
  (the caller hasn't fed it anything yet).
- The IV evolves byte-by-byte as bytes pass through; each direction has its
  own independent IV that starts at zero.
- Schedule (P/S arrays) is identical for both directions — they only differ
  in IV state.

### Login port (9959)

`AuthCryptography` (separate from BF_cfb64) — counter-based, no DH. Not our
focus; the existing [src/Crypto/AuthCryptographer.cs](../src/Crypto/AuthCryptographer.cs)
handles it. The 8-byte `C5 48 69 12 ...` that's always the first s→c chunk
on 9959 is the standard 5065-style auth greeting.

---

## Anti-cheat behavior

- The launcher is **mandatory**. Spawning `Conquer.exe` directly produces
  rejection on the server side; the launcher does integrity attestation we
  haven't characterized.
- Frida is detected. Symptoms:
  - `frida.ProcessNotRespondingError` on `frida.attach()` if the AC has
    already armed (happens when re-attaching to an already-Frida-touched
    process before a full client restart).
  - Session close 10–20s after attach succeeds if Frida stays resident.
- **Mitigation that works**: attach the instant `Conquer.exe` is visible,
  capture schedules within the first second, `session.detach()` immediately.
  Once Frida is gone, the AC has nothing to detect. The proxy doesn't
  trigger detection — it's just a SOCKS proxy from the client's POV.
- After a Frida kick, **fully exit Conquer.exe and the launcher** before
  retrying. Attaching to a still-running process that already had Frida
  attached fails.
- Run scripts in an **Administrator cmd**. `frida.get_local_device().enumerate_processes()`
  needs elevated rights to see Conquer.exe when the launcher spawns it under
  a slightly different token.

---

## Capture script ([tools/frida_key_capture.py](../tools/frida_key_capture.py))

Hooks `BF_set_key` at RVA `0x1A07E0` inside `Conquer.exe`. On each call:

- `keylen == 16` → the DR654 (login) schedule. Capture once.
- `keylen > 16` → the game schedule. Capture once.

When both are in hand, sends a `done` message to Python, which writes
`session_<timestamp>.json` atomically (.tmp → rename) into the proxy's
keyfile directory and detaches Frida.

### `watch` mode

The most reliable launch mode: `python tools\frida_key_capture.py watch`
polls `device.enumerate_processes()` every 25ms for a new process whose name
contains "Conquer.exe", attaches the moment it sees one. This gives the
smallest possible attach window — Frida is resident only for the few seconds
between Conquer.exe spawn and the second `BF_set_key` call completing.

### Keyfile (v3 schema)

```json
{
  "version": 3,
  "login": { "p": [18 hex u32], "s": [1024 hex u32] },
  "game":  { "p": [18 hex u32], "s": [1024 hex u32] },
  "p": [...], "s": [...]
}
```

`p` is the OpenSSL `BF_KEY.P[18]` array (host-endian u32, hex). `s` is
`BF_KEY.S[4][256]` flattened (1024 entries). Top-level `p`/`s` is a v2
back-compat alias for `game`.

Schedule values are loaded directly into `BlowfishEcb` via `LoadSchedule(p, s)`
([src/Crypto/GameCryptographer.cs](../src/Crypto/GameCryptographer.cs)),
bypassing our own `SetKey` algorithm entirely. This is critical: we can't
trust that our OpenSSL-style key schedule matches Rev's, so we load the
exact bytes the client computed.

---

## Proxy ([src/Proxy/ProxyMain.cs](../src/Proxy/ProxyMain.cs))

### Connection lifecycle for 5817

1. Conquer.exe → Proxifier → proxy:1080 → SOCKS5 CONNECT → `Session.BridgeGameObserveOnly()`.
2. Open upstream socket to `rev:5817`.
3. Spawn two pumps (`ObservePump`) — one per direction. Each pump reads
   ciphertext, forwards it untouched, captures to disk, and stashes a copy
   in `_s2cPending`/`_c2sPending` if the keyfile hasn't loaded yet.
4. `KeyfileWatcher` polls the keyfile dir; loads the newest fresh JSON
   (filtered by `LastWriteTimeUtc >= sessionStart` so stale captures from
   prior runs are ignored).
5. When the keyfile loads, `FlushBacklogsOnce` immediately drains any
   stashed pre-key c→s bytes through `DecodeC2s`. (We don't wait for the
   next live c→s chunk — the entire auth packet may have been delivered
   pre-key and no further c→s chunk arrives until the server responds.)
6. **s→c backlog is discarded**, not replayed. Empirically the pre-keyfile
   s→c bytes are often misaligned with the BF_cfb64 stream (TCP-level
   chunking edges, possibly server-side buffering). Discarding the backlog
   loses ~first ~10 packets but every subsequent packet decodes cleanly.
7. **c→s backlog is replayed through `DecodeC2s`** because the auth packet
   ABSOLUTELY IS part of the cipher stream and skipping it would desync
   every subsequent c→s call.

### `DecodeC2s` — the two-key handoff

The asymmetric part of the protocol. Pseudocode:

```
accumulate raw c→s bytes into _c2sRawAccum
in parallel, decrypt those bytes with DR654 schedule into _c2sLoginDecrypted (shadow)
scan _c2sLoginDecrypted for the literal byte sequence "TQClient"
  not found yet → return; wait for more bytes
  found at offset N:
    auth packet length = N + 8
    emit auth packet (informational; doesn't parse as standard TQ)
    take raw bytes at offset [authPacketLen..] from _c2sRawAccum
    decrypt those through the game-key cipher (fresh, IV=0)
    walk packets
    set _c2sGameKeyActive = true, discard shadow buffers
```

After the handoff, c→s steady-state is just `state.Crypto.DecryptC2s(chunk)`
on every read. The auth packet doesn't follow standard `[u16-len][u16-type]`
framing — its body is an opaque token blob — but it always ends in `TQClient`.

### s→c path

Single-key, simpler:

```
state.Crypto.DecryptS2c(chunk) → WalkPackets
```

s→c uses the game key from byte 0 of the 5817 stream. IV starts at 0.

### Why we load schedules directly (not from a key string)

When you call `new GameCryptography(Common.ENCRYPTION_KEY)`, our own
`BlowfishEcb.SetKey` runs an OpenSSL-flavored key-schedule derivation.
Whether that matches Rev's `BF_set_key` output exactly is an open question
— and during debugging we saw evidence it does **not** for at least some
build of Conquer.exe (TQClient trailer never appeared in DR654-decrypted
shadow buffer, then immediately worked when we switched to the captured
schedule).

So **always prefer captured schedules over key strings**. The
`GameCryptography.LoadSchedules(p, s)` path bypasses `SetKey` and just
copies the P/S arrays into place. This is the path that works for both
DR654 (c→s auth) and game key (everything else).

---

## TQ packet framing (steady-state)

Once decrypted, both c→s and s→c packets follow standard TQ format:

```
offset 0:  u16 length  (LE, total packet size including header but excluding trailer)
offset 2:  u16 type
offset 4:  body...
offset L:  trailer "TQClient" or "TQServer" (8 bytes ASCII)
```

`WalkPackets` walks the buffer using the length field. The trailer is a
sanity check (the diag confirmed both directions actually emit it).

Known type IDs we've observed and what they correspond to (from 5065 source
referenced in [tools/frida_packet_reader.py:39](../tools/frida_packet_reader.py#L39)):

- `1004` Talk (chat)
- `1005` Walk
- `1006` HeroInformation
- `1008` ItemInformation
- `1009` ItemAction
- `1010` GeneralData / Action
- `1012` (login response continuation)
- `1015` Strings
- `1022` Interact / Combat
- `1025` WeaponProf
- `1033` ServerTime
- `1052` Connect (the *post-auth* connect packet, NOT the DR654 auth packet)
- `1110` MapStatus
- `1128` (heartbeat-ish)
- `2030` SpawnNpc
- `2064` Nobility
- `2685` (AC report fragment — zero-padded; the parser's "type=0 size=8 00 00..." spam comes from these)
- `10005`, `10010`, `10014`, `10017` — Rev-specific extensions (5065 doesn't have these)

The `type=2685` packets contain large zero-padded regions that confuse the
naive packet walker — those are AC reports, not real protocol data, and the
"malformed, stop walking" lines are usually them.

---

## Workflow recap

In TWO admin cmd windows on the Windows box:

**Window 1 — proxy**
```
dotnet run --project conquer-rev-observer.csproj
```

**Window 2 — Frida capture**
```
python tools\frida_key_capture.py watch
```

Then start Rev's launcher and log in. Frida captures the schedules
during login and detaches. The proxy logs decrypted packets in real time
for the rest of the session (until AC kicks for unrelated reasons or you
quit). Raw ciphertext per-chunk is also written to
`bin\Debug\net8.0\captures\<timestamp>__<host>_<port>\{c2s,s2c}.bin` for
offline replay.

### Before re-running

- Fully exit `Conquer.exe` AND the launcher. Frida injection on a
  previously-Frida-touched process fails.
- Optional: clean `bin\Debug\net8.0\captures\keys\*.json*` to keep the dir
  tidy. The proxy filters by mtime so stale files don't break correctness,
  but they accumulate.
- Run cmd as Administrator (`enumerate_processes` needs it).

---

## File map

- [src/Proxy/ProxyMain.cs](../src/Proxy/ProxyMain.cs) — SOCKS5 server, session
  bridge, observe-only pumps, keyfile watcher, two-key c→s decoder.
- [src/Crypto/GameCryptographer.cs](../src/Crypto/GameCryptographer.cs) —
  Blowfish CFB-64 engine, `LoadSchedules()`, `DecryptC2s`/`DecryptS2c`/`*Slice`.
- [src/Crypto/AuthCryptographer.cs](../src/Crypto/AuthCryptographer.cs) —
  login-port (9959) counter cipher.
- [src/Crypto/BlowfishExchange.cs](../src/Crypto/BlowfishExchange.cs) — DH
  handshake helpers (used for legacy MitM-DH `BridgeGame`; current
  `BridgeGameObserveOnly` doesn't use these).
- [src/Common.cs](../src/Common.cs) — `ENCRYPTION_KEY = "DR654dt34trg4UI6"`,
  DH constants.
- [tools/frida_key_capture.py](../tools/frida_key_capture.py) — production
  capture script (write keyfile + detach).
- [tools/frida_diag.py](../tools/frida_diag.py) — verbose diagnostic hook
  (logs every BF_set_key and BF_cfb64 call). Use only for protocol R&D —
  attaching this AND the capture script doubles the AC's detection surface.
- [tools/frida_packet_reader.py](../tools/frida_packet_reader.py) — older
  approach: read plaintext directly from `BF_cfb64_encrypt`/`CCipher` via
  Frida instead of MitM. Superseded by the proxy + capture combo (less AC
  exposure), but kept around because the packet-type table and TQ-parsing
  helpers in it are reusable.
- [tools/frida_bf_setkey_hook.py](../tools/frida_bf_setkey_hook.py) — even
  older diagnostic that dumps the BF_KEY struct after every set_key. The
  comment in it about "If P[0] != 0x606d5cbd here, something tampered with
  the BF_KEY" is what initially convinced us Rev used OpenSSL-standard
  `BF_set_key`. **That assumption turned out to be wrong** for the DR654
  case (or at least, our `BlowfishEcb.SetKey` doesn't match it), which is
  why we now capture both schedules instead of deriving DR654 from the
  ASCII key string.

---

## Conquer.exe RVAs (for the build we hooked)

These are relative to `ImageBase=0x00400000`. If Conquer.exe gets re-built
or repacked these will shift and need to be re-found via static analysis.

- `BF_set_key`        @ VA `0x005A07E0` → RVA `0x1A07E0`
- `BF_cfb64_encrypt`  @ VA `0x005A05E0` → RVA `0x1A05E0`
- `BF_encrypt`        @ VA `0x005AA390` → RVA `0x1AA390`
- `CCipher::Encrypt`  @ VA `0x00588A9E` → RVA `0x188A9E`
- `CCipher::Decrypt`  @ VA `0x00588AE4` → RVA `0x188AE4`

These were found via the unique xref to the Blowfish P-init constant table
at VA `0x006242A8`.

---

## Open issues / known limitations

- **Pre-keyfile s→c bytes are discarded.** We lose the first ~10 server
  packets (the initial player-info / login-response burst). Steady-state is
  fine. Could be fixed by delaying the proxy from forwarding s→c bytes
  until the keyfile loads, but that adds latency and might trigger client
  timeouts.
- **The "00 00 00 00 ... 54 51 (TQ...)" parser spam** is the WalkPackets
  walker getting confused inside zero-padded type=2685 AC report packets.
  Cosmetic, not a decryption error.
- **Build-specific RVAs.** If Rev pushes a new `Conquer.exe`, the
  BF_set_key/BF_cfb64 offsets in [tools/frida_key_capture.py](../tools/frida_key_capture.py)
  may need updating. Find them again via the Blowfish P-init constant table.
- **No human-readable packet parsing yet.** Output is hex + type ID. Plan:
  add per-type field decoders modeled on the 5065 Redux source.
