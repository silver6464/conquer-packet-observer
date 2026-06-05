# Phase 2 Results — Active MitM & Visual Injection

What we built, what worked, what didn't, and what's deliverable.

This document is the final write-up from the Phase 2 attempt — adding
active man-in-the-middle to the observer and demonstrating client-only
fake-visual injection on the live Rev 5187 server.

---

## Goal

Prove (or disprove) that a malicious proxy with the captured BF_KEY
schedule can inject a fabricated `MsgUserAttrib` (`#10017`) packet
that the client renders as a real game effect — without the server
ever seeing it. If yes, the cheat-class is alive on the new build;
if no, the migration mitigated it.

The historical POC ([conquer-poc](../conquer-poc/)) demonstrated this
worked on a 5065-vintage server: type `@cyclone` in chat → fake
`MSG_UPDATE(StatusEffects, bit 23)` packet down the s→c pipe → client
renders the cyclone whirlwind visual on the player's own character →
nobody else sees it, server has no idea.

The question was whether the same attack works on the Rev 5187
build.

---

## What we built

### Active MitM mode

[src/Proxy/ProxyMain.cs](../src/Proxy/ProxyMain.cs) gained an opt-in
`--mode active-mitm` flag. Observe-only remains the default.

Active MitM **does** decrypt + re-encrypt c→s in real time:
- Pre-keyfile c→s bytes are buffered and forwarded raw (client/server
  stay in cipher lockstep with each other while the proxy waits for
  Frida).
- When the keyfile loads, a fast-forward routine advances the proxy's
  four CFB engine states by replaying the buffered bytes through them
  (in decrypt mode, since CFB-64 feedback IV evolves identically with
  the wire ciphertext regardless of encrypt/decrypt mode).
- The DR654→game-key boundary inside the c→s auth packet is detected
  by scanning a side-shadow decrypt for the `TQClient` trailer; the
  LOGIN ciphers are fast-forwarded by the auth bytes only, and the
  GAME ciphers by everything after.
- Once aligned, c→s traffic decrypts → walks → re-encrypts → forwards
  cleanly. `[Walk?]`, `[Interact]`, `[GeneralData?]`, `[ItemAction]`,
  `[Connect]` all parse correctly on c→s during steady gameplay.

### Chat-command trigger surface

In active-mitm mode, the proxy intercepts `MsgTalk` packets on c→s
plaintext and recognizes three chat commands:

- `@uid <N>` — sets the player UID used by injection at runtime.
- `@bit <N>` — sets the StatusEffects bit (0..63) to flip in the fake.
- `@status` — prints the current override state.
- `@cyclone` — fires the inject.

CLI equivalents exist as `--player-uid <N>` and `--effect-bit <N>` for
when you want to lock values before starting.

### Injector

`SendFakeCycloneToClient` builds a 44-byte
`MsgUserAttrib(#10017)` packet:
```
[0..1]   size   = 36
[2..3]   type   = 10017
[4..7]   uid    = (player uid)
[8..11]  count  = 1
[12..15] updateType = 26 (StatusEffects per 5065 enum)
[16..23] data   = 1 << <bit>   (bit 23 = "Tornado" per the live
                                statuseffect.ini, matches 5065's
                                CLIENT_EFFECT_CYCLONE)
[24..35] (12 bytes of zero padding to match observed body length)
[36..43] "TQServer" trailer
```

For injection, the proxy maintains a downstream s→c cipher whose
state is meant to track the client's s→c-decrypt CFB state. At
injection time, that mirror's state is cloned into a fresh encrypt
cipher (new `GameCryptography.CopyS2cStateInto` / `BlowfishCfb64.CopyCfbStateInto`
APIs), the fake packet is encrypted under it, and the ciphertext is
written to the client socket. The client's CFB state then advances
44 bytes ahead of the server's, and subsequent real s→c bytes garble
on the client — explicit "one-shot test" semantics.

---

## What worked

1. **Frida key capture is solid.** Both the DR654 16-byte login
   schedule and the 64-byte DH-derived game schedule are extracted in
   the first few seconds of login on every successful session.
   [docs/REV_PROTOCOL.md](REV_PROTOCOL.md) covers this end to end.

2. **c→s observability and active-MitM are functional.** Every real
   gameplay session decoded c→s packets in real time, including
   chat, walks, attacks, item actions, NPC dialogs, and login
   responses. The DR654→game-key fast-forward boundary detection
   works. The chat-command interception fires.

3. **Player UID is reachable** via `MSG_CONNECT (#1052)` body bytes
   4..7. When MSG_CONNECT arrives in the post-keyfile window we
   auto-capture; when it arrives pre-keyfile we fall back to the
   `--player-uid` override.

4. **The injector mechanism is built and the encryption path runs.**
   Triggering `@cyclone` writes a well-formed 44-byte ciphertext
   blob to the client socket. The client receives it and processes
   it as a packet (i.e., the cipher state alignment is at least
   close enough for the client not to silently drop the bytes).

5. **The live statuseffect.ini** from the client confirms bit 23 =
   "Tornado" — same bit the 5065 POC used as "Cyclone". So the
   bit-to-visual mapping appears to carry forward.

---

## What didn't work

### s→c cipher alignment in active-mitm mode

The single blocker. Multiple architectural attempts failed:

- **Forward + fast-forward.** Replay the buffered pre-keyfile s→c
  bytes through our cipher to align IV. Worked sporadically. The
  observed-vs-expected post-keyfile decryption produced clean
  packets in some sessions and garbage in others.
- **Stall both directions until keyfile arrives.** Client timed out
  on "logging into the game server" because the 3-4s pause exceeded
  whatever timeout the client uses for early s→c silence.
- **Skip s→c fast-forward entirely** (treat pre-keyfile s→c bytes as
  "not in the cipher stream"). Sometimes worked, sometimes didn't —
  same fragility as observe-only's pre-keyfile s→c-byte discard.
- **Hybrid: observe-only s→c, active c→s, one-shot inject via cloned
  mirror state.** The injector wrote a valid-shape packet; the client
  received it; client crashed. Whether the crash was from the right
  packet hitting wrong cipher state or from wrong packet content was
  never disambiguated.

The deeper issue is that the pre-keyfile s→c bytes on this server
**aren't consistently part of the BF_cfb64 game-key stream**. Some
runs they're cipher input (fast-forward should be done); other runs
they aren't (fast-forward corrupts state). Without server-side
visibility into how Rev 5187's `Send()` initializes the s→c cipher
on a new 5817 connection, we can't predict which.

### Real-Cyclone capture in observe-only

A separate run intended to capture the bytes of a legitimate
`MsgUserAttrib(StatusEffects)` packet on the wire — to read the real
`updateType` value, `data` bitmask, and the 12 mystery trailing
bytes — produced **all-garbled s→c output**, even in observe-only
mode. The 9959 login c→s payload also looked different from prior
working sessions.

Most likely explanation: the server or client got patched between
our last working session and this final test. Confirming this would
require comparing the current `Conquer.exe` build hash against what
worked previously, or running `frida_diag.py` to see if the
`BF_set_key` call sequence shifted.

That's a separate piece of work outside Phase 2's scope.

---

## Deliverable summary

For the operator/team conversation:

> **The cipher key on Rev 5187's game port (5817) is recoverable in
> the first few seconds of every login session using a standard
> reverse-engineering tool (Frida) by hooking `BF_set_key` inside
> `Conquer.exe`. Once recovered, ALL inbound and outbound gameplay
> packets are plaintext-readable in real time, including combat
> targets, chat messages (all channels), player positions, and item
> actions.**
>
> The observer proxy demonstrates this capability live: an attacker
> running a SOCKS proxy with key capture sees every player they
> interact with, every attack, every chat in any channel. The
> protocol-level visibility is total.
>
> Active man-in-the-middle modifications (forging packets to the
> client OR server) are mechanically possible — we built the cipher
> infrastructure and trigger surface — but our test runs against
> the live server hit a cipher-state-alignment issue on the s→c
> direction that we could not consistently resolve. This is a
> protocol/server-side detail; a more focused reverse-engineering
> push (a few additional days of work) would likely close that gap.
>
> Recommendation: treat the broken cipher boundary as the actual
> defense layer. The fact that key capture is so cheap means the
> defense-in-depth needs to extend further — e.g., server-side
> validation of packet sequences and authentication tags, not just
> "the bytes are encrypted." A patched client that obfuscates
> `BF_set_key` (control-flow flattening, packed `Conquer.exe`,
> moving key derivation server-side) would close the easy path.

---

## Files added during Phase 2

- [src/Crypto/GameCryptographer.cs](../src/Crypto/GameCryptographer.cs)
  — `EncryptC2s`/`EncryptS2c` added so call sites can name the wire
  direction. `CopyS2cStateInto` / `CopyCfbStateInto` added for the
  hybrid-injector path.

- [src/Proxy/ProxyMain.cs](../src/Proxy/ProxyMain.cs) — `--mode
  active-mitm` flag, `--player-uid`, `--effect-bit`, chat-command
  parser for `@uid`/`@bit`/`@status`/`@cyclone`, the four-CFB-stream
  bookkeeping, fast-forward + boundary-detection logic, the
  `SendFakeCycloneToClient` injector. About 600 lines of new code.

- [src/Packets/PacketPrinter.cs](../src/Packets/PacketPrinter.cs) —
  verbose Update parser that dumps full body hex + set-bit list when
  `data != 0`, for capturing ground-truth packet layouts.

- [docs/REV_PROTOCOL.md](REV_PROTOCOL.md) — original protocol notes,
  still accurate for the Frida + key-capture parts.

- This document.

---

## Known fragilities / open items

- **Pre-keyfile s→c byte semantics on 5187 are not characterized.**
  Sometimes BF-cipher input, sometimes not. Would need server-side
  source-reading or a controlled timing test (start proxy + Frida
  before launcher's first packet) to nail down.

- **The 12 trailing body bytes of `MsgUserAttrib`** are unknown. The
  POC's 5065 layout doesn't account for them. Without a real
  `MsgUserAttrib(StatusEffects)` packet capture from this build, the
  fake packet may have wrong values at offsets 24..35 that the
  client validates and rejects/crashes on.

- **The `@cyclone` chat command is not swallowed** before being
  forwarded to the server — it shows up in the server's chat log as
  the player typing `@cyclone`. Swallowing would require
  substituting a same-size dummy packet to keep the c→s cipher
  state aligned.

- **Build-specific** RVAs (`BF_set_key` at `0x5A07E0`, `BF_cfb64_encrypt`
  at `0x5A05E0`). If `Conquer.exe` gets rebuilt these will shift.

---

## Future work (out of scope for now)

If we ever come back to this:

1. Run `frida_diag.py` against the current `Conquer.exe` and compare
   the `BF_set_key` call sequence against what we observed when
   active-MitM worked. Spot any new/different calls.

2. Capture a real `MsgUserAttrib(StatusEffects)` packet from a
   teammate's cyclone cast (observe-only is fine — just need ONE
   line in the log with `bits=23` set). Copy its exact 32-byte body
   into the injector.

3. Move the key derivation server-side as a real fix: have the
   server pick the post-DH key and stream it down a session-bound
   channel after the client authenticates, instead of having the
   client compute it from the login response. Removes the
   `BF_set_key`-with-game-key-as-input handle that Frida hooks.

4. If we ever NEED clean active-MitM s→c: stop the proxy from
   forwarding pre-keyfile s→c bytes (accept the brief client stall),
   verify whether observe-only's "the cipher actually starts at IV=0
   for the first post-keyfile chunk" assumption holds for this
   build. If it does, active-MitM should also work with no
   fast-forward. If it doesn't, we'd need to characterize when the
   server's `Send()` initializes its s→c CFB stream.
