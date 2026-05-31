# Reverse-engineering Revelation Conquer's wire protection

This document records a successful reverse-engineering of the encryption layer
used by the Revelation Conquer private server (referred to throughout as
**"Rev"**, hosted at `139.99.125.223`). The investigation started from zero
knowledge of their crypto and ended with a working decryptor for the pre-DH
game-port handshake.

It was conducted on a legitimately-registered account, on the operator's own
sessions, with the goal of understanding Rev's protection scheme so the
operator can apply equivalent defenses to their own Conquer 5065-derived
server (Redux). It is not an offensive guide. Decryption is observation; we
never injected into Rev's live server.

---

## TL;DR

Rev uses the **same wire protocol as Conquer 5065** with three modifications:

1. The static pre-DH Blowfish key is still `DR654dt34trg4UI6` — same ASCII
   string as 5065 ships with. **That is a decoy.**
2. The Blowfish algorithm itself is patched in their client binary. With the
   same key, stock OpenSSL Blowfish produces a different key schedule than
   Rev's Conquer.exe does. Any off-the-shelf Blowfish implementation fails to
   decrypt the stream even though the "key" is public.
3. The Diffie-Hellman prime `P` used during the post-handshake session-key
   exchange is different from 5065's (which is itself a widely-known constant).

These three together mean Rev's traffic cannot be decrypted by anyone running
unmodified OpenSSL or porting the 5065 source — you need their exact algorithm.
This is *security by algorithmic obscurity*, not security by key length. It
works against casual attackers (memory dumps and key extraction reveal a decoy
that doesn't decrypt anything) until somebody hooks the running client and
calls Rev's modified cipher as a black box. Which is what we did.

The whole investigation took roughly one extended session and produced four
Python/Frida tools that live in [`tools/`](../tools/). The main artifact is
`frida_bf_rpc_decrypt.py`, which decrypts captured Rev `s2c.bin` traffic by
RPC-calling the real `BF_encrypt` function inside a running Conquer.exe.

---

## The protection scheme, in detail

### Wire framing (same as 5065)

The pre-DH server hello on game port 5817 is a `[len][type][body]` TQ
protocol packet, Blowfish-CFB-64 encrypted with a static key. The plaintext
layout, byte-for-byte from a real decrypted Rev hello:

```
offset
0x000  12 bytes random pad                  ← Rev pads with 12; 5065 pads with 11
0x00c  uint32 size_field
0x010  uint32 junk_length (= 9)             ← then 9 junk bytes
0x01b  ... 14 bytes IVs (length-prefixed) ...
0x039  uint32 P_length (= 128)
0x03d  128 ASCII hex chars: the DH prime P  ← Rev's custom P
0x0bd  uint32 G_length (= 2)
0x0c1  "05"                                 ← G = 5 (same as 5065)
0x0c4  uint32 pubkey_length (= 128)
0x0c8  128 ASCII hex chars: server pubkey
0x148  "TQServer"                           ← 8-byte trailer (same as 5065)
```

Total length: 330 bytes encrypted.

### Cipher (modified Blowfish)

OpenSSL 0.9.8g is statically linked into Rev's Conquer.exe. We confirmed by
strings: `OPENSSL_VERSION_TEXT = "OpenSSL 0.9.8g 19 Oct 2007"`. The cipher
mode is byte-CFB-64 (`BF_cfb64_encrypt`) with zero IV at session start.

What is **not** stock: when `BF_set_key` is called with key
`DR654dt34trg4UI6`, the resulting Blowfish key schedule does not match what
any reference implementation produces.

| | Canonical OpenSSL with DR654 | Rev Conquer.exe with DR654 |
|---|---|---|
| P[0] | `0xc2b12f9f` | `0x2d628eae` |
| P[1] | `0x31625a36` | `0xc173ed1c` |
| S[0][0] | (depends on impl) | `0xb42ed573` |
| BF_encrypt(0, 0) | `0xc132fb2e 0x59c1b542` | `0x8fe34bbb 0xa8b61810` |

We did not isolate exactly which step is patched (initial constants? Feistel
F-function? round count?), because we didn't need to — once we identified
that `BF_encrypt` itself can be called via Frida as a remote oracle, we have
a working decryptor without ever knowing what the round function does
internally. Reverse-engineering the precise modification would be a Ghidra
session; the document at the end lists this as a remaining open task.

### Custom Diffie-Hellman prime

5065's source ships this DH prime (in `Redux/Cryptography/BlowfishExchange.cs`):

```
E7A69EBDF105F2A6BBDEAD7E798F76A209AD73FB466431E2E7352ED262F8C558
F10BEFEA977DE9E21DCEE9B04D245F300ECCBBA03E72630556D011023F9E857F
```

Rev replaced it with:

```
A320A85EDD79171C341459E94807D71D39BB3B3F3B5161CA84894F3AC3FC7FEC
317A2DDEC83B66D30C29261C6492643061AECFCF4A051816D7C359A6A7B7D8FB
```

Same size (512 bits) and same generator G=5. From a cryptographic point of
view this changes nothing — DH is parameterised over P and G and works for
any safe prime — but it does mean a client built against 5065's hardcoded
constants will fail the handshake.

---

## How we got here

The investigation took several false starts before landing on the working
approach. Each is documented here so the next person doesn't repeat them.

### Things we tried that did not work

**1. Memory dump scanning.** We took a process dump of Conquer.exe with
Process Hacker (340 MB) and scanned for high-entropy 16-byte ASCII strings,
guessing the active key would be there. Found two copies of the decoy
`DR654dt34trg4UI6` (one in the on-disk file mapping, one in the loaded
image) and one promising candidate, `&*k|16tm8@yZ6>wM`, that appeared at
two distinct offsets with identical surrounding bytes. The candidate turned
out to be a fragment of a different lookup table — coincidentally
printable. No actual key was extracted this way.

**2. Cipher mode brute-force.** Assuming DR654 was the real key but the
cipher mode was different, we tried every variation: CFB-64 with segment
sizes 8/16/32/64, CBC, ECB, OFB, with IVs of all-zero, all-FF, key-prefix,
key-suffix, and various key permutations (reversed bytes, XOR-with-0xFF).
None decrypted. In hindsight: the key schedule itself was wrong, so no
amount of mode-shuffling at the cipher boundary could fix it.

**3. TQ-Cipher (pre-Blowfish XOR-counter cipher).** Comet 5187 reference
shows older versions used a static-IV XOR cipher before Blowfish. Tried
applying it (with and without subsequent Blowfish). No match.

**4. Known-plaintext slide search.** We knew the plaintext should contain
the DH prime as 128 ASCII hex bytes somewhere. We slid the standard 5065
prime across every offset in the ciphertext, XORed to derive the implied
keystream, and looked for randomness. Inconclusive — partly because Rev
uses a *different* prime than the one we were searching for, partly
because random-looking implied-keystreams could fit at many positions
without proving correct alignment.

**5. Reading the `BF_set_key` body in the disassembly.** Roughly an hour of
manual x86 reading produced a perfectly normal-looking `BF_set_key` that
copied the standard pi-digit P-array constants, did the standard cyclic
key-byte XOR step, and called what looked like a stock Feistel
`BF_encrypt` 521 times to scramble P and S. Yet the result didn't match
stock OpenSSL. Conclusion: the patch is hidden inside one of the steps in
a way that doesn't stand out at human-disassembly granularity. Continuing
this path would mean a full Ghidra decompile.

### What worked: Frida hooks

The breakthrough was switching from "guess the algorithm" to "make the
algorithm tell us its inputs and outputs".

**Step 1: Find `BF_set_key` by xref.** The Blowfish P-init table
(`0x243F6A88, 0x85A308D3, ...`) is a unique compile-time constant. We
searched Conquer.exe for those bytes — exactly one copy, at virtual
address `0x006242A8`. Then searched `.text` for any instruction that
references that address — exactly one, at VA `0x005A07F6` (`mov esi,
0x006242A8`). The enclosing function (the only function that reads the
P-init table) is `BF_set_key`, prologue at VA `0x005A07E0`.

**Step 2: Find `BF_cfb64_encrypt` by xref-after-BF_set_key.** Two
consecutive `call` instructions after each `BF_set_key` call site go to
the same target, VA `0x005A05E0`. By cdecl arg order and the surrounding
push pattern, that's `BF_cfb64_encrypt(in, out, length, schedule, ivec,
num, enc)`.

**Step 3: Find `BF_encrypt` (the inner Feistel) by xref-from-BF_set_key.**
`BF_set_key`'s scramble loop calls one function 521 times. That function
is at VA `0x005AA390` and is `BF_encrypt`.

**Step 4: Hook all three with Frida and learn the algorithm by black-box
oracle.** Confirmed: the BF_KEY struct populated by `BF_set_key(DR654)` is
deterministic across runs but differs from stock. Confirmed: given an
identical BF_KEY, calling `BF_encrypt` in our Python with a textbook
16-round Feistel does not match what Conquer's `BF_encrypt` returns. The
algorithm is patched.

**Step 5: Frida RPC oracle.** Rather than reverse the patch, we exposed
Conquer's real `BF_encrypt` as a callable function over Frida RPC. Python
loads a captured BF_KEY into the live Conquer process, then implements
CFB-64 by calling out to Conquer for every 8-byte block. Verified against
a known plaintext-ciphertext pair captured from the same client session.

That gave a working decryptor. We then decrypted a captured 330-byte Rev
server hello and read the protocol structure.

---

## Located inside Conquer.exe

Image base `0x00400000`. All addresses are virtual.

| Item | VA | Notes |
|---|---|---|
| `BF_set_key`        | `0x005A07E0` | x86 cdecl, signature `(BF_KEY*, int, const unsigned char*)` |
| `BF_cfb64_encrypt`  | `0x005A05E0` | 7-arg cdecl, OpenSSL-shape signature |
| `BF_encrypt`        | `0x005AA390` | inner Feistel, takes `(data*, key*)` |
| Blowfish P-init table | `0x006242A8` | standard pi-digit constants in `.rdata` |
| `"DR654dt34trg4UI6"` string | `0x006235D4` | decoy key, in `.rdata` |
| OpenSSL version string | various | `OpenSSL 0.9.8g 19 Oct 2007` |
| Anti-cheat exfil string | live encrypted | `<accountId>||1||Edit Memory Conquer.exe` |

That last entry is interesting: when Frida is attached, the client *itself*
sends an encrypted packet to the server's anti-cheat channel containing the
literal string `Edit Memory Conquer.exe`. The server then disconnects the
client. So SecurePlay's tamper-detect logic runs on the client side and
reports findings via the normal authenticated game socket. Useful pattern
to know about, both as an attacker (it's why a long Frida session gets
booted) and as a defender (we can mirror this in our own server).

---

## Tools we built

All in `proj/conquer-rev-observer/tools/`.

### `frida_bf_setkey_hook.py`

Hooks `BF_set_key`, `BF_cfb64_encrypt`, and `BF_encrypt` in a running
Conquer.exe and prints diagnostic information about each call:

- For `BF_set_key`: the raw key bytes, the resulting `BF_KEY` struct
  contents (P-array and S-boxes), and a hex dump of the full 4168-byte
  schedule.
- For `BF_cfb64_encrypt`: input/output buffers, IV, `num` register, and
  encrypt/decrypt direction.
- For `BF_encrypt`: 8-byte in and out (for black-box oracle work).

Use this when you want to *observe* the cipher state, not decrypt. It's how
we discovered everything in the previous section.

### `frida_bf_rpc_decrypt.py`

The actual decryptor. Attaches to a running Conquer.exe, exposes Conquer's
`BF_encrypt` as a Python-callable function via Frida RPC, and implements
the standard OpenSSL CFB-64 algorithm in Python around that oracle. A
4168-byte `BF_KEY` schedule corresponding to `BF_set_key(DR654...)` is
hard-coded in the script, so you don't need Frida to dump a fresh one each
time — any running Rev Conquer.exe will do, because the schedule for that
key is deterministic and identical across launches.

Self-tests on startup using two captured `(in, out)` pairs. If the
self-test passes, the decrypt of captured `s2c.bin` traffic will work too.

### `frida_bf_rpc_verify.py`

Small standalone sanity-check tool. Imports the CFB-64 wrapper from
`frida_bf_rpc_decrypt.py`, runs it against a hard-coded 15-byte ciphertext
that we know from Frida produces a specific 12-byte plaintext, and prints
match/mismatch. Useful when modifying the CFB framing or wanting to confirm
the whole RPC pipeline is healthy without running a full decrypt.

### `frida_packet_reader.py`

Read-only live packet decoder. Hooks `BF_cfb64_encrypt` and logs both
incoming (`s2c`) and outgoing (`c2s`) plaintext. Parses each buffer by the
standard TQ `[len][type][body]` header and looks up the packet-type ID in
a table extracted from the 5065 source filenames. Pretty-prints chat,
walk, spawn, interact, and a handful of other known types.

This is the tool that observes "you can read packets" without doing any
MitM or modification. It hooks the client's own cipher and reads what the
client is already decrypting. Note: SecurePlay will likely flag the Frida
attach within a minute, causing a disconnect, so sessions are short.

---

## Reproducing the decrypt

Prerequisites:
- A Windows machine with Conquer.exe (Rev's client) installed
- Python 3 on Windows with `frida-tools` installed (`pip install frida-tools`)
- The four scripts from `tools/` copied to that machine
- A capture of `s2c.bin` from a Rev 5817 session (collected via the SOCKS5
  observer that lives at the root of this repo)

Steps:

1. Launch Conquer.exe via Rev's launcher. Connect to a game (so the game-port
   `BF_set_key` has actually run with `DR654`). It's fine to be sitting at
   the login screen — what matters is that the BF_KEY struct exists in
   memory, which happens immediately on the first game-port connect.

2. Get the PID. Process Hacker or `tasklist` works.

3. Sanity check the pipeline:
   ```
   python frida_bf_rpc_verify.py <PID>
   ```
   Expect two `MATCH: True` lines. If either fails, the script's hard-coded
   `BFKEY_HEX` constant is out of date (shouldn't happen — the schedule for
   DR654 is deterministic).

4. Decrypt a captured `s2c.bin`:
   ```
   python frida_bf_rpc_decrypt.py <PID> s2c.bin 512
   ```
   First 330 bytes will be the server hello, structured as described at the
   top of this document. Bytes past the hello are encrypted under the
   DH-derived session key (not DR654), so they'll look like noise — that's
   expected.

5. To watch packets live during play instead of from a capture:
   ```
   python frida_packet_reader.py <PID>
   ```
   Then move your character, chat, interact, etc., and watch decoded
   packets stream to stdout. You'll have roughly 30-90 seconds before
   SecurePlay disconnects you.

---

## Anti-cheat observations

Some incidental findings about Rev's anti-cheat layer (`SecurePlay.dll` /
`AnticheatLibrary.dll`), worth documenting because they inform our own
server's defense design.

- **Tamper detection is client-side.** The DLL scans Conquer.exe's loaded
  image for unexpected modifications (Frida's inline hooks, debugger
  breakpoint instructions, etc.). When it finds one, it reports the finding
  to the server via the normal authenticated game socket — we see this as
  an encrypted packet with payload `<accountId>||1||Edit Memory Conquer.exe`.

- **Periodic heartbeat.** A separate channel on port 9528 sends a heartbeat
  every ~54 seconds during play. We did not fully reverse the heartbeat
  format. What we did confirm: it's not a one-time check; it runs for the
  duration of the session, so simply bypassing it at startup is
  insufficient.

- **Detection-to-disconnect latency.** Empirically, ~30-90 seconds between
  Frida attach and server-initiated disconnect, with `Edit Memory` events
  appearing in the stream shortly before the kick.

- **`SecurePlay.dll` is debug-build.** It imports `MSVCP100D.dll` and
  `MSVCR100D.dll`, which are the *debug* C++ runtime — an oversight on
  Rev's part. We did not exploit it.

- **No server-side anti-cheat handshake.** The DLL ships with no hard-coded
  IPs, no cert pinning, and no symmetric secrets. All its decisions are
  local; the only network channel is the reporting back to the game server.

---

## Implications for designing Redux 5065 protection

The original motivation: take what we learned and apply equivalent
protection to our own Redux 5065 server. Concretely:

**1. Keep the public key as a decoy.** Leave `Common.ENCRYPTION_KEY =
"DR654dt34trg4UI6"` exactly as it is in the source. The string in `.rdata`
becomes a honeypot for casual attackers — anyone who finds it and tries to
use it with a stock Blowfish library gets garbage.

**2. Modify Blowfish in `Redux/Cryptography/GameCryptographer.cs`.** Options
ranked by reversal difficulty:

- **Round count.** Change 16 rounds to 15 or 17. One-line change. Any
  attacker with a textbook Blowfish gets noise. Easy to reverse from a
  binary (round count is countable in the disassembly).

- **Round count + extra constant XOR per round.** Same one-line change
  plus an extra XOR with a session-derived constant inside each round.
  Slightly harder to reverse — the attacker now has to identify the
  extra operation in the round body.

- **Permuted S-box order in the F-function.** Change
  `((S0[a]+S1[b])^S2[c])+S3[d]` to e.g.
  `((S1[a]+S0[b])^S3[c])+S2[d]` or any other arrangement. The compiled
  code looks normal at the assembly level (just different `mov`
  offsets), which is why our manual disassembly of Rev's BF_encrypt
  missed the change — the F-function call shape is identical.

- **Different P-init / S-box init constants.** Replace the 18+1024
  pi-digit constants with another deterministic stream. Most
  reversal-resistant: the attacker who finds your `BF_set_key` xref
  sees a non-standard constant table and has to figure out the
  generation rule.

**3. Different DH prime.** Pick any 512-bit safe prime that isn't 5065's
default and burn it in. Costs nothing, breaks anyone who copies the 5065
source.

**4. Optional: client-side memory integrity check + reporting channel.**
Mirror Rev's anti-cheat pattern. Have the client periodically hash its own
loaded image and ship the hash to the server inside an encrypted packet.
Doesn't stop a determined reverse-engineer (the check itself can be
patched out) but it filters out lazy attackers and gives you a server-side
log of who is tampering.

**5. Document the modification privately.** Keep one trusted internal
record of what you actually changed and why. Don't rely on memory or on
"the code is the doc" — when you need to ship a new client build or fix a
bug, knowing exactly what's modified saves hours.

---

## Open questions / future work

- **Exact identification of the Blowfish modification in BF_encrypt.** A
  Ghidra session on Conquer.exe at VA `0x005AA390` would tell us. Not
  required for any current use — the Frida RPC oracle works around it —
  but it would let us write a standalone (Frida-free) decryptor in Python.

- **Post-DH session-key decryption.** Currently we can decrypt the pre-DH
  330-byte server hello. Once DH completes, the cipher re-keys with the
  derived shared secret and our DR654 BF_KEY no longer applies. A full
  MitM in the observer proxy could intercept both DH exchanges, derive the
  same shared secret on both sides, and decrypt the entire session.
  Possible but a substantial extension.

- **Anti-cheat heartbeat format on port 9528.** The traffic shape (32-byte
  ASCII hex tokens with `"true"` replies) was observed during early proxy
  passes but the validation algorithm wasn't recovered. We could either
  reverse-engineer this fully or let it alone — it's a separate channel
  from the game socket and doesn't matter for game-packet research.

---

## A note on ethics

This document exists because the operator wanted to understand a private
server's protection in order to build equivalent protection for their own
server. The investigation was conducted on the operator's own legitimately
registered account, in their own sessions, and never modified any traffic
sent to Rev's servers. Everything described here is observation-only.

The cyclone / hare / aimbot proof-of-concept work referenced in earlier
project history was done against the operator's own Redux 5065 server
running in their own environment, not against Rev. That distinction stays.
This document is for understanding protection, not for circumventing it on
someone else's live system.
