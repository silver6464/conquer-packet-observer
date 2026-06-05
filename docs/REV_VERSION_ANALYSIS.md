# Rev Server Version Analysis

What patch level is "Rev 5187" actually running? Triangulating from observed
wire packets against the conquer-online wiki packet docs.

## TL;DR

**Rev "5187" is a Frankenstein build with a patch 5165 base** and selective
backports from later patches. Each packet family is independently at its own
patch level. The "5187" version number ≈ "patch 5165 + ~22 internal revs"
fits this picture.

## Per-packet matches

Comparison method: take the observed wire `sz` for each packet type, subtract
header (4) + trailer (8) to get body length, find the wiki patch whose
documented body length matches exactly.

| Packet | Observed wire sz | Body length | Matching wiki patch |
|---|---|---|---|
| MsgConnect (1052) | 36 | 24 | **patch 5615** (build version + lang + mac fields) |
| MsgUserInfo (1006) | 114 | 102 | **patch 5165** (87 + name strings) ✓ exact |
| MsgInteract (1022) | 40 | 28 | **patch 5017** (our existing InteractPacket struct) |
| MsgAction (10010, LONG) | 40 | 28 | **patch 5165** body size, with character ID at offset 4 instead of offset 8 |
| MsgAction (10010, SHORT) | 36 | 24 | empirical — Rev's server-ack form |
| MsgWalk (10005) | 24 | 12 | wiki patch 5517 stripped (dir/uid/ts only; drops movementType + mapId) |
| MsgUserAttrib (10017) | 44 | 32 | **patch 5672** (3 value fields: v1:u64 v2:u64 v3:u32) ✓ exact |
| MsgPlayer (10014) | 154 | 142 | between patch 5103 and 5672 — no exact wiki match |

## Reading

- **The strongest single signal** is `MsgUserInfo` at patch 5165 — that
  packet's body size formula `87 + name strings` produces 106 exactly when
  the character name is 8 chars plus a 10-char spouse field, matching the
  on-wire `length=106` we observed for player "dandruff". The 5165 patch
  number also lines up tightly with the version string "5187".

- **MsgConnect at patch 5615** is unambiguous (the `build:u16` + 2-char
  language code + 6-byte MAC layout is unique to 5615+).

- **MsgUserAttrib at patch 5672** is also unambiguous (the 3-value-field
  body is 5672-specific; 5103 had a 2-value body of different sizes).

- **MsgPlayer's body length (142)** falls in a no-man's-land — the wiki has
  patch 5103 with `100 + strings` and patch 5672 with `232 + strings`.
  Rev's 142 ≈ 5103 + 42 bytes of additional fields, suggesting a custom
  intermediate build.

## What this means for the observer

The `Layout` field in [src/Packets/PacketTypes.cs](../src/Packets/PacketTypes.cs)
tags each packet with the wiki patch its body shape best matches. Parsers
in [src/Packets/PacketPrinter.cs](../src/Packets/PacketPrinter.cs) follow
those layouts. When the wire shape doesn't match any wiki patch exactly
(MsgPlayer, MsgWalk), the Layout tag says `"rev"` and the parser surfaces
the closest interpretable fields without claiming more precision than we
have.

If Rev ever changes their server build, expect the per-packet patch levels
to drift independently. New unknowns get flagged as `Unknown#N`; cross-
reference the wiki by body size to figure out which patch they came from
(or whether they're Rev-custom).

## Open questions

- Does Rev's launcher version string ("5187") encode the base patch
  number directly, or is it the operator's internal release tag?
- The MsgAction layout has Character ID at body offset 0 (patch 5615
  style) but the body size is from patch 5165. Did Rev backport just the
  field re-ordering? Or is this an older patch we don't have a wiki page
  for?
- The MsgPlayer 142-byte body is the most interesting one to fully
  reverse — knowing every field would let us decode every player spawn
  with full equipment, location, status flags, etc. The wiki's patch
  5672 layout is the closest reference but with extra fields removed.
