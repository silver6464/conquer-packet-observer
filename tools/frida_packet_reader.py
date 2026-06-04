"""
Read packets in real time from Rev Conquer (139.99.125.223:5817) by hooking
BF_cfb64_encrypt inside Conquer.exe. Both the pre-DH and post-DH cipher states
are visible to this hook — we just observe what the running client encrypts /
decrypts.

Read-only. NOT a MitM, NOT an injection tool — we observe the user's own
legitimate game traffic via the client's own cipher routines.

Parsing follows the standard 5065 TQ-protocol header:
  [len:u16 LE][type:u16 LE][body ...][trailer 'TQServer' or 'TQClient']

Known packet types are taken from the 5065 source filenames; unknowns are
displayed by id with a hex dump.

Usage on Windows:
    python frida_packet_reader.py <Conquer.exe PID>
    (then play the game, packets stream to stdout)
"""
import sys
import time
import frida

BF_CFB64_ENCRYPT_RVA   = 0x005A05E0 - 0x00400000   # 0x1A05E0
CCIPHER_ENCRYPT_RVA    = 0x00588A9E - 0x00400000   # 0x188A9E  CCipher::Encrypt(in, out, len)
CCIPHER_DECRYPT_RVA    = 0x00588AE4 - 0x00400000   # 0x188AE4  CCipher::Decrypt(in, out, len)

# Anti-cheat report markers — when these substrings appear in a plaintext
# buffer, it's almost certainly a SecurePlay/AnticheatLibrary tamper report.
# Highlighted in the output so they're easy to spot in busy traffic.
AC_REPORT_MARKERS = (
    b"Edit Memory",
    b"Conquer.exe",
    b"||1||",
    b"||2||",
    b"||3||",
)

# Packet-type table sourced from proj/conquer-redux-5065/Redux/Packets/{Game,Login}/
# filenames. Type IDs are the bracketed prefixes.
PACKET_TYPES = {
    1001: "Register",            1004: "Talk",              1005: "Walk",
    1006: "HeroInformation",     1008: "ItemInformation",   1009: "ItemAction",
    1010: "GeneralData",         1014: "SpawnEntity",       1015: "Strings",
    1017: "Update",              1019: "Associate",         1022: "Interact",
    1023: "TeamInteraction",     1024: "AssignAttributes",  1025: "WeaponProf",
    1026: "TeamMemberInfo",      1027: "SocketGem",         1033: "ServerTime",
    1052: "Connect",             1055: "AuthResponse",      1056: "PasswordSeed",
    1058: "GuildDonation",       1086: "Account",           1100: "MacAddress",
    1101: "GroundItem",          1102: "Warehouse",         1103: "ConquerSkill",
    1105: "SkillEffect",         1106: "GuildAttrInfo",     1107: "Guild",
    1108: "VendorItem",          1109: "SobSpawn",          1110: "MapStatus",
    1112: "GuildMemberInfo",
    2030: "SpawnNpc",            2031: "Npc",               2032: "NpcDialog",
    2033: "AssociateInformation",2036: "Compose",           2043: "OfflineTGInfo",
    2044: "OfflineTG",           2050: "Broadcast",         2064: "Nobility",
    2065: "MentorAction",        2066: "MentorInformation", 2067: "MentorPrize",
}

CHAT_TYPES = {
    2000: "Talk",        2001: "Whisper",     2002: "Action",
    2003: "Team",        2004: "Guild",       2005: "Local",
    2006: "Service",     2007: "Ghost",       2008: "Spouse",
    2009: "System",      2011: "Yell",        2012: "Friend",
    2014: "Center",      2015: "TopLeft",     2105: "EnterMap",
    2104: "Broadcast",
    2102: "Dialog",      2101: "Trade",
}

# Walking directions per Common.cs in 5065
DIRECTION_NAMES = ["N", "NW", "W", "SW", "S", "SE", "E", "NE", "Stay"]

JS = r"""
'use strict';
(function () {

const BF_CFB64_ENCRYPT_RVA = ptr(""" + hex(BF_CFB64_ENCRYPT_RVA) + r""");
const CCIPHER_ENCRYPT_RVA  = ptr(""" + hex(CCIPHER_ENCRYPT_RVA)  + r""");
const CCIPHER_DECRYPT_RVA  = ptr(""" + hex(CCIPHER_DECRYPT_RVA)  + r""");

const conquer = Process.findModuleByName('Conquer.exe');
if (!conquer) {
    console.error('[!] Conquer.exe not loaded');
} else {
    const cfb     = conquer.base.add(BF_CFB64_ENCRYPT_RVA);
    const ccEnc   = conquer.base.add(CCIPHER_ENCRYPT_RVA);
    const ccDec   = conquer.base.add(CCIPHER_DECRYPT_RVA);
    console.log('[+] Hooking BF_cfb64_encrypt   at ' + cfb);
    console.log('[+] Hooking CCipher::Encrypt   at ' + ccEnc);
    console.log('[+] Hooking CCipher::Decrypt   at ' + ccDec);

    // --- Low-level: BF_cfb64_encrypt (raw cipher boundary) -------------
    // We tag each call by:
    //   - enc=0 means decrypt (server -> client) — incoming traffic
    //   - enc=1 means encrypt (client -> server) — outgoing traffic
    // The PLAINTEXT we want is the buffer that's plaintext at this point:
    //   enc=0: out buffer (after decrypt) — read in onLeave
    //   enc=1: in buffer  (before encrypt) — read in onEnter
    Interceptor.attach(cfb, {
        onEnter: function (args) {
            this.inbuf  = args[0];
            this.outbuf = args[1];
            this.length = args[2].toInt32();
            this.enc    = args[6].toInt32();
            if (this.length <= 0 || this.length > 65536) { this.skip = true; return; }
            if (this.enc === 1) {
                // Outgoing — plaintext is the input.
                try {
                    const pt = this.inbuf.readByteArray(this.length);
                    send({ direction: 'c2s', length: this.length }, pt);
                } catch (e) {}
            }
        },
        onLeave: function (_retval) {
            if (this.skip) return;
            if (this.enc === 0) {
                // Incoming — plaintext is the output (post-decrypt).
                try {
                    const pt = this.outbuf.readByteArray(this.length);
                    send({ direction: 's2c', length: this.length }, pt);
                } catch (e) {}
            }
        }
    });

    // --- High-level: CCipher::Encrypt / Decrypt -------------------------
    // __thiscall: ECX = this; args on stack starting [esp+4]:
    //   args[0] = in buffer
    //   args[1] = out buffer
    //   args[2] = length
    //
    // Why this on top of BF_cfb64_encrypt:
    //   * CCipher::Encrypt is what SecurePlay.dll / AnticheatLibrary.dll call
    //     (cross-module) to ship a tamper report. The plaintext arrives here
    //     as one logical buffer.
    //   * BF_cfb64_encrypt may also be called for handshake/junk during DH
    //     setup, where the data isn't an application-level packet.
    //   * Tagging the source as 'ac' (anti-cheat / app-level send) lets the
    //     Python side highlight payloads that match report markers.
    Interceptor.attach(ccEnc, {
        onEnter: function (args) {
            // __thiscall on x86 MSVC: this=ECX, stack args from [esp+4]
            this.inbuf  = args[0];
            this.length = args[2].toInt32();
            if (this.length <= 0 || this.length > 65536) { this.skip = true; return; }
            try {
                const pt = this.inbuf.readByteArray(this.length);
                send({ direction: 'c2s', length: this.length, source: 'ccipher' }, pt);
            } catch (e) {}
        }
    });

    Interceptor.attach(ccDec, {
        onEnter: function (args) {
            this.outbuf = args[1];
            this.length = args[2].toInt32();
            if (this.length <= 0 || this.length > 65536) { this.skip = true; return; }
        },
        onLeave: function (_retval) {
            if (this.skip) return;
            try {
                const pt = this.outbuf.readByteArray(this.length);
                send({ direction: 's2c', length: this.length, source: 'ccipher' }, pt);
            } catch (e) {}
        }
    });

    console.log('[+] Packet reader installed. Play the game.');
}

})();
"""


def parse_netstrings(body: bytes, off: int):
    """NetStringPacker: [count:1][len:1][bytes]..."""
    out = []
    if off >= len(body):
        return out
    count = body[off]; off += 1
    for _ in range(count):
        if off >= len(body):
            break
        n = body[off]; off += 1
        if off + n > len(body):
            break
        out.append(body[off:off + n].decode("latin-1", errors="replace"))
        off += n
    return out


def parse_packet(plaintext: bytes):
    """Returns a dict describing one packet."""
    if len(plaintext) < 4:
        return None
    length = int.from_bytes(plaintext[0:2], "little")
    ptype  = int.from_bytes(plaintext[2:4], "little")
    body   = plaintext[4:length] if length <= len(plaintext) else plaintext[4:]
    return {
        "type_id": ptype,
        "type_name": PACKET_TYPES.get(ptype, f"Unknown#{ptype}"),
        "length": length,
        "body": body,
        "raw_len": len(plaintext),
    }


def pretty_packet(direction: str, pkt: dict) -> str:
    dirtag = "<--" if direction == "s2c" else "-->"
    head = f"{dirtag} [{pkt['type_name']:18s} #{pkt['type_id']:>4d}] len={pkt['length']}"
    body = pkt["body"]
    detail = ""
    tid = pkt["type_id"]

    if tid == 1004:  # Talk
        # color:u32, type:u32, time:u32, hearerLook:u32, speakerLook:u32, then strings
        if len(body) >= 20:
            chat_type = int.from_bytes(body[4:8], "little")
            chat_type_name = CHAT_TYPES.get(chat_type, f"chat#{chat_type}")
            strings = parse_netstrings(body, 20)
            speaker = strings[0] if len(strings) > 0 else ""
            hearer  = strings[1] if len(strings) > 1 else ""
            target  = strings[2] if len(strings) > 2 else ""
            message = strings[3] if len(strings) > 3 else ""
            detail = f"  {chat_type_name}  <{speaker}> -> <{hearer}>: {message!r}"

    elif tid == 1005:  # Walk
        if len(body) >= 8:
            uid = int.from_bytes(body[0:4], "little")
            dir_byte = body[4]
            mode = body[5]
            d = DIRECTION_NAMES[dir_byte % 9]
            detail = f"  uid={uid} dir={d}({dir_byte}) mode={mode}"

    elif tid == 1010:  # GeneralData / Action
        # subType:u32 at offset 0, uid:u32 at +4, params at +8...
        if len(body) >= 24:
            uid = int.from_bytes(body[20:24], "little")
            sub = int.from_bytes(body[18:20], "little")
            x = int.from_bytes(body[12:14], "little") if len(body) >= 14 else 0
            y = int.from_bytes(body[14:16], "little") if len(body) >= 16 else 0
            detail = f"  uid={uid} sub={sub} x={x} y={y}"

    elif tid == 1014:  # SpawnEntity — first 4 bytes after header is variable; just show first UID + name
        if len(body) >= 8:
            uid = int.from_bytes(body[0:4], "little")
            detail = f"  uid={uid}"

    elif tid == 1017:  # Update
        if len(body) >= 12:
            uid = int.from_bytes(body[4:8], "little")
            update_type = int.from_bytes(body[12:16], "little") if len(body) >= 16 else 0
            detail = f"  uid={uid} updateType={update_type}"

    elif tid == 1022:  # InteractPacket
        if len(body) >= 12:
            attacker = int.from_bytes(body[4:8], "little")
            target   = int.from_bytes(body[8:12], "little") if len(body) >= 12 else 0
            atype    = int.from_bytes(body[12:16], "little") if len(body) >= 16 else 0
            detail = f"  atk={attacker} tgt={target} type={atype}"

    elif tid == 1052:  # Connect
        if len(body) >= 12:
            account_id = int.from_bytes(body[4:8], "little")
            detail = f"  accountId={account_id}"

    elif tid == 1110:  # MapStatus
        if len(body) >= 8:
            map_id = int.from_bytes(body[4:8], "little")
            detail = f"  mapId={map_id}"

    # Fallback: brief hex of first 32 bytes
    if not detail:
        sample = body[:32]
        h = " ".join(f"{b:02x}" for b in sample)
        a = "".join(chr(b) if 32 <= b < 127 else "." for b in sample)
        detail = f"  body[:32]={h}  '{a}'"

    return head + detail


def split_into_packets(stream: bytes):
    """One BF_cfb64 call may contain several concatenated packets. Walk them
    by the length header until exhausted or a malformed entry is hit."""
    off = 0
    while off + 4 <= len(stream):
        length = int.from_bytes(stream[off:off + 2], "little")
        # Sanity: bogus length means we're misaligned (maybe at the TQServer
        # trailer or junk padding). Stop here.
        if length < 4 or length > 32 * 1024 or off + length > len(stream):
            break
        yield stream[off:off + length]
        off += length


def find_report_markers(buf: bytes):
    """Return a list of marker substrings present in `buf`."""
    return [m.decode("latin-1") for m in AC_REPORT_MARKERS if m in buf]


def hex_ascii_dump(buf: bytes, limit: int = 96) -> str:
    sample = buf[:limit]
    h = " ".join(f"{b:02x}" for b in sample)
    a = "".join(chr(b) if 32 <= b < 127 else "." for b in sample)
    suffix = f" ...(+{len(buf) - limit} more)" if len(buf) > limit else ""
    return f"hex={h}  ascii='{a}'{suffix}"


def main():
    if len(sys.argv) < 2:
        print("Usage: python frida_packet_reader.py <PID>")
        sys.exit(1)
    pid = int(sys.argv[1])
    session = frida.attach(pid)
    script = session.create_script(JS)

    # De-dup window: each plaintext buffer arrives from both BF_cfb64 and
    # CCipher hooks. Keep a tiny LRU of recent (direction, len, head16) keys.
    seen = []  # list of (key, timestamp)
    SEEN_TTL = 0.5  # seconds

    def is_dup(direction: str, payload: bytes) -> bool:
        key = (direction, len(payload), payload[:16])
        now = time.monotonic()
        # purge stale
        while seen and now - seen[0][1] > SEEN_TTL:
            seen.pop(0)
        for k, _ in seen:
            if k == key:
                return True
        seen.append((key, now))
        return False

    def on_message(msg, payload_bytes):
        if msg["type"] != "send":
            if msg["type"] == "error":
                print("[js ERROR]", msg["description"])
            return
        meta = msg["payload"]
        direction = meta["direction"]
        source    = meta.get("source", "bf")  # 'bf' (BF_cfb64) or 'ccipher'
        if not payload_bytes:
            return

        # Scan FULL plaintext for anti-cheat report markers before per-packet
        # parsing — the report may not parse as a clean TQ packet.
        markers = find_report_markers(payload_bytes)
        if markers:
            tag = "!! ANTI-CHEAT REPORT" if direction == "c2s" else "!! AC RESPONSE"
            print(f"\n{'*' * 72}")
            print(f"{tag}  [{source}]  dir={direction}  len={len(payload_bytes)}  "
                  f"markers={markers}")
            print(f"  {hex_ascii_dump(payload_bytes, 256)}")
            print(f"{'*' * 72}\n")
            # Don't suppress the normal packet parse path — but skip dedup so
            # this exact buffer doesn't get hidden if it also arrives via BF.
        else:
            if is_dup(direction, payload_bytes):
                return

        # The same buffer can hold multiple packets concatenated.
        for one in split_into_packets(payload_bytes):
            pkt = parse_packet(one)
            if pkt is None:
                continue
            src_tag = f"({source})" if source != "bf" else ""
            print(pretty_packet(direction, pkt) + (f"  {src_tag}" if src_tag else ""))

    script.on("message", on_message)
    script.load()
    print("[*] Packet reader running. Ctrl+C to stop.")
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    session.detach()


if __name__ == "__main__":
    main()
