using System;
using System.Text;
using ConquerPoc.Enum;
using ConquerPoc.Packets.Game;

namespace ConquerPoc.Packets
{
    /// <summary>
    /// Read-only packet pretty-printer. Takes a decrypted packet's bytes and
    /// emits a single-line human-readable description, dispatched by type ID.
    ///
    /// Per-type parsers are best-effort. Unknown or malformed bodies fall back
    /// to a hex dump of the first 32 bytes so we still see *something* useful
    /// in the log. 5517-renumbered packet types get a "?" in their label to
    /// flag that the body-shape assumption hasn't been fully verified.
    ///
    /// SCOPE: read-only. This class never builds a packet or modifies one.
    /// </summary>
    public static unsafe class PacketPrinter
    {
        // chat channels (5065's CHAT_TYPES). Names mostly carry over.
        private static readonly System.Collections.Generic.Dictionary<int, string> CHAT_CHANNEL = new System.Collections.Generic.Dictionary<int, string>
        {
            { 2000, "Talk" },     { 2001, "Whisper" },  { 2002, "Action" },
            { 2003, "Team" },     { 2004, "Guild" },    { 2005, "Local" },
            { 2006, "Service" },  { 2007, "Ghost" },    { 2008, "Spouse" },
            { 2009, "System" },   { 2011, "Yell" },     { 2012, "Friend" },
            { 2014, "Center" },   { 2015, "TopLeft" },
            { 2101, "Trade" },    { 2102, "Dialog" },   { 2104, "Broadcast" },
            { 2105, "EnterMap" },
        };

        private static readonly string[] DIRECTION_NAMES = { "N", "NW", "W", "SW", "S", "SE", "E", "NE", "Stay" };

        /// <summary>
        /// Format ONE packet (already extracted at <paramref name="offset"/>,
        /// <paramref name="total"/> bytes long) from <paramref name="chunk"/>.
        /// </summary>
        public static string Format(byte[] chunk, int offset, int total, ushort type)
        {
            string label = PacketTypes.Label(type);
            string body = TryParseBody(chunk, offset, total, type);
            if (body == null)
                body = HexBody(chunk, offset, total);
            return $"[{label,-22} #{type,5}] sz={total,4} {body}";
        }

        // Returns null if we don't have a per-type parser for this type;
        // caller falls back to hex.
        private static string TryParseBody(byte[] chunk, int off, int total, ushort type)
        {
            // Common header: 4 bytes (u16 length, u16 type). Body starts at off+4.
            // Total includes 8-byte trailer at the end ("TQServer" or "TQClient").
            int bodyStart = off + 4;
            int bodyLen = total - 4 - 8; // exclude header + trailer
            if (bodyLen < 0) return null;

            switch (type)
            {
                case 1004: return ParseTalk(chunk, bodyStart, bodyLen);
                case 1005: return ParseWalk5065(chunk, bodyStart, bodyLen);
                // 10005 Walk body layout on Rev 5517 is NOT the same as 5065
                // (5065 expected uid:u32 dir:u8 mode:u8 at body offset 0,
                // but Rev 5517 puts something else there — the values we
                // read as dir/mode are out of range). Parking parsing
                // until we figure out the real layout; fall through to hex.
                case 10005: return null;
                case 1010:
                case 10010: return ParseGeneralData(chunk, bodyStart, bodyLen);
                case 1014:
                case 10014: return ParseSpawnEntity(chunk, bodyStart, bodyLen);
                case 1017:
                case 10017: return ParseUpdate(chunk, bodyStart, bodyLen);
                case 1022: return ParseInteract(chunk, off, total);
                case 1033: return ParseServerTime(chunk, bodyStart, bodyLen);
                case 1052: return ParseConnect(chunk, bodyStart, bodyLen);
                case 1110: return ParseMapStatus(chunk, bodyStart, bodyLen);
                case 2685: return $"{{ ac-report, body={bodyLen}b }}";
            }
            return null;
        }

        // ---- per-type parsers ------------------------------------------------

        // MSG_TALK (1004): color:u32, type:u32, time:u32, hearerLook:u32, speakerLook:u32, then NetString list (count + len-prefixed entries)
        private static string ParseTalk(byte[] b, int off, int len)
        {
            if (len < 20) return null;
            int chatType = ReadI32(b, off + 4);
            string channel = CHAT_CHANNEL.TryGetValue(chatType, out var c) ? c : $"chat#{chatType}";
            var strings = ParseNetStrings(b, off + 20, len - 20);
            string speaker = strings.Length > 0 ? strings[0] : "";
            string hearer  = strings.Length > 1 ? strings[1] : "";
            string text    = strings.Length > 3 ? strings[3] : "";
            // For service/system/yell where there's no hearer, omit it
            return string.IsNullOrEmpty(hearer)
                ? $"{{ ch={channel} <{speaker}> {Q(text)} }}"
                : $"{{ ch={channel} <{speaker}>->{hearer} {Q(text)} }}";
        }

        // MSG_WALK (5065 #1005): uid:u32, dir:u8, mode:u8. Rev 5517's #10005
        // uses a different body layout — not parsed (see TryParseBody switch).
        private static string ParseWalk5065(byte[] b, int off, int len)
        {
            if (len < 6) return null;
            uint uid = ReadU32(b, off);
            byte dirByte = b[off + 4];
            byte mode = b[off + 5];
            string dir = dirByte < DIRECTION_NAMES.Length ? DIRECTION_NAMES[dirByte] : $"?{dirByte}";
            return $"{{ uid={uid} dir={dir} mode={mode} }}";
        }

        // MSG_ACTION/GeneralData (1010 / 10010): widely variable layout depending on action.
        // Common fields we can identify: uid at offset 4-7, action at offset 18-19, x/y often at 12-15.
        private static string ParseGeneralData(byte[] b, int off, int len)
        {
            if (len < 16) return null;
            uint uid = ReadU32(b, off + 4);
            ushort act = len >= 20 ? (ushort)ReadU16(b, off + 18) : (ushort)0;
            ushort x   = len >= 14 ? (ushort)ReadU16(b, off + 12) : (ushort)0;
            ushort y   = len >= 16 ? (ushort)ReadU16(b, off + 14) : (ushort)0;
            return $"{{ uid={uid} act={act} pos=({x},{y}) }}";
        }

        // MSG_SPAWN_ENTITY (1014 / 10014): big variable struct. Just show the head UID.
        private static string ParseSpawnEntity(byte[] b, int off, int len)
        {
            if (len < 4) return null;
            uint uid = ReadU32(b, off);
            return $"{{ uid={uid} body={len}b }}";
        }

        // MSG_UPDATE (1017 / 10017): uid:u32 at 4-7, count:u32 at 8-11,
        // updateType:u32 at 12-15, data:u64 at 16-23. Rev 5517 has 12 extra
        // bytes of body we don't yet understand — show their hex so we
        // can reverse-engineer the layout from observed packets.
        //
        // When data != 0 we ALSO dump the entire body as a hex blob and
        // tag the bit positions set in `data`. The latter lets us spot
        // which status-effect bits a real packet sets (per the live
        // statuseffect.ini bit-shift mapping).
        private static string ParseUpdate(byte[] b, int off, int len)
        {
            if (len < 12) return null;
            uint uid = ReadU32(b, off + 4);
            uint count = len >= 12 ? (uint)ReadU32(b, off + 8) : 0;
            uint upd = len >= 16 ? (uint)ReadU32(b, off + 12) : 0;
            ulong data = len >= 24 ? (ulong)BitConverter.ToUInt64(b, off + 16) : 0UL;
            string tail = "";
            if (len > 24)
            {
                int extra = len - 24;
                int dumpLen = System.Math.Min(extra, 12);
                var sb = new StringBuilder();
                for (int i = 0; i < dumpLen; i++) sb.Append(b[off + 24 + i].ToString("X2"));
                tail = $" extra[{extra}b]={sb}";
            }
            string bitTag = "";
            if (data != 0)
            {
                var bits = new System.Collections.Generic.List<int>();
                for (int i = 0; i < 64; i++) if ((data & (1UL << i)) != 0) bits.Add(i);
                bitTag = $" bits={string.Join(",", bits)}";
            }
            string fullBody = "";
            if (data != 0 && len > 0)
            {
                // Full body hex dump (useful for capturing a ground-truth
                // Update(StatusEffects) packet's exact bytes). Only print
                // when data != 0 to avoid noise on the constant idle
                // updateType=100 traffic.
                var sb = new StringBuilder();
                for (int i = 0; i < len; i++) sb.Append(b[off + i].ToString("X2"));
                fullBody = $" body={sb}";
            }
            return $"{{ uid={uid} count={count} updateType={upd} data=0x{data:X16}{bitTag}{tail}{fullBody} }}";
        }

        // MSG_INTERACT (1022): 28-byte struct. Use the existing InteractPacket
        // decode path so MagicAttack obfuscation is handled.
        private static string ParseInteract(byte[] chunk, int off, int total)
        {
            if (total < 28) return null;
            try
            {
                fixed (byte* basePtr = chunk)
                {
                    InteractPacket pkt = basePtr + off;
                    string action = pkt.Action.ToString();
                    string extra = pkt.Action == InteractAction.MagicAttack
                        ? $" magic={pkt.MagicType} lvl={pkt.MagicLevel}"
                        : $" val={pkt.Value}";
                    return $"{{ ts={pkt.Timestamp} atk={pkt.UID} tgt={pkt.Target} pos=({pkt.X},{pkt.Y}) action={action}{extra} }}";
                }
            }
            catch (Exception e)
            {
                return $"{{ parse-error: {e.GetType().Name} }}";
            }
        }

        // MSG_SERVER_TIME (1033): year/month/day/hour/min/sec/ms or similar — show first int as a starting clue.
        private static string ParseServerTime(byte[] b, int off, int len)
        {
            if (len < 4) return null;
            uint tick = ReadU32(b, off);
            return $"{{ tick={tick} bodyLen={len} }}";
        }

        // MSG_CONNECT (1052): post-auth connect packet (the unencrypted-by-game-key Connect, 36 bytes).
        // Body layout (5065): some token-ish bytes then "0014 0000" => UID-ish.
        private static string ParseConnect(byte[] b, int off, int len)
        {
            if (len < 8) return null;
            // We mostly just want to log that a Connect happened; show hex tail.
            return $"{{ connect body={len}b }}";
        }

        // MSG_MAP_STATUS (1110): mapId:u32 at offset 4
        private static string ParseMapStatus(byte[] b, int off, int len)
        {
            if (len < 8) return null;
            uint mapId = ReadU32(b, off + 4);
            return $"{{ mapId={mapId} }}";
        }

        // ---- helpers ---------------------------------------------------------

        // NetStringPacker layout: [count:1][len:1][bytes]...
        private static string[] ParseNetStrings(byte[] b, int off, int len)
        {
            if (len <= 0 || off >= b.Length) return Array.Empty<string>();
            int count = b[off]; off += 1; len -= 1;
            var outs = new System.Collections.Generic.List<string>();
            for (int i = 0; i < count && len > 0; i++)
            {
                int n = b[off]; off += 1; len -= 1;
                if (n > len) break;
                outs.Add(Encoding.UTF8.GetString(b, off, n));
                off += n; len -= n;
            }
            return outs.ToArray();
        }

        private static string Q(string s)
        {
            if (s == null) return "\"\"";
            // Trim to a reasonable length so chat with huge payloads doesn't blow up the log.
            if (s.Length > 120) s = s.Substring(0, 120) + "...";
            return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
        }

        private static int ReadI32(byte[] b, int off)
        {
            return BitConverter.ToInt32(b, off);
        }

        private static uint ReadU32(byte[] b, int off)
        {
            return BitConverter.ToUInt32(b, off);
        }

        private static int ReadU16(byte[] b, int off)
        {
            return BitConverter.ToUInt16(b, off);
        }

        private static string HexBody(byte[] chunk, int off, int total)
        {
            int dumpLen = System.Math.Min(total, 32);
            var sb = new StringBuilder();
            for (int i = 0; i < dumpLen; i++)
                sb.Append(chunk[off + i].ToString("X2")).Append(' ');
            if (total > dumpLen) sb.Append("...");
            return sb.ToString().TrimEnd();
        }
    }
}
