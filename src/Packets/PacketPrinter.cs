using System;
using System.Collections.Generic;
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
                // 10005 Walk body layout on Rev 5517 isn't fully nailed down.
                // Leave it to the hex fallback; we get the type label right
                // from the registry.
                case 10005: return null;
                case 1006: return ParseUserInfo(chunk, bodyStart, bodyLen);
                case 1008: return ParseItemInfo(chunk, bodyStart, bodyLen);
                case 1009: return ParseItem(chunk, bodyStart, bodyLen);
                case 1010:
                case 10010: return ParseAction(chunk, bodyStart, bodyLen);
                case 1012: return ParseTick(chunk, bodyStart, bodyLen);
                case 1014:
                case 10014: return ParsePlayer(chunk, bodyStart, bodyLen);
                case 1017:
                case 10017: return ParseUserAttrib(chunk, bodyStart, bodyLen);
                case 1022: return ParseInteract(chunk, off, total);
                case 1025: return ParseWeaponSkill(chunk, bodyStart, bodyLen);
                case 1033: return ParseData(chunk, bodyStart, bodyLen);
                case 1052: return ParseConnect(chunk, bodyStart, bodyLen);
                case 1101: return ParseMapItem(chunk, bodyStart, bodyLen);
                case 1110: return ParseMapInfo(chunk, bodyStart, bodyLen);
                case 2030: return ParseNpcInfo(chunk, bodyStart, bodyLen);
                case 2032: return ParseTaskDialog(chunk, bodyStart, bodyLen);
                case 2064: return ParsePeerage(chunk, bodyStart, bodyLen);
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

        // MsgAction (1010 / 10010): generic request/response. Patch 5517
        // layout per conquer-wiki: CharacterID:u32 Command:u32 Args[2]:u16
        // Timestamp:u32 Action:u16 Direction:u16 X:u16 Y:u16 Map:u32 Color:u32.
        // We show the most useful fields and the action name.
        private static string ParseAction(byte[] b, int off, int len)
        {
            if (len < 28) return null;
            uint chrId = ReadU32(b, off);
            uint cmd   = ReadU32(b, off + 4);
            uint ts    = ReadU32(b, off + 12);
            ushort act = (ushort)ReadU16(b, off + 16);
            ushort dir = (ushort)ReadU16(b, off + 18);
            ushort x   = (ushort)ReadU16(b, off + 20);
            ushort y   = (ushort)ReadU16(b, off + 22);
            return $"{{ chr={chrId} cmd={cmd} ts={ts} action={ActionName(act)}({act}) dir={dir} pos=({x},{y}) }}";
        }

        // MsgPlayer (1014 / 10014): spawn-entity, ~140-byte variable body.
        // Wiki has the full struct; for now just surface the leading UID +
        // mesh/look fields that tell you who got spawned.
        private static string ParsePlayer(byte[] b, int off, int len)
        {
            if (len < 12) return null;
            uint uid = ReadU32(b, off);
            uint mesh = len >= 8 ? (uint)ReadU32(b, off + 4) : 0;
            return $"{{ uid={uid} mesh={mesh} body={len}b }}";
        }

        // MsgUserAttrib (1017 / 10017): patch 5672 layout per the wiki.
        //   uid:u32 updateCount:u32 statusType:u32 value1:u64 value2:u64 value3:u32
        // Total body = 32 bytes (matches our wire sz=44 = 4 hdr + 32 body + 8 trailer).
        // statusType is the StatusEffects enum (bit-shift values; see the
        // conquer-wiki MsgUserAttrib-Status enum). When value1 has bits set
        // we annotate with the matching status-effect names.
        private static string ParseUserAttrib(byte[] b, int off, int len)
        {
            if (len < 12) return null;
            uint uid = ReadU32(b, off);
            uint count = len >= 8 ? (uint)ReadU32(b, off + 4) : 0;
            uint status = len >= 12 ? (uint)ReadU32(b, off + 8) : 0;
            ulong v1 = len >= 20 ? BitConverter.ToUInt64(b, off + 12) : 0UL;
            ulong v2 = len >= 28 ? BitConverter.ToUInt64(b, off + 20) : 0UL;
            uint v3 = len >= 32 ? (uint)ReadU32(b, off + 28) : 0;

            // Show v1 as a status-effects bit list only when this is
            // actually a StatusEffects update (statusType is the wiki's
            // STATUS enum; the live statuseffect.ini key 23 = CYCLONE is
            // a *bit position in v1*, not a statusType value).
            string statusName = StatusEffectName(status);
            string bitTag = "";
            if (v1 != 0)
            {
                var bits = new System.Collections.Generic.List<string>();
                for (int i = 0; i < 64; i++)
                {
                    if ((v1 & (1UL << i)) == 0) continue;
                    string nm = StatusEffectBitName(i);
                    bits.Add(nm != null ? $"{i}({nm})" : i.ToString());
                }
                bitTag = $" bits=[{string.Join(",", bits)}]";
            }
            string tail = v3 != 0 ? $" v3={v3}" : "";
            string v2tag = v2 != 0 ? $" v2=0x{v2:X16}" : "";
            return $"{{ uid={uid} cnt={count} status={statusName}({status}) v1=0x{v1:X16}{bitTag}{v2tag}{tail} }}";
        }

        // MsgInteract (1022): 28-byte struct (incl. header+trailer math).
        // Use the existing InteractPacket decode path so the MagicAttack
        // obfuscation reverse is handled.
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

        // MsgWeaponSkill (1025): proficiency/skill exp updates. Wiki layout
        // varies by patch; the consistent pieces are skill id and experience.
        private static string ParseWeaponSkill(byte[] b, int off, int len)
        {
            if (len < 12) return null;
            uint skillId = ReadU32(b, off);
            uint level = len >= 8 ? (uint)ReadU32(b, off + 4) : 0;
            uint exp = len >= 12 ? (uint)ReadU32(b, off + 8) : 0;
            return $"{{ skill={skillId} lvl={level} exp={exp} }}";
        }

        // MsgData (1033): server time + dataarray scratch packet. Treat as a
        // tagged 4-int blob.
        private static string ParseData(byte[] b, int off, int len)
        {
            if (len < 4) return null;
            uint a = ReadU32(b, off);
            uint c = len >= 8 ? (uint)ReadU32(b, off + 4) : 0;
            return $"{{ a={a} b={c} body={len}b }}";
        }

        // MsgConnect (1052): client identity + build version. Patch 5615 layout.
        //   identity:u32 additionalData:u32 buildVersion:u16 language:char[2]
        //   macAddress:byte[6] resDatContents:u32
        private static string ParseConnect(byte[] b, int off, int len)
        {
            if (len < 8) return null;
            uint identity = ReadU32(b, off);
            uint additional = ReadU32(b, off + 4);
            ushort buildVersion = len >= 10 ? (ushort)ReadU16(b, off + 8) : (ushort)0;
            string lang = len >= 12 ? Encoding.ASCII.GetString(b, off + 10, 2) : "";
            return $"{{ identity={identity} additional={additional} build={buildVersion} lang={lang} }}";
        }

        // MsgTick (1012): server-time/sync packet. Mostly an opaque cookie;
        // surface enough to spot it in the log.
        private static string ParseTick(byte[] b, int off, int len)
        {
            if (len < 4) return null;
            uint uid = ReadU32(b, off);
            return $"{{ uid={uid} body={len}b }}";
        }

        // MsgItemInfo (1008): item descriptor. Wiki shows: uid:u32, itemType:u32,
        // amount:u16/u32 depending on patch. Surface the id + type at minimum.
        private static string ParseItemInfo(byte[] b, int off, int len)
        {
            if (len < 8) return null;
            uint itemUid = ReadU32(b, off);
            uint itemType = ReadU32(b, off + 4);
            return $"{{ itemUid={itemUid} itemType={itemType} body={len}b }}";
        }

        // MsgItem (1009): item action request/response. action is the
        // discriminator. Wire shape: uid:u32 zero:u32 action:u32 timestamp:u32.
        private static string ParseItem(byte[] b, int off, int len)
        {
            if (len < 16) return null;
            uint uid = ReadU32(b, off);
            uint action = ReadU32(b, off + 8);
            uint ts = ReadU32(b, off + 12);
            return $"{{ uid={uid} action={action} ts={ts} }}";
        }

        // MsgMapItem (1101): ground item / loot. Wiki: itemUid:u32 lookface:u32
        // x:u16 y:u16 mode:u16 mask:u16.
        private static string ParseMapItem(byte[] b, int off, int len)
        {
            if (len < 12) return null;
            uint itemUid = ReadU32(b, off);
            uint look = ReadU32(b, off + 4);
            ushort x = (ushort)ReadU16(b, off + 8);
            ushort y = (ushort)ReadU16(b, off + 10);
            return $"{{ itemUid={itemUid} look={look} pos=({x},{y}) }}";
        }

        // MsgMapInfo (1110): mapId:u32 at body offset 4 (after a leading u32).
        private static string ParseMapInfo(byte[] b, int off, int len)
        {
            if (len < 8) return null;
            uint mapId = ReadU32(b, off + 4);
            return $"{{ mapId={mapId} }}";
        }

        // MsgNpcInfo (2030): npc spawn. uid:u32 lookface:u16 x:u16 y:u16
        // type:u16 something:u16 ...
        private static string ParseNpcInfo(byte[] b, int off, int len)
        {
            if (len < 12) return null;
            uint uid = ReadU32(b, off);
            ushort x = (ushort)ReadU16(b, off + 8);
            ushort y = (ushort)ReadU16(b, off + 10);
            return $"{{ npcUid={uid} pos=({x},{y}) body={len}b }}";
        }

        // MsgTaskDialog (2032): NPC dialog. action discriminator at offset 8.
        private static string ParseTaskDialog(byte[] b, int off, int len)
        {
            if (len < 12) return null;
            uint taskId = ReadU32(b, off);
            uint dialogId = ReadU32(b, off + 4);
            uint action = ReadU32(b, off + 8);
            return $"{{ task={taskId} dialog={dialogId} action={action} }}";
        }

        // MsgPeerage (2064): nobility/rank info. Lead with uid + the action.
        private static string ParsePeerage(byte[] b, int off, int len)
        {
            if (len < 12) return null;
            uint action = ReadU32(b, off);
            uint uid = ReadU32(b, off + 4);
            return $"{{ action={action} uid={uid} body={len}b }}";
        }

        // MsgUserInfo (1006): character info on login. Patch 5165 layout per
        // wiki: identity:u32 mesh:u32 hair:u16 silver:u32 cp:u32 exp:u64
        // [22 bytes pad] strength:u16 agility:u16 vitality:u16 spirit:u16
        // freeAttr:u16 hp:u16 sp:u16 pk:u16 level:u8 class:u8 [1 pad]
        // reborn:u8 [1 pad] quizPoints:u32 [12 pad] strListCount:u8 ...
        private static string ParseUserInfo(byte[] b, int off, int len)
        {
            if (len < 90) return null;
            uint identity = ReadU32(b, off);
            uint mesh = ReadU32(b, off + 4);
            uint silver = ReadU32(b, off + 10);
            uint cp = ReadU32(b, off + 14);
            byte level = b[off + 62];
            byte cls = b[off + 63];
            // String list begins at body offset 83. Read first string = char name.
            string charName = TryReadFirstNetString(b, off + 83, len - 83);
            return $"{{ id={identity} name=\"{charName}\" mesh={mesh} silver={silver} cp={cp} lvl={level} class={cls} }}";
        }

        // ---- enum lookups ----------------------------------------------------

        // StatusEffects bit positions per conquer-wiki/Enums/MsgUserAttrib-Status.
        // Each entry: the bit-shift count → effect name. Compose with v1 like
        // (v1 & (1 << N)) != 0.
        private static readonly Dictionary<int, string> STATUS_EFFECT_BITS = new Dictionary<int, string>
        {
            { 0, "BLUE_FLASHING_NAME" }, { 1, "POISONED" }, { 2, "REMOVE_MESH" },
            { 4, "XP_CIRCLE" }, { 5, "RESTRICT_MOVEMENT" }, { 6, "TEAM_LEADER" },
            { 7, "STAR_OF_ACCURACY" }, { 8, "SHIELD" }, { 9, "STIGMA" },
            { 10, "DEAD" }, { 11, "FADE" }, { 14, "RED_NAME" }, { 15, "BLACK_NAME" },
            { 18, "SUPERMAN" }, { 19, "BODY_SHIELD" }, { 20, "GOD_BELIEVE" },
            { 22, "TRANSPARENT" }, { 23, "CYCLONE" }, { 27, "FLY" },
            { 30, "LUCK_DIFFUSE" }, { 31, "LUCK_ABSORB" }, { 32, "CURSED" },
            { 33, "BLESSED" }, { 34, "TOP_LEADER" }, { 35, "TOP_DEPUTY" },
            { 36, "TOP_MONTHLY_PK" }, { 37, "TOP_WEEKLY_PK" }, { 38, "TOP_WARRIOR" },
            { 39, "TOP_TROJAN" }, { 40, "TOP_ARCHER" }, { 41, "TOP_WATER" },
            { 42, "TOP_FIRE" }, { 43, "TOP_NINJA" }, { 46, "VORTEX" },
            { 47, "FATAL_STRIKE" }, { 48, "CHAMPION" }, { 50, "MOUNT" },
            { 51, "TOP_SPOUSE" }, { 52, "ORANGE_SPARKLES" }, { 53, "PURPLE_SPARKLES" },
            { 54, "DAZED" }, { 55, "RESTORE_AURA" }, { 56, "MOVE_SPEED_RECOVERED" },
            { 57, "GODLY_SHIELD" }, { 58, "SHOCK_DAZE" }, { 59, "FREEZE" },
            { 60, "CHAOS_CYCLE" },
        };

        private static string StatusEffectBitName(int bit)
        {
            return STATUS_EFFECT_BITS.TryGetValue(bit, out var n) ? n : null;
        }

        // MsgUserAttrib `statusType` (the OUTER field, not a bit-shift) tags
        // what kind of update this is. Common values seen on the wire:
        //   0=Life 1=MaxLife 2=Mana 3=MaxMana 4=Money 5=Experience 6=Pk
        //   7=Profession 18=HeavenBlessing 19=DoubleExpTime 23=Reborn
        //   25=UserStatus 26=StatusEffects 27=Hair 28=Xp 29=LuckyTime
        //   30=CP 41=EnlightPoints (per 5065 enum; carries forward).
        private static readonly Dictionary<uint, string> USER_ATTRIB_STATUS = new Dictionary<uint, string>
        {
            { 0, "Life" }, { 1, "MaxLife" }, { 2, "Mana" }, { 3, "MaxMana" },
            { 4, "Money" }, { 5, "Experience" }, { 6, "Pk" }, { 7, "Profession" },
            { 8, "SizeAdd" }, { 9, "Stamina" }, { 10, "MoneySaved" },
            { 11, "AdditionalPoint" }, { 12, "Lookface" }, { 13, "Level" },
            { 14, "Spirit" }, { 15, "Vitality" }, { 16, "Strength" },
            { 17, "Agility" }, { 18, "HeavenBlessing" }, { 19, "DoubleExpTime" },
            { 20, "GuildDonation" }, { 21, "CurseTime" }, { 22, "AddTime" },
            { 23, "Reborn" }, { 25, "UserStatus" }, { 26, "StatusEffects" },
            { 27, "Hair" }, { 28, "Xp" }, { 29, "LuckyTime" }, { 30, "CP" },
            { 32, "OnlineTraining" }, { 37, "ExtraBP" }, { 39, "Merchant" },
            { 40, "Quiz" }, { 41, "EnlightPoints" }, { 44, "BonusBP" },
            { 45, "BoundCp" }, { 49, "AzureShield" }, { 100, "Heartbeat" },
        };

        private static string StatusEffectName(uint t)
        {
            return USER_ATTRIB_STATUS.TryGetValue(t, out var n) ? n : "type" + t;
        }

        // MsgAction `Action` discriminator. From Comet 5187 source's
        // MsgAction.ActionType enum (Comet.Game/Packets/MsgAction.cs).
        private static readonly Dictionary<ushort, string> ACTION_NAMES = new Dictionary<ushort, string>
        {
            { 74, "LoginSpawn" }, { 75, "LoginInventory" },
            { 76, "LoginRelationships" }, { 77, "LoginProficiencies" },
            { 78, "LoginSpells" }, { 79, "CharacterDirection" },
            { 81, "CharacterEmote" }, { 85, "MapPortal" }, { 86, "MapTeleport" },
            { 92, "CharacterLevelUp" }, { 93, "SpellAbortXp" },
            { 94, "CharacterRevive" }, { 95, "CharacterDelete" },
            { 96, "CharacterPkMode" }, { 97, "LoginGuild" }, { 99, "MapMine" },
            { 101, "MapTeamLeaderStar" }, { 102, "MapQuery" },
            { 104, "MapSkyColor" }, { 106, "MapTeamMemberStar" },
            { 108, "MapKickBack" }, { 109, "SpellRemove" },
            { 110, "ProficiencyRemove" }, { 111, "BoothSpawn" },
            { 112, "BoothSuspend" }, { 113, "BoothResume" },
            { 114, "BoothLeave" }, { 116, "ClientCommand" },
            { 117, "CharacterObservation" }, { 118, "SpellAbortTransform" },
            { 120, "SpellAbortFlight" }, { 121, "MapGold" },
            { 123, "RelationshipsEnemy" }, { 126, "ClientDialog" },
            { 132, "LoginComplete" }, { 133, "MapEffect" },
            { 134, "LoginOfflineMessages" }, { 135, "MapRemoveSpawn" },
            { 137, "MapJump" }, { 145, "CharacterDead" },
            { 146, "MapTeleportEnd" }, { 148, "RelationshipsFriend" },
            { 151, "CharacterAvatar" }, { 152, "CharacterPartnerInfo" },
            { 161, "CharacterAway" }, { 162, "MapPathfinding" },
        };

        private static string ActionName(ushort a)
        {
            return ACTION_NAMES.TryGetValue(a, out var n) ? n : "a" + a;
        }

        // First entry of a NetString list ([count:u8][len:u8][bytes]...).
        // Used by ParseUserInfo to pull the character name without parsing
        // the rest of the string list.
        private static string TryReadFirstNetString(byte[] b, int off, int remaining)
        {
            if (remaining < 2 || off + 1 >= b.Length) return "";
            int count = b[off];
            if (count == 0) return "";
            int nameLen = b[off + 1];
            if (nameLen <= 0 || off + 2 + nameLen > b.Length) return "";
            return Encoding.UTF8.GetString(b, off + 2, nameLen);
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
