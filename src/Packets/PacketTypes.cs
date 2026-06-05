using System.Collections.Generic;

namespace ConquerPoc.Packets
{
    /// <summary>
    /// Packet-type registry. Names are sourced from the canonical Conquer
    /// Online wiki ([Packets/Packets.md] in conquer-wiki), cross-checked
    /// against the Comet 5187 server source's PacketType enum.
    ///
    /// Some IDs have two valid names — a "current" name used in the Comet
    /// 5187 source and an older "5065-era" name used in Redux. We use the
    /// wiki name (which generally matches Comet 5187) so logs read like
    /// the documentation. The lookup also stores a short tag for packets
    /// where the wire layout differs across patches.
    /// </summary>
    public static class PacketTypes
    {
        public sealed class Entry
        {
            public ushort Id;
            public string Name;
            // Brief layout tag (e.g. "patch5165"). Empty when not relevant.
            public string Layout;
        }

        // Wiki-canonical names. Source: conquer-wiki/Packets/Packets.md.
        //
        // Rev "5187" version analysis (from wire-vs-wiki triangulation
        // 2026-06-05). The version number 5187 implies a base around patch
        // 5165, but in practice each packet family is at its own patch
        // level — Rev is a Frankenstein build with selectively backported
        // upgrades. Per-packet confirmed layouts:
        //
        //   MsgConnect  (1052) ............ patch 5615 (body=24, has build+lang+mac)
        //   MsgUserInfo (1006) ............ patch 5165 (body=102, matches name="dandruff" exactly)
        //   MsgInteract (1022) ............ patch 5017 (body=24, our InteractPacket struct)
        //   MsgAction   (10010, LONG)...... ~patch 5165, body=28 — chr-id at offset 4
        //                                    (5615-style placement), 5165 size
        //   MsgAction   (10010, SHORT)..... empirical, body=24 — server-side acks
        //   MsgWalk     (10005) ........... ~patch 5517-stripped, body=12 (dir+uid+ts only)
        //   MsgUserAttrib (10017) ......... patch 5672 (body=32, has 3 value fields)
        //   MsgPlayer   (10014) ........... between patch 5103 and 5672 (body=142),
        //                                    no exact wiki match — body customized
        //
        // The Layout tags below mark the wiki patch we used as the parsing
        // reference. "rev" means we don't have a wiki match — Rev-custom shape.
        private static readonly Dictionary<ushort, Entry> KNOWN = new Dictionary<ushort, Entry>
        {
            { 1001, new Entry { Id=1001, Name="MsgRegister" } },
            { 1004, new Entry { Id=1004, Name="MsgTalk" } },
            { 1005, new Entry { Id=1005, Name="MsgWalk" } },              // old; renumbered to 10005 in Rev
            { 1006, new Entry { Id=1006, Name="MsgUserInfo", Layout="patch5165" } },
            { 1008, new Entry { Id=1008, Name="MsgItemInfo" } },
            { 1009, new Entry { Id=1009, Name="MsgItem" } },
            { 1010, new Entry { Id=1010, Name="MsgAction" } },             // old; renumbered to 10010
            { 1012, new Entry { Id=1012, Name="MsgTick" } },               // was wrongly "AccountSpawn" before
            { 1014, new Entry { Id=1014, Name="MsgPlayer" } },             // old; renumbered to 10014
            { 1015, new Entry { Id=1015, Name="MsgName" } },
            { 1016, new Entry { Id=1016, Name="MsgWeather" } },
            { 1017, new Entry { Id=1017, Name="MsgUserAttrib" } },         // old; renumbered to 10017
            { 1019, new Entry { Id=1019, Name="MsgFriend" } },
            { 1022, new Entry { Id=1022, Name="MsgInteract", Layout="patch5017" } },
            { 1023, new Entry { Id=1023, Name="MsgTeam" } },
            { 1024, new Entry { Id=1024, Name="MsgAllot" } },
            { 1025, new Entry { Id=1025, Name="MsgWeaponSkill" } },
            { 1026, new Entry { Id=1026, Name="MsgTeamMember" } },
            { 1027, new Entry { Id=1027, Name="MsgGemEmbed" } },
            { 1028, new Entry { Id=1028, Name="MsgFuse" } },
            { 1032, new Entry { Id=1032, Name="MsgBattleEffectiveness" } },
            { 1033, new Entry { Id=1033, Name="MsgData" } },
            { 1034, new Entry { Id=1034, Name="MsgDetainItemInfo" } },
            { 1036, new Entry { Id=1036, Name="MsgGodExp" } },
            { 1037, new Entry { Id=1037, Name="MsgPing" } },
            { 1041, new Entry { Id=1041, Name="MsgEnemyList" } },
            { 1052, new Entry { Id=1052, Name="MsgConnect", Layout="patch5615" } },
            { 1055, new Entry { Id=1055, Name="MsgConnectEx" } },
            { 1056, new Entry { Id=1056, Name="MsgTrade" } },
            { 1058, new Entry { Id=1058, Name="MsgSynpOffer" } },
            { 1059, new Entry { Id=1059, Name="MsgEncryptCode" } },
            { 1086, new Entry { Id=1086, Name="MsgAccount" } },
            { 1100, new Entry { Id=1100, Name="MsgPCNum" } },
            { 1101, new Entry { Id=1101, Name="MsgMapItem" } },
            { 1102, new Entry { Id=1102, Name="MsgPackage" } },
            { 1103, new Entry { Id=1103, Name="MsgMagicInfo" } },
            { 1104, new Entry { Id=1104, Name="MsgFlushExp" } },
            { 1105, new Entry { Id=1105, Name="MsgMagicEffect" } },
            { 1106, new Entry { Id=1106, Name="MsgSyndicateAttributeInfo" } },
            { 1107, new Entry { Id=1107, Name="MsgSyndicate" } },
            { 1108, new Entry { Id=1108, Name="MsgItemInfoEx" } },
            { 1109, new Entry { Id=1109, Name="MsgNpcInfoEx" } },
            { 1110, new Entry { Id=1110, Name="MsgMapInfo" } },
            { 1111, new Entry { Id=1111, Name="MsgMessageBoard" } },
            { 1112, new Entry { Id=1112, Name="MsgSynMemberInfo" } },
            { 1113, new Entry { Id=1113, Name="MsgDice" } },
            { 1114, new Entry { Id=1114, Name="MsgSyncAction" } },
            { 1128, new Entry { Id=1128, Name="MsgVipUserHandle" } },     // not MsgUserAttrib (which is 1017/10017)
            { 1129, new Entry { Id=1129, Name="MsgVipFunctionValidNotify" } },
            { 1130, new Entry { Id=1130, Name="MsgTitle" } },
            { 1134, new Entry { Id=1134, Name="MsgTaskStatus" } },         // not MsgUserItems
            { 1135, new Entry { Id=1135, Name="MsgTaskDetailInfo" } },
            { 1136, new Entry { Id=1136, Name="MsgAchievement" } },
            { 1150, new Entry { Id=1150, Name="MsgFlower" } },
            { 1151, new Entry { Id=1151, Name="MsgRank" } },
            { 1213, new Entry { Id=1213, Name="MsgLoginChallengeS" } },
            { 1214, new Entry { Id=1214, Name="MsgLoginProofC" } },
            { 1312, new Entry { Id=1312, Name="MsgFamily" } },
            { 1313, new Entry { Id=1313, Name="MsgFamilyOccupy" } },
            { 1350, new Entry { Id=1350, Name="MsgGameServerShutDown" } },
            { 2030, new Entry { Id=2030, Name="MsgNpcInfo" } },             // formerly "SpawnNpc"
            { 2031, new Entry { Id=2031, Name="MsgNpc" } },
            { 2032, new Entry { Id=2032, Name="MsgTaskDialog" } },
            { 2033, new Entry { Id=2033, Name="MsgFriendInfo" } },
            { 2036, new Entry { Id=2036, Name="MsgDataArray" } },
            { 2041, new Entry { Id=2041, Name="MsgAnnounceList" } },
            { 2042, new Entry { Id=2042, Name="MsgAnnounceInfo" } },
            { 2043, new Entry { Id=2043, Name="MsgTrainingInfo" } },
            { 2044, new Entry { Id=2044, Name="MsgTraining" } },
            { 2046, new Entry { Id=2046, Name="MsgTradeBuddy" } },
            { 2047, new Entry { Id=2047, Name="MsgTradeBuddyInfo" } },
            { 2048, new Entry { Id=2048, Name="MsgEquipLock" } },           // not MsgUserInfoEx
            { 2050, new Entry { Id=2050, Name="MsgPigeon" } },
            { 2051, new Entry { Id=2051, Name="MsgPigeonQuery" } },
            { 2064, new Entry { Id=2064, Name="MsgPeerage" } },             // formerly "Nobility" — same thing
            { 2065, new Entry { Id=2065, Name="MsgGuide" } },
            { 2066, new Entry { Id=2066, Name="MsgGuideInfo" } },
            { 2067, new Entry { Id=2067, Name="MsgContribute" } },
            { 2068, new Entry { Id=2068, Name="MsgQuiz" } },
            { 2070, new Entry { Id=2070, Name="MsgSuitStatus" } },
            { 2071, new Entry { Id=2071, Name="MsgRelation" } },
            { 2078, new Entry { Id=2078, Name="MsgUserIPInfo" } },
            { 2079, new Entry { Id=2079, Name="MsgServerInfo" } },
            { 2080, new Entry { Id=2080, Name="MsgChangeName" } },
            { 2081, new Entry { Id=2081, Name="MsgDeadMark" } },
            { 2110, new Entry { Id=2110, Name="MsgSuperFlag" } },
            { 2225, new Entry { Id=2225, Name="MsgSynRecruitAdvertising" } },
            { 2227, new Entry { Id=2227, Name="MsgSynRecruitAdvertisingOpt" } },
            { 2286, new Entry { Id=2286, Name="MsgMapItem" } },
            { 2430, new Entry { Id=2430, Name="MsgNationality" } },
            { 2501, new Entry { Id=2501, Name="MsgCrossSwitch" } },

            // Rev-specific anti-cheat packet. Large (763 bytes), high zero-
            // padding, ASCII hex blob at start. Not a gameplay packet.
            { 2685, new Entry { Id=2685, Name="MsgACReport" } },

            // Renumbered IDs on Rev 5187 (also patch 5103 era per the wiki).
            // Body layouts match their 1000s-range counterparts at the same
            // patch level.
            { 10005, new Entry { Id=10005, Name="MsgWalk",       Layout="rev (stripped 5517: dir/uid/ts only)" } },
            { 10010, new Entry { Id=10010, Name="MsgAction",     Layout="patch5165 (chr-id at body offset 0, sz=40 LONG / sz=36 SHORT)" } },
            { 10014, new Entry { Id=10014, Name="MsgPlayer",     Layout="rev (between 5103 and 5672, body=142)" } },
            { 10017, new Entry { Id=10017, Name="MsgUserAttrib", Layout="patch5672 (body=32, uid/cnt/status/v1/v2/v3)" } },
        };

        public static Entry Lookup(ushort id)
        {
            if (KNOWN.TryGetValue(id, out var e)) return e;
            return new Entry { Id = id, Name = $"Unknown#{id}" };
        }

        public static string Label(ushort id) => Lookup(id).Name;
    }
}
