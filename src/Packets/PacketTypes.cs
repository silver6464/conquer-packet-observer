using System.Collections.Generic;

namespace ConquerPoc.Packets
{
    /// <summary>
    /// Packet-type registry. Two tables: 5065 IDs (the source we ported from)
    /// and Rev's 5517 IDs (some carried over, some renumbered into the 10000s).
    ///
    /// Resolution order: look up by ID in 5065 table first (it has the well-known
    /// names). If not found, try 5517 table. If still not found, return
    /// "Unknown#N" so we can spot novel packet types in the log and add them.
    ///
    /// Both name lookups return a *display name* and an *era tag* that tells the
    /// printer how confident we are. 5065-era names are reliable. 5517-era names
    /// are best-effort guesses based on observed body shapes — they get a "?"
    /// suffix in the output so we never imply more certainty than we have.
    /// </summary>
    public static class PacketTypes
    {
        public enum Era { Known5065, Candidate5517, Unknown }

        public sealed class Entry
        {
            public ushort Id;
            public string Name;
            public Era Era;
        }

        // Known 5065 packet types. Source: filenames in proj/conquer-redux-5065/
        //   Redux/Packets/{Game,Login}/.
        private static readonly Dictionary<ushort, string> NAMES_5065 = new Dictionary<ushort, string>
        {
            { 1001, "Register" },         { 1004, "Talk" },              { 1005, "Walk" },
            { 1006, "HeroInformation" },  { 1008, "ItemInformation" },   { 1009, "ItemAction" },
            { 1010, "GeneralData" },      { 1012, "AccountSpawn" },      { 1014, "SpawnEntity" },
            { 1015, "Strings" },          { 1017, "Update" },            { 1019, "Associate" },
            { 1022, "Interact" },
            { 1023, "TeamInteraction" },  { 1024, "AssignAttributes" },  { 1025, "WeaponProf" },
            { 1026, "TeamMemberInfo" },   { 1027, "SocketGem" },         { 1032, "Action2" },
            { 1033, "ServerTime" },       { 1052, "Connect" },           { 1055, "AuthResponse" },
            { 1056, "PasswordSeed" },     { 1058, "GuildDonation" },     { 1086, "Account" },
            { 1100, "MacAddress" },       { 1101, "GroundItem" },        { 1102, "Warehouse" },
            { 1103, "ConquerSkill" },     { 1105, "SkillEffect" },       { 1106, "GuildAttrInfo" },
            { 1107, "Guild" },            { 1108, "VendorItem" },        { 1109, "SobSpawn" },
            { 1110, "MapStatus" },        { 1112, "GuildMemberInfo" },   { 1128, "MsgUserAttrib" },
            { 1134, "MsgUserItems" },
            { 2030, "SpawnNpc" },         { 2031, "Npc" },               { 2032, "NpcDialog" },
            { 2033, "AssociateInfo" },    { 2036, "Compose" },           { 2043, "OfflineTGInfo" },
            { 2044, "OfflineTG" },        { 2048, "MsgUserInfoEx" },     { 2050, "Broadcast" },
            { 2064, "Nobility" },         { 2065, "MentorAction" },      { 2066, "MentorInformation" },
            { 2067, "MentorPrize" },
        };

        // Rev 5517 packet types. Empirically observed in proxy logs. Treat these
        // as candidates — the *name* is a best-effort guess that the body shape
        // matches the same-name 5065 layout. Verify by parsing and eyeballing.
        private static readonly Dictionary<ushort, string> NAMES_5517 = new Dictionary<ushort, string>
        {
            { 10005, "Walk" },       // ~24-byte body, looks like a uid+counter pattern
            { 10010, "GeneralData" }, // ~36/40-byte body, contains uid + position data
            { 10014, "SpawnEntity" }, // ~150+ byte body matching SpawnEntity scale
            { 10017, "Update" },     // ~44-byte body, fits Update layout
            // Rev-specific anti-cheat packet: large (763 bytes), high zero-padding,
            // ASCII hex blob at start. Not a gameplay packet.
            { 2685, "ACReport" },
        };

        public static Entry Lookup(ushort id)
        {
            if (NAMES_5065.TryGetValue(id, out var n5065))
                return new Entry { Id = id, Name = n5065, Era = Era.Known5065 };
            if (NAMES_5517.TryGetValue(id, out var n5517))
                return new Entry { Id = id, Name = n5517, Era = Era.Candidate5517 };
            return new Entry { Id = id, Name = $"Unknown#{id}", Era = Era.Unknown };
        }

        // Display label including era marker. 5065 names are unmodified. 5517
        // candidates get a "?" suffix to flag uncertainty.
        public static string Label(ushort id)
        {
            var e = Lookup(id);
            return e.Era == Era.Candidate5517 ? e.Name + "?" : e.Name;
        }
    }
}
