using System;
using System.Diagnostics;
using System.Text;

namespace ConquerPoc
{
    /// <summary>
    /// Minimal Redux.Common subset needed by copied packet/crypto code.
    /// ENCRYPTION_KEY, ExchangeShortBits/LongBits, and Clock must produce byte-identical
    /// output to the real server's versions or the wire protocol breaks.
    /// </summary>
    public static class Common
    {
        public static readonly byte[] ENCRYPTION_KEY = Encoding.ASCII.GetBytes("DR654dt34trg4UI6");
        public static readonly Random Random = new Random();

        private static readonly Stopwatch _clock = Stopwatch.StartNew();
        public static long Clock { get { return _clock.ElapsedMilliseconds; } }

        public static uint ExchangeShortBits(uint data, int bits)
        {
            data &= 0xffff;
            return ((data >> bits) | (data << (16 - bits))) & 0xffff;
        }

        public static uint ExchangeLongBits(uint data, int bits)
        {
            return (data >> bits) | (data << (32 - bits));
        }
    }

    public static class Constants
    {
        // 5065 (legacy) packet type IDs. Some carry over unchanged to Rev's
        // 5517 build (Talk, Interact, Connect, HeroInformation, ServerTime);
        // others were renumbered into the 10000s range (see Constants5517).
        public const ushort MSG_INTERACT = 1022;
        public const ushort MSG_WALK = 1005;
        public const ushort MSG_TALK = 1004;
        public const ushort MSG_ACTION = 1010;
        public const ushort MSG_CONNECT = 1052;
        public const ushort MSG_UPDATE = 1017;
        public const ushort MSG_SPAWN_ENTITY = 1014;

        // 9-direction delta tables matching Redux/Common.cs:22-23.
        // Conquer movement directions: 0=N, 1=NW, 2=W, 3=SW, 4=S, 5=SE, 6=E, 7=NE, 8=stay.
        public static readonly sbyte[] DeltaX = new sbyte[] { 0, -1, -1, -1, 0, 1, 1, 1, 0 };
        public static readonly sbyte[] DeltaY = new sbyte[] { 1, 1, 0, -1, -1, -1, 0, 1, 0 };

        // UpdateType enum values from Redux/Enum/UpdateType.cs
        public const uint UPDATE_TYPE_STATUS_EFFECTS = 26;

        // ClientEffect bitmask values from Redux/Enum/ClientEffect.cs
        public const ulong CLIENT_EFFECT_CYCLONE = 1UL << 23;
    }

    /// <summary>
    /// Packet type IDs observed on the Rev 5517 server. Some packet shapes
    /// match 5065 layouts under new IDs — those are flagged as candidates
    /// for "best-effort" parsing in PacketPrinter, NOT confirmed mappings.
    /// </summary>
    public static class Constants5517
    {
        // Best-effort mapping from observed packet shapes. Each one is a
        // hypothesis: the body shape matches the same-name 5065 layout.
        // Verify before depending on these for anything beyond labeling.
        public const ushort MSG_WALK_LIKE        = 10005;
        public const ushort MSG_ACTION_LIKE      = 10010;
        public const ushort MSG_SPAWN_ENTITY_LIKE = 10014;
        public const ushort MSG_UPDATE_LIKE      = 10017;

        // Rev-specific / not in 5065. type=2685 is consistently large
        // (763 bytes) with mostly-zero body and ASCII hex blob at the start.
        // Strongly suspected to be an anti-cheat (SecurePlay) report; we
        // label and skip its body parse.
        public const ushort MSG_AC_REPORT = 2685;
    }
}
