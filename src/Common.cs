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
}
