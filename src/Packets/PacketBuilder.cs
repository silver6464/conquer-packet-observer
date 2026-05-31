using System.Text;

namespace ConquerPoc.Packets
{
    public unsafe partial class PacketBuilder
    {
        public static void AppendHeader(byte* ptr, int size, ushort type)
        {
            *((ushort*)ptr) = (ushort)(size - 8);
            *((ushort*)(ptr + 2)) = type;
        }
    }
}

