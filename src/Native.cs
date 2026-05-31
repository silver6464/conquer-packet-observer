using System;

namespace ConquerPoc
{
    public unsafe class MSVCRT
    {

        #region memcpy
        public static void* memcpy(byte* dst, byte* src, int length)
        {
            for (var i = 0; i < length; i++)
                *(dst + i) = *(src + i);
            return dst;
        }
        public static void* memcpy(sbyte* dst, sbyte* src, int length)
        {
            for (var i = 0; i < length; i++)
                *(dst + i) = *(src + i);
            return dst;
        }

        public static void* memcpy(sbyte* dst, byte* src, int length)
        {
            for (var i = 0; i < length; i++)
                *(dst + i) = *((sbyte*)(src + i)); 
            return dst;
        }

        public static void* memcpy(byte* dst, sbyte* src, int length)
        {
            for (var i = 0; i < length; i++)
                *(dst + i) = *((byte*)(src + i));
            return dst;
        }

        public static void* memcpy(uint* dst, byte* src, int length)
        {
            var bdst = (byte*)dst;
            for (var i = 0; i < length; i++)
                bdst[i] = src[i];
            return dst;
        }

        #endregion


        #region memset
        public static void* memset(byte* dst, byte fill, int length)
        {
            for (var i = 0; i < length; i++)
                *(dst + i) = fill;
            return dst;
        }
        public static void* memset(sbyte* dst, sbyte fill, int length)
        {
            for (var i = 0; i < length; i++)
                *(dst + i) = fill;
            return dst;
        }
        #endregion


    }

    public static unsafe class NativeExtensions
    {
        public static void CopyTo(this string str, void* pDest)
        {
            var dest = (byte*) pDest;
            for (var i = 0; i < str.Length; i++)
            {
                dest[i] = (byte) str[i];
            }
        }

        public static byte[] UnsafeClone(this byte[] buffer)
        {
            var bufCopy = new byte[buffer.Length];
            Buffer.BlockCopy(buffer, 0, bufCopy, 0, buffer.Length);
            return bufCopy;
        }
    }
}