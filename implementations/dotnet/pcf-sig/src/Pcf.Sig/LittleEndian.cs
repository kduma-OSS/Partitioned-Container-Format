namespace Pcf.Sig;

/// <summary>
/// Little-endian binary I/O helpers used throughout the library. Mirrors the
/// equivalent helper in the base PCF crate so the on-disk byte layout is
/// readable field-by-field in the spec's order.
/// </summary>
internal static class LittleEndian
{
    public static void WriteU16(byte[] b, int o, ushort v)
    {
        b[o] = (byte)(v & 0xFF);
        b[o + 1] = (byte)((v >> 8) & 0xFF);
    }

    public static void WriteU32(byte[] b, int o, uint v)
    {
        b[o] = (byte)(v & 0xFF);
        b[o + 1] = (byte)((v >> 8) & 0xFF);
        b[o + 2] = (byte)((v >> 16) & 0xFF);
        b[o + 3] = (byte)((v >> 24) & 0xFF);
    }

    public static void WriteU64(byte[] b, int o, ulong v)
    {
        for (int i = 0; i < 8; i++)
        {
            b[o + i] = (byte)((v >> (i * 8)) & 0xFF);
        }
    }

    public static void WriteI64(byte[] b, int o, long v) => WriteU64(b, o, unchecked((ulong)v));

    public static ushort ReadU16(byte[] b, int o) =>
        (ushort)(b[o] | (b[o + 1] << 8));

    public static uint ReadU32(byte[] b, int o) =>
        (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24));

    public static ulong ReadU64(byte[] b, int o)
    {
        ulong v = 0;
        for (int i = 0; i < 8; i++)
        {
            v |= (ulong)b[o + i] << (i * 8);
        }
        return v;
    }

    public static long ReadI64(byte[] b, int o) => unchecked((long)ReadU64(b, o));
}
