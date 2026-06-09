namespace Pcf.Dcp;

/// <summary>
/// Explicit little-endian integer helpers. PCF mandates little-endian for every
/// multi-byte integer; reading/writing the bytes by hand keeps the encoding
/// independent of the host's native byte order.
/// </summary>
internal static class LittleEndian
{
    public static void WriteU16(byte[] b, int o, ushort v)
    {
        b[o] = (byte)(v & 0xFF);
        b[o + 1] = (byte)((v >> 8) & 0xFF);
    }

    public static void WriteU64(byte[] b, int o, ulong v)
    {
        for (int i = 0; i < 8; i++)
        {
            b[o + i] = (byte)((v >> (8 * i)) & 0xFF);
        }
    }

    public static ushort ReadU16(byte[] b, int o) => (ushort)(b[o] | (b[o + 1] << 8));

    public static ulong ReadU64(byte[] b, int o)
    {
        ulong v = 0;
        for (int i = 0; i < 8; i++)
        {
            v |= (ulong)b[o + i] << (8 * i);
        }
        return v;
    }
}
