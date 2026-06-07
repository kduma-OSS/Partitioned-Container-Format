namespace Pcf;

/// <summary>
/// Self-contained reflected-CRC routines for the three CRC algorithms in the
/// PCF hash registry (spec section 8.1). Each is parameterised by its reflected
/// polynomial, initial value and final XOR exactly as the specification states.
/// The bitwise form is intentionally simple and auditable; the test suite pins
/// each variant to its canonical check value for the input "123456789".
/// </summary>
internal static class Crc
{
    /// <summary>CRC-32/ISO-HDLC (the CRC used by zlib, gzip and PNG).</summary>
    public static uint Crc32IsoHdlc(byte[] data) =>
        Compute32(data, 0xEDB8_8320u, 0xFFFF_FFFFu, 0xFFFF_FFFFu);

    /// <summary>CRC-32C (Castagnoli).</summary>
    public static uint Crc32c(byte[] data) =>
        Compute32(data, 0x82F6_3B78u, 0xFFFF_FFFFu, 0xFFFF_FFFFu);

    /// <summary>
    /// CRC-64/XZ (as used by xz/liblzma and System.IO.Hashing.Crc64). The
    /// bitwise right-shift form below takes the <em>reflected</em> polynomial
    /// 0xC96C5795D7870F42, i.e. the bit-reversal of the spec's stated
    /// 0x42F0E1EBA9EA3693.
    /// </summary>
    public static ulong Crc64Xz(byte[] data) =>
        Compute64(data, 0xC96C_5795_D787_0F42ul, 0xFFFF_FFFF_FFFF_FFFFul, 0xFFFF_FFFF_FFFF_FFFFul);

    private static uint Compute32(byte[] data, uint poly, uint init, uint xorout)
    {
        uint crc = init;
        foreach (byte b in data)
        {
            crc ^= b;
            for (int i = 0; i < 8; i++)
            {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ poly : crc >> 1;
            }
        }
        return crc ^ xorout;
    }

    private static ulong Compute64(byte[] data, ulong poly, ulong init, ulong xorout)
    {
        ulong crc = init;
        foreach (byte b in data)
        {
            crc ^= b;
            for (int i = 0; i < 8; i++)
            {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ poly : crc >> 1;
            }
        }
        return crc ^ xorout;
    }
}
