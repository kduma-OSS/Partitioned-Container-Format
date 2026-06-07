using System;
using System.Text;

namespace Pcf.Tests;

/// <summary>Shared helpers and the canonical spec test vector (section 15).</summary>
internal static class TestSupport
{
    /// <summary>Parse a whitespace-tolerant hex string into bytes.</summary>
    public static byte[] FromHex(string hex)
    {
        var sb = new StringBuilder(hex.Length);
        foreach (char ch in hex)
        {
            if (!char.IsWhiteSpace(ch))
            {
                sb.Append(ch);
            }
        }
        string s = sb.ToString();
        var bytes = new byte[s.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);
        }
        return bytes;
    }

    /// <summary>A 16-byte UID filled with a single byte value.</summary>
    public static byte[] Uid(byte value)
    {
        var u = new byte[Constants.UidSize];
        for (int i = 0; i < u.Length; i++)
        {
            u[i] = value;
        }
        return u;
    }

    /// <summary>
    /// The complete 395-byte canonical container from spec section 15,
    /// transcribed from the specification's plain hex dump.
    /// </summary>
    public static readonly byte[] CanonicalVector = FromHex(@"
        89 4B 50 52 54 0D 0A 1A 01 00 00 00 14 00 00 00
        00 00 00 00 02 00 00 00 00 00 00 00 00 10 F5 EB
        FE 8C 26 B1 70 F7 C9 7C F9 2E D2 4C F6 1E 04 2B
        BD FA C5 09 9B C7 80 1F 0E 81 0F C3 27 B6 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 10 00
        00 00 11 11 11 11 11 11 11 11 11 11 11 11 11 11
        11 11 61 6C 70 68 61 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 78 01 00 00 00 00 00 00 0B 00 00 00 00 00
        00 00 0B 00 00 00 00 00 00 00 10 DC 02 CF 82 CE
        C2 34 05 61 7A D4 BF 90 1C 09 75 B6 4A 4B E5 7C
        30 3A 8F 5C F0 A2 C2 51 CB 90 BC 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 FF FF FF FF 22
        22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 72
        61 77 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 83
        01 00 00 00 00 00 00 08 00 00 00 00 00 00 00 08
        00 00 00 00 00 00 00 02 3B BC 2C 8A 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 48 65 6C 6C 6F 2C 20 50
        43 46 21 00 01 02 03 04 05 06 07");

    /// <summary>
    /// Build the same logical container described in spec section 15 and return
    /// its compacted image. An independent implementation that does this MUST
    /// produce <see cref="CanonicalVector"/> byte-for-byte.
    /// </summary>
    public static byte[] BuildCanonical()
    {
        var c = Container.CreateWith(new System.IO.MemoryStream(), 8, HashAlgo.Sha256);
        c.AddPartition(0x0000_0010, Uid(0x11), "alpha",
            Encoding.ASCII.GetBytes("Hello, PCF!"), 0, HashAlgo.Sha256);
        c.AddPartition(0xFFFF_FFFF, Uid(0x22), "raw",
            new byte[] { 0, 1, 2, 3, 4, 5, 6, 7 }, 0, HashAlgo.Crc32c);
        return c.CompactedImage();
    }
}
