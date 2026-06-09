using System.Security.Cryptography;
using System.Text;

namespace Pcf.Dcp.Tests;

internal static class TestSupport
{
    /// <summary>A 16-byte uid all equal to <paramref name="b"/>.</summary>
    public static byte[] Fill(byte b)
    {
        var u = new byte[16];
        for (int i = 0; i < 16; i++) u[i] = b;
        return u;
    }

    public static byte[] Bytes(string s) => Encoding.UTF8.GetBytes(s);

    public static string Str(byte[] b) => Encoding.UTF8.GetString(b);

    public static string Hex(byte[] b)
    {
        var sb = new StringBuilder(b.Length * 2);
        foreach (var x in b) sb.Append(x.ToString("x2"));
        return sb.ToString();
    }

    public static string Sha256Hex(byte[] b)
    {
        using var sha = SHA256.Create();
        return Hex(sha.ComputeHash(b));
    }
}
