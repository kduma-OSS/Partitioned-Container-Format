using System;

namespace Pcf.Sig.Tests;

internal static class TestSupport
{
    public static byte[] Uid(int n)
    {
        var u = new byte[16];
        u[0] = (byte)n;
        u[15] = 0xAA;
        return u;
    }

    public static byte[] Repeat(byte b, int len)
    {
        var x = new byte[len];
        for (int i = 0; i < len; i++) x[i] = b;
        return x;
    }

    public static string Hex(byte[] b)
    {
        var sb = new System.Text.StringBuilder(b.Length * 2);
        foreach (var x in b) sb.Append(x.ToString("x2"));
        return sb.ToString();
    }
}
