using System.Text;
using Pcf;

namespace Pcf.Dcp;

/// <summary>The canonical PCF-DCP v1.0 test vector (spec Section 17).</summary>
public static class ReferenceVector
{
    private static byte[] Fill(byte b)
    {
        var u = new byte[16];
        for (int i = 0; i < 16; i++)
        {
            u[i] = b;
        }
        return u;
    }

    /// <summary>
    /// Build the byte-exact 700-byte reference file from spec Section 17: one
    /// DCP container ("dcp", uid 16×0xDC) holding inner "A" ("Hello, World!" as
    /// two extents, the second shared) and inner "B" ("World!" deduplicated onto
    /// A's second extent). Building this logical container and emitting the
    /// canonical layout MUST reproduce these exact bytes.
    /// </summary>
    public static byte[] Build()
    {
        var arena = new Arena();
        arena.AddInner(0x0000_0010, Fill(0xA1), "A",
            Encoding.UTF8.GetBytes("Hello, World!"), HashAlgo.Sha256, Chunker.Fixed(7));
        arena.AddInner(0x0000_0010, Fill(0xB2), "B",
            Encoding.UTF8.GetBytes("World!"), HashAlgo.Sha256, Chunker.Whole());

        var w = new DcpWriter();
        w.AddContainer(Fill(0xDC), "dcp", arena);
        return w.ToImage();
    }
}
