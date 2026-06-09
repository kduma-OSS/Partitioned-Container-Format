namespace Pcf.Dcp;

/// <summary>
/// How a Writer splits an inner partition's content into extents (spec Section
/// 10.2; chunking is writer-side policy).
/// </summary>
public sealed class Chunker
{
    /// <summary>Whether this chunker emits one extent for the whole content.</summary>
    public bool IsWhole { get; }

    /// <summary>Fixed chunk size in bytes (meaningful only when not whole).</summary>
    public int Size { get; }

    private Chunker(bool whole, int size)
    {
        IsWhole = whole;
        Size = size;
    }

    /// <summary>One extent for the whole content.</summary>
    public static Chunker Whole() => new Chunker(true, 0);

    /// <summary>Fixed-size chunks of <paramref name="n"/> bytes (0 = whole).</summary>
    public static Chunker Fixed(int n) => new Chunker(n <= 0, n);
}
