<?php

declare(strict_types=1);

namespace Kduma\PCFDCP;

/**
 * How a Writer splits an inner partition's content into extents (spec Section
 * 10.2; chunking is writer-side policy).
 */
final class Chunker
{
    private function __construct(
        public readonly bool $isWhole,
        public readonly int $size,
    ) {
    }

    /** One extent for the whole content. */
    public static function whole(): self
    {
        return new self(true, 0);
    }

    /** Fixed-size chunks of $n bytes (0 = whole). */
    public static function fixed(int $n): self
    {
        return new self($n <= 0, $n);
    }
}
