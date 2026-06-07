<?php

declare(strict_types=1);

namespace Kduma\PCFSIG;

/** One metadata TLV entry (spec Section 6.4). */
final class KeyMetadata
{
    public function __construct(
        public readonly int $tag,
        public readonly string $value,
    ) {
    }
}
