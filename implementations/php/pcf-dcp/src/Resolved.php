<?php

declare(strict_types=1);

namespace Kduma\PCFDCP;

use Kduma\PCF\PartitionEntry;

/** The result of resolving a uid against top-level ∪ inner (spec 2.1). */
final class Resolved
{
    private function __construct(
        public readonly bool $isTopLevel,
        public readonly ?PartitionEntry $entry,
        public readonly ?InnerLocation $inner,
    ) {
    }

    public static function topLevel(PartitionEntry $entry): self
    {
        return new self(true, $entry, null);
    }

    public static function innerPartition(InnerLocation $inner): self
    {
        return new self(false, null, $inner);
    }
}
