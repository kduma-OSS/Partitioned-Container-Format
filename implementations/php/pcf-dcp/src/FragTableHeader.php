<?php

declare(strict_types=1);

namespace Kduma\PCFDCP;

/** The 9-byte header that begins each Fragment Table block (spec 8.1). */
final class FragTableHeader
{
    public function __construct(
        public int $nextFragtableOffset,
        public int $fragmentCount,
    ) {
    }

    /** Serialise to the on-disk 9-byte layout. */
    public function toBytes(): string
    {
        return pack('P', $this->nextFragtableOffset) . \chr($this->fragmentCount & 0xFF);
    }

    /** Parse from the on-disk 9-byte layout (optionally at an offset). */
    public static function fromBytes(string $b, int $offset = 0): self
    {
        return new self(
            unpack('P', substr($b, $offset + 0, 8))[1],
            \ord($b[$offset + 8]),
        );
    }
}
