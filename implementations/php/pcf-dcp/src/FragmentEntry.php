<?php

declare(strict_types=1);

namespace Kduma\PCFDCP;

/** One Fragment Entry: a single extent of an inner partition (spec 8.2). */
final class FragmentEntry
{
    public function __construct(
        public int $extentOffset,
        public int $extentLength,
        public int $kind,
        public int $flags,
    ) {
    }

    /** Serialise to the on-disk 18-byte layout. */
    public function toBytes(): string
    {
        return pack('P', $this->extentOffset)
            . pack('P', $this->extentLength)
            . \chr($this->kind & 0xFF)
            . \chr($this->flags & 0xFF);
    }

    /** Parse from the on-disk 18-byte layout (optionally at an offset). */
    public static function fromBytes(string $b, int $offset = 0): self
    {
        return new self(
            unpack('P', substr($b, $offset + 0, 8))[1],
            unpack('P', substr($b, $offset + 8, 8))[1],
            \ord($b[$offset + 16]),
            \ord($b[$offset + 17]),
        );
    }

    /** Whether this entry's kind is DATA. */
    public function isData(): bool
    {
        return $this->kind === Consts::KIND_DATA;
    }

    /** Whether the SHARED flag (bit 0) is set. */
    public function isShared(): bool
    {
        return ($this->flags & Consts::FLAG_SHARED) !== 0;
    }
}
