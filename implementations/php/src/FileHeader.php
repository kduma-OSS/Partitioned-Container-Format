<?php

declare(strict_types=1);

namespace Kduma\PCF;

/**
 * The fixed 20-byte file header (spec section 4).
 */
final class FileHeader
{
    public function __construct(
        public int $versionMajor,
        public int $versionMinor,
        public int $partitionTableOffset,
    ) {
    }

    /** Serialise to the on-disk 20-byte layout. */
    public function toBytes(): string
    {
        return Consts::MAGIC
            . pack('v', $this->versionMajor)
            . pack('v', $this->versionMinor)
            . pack('P', $this->partitionTableOffset);
    }

    /**
     * Parse from the on-disk 20-byte layout, validating magic and major
     * version (spec conformance checks C1, C2).
     */
    public static function fromBytes(string $b): self
    {
        if (\strlen($b) < Consts::HEADER_SIZE) {
            throw PcfException::io('short read: file header truncated');
        }
        if (substr($b, 0, 8) !== Consts::MAGIC) {
            throw PcfException::badMagic();
        }
        $versionMajor = unpack('v', substr($b, 8, 2))[1];
        if ($versionMajor !== Consts::VERSION_MAJOR) {
            throw PcfException::unsupportedMajor($versionMajor);
        }
        $versionMinor = unpack('v', substr($b, 10, 2))[1];
        $partitionTableOffset = unpack('P', substr($b, 12, 8))[1];

        return new self($versionMajor, $versionMinor, $partitionTableOffset);
    }
}
