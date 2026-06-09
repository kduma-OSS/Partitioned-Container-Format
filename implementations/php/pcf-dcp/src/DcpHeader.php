<?php

declare(strict_types=1);

namespace Kduma\PCFDCP;

/** The fixed 24-byte DCP Header at arena offset 0 (spec Section 6). */
final class DcpHeader
{
    public function __construct(
        public int $profileVersionMajor,
        public int $profileVersionMinor,
        public int $flags,
        public int $innerTableOffset,
        public int $arenaUsed,
    ) {
    }

    /** Serialise to the on-disk 24-byte layout. */
    public function toBytes(): string
    {
        return Consts::DCP_MAGIC
            . \chr($this->profileVersionMajor & 0xFF)
            . \chr($this->profileVersionMinor & 0xFF)
            . pack('v', $this->flags & 0xFFFF)
            . pack('P', $this->innerTableOffset)
            . pack('P', $this->arenaUsed);
    }

    /** Parse from the on-disk 24-byte layout, validating the magic. */
    public static function fromBytes(string $b): self
    {
        if (\strlen($b) < Consts::DCP_HEADER_SIZE || substr($b, 0, 4) !== Consts::DCP_MAGIC) {
            throw PcfDcpException::badDcpMagic();
        }

        return new self(
            \ord($b[4]),
            \ord($b[5]),
            unpack('v', substr($b, 6, 2))[1],
            unpack('P', substr($b, 8, 8))[1],
            unpack('P', substr($b, 16, 8))[1],
        );
    }

    /** Read a DCP Header from the start of an arena byte string. */
    public static function read(string $arena): self
    {
        if (\strlen($arena) < Consts::DCP_HEADER_SIZE) {
            throw PcfDcpException::badDcpMagic();
        }

        return self::fromBytes(substr($arena, 0, Consts::DCP_HEADER_SIZE));
    }
}
