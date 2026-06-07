<?php

declare(strict_types=1);

namespace Kduma\PCF;

/**
 * The optional fixed 20-byte file trailer (spec section 4, "File Trailer").
 *
 * A trailer is present only when the file header's partition_table_offset holds
 * the {@see Consts::PT_OFFSET_TRAILER} sentinel. It occupies the final
 * {@see Consts::TRAILER_SIZE} bytes of the file and records the real offset of
 * the partition-table head together with the chain direction. Because every
 * append places a fresh trailer at the new end of file, the file's last bytes
 * always point at the newest table — enabling append-only writers with no
 * in-place header rewrite.
 */
final class Trailer
{
    public function __construct(
        public int $partitionTableOffset,
        public int $chainFlags,
    ) {
    }

    /** Serialise to the on-disk 20-byte layout (reserved bytes 9..12 are zero). */
    public function toBytes(): string
    {
        return pack('P', $this->partitionTableOffset)
            . chr($this->chainFlags & 0xFF)
            . "\x00\x00\x00"
            . Consts::TRAILER_MAGIC;
    }

    /**
     * Parse from the on-disk 20-byte layout, validating the trailer magic.
     *
     * @throws PcfException (BadTrailer) if the magic does not match.
     */
    public static function fromBytes(string $b): self
    {
        if (\strlen($b) < Consts::TRAILER_SIZE) {
            throw PcfException::badTrailer();
        }
        if (substr($b, 12, 8) !== Consts::TRAILER_MAGIC) {
            throw PcfException::badTrailer();
        }
        $off = unpack('P', substr($b, 0, 8))[1];

        return new self($off, \ord($b[8]));
    }
}
