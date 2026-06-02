<?php

declare(strict_types=1);

namespace Kduma\PCF;

/**
 * The fixed 141-byte partition entry (spec section 5.2).
 */
final class PartitionEntry
{
    /**
     * @param int    $partitionType Application-defined type (0 and 0xFFFFFFFF reserved).
     * @param string $uid           16-byte unique identifier.
     * @param string $label         32-byte ASCII label, NUL-padded.
     * @param string $dataHash      64-byte data hash field.
     */
    public function __construct(
        public int $partitionType,
        public string $uid,
        public string $label,
        public int $startOffset,
        public int $maxLength,
        public int $usedBytes,
        public HashAlgo $dataHashAlgo,
        public string $dataHash,
    ) {
    }

    /** Serialise to the on-disk 141-byte layout. */
    public function toBytes(): string
    {
        return pack('V', $this->partitionType)
            . str_pad(substr($this->uid, 0, Consts::UID_SIZE), Consts::UID_SIZE, "\x00")
            . str_pad(substr($this->label, 0, Consts::LABEL_SIZE), Consts::LABEL_SIZE, "\x00")
            . pack('P', $this->startOffset)
            . pack('P', $this->maxLength)
            . pack('P', $this->usedBytes)
            . \chr($this->dataHashAlgo->id())
            . str_pad(substr($this->dataHash, 0, Consts::HASH_FIELD_SIZE), Consts::HASH_FIELD_SIZE, "\x00");
    }

    /** Parse from the on-disk 141-byte layout. */
    public static function fromBytes(string $b): self
    {
        if (\strlen($b) < Consts::ENTRY_SIZE) {
            throw PcfException::io('short read: partition entry truncated');
        }
        $partitionType = unpack('V', substr($b, 0, 4))[1];
        $uid = substr($b, 4, 16);
        $label = substr($b, 20, 32);
        $startOffset = unpack('P', substr($b, 52, 8))[1];
        $maxLength = unpack('P', substr($b, 60, 8))[1];
        $usedBytes = unpack('P', substr($b, 68, 8))[1];
        $dataHashAlgo = HashAlgo::fromId(\ord($b[76]));
        $dataHash = substr($b, 77, 64);

        return new self(
            $partitionType,
            $uid,
            $label,
            $startOffset,
            $maxLength,
            $usedBytes,
            $dataHashAlgo,
            $dataHash,
        );
    }

    /**
     * Apply the conformance checks a reader must run on a live entry
     * (spec C5, C6, C7).
     */
    public function validate(): void
    {
        if ($this->partitionType === Consts::TYPE_RESERVED) {
            throw PcfException::reservedType();
        }
        if ($this->uid === Consts::NIL_UID) {
            throw PcfException::nilUid();
        }
        if ($this->usedBytes > $this->maxLength) {
            throw PcfException::usedExceedsMax();
        }
        self::decodeLabel($this->label); // validates label bytes
    }

    /** Decode the label as a string (reads up to the first NUL). */
    public function labelString(): string
    {
        return self::decodeLabel($this->label);
    }

    /** Free bytes remaining in the partition (max_length - used_bytes). */
    public function freeBytes(): int
    {
        return max(0, $this->maxLength - $this->usedBytes);
    }

    /** Build a 32-byte label field from a string (spec section 10). */
    public static function encodeLabel(string $s): string
    {
        if (\strlen($s) > Consts::LABEL_SIZE) {
            throw PcfException::invalidLabel();
        }
        $len = \strlen($s);
        for ($i = 0; $i < $len; ++$i) {
            $c = \ord($s[$i]);
            if ($c === 0 || $c >= 0x80) {
                throw PcfException::invalidLabel();
            }
        }

        return str_pad($s, Consts::LABEL_SIZE, "\x00");
    }

    /**
     * Decode a 32-byte label field: read until the first NUL or 32 bytes,
     * rejecting any byte >= 0x80 (spec section 10).
     */
    public static function decodeLabel(string $label): string
    {
        $end = Consts::LABEL_SIZE;
        for ($i = 0; $i < Consts::LABEL_SIZE; ++$i) {
            $c = \ord($label[$i]);
            if ($c === 0) {
                $end = $i;
                break;
            }
            if ($c >= 0x80) {
                throw PcfException::invalidLabel();
            }
        }

        return substr($label, 0, $end);
    }
}
