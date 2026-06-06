<?php

declare(strict_types=1);

namespace Kduma\PCF;

/**
 * The 74-byte table-block header and table-block hashing (spec section 5.1,
 * 8.4).
 */
final class TableBlockHeader
{
    public function __construct(
        public int $partitionCount,
        public int $nextTableOffset,
        public HashAlgo $tableHashAlgo,
        public string $tableHash,
    ) {
    }

    /** Serialise to the on-disk 74-byte layout. */
    public function toBytes(): string
    {
        return \chr($this->partitionCount & 0xFF)
            . pack('P', $this->nextTableOffset)
            . \chr($this->tableHashAlgo->id())
            . str_pad(substr($this->tableHash, 0, Consts::HASH_FIELD_SIZE), Consts::HASH_FIELD_SIZE, "\x00");
    }

    /** Parse from the on-disk 74-byte layout. */
    public static function fromBytes(string $b): self
    {
        if (\strlen($b) < Consts::TABLE_HEADER_SIZE) {
            throw PcfException::io('short read: table block header truncated');
        }
        $partitionCount = \ord($b[0]);
        $nextTableOffset = unpack('P', substr($b, 1, 8))[1];
        $tableHashAlgo = HashAlgo::fromId(\ord($b[9]));
        $tableHash = substr($b, 10, 64);

        return new self($partitionCount, $nextTableOffset, $tableHashAlgo, $tableHash);
    }

    /**
     * Compute the table hash over [header-with-zeroed-hash || entries]
     * (spec section 8.4). The table_hash_algo byte is included; the 64-byte
     * hash field is treated as zero; trailing reserved space is excluded.
     *
     * @param PartitionEntry[] $entries
     */
    public static function computeTableHash(HashAlgo $algo, int $nextTableOffset, array $entries): string
    {
        $header = new self(\count($entries), $nextTableOffset, $algo, str_repeat("\x00", Consts::HASH_FIELD_SIZE));
        $image = $header->toBytes();
        foreach ($entries as $e) {
            $image .= $e->toBytes();
        }

        return $algo->compute($image);
    }
}
