<?php

declare(strict_types=1);

namespace Kduma\PCF;

/**
 * One table block read from disk: its absolute offset, its parsed
 * {@see TableBlockHeader} (including table_hash and next_table_offset), and its
 * {@see PartitionEntry} list.
 *
 * This is a read-only view returned by {@see Container::readBlockAt()}. It lets
 * code layered on PCF group blocks, inspect each block's table_hash, and follow
 * non-default next_table_offset chains, instead of {@see Container::entries()}
 * which flattens the whole chain.
 */
final class BlockView
{
    /**
     * @param PartitionEntry[] $entries the block's entries, in stored order
     */
    public function __construct(
        public int $offset,
        public TableBlockHeader $header,
        public array $entries,
    ) {
    }
}
