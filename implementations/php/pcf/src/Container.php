<?php

declare(strict_types=1);

namespace Kduma\PCF;

use Kduma\PCF\Storage\MemoryStorage;
use Kduma\PCF\Storage\StorageInterface;

/**
 * The high-level container type: reading and writing whole PCF files over any
 * {@see StorageInterface} (in-memory or stream-backed).
 *
 * Reader vs. writer scope
 * -----------------------
 * The reader side (open, entries, readPartitionData, verify) is fully general:
 * it accepts any conforming file, including arbitrary region placement and
 * overflow-block chains.
 *
 * The writer side implements one documented placement strategy (the format
 * deliberately leaves layout to the writer, spec section 12 / A7, A9):
 *
 *  - The first table block sits immediately after the header and is created with
 *    reserved capacity for $firstBlockCapacity entries, so entries can be
 *    appended in place without moving data.
 *  - Partition data is appended at a growing end-of-data cursor; each partition
 *    may reserve $extraReserve spare bytes for later in-place growth.
 *  - When every known block is full, a new overflow block is appended and linked
 *    into the chain.
 *  - Block capacity is not stored in the file (spec A9); it is tracked only in
 *    memory for the lifetime of this handle. After open(), blocks are treated as
 *    having no spare capacity, so subsequent additions go into fresh overflow
 *    blocks. compactedImage() rebuilds a tightly packed file.
 */
final class Container
{
    /**
     * In-memory bookkeeping for one table block (not stored on disk).
     *
     * @var array<int, array{offset:int,capacity:int,count:int,algo:HashAlgo,next:int}>
     */
    private array $blocks = [];

    private int $dataEof = 0;

    /**
     * Resolved absolute offset of the partition-table head: the header pointer
     * for a classic file, or the offset from the file {@see Trailer} when the
     * header holds {@see Consts::PT_OFFSET_TRAILER}. 0 denotes an empty table.
     */
    private int $tableHead = 0;

    /** Chain-direction flags resolved at open time (see {@see Trailer}). */
    private int $chainFlags = Consts::CHAIN_FORWARD;

    private function __construct(
        private StorageInterface $storage,
        private FileHeader $header,
        private int $defaultCapacity,
        private HashAlgo $tableHashAlgo,
    ) {
    }

    // ---- construction ------------------------------------------------------

    /**
     * Create an empty container with sensible defaults (first block capacity 16,
     * table hashing with SHA-256).
     */
    public static function create(?StorageInterface $storage = null): self
    {
        return self::createWith($storage ?? new MemoryStorage(), 16, HashAlgo::Sha256);
    }

    /**
     * Create an empty container, choosing the first block's reserved capacity
     * and the table-hash algorithm.
     */
    public static function createWith(
        StorageInterface $storage,
        int $firstBlockCapacity,
        HashAlgo $tableHashAlgo,
    ): self {
        $cap = max(1, min($firstBlockCapacity, Consts::MAX_ENTRIES_PER_BLOCK));
        $header = new FileHeader(Consts::VERSION_MAJOR, Consts::VERSION_MINOR, Consts::HEADER_SIZE);
        $storage->writeAt(0, $header->toBytes());

        $self = new self($storage, $header, $cap, $tableHashAlgo);
        $self->writeBlock(Consts::HEADER_SIZE, 0, $tableHashAlgo, []);
        $self->blocks[] = [
            'offset' => Consts::HEADER_SIZE,
            'capacity' => $cap,
            'count' => 0,
            'algo' => $tableHashAlgo,
            'next' => 0,
        ];
        $self->dataEof = Consts::HEADER_SIZE + Consts::TABLE_HEADER_SIZE + $cap * Consts::ENTRY_SIZE;
        $self->tableHead = Consts::HEADER_SIZE;

        return $self;
    }

    /**
     * Open an existing container, validating the header (spec C1, C2).
     *
     * When the header's partition_table_offset is the
     * {@see Consts::PT_OFFSET_TRAILER} sentinel, the partition-table head and
     * chain direction are read from the file {@see Trailer} (located by scanning
     * backward from the end of the file). Chain traversal is identical in both
     * directions (follow next_table_offset until 0); the direction only conveys
     * which end is newest, exposed via {@see chainIsBackward()}.
     */
    public static function open(StorageInterface $storage): self
    {
        $header = FileHeader::fromBytes($storage->readAt(0, Consts::HEADER_SIZE));
        $self = new self($storage, $header, 16, HashAlgo::Sha256);

        if ($header->partitionTableOffset === Consts::PT_OFFSET_TRAILER) {
            [$self->tableHead, $self->chainFlags] = self::locateTrailer($storage);
        } else {
            $self->tableHead = $header->partitionTableOffset;
            $self->chainFlags = Consts::CHAIN_FORWARD;
        }

        $blocks = [];
        $off = $self->tableHead;
        while ($off !== 0) {
            $h = $self->readBlockHeader($off);
            $blocks[] = [
                'offset' => $off,
                'capacity' => $h->partitionCount, // no known spare after open
                'count' => $h->partitionCount,
                'algo' => $h->tableHashAlgo,
                'next' => $h->nextTableOffset,
            ];
            $off = $h->nextTableOffset;
        }
        if (isset($blocks[0])) {
            $self->tableHashAlgo = $blocks[0]['algo'];
        }
        $self->blocks = $blocks;
        $self->dataEof = $storage->size();

        return $self;
    }

    /** The backing store. */
    public function storage(): StorageInterface
    {
        return $this->storage;
    }

    /**
     * The parsed file header. In trailer mode its partition_table_offset holds
     * the {@see Consts::PT_OFFSET_TRAILER} sentinel; use {@see tableHead()} for
     * the resolved head.
     */
    public function header(): FileHeader
    {
        return $this->header;
    }

    /**
     * The resolved absolute offset of the partition-table head (0 if empty).
     * This is the value to follow regardless of header-pointer vs trailer mode.
     */
    public function tableHead(): int
    {
        return $this->tableHead;
    }

    /**
     * Whether the chain is backward-linked (head = newest block,
     * next_table_offset points at the previous/older block). Classic
     * header-pointer files are always forward.
     */
    public function chainIsBackward(): bool
    {
        return ($this->chainFlags & 1) !== 0;
    }

    /**
     * Locate the most recent valid file trailer by scanning backward from the
     * end of the file for the last 20-byte window ending in
     * {@see Consts::TRAILER_MAGIC} whose recorded head is empty (0) or
     * references a parseable table block. Bytes after that trailer — an
     * incomplete or aborted append — are ignored, which gives append-only
     * writers crash recovery for free. In the clean case the trailer is the
     * final {@see Consts::TRAILER_SIZE} bytes.
     *
     * @return array{0:int,1:int} [head, chainFlags]
     */
    private static function locateTrailer(StorageInterface $storage): array
    {
        $end = $storage->size();
        while ($end >= Consts::TRAILER_SIZE) {
            $start = $end - Consts::TRAILER_SIZE;
            $window = $storage->readAt($start, Consts::TRAILER_SIZE);
            if (substr($window, 12, 8) === Consts::TRAILER_MAGIC) {
                $t = Trailer::fromBytes($window);
                $head = $t->partitionTableOffset;
                if ($head === 0) {
                    return [0, $t->chainFlags];
                }
                if ($head >= 0 && $head <= $start - Consts::TABLE_HEADER_SIZE) {
                    try {
                        TableBlockHeader::fromBytes($storage->readAt($head, Consts::TABLE_HEADER_SIZE));

                        return [$head, $t->chainFlags];
                    } catch (PcfException) {
                        // Spurious magic in an aborted tail; keep scanning.
                    }
                }
            }
            --$end;
        }
        throw PcfException::badTrailer();
    }

    // ---- low-level I/O -----------------------------------------------------

    private function readBlockHeader(int $off): TableBlockHeader
    {
        return TableBlockHeader::fromBytes($this->storage->readAt($off, Consts::TABLE_HEADER_SIZE));
    }

    /**
     * @return array{0: TableBlockHeader, 1: PartitionEntry[]}
     */
    private function readBlock(int $off): array
    {
        $h = $this->readBlockHeader($off);
        $entries = [];
        for ($i = 0; $i < $h->partitionCount; ++$i) {
            $entryOff = $off + Consts::TABLE_HEADER_SIZE + $i * Consts::ENTRY_SIZE;
            $entries[] = PartitionEntry::fromBytes($this->storage->readAt($entryOff, Consts::ENTRY_SIZE));
        }

        return [$h, $entries];
    }

    /**
     * @param PartitionEntry[] $entries
     */
    private function writeBlock(int $off, int $next, HashAlgo $algo, array $entries): void
    {
        $hash = TableBlockHeader::computeTableHash($algo, $next, $entries);
        $header = new TableBlockHeader(\count($entries), $next, $algo, $hash);
        $buf = $header->toBytes();
        foreach ($entries as $e) {
            $buf .= $e->toBytes();
        }
        $this->storage->writeAt($off, $buf);
    }

    // ---- reading -----------------------------------------------------------

    /**
     * All live partition entries, in chain order.
     *
     * @return PartitionEntry[]
     */
    public function entries(): array
    {
        $out = [];
        $off = $this->tableHead;
        while ($off !== 0) {
            [$h, $entries] = $this->readBlock($off);
            foreach ($entries as $e) {
                $out[] = $e;
            }
            $off = $h->nextTableOffset;
        }

        return $out;
    }

    /**
     * Read a single table block at an absolute offset, returning its parsed
     * header (including table_hash) and entries.
     *
     * Unlike {@see entries()}, which flattens the whole chain, this exposes one
     * block at a time so a caller can follow an arbitrary next_table_offset
     * chain and inspect each block's table_hash. Read-only.
     */
    public function readBlockAt(int $offset): BlockView
    {
        [$h, $entries] = $this->readBlock($offset);

        return new BlockView($offset, $h, $entries);
    }

    /** Read a partition's used data. */
    public function readPartitionData(PartitionEntry $entry): string
    {
        if ($entry->usedBytes === 0) {
            return '';
        }

        return $this->storage->readAt($entry->startOffset, $entry->usedBytes);
    }

    /**
     * @return array{0:int,1:int,2:PartitionEntry} [blockOffset, slotIndex, entry]
     */
    private function locate(string $uid): array
    {
        $off = $this->tableHead;
        while ($off !== 0) {
            [$h, $entries] = $this->readBlock($off);
            foreach ($entries as $i => $e) {
                if ($e->uid === $uid) {
                    return [$off, $i, $e];
                }
            }
            $off = $h->nextTableOffset;
        }
        throw PcfException::notFound();
    }

    private function blockIndex(int $offset): int
    {
        foreach ($this->blocks as $i => $b) {
            if ($b['offset'] === $offset) {
                return $i;
            }
        }
        throw PcfException::io('internal: block offset must be tracked');
    }

    // ---- writing -----------------------------------------------------------

    /**
     * Add a new partition. The data is appended at the end-of-data cursor and
     * reserves $extraReserve spare bytes for later in-place growth.
     */
    public function addPartition(
        int $partitionType,
        string $uid,
        string $label,
        string $data,
        int $extraReserve = 0,
        HashAlgo $dataHashAlgo = HashAlgo::Sha256,
    ): void {
        if ($partitionType === Consts::TYPE_RESERVED) {
            throw PcfException::reservedType();
        }
        $uid = str_pad(substr($uid, 0, Consts::UID_SIZE), Consts::UID_SIZE, "\x00");
        if ($uid === Consts::NIL_UID) {
            throw PcfException::nilUid();
        }
        foreach ($this->entries() as $e) {
            if ($e->uid === $uid) {
                throw PcfException::duplicateUid();
            }
        }

        $label = PartitionEntry::encodeLabel($label);
        $used = \strlen($data);
        $max = $used + $extraReserve;
        $start = $this->dataEof;
        if ($used > 0) {
            $this->storage->writeAt($start, $data);
        }
        $this->dataEof += $max;
        $dataHash = $dataHashAlgo->compute($data);

        $entry = new PartitionEntry(
            $partitionType,
            $uid,
            $label,
            $start,
            $max,
            $used,
            $dataHashAlgo,
            $dataHash,
        );

        // Find an existing block with reserved room.
        $target = null;
        foreach ($this->blocks as $i => $b) {
            if ($b['count'] < $b['capacity'] && $b['count'] < Consts::MAX_ENTRIES_PER_BLOCK) {
                $target = $i;
                break;
            }
        }

        if ($target !== null) {
            $boff = $this->blocks[$target]['offset'];
            [, $entries] = $this->readBlock($boff);
            $entries[] = $entry;
            $this->writeBlock($boff, $this->blocks[$target]['next'], $this->blocks[$target]['algo'], $entries);
            $this->blocks[$target]['count']++;

            return;
        }

        // Allocate a new overflow block at the end-of-data cursor.
        $newOff = $this->dataEof;
        $cap = max(1, min($this->defaultCapacity, Consts::MAX_ENTRIES_PER_BLOCK));
        $this->dataEof = $newOff + Consts::TABLE_HEADER_SIZE + $cap * Consts::ENTRY_SIZE;
        $algo = $this->tableHashAlgo;
        $this->writeBlock($newOff, 0, $algo, [$entry]);

        // Re-link the previous tail block to point at the new block.
        $tailIdx = \count($this->blocks) - 1;
        $tail = $this->blocks[$tailIdx];
        [, $tentries] = $this->readBlock($tail['offset']);
        $this->writeBlock($tail['offset'], $newOff, $tail['algo'], $tentries);
        $this->blocks[$tailIdx]['next'] = $newOff;
        $this->blocks[] = [
            'offset' => $newOff,
            'capacity' => $cap,
            'count' => 1,
            'algo' => $algo,
            'next' => 0,
        ];
    }

    /**
     * Replace a partition's data in place (spec section 8.5, hash cascade).
     * Fails if $newData exceeds the partition's reservation.
     */
    public function updatePartitionData(string $uid, string $newData): void
    {
        $uid = str_pad(substr($uid, 0, Consts::UID_SIZE), Consts::UID_SIZE, "\x00");
        [$boff, $slot, $entry] = $this->locate($uid);
        if (\strlen($newData) > $entry->maxLength) {
            throw PcfException::dataTooLarge();
        }
        if ($newData !== '') {
            $this->storage->writeAt($entry->startOffset, $newData);
        }
        $entry->usedBytes = \strlen($newData);
        $entry->dataHash = $entry->dataHashAlgo->compute($newData);

        [, $entries] = $this->readBlock($boff);
        $entries[$slot] = $entry;
        $bi = $this->blockIndex($boff);
        $this->writeBlock($boff, $this->blocks[$bi]['next'], $this->blocks[$bi]['algo'], $entries);
    }

    /**
     * Remove a partition. Entries after it in the same block shift down; the
     * freed data region becomes dead space until compaction reclaims it
     * (spec section 11.4).
     */
    public function removePartition(string $uid): void
    {
        $uid = str_pad(substr($uid, 0, Consts::UID_SIZE), Consts::UID_SIZE, "\x00");
        [$boff, $slot] = $this->locate($uid);
        [, $entries] = $this->readBlock($boff);
        array_splice($entries, $slot, 1);
        $bi = $this->blockIndex($boff);
        $this->writeBlock($boff, $this->blocks[$bi]['next'], $this->blocks[$bi]['algo'], $entries);
        $this->blocks[$bi]['count']--;
    }

    // ---- integrity ---------------------------------------------------------

    /**
     * Verify every table block and every partition's data against its stored
     * hash, and run the per-entry conformance checks (spec section 12).
     */
    public function verify(): void
    {
        $off = $this->tableHead;
        while ($off !== 0) {
            [$h, $entries] = $this->readBlock($off);
            if ($h->tableHashAlgo->verifies()) {
                $computed = TableBlockHeader::computeTableHash($h->tableHashAlgo, $h->nextTableOffset, $entries);
                $n = $h->tableHashAlgo->digestLen();
                if (!hash_equals(substr($computed, 0, $n), substr($h->tableHash, 0, $n))) {
                    throw PcfException::tableHashMismatch();
                }
            }
            foreach ($entries as $e) {
                $e->validate();
                $data = $this->readPartitionData($e);
                if (!$e->dataHashAlgo->verify($data, $e->dataHash)) {
                    throw PcfException::dataHashMismatch();
                }
            }
            $off = $h->nextTableOffset;
        }
    }

    // ---- compaction --------------------------------------------------------

    /**
     * Build a freshly compacted image: all dead space removed, every max_length
     * trimmed to used_bytes, partitions placed contiguously after a tightly
     * packed table (spec section 11.5). The current handle is left unchanged;
     * write the bytes to a new store and re-open it.
     */
    public function compactedImage(): string
    {
        // Gather live entries and their data, in chain order.
        /** @var array<int, array{0:PartitionEntry,1:string}> $live */
        $live = [];
        $off = $this->tableHead;
        while ($off !== 0) {
            [$h, $entries] = $this->readBlock($off);
            foreach ($entries as $e) {
                $live[] = [$e, $this->readPartitionData($e)];
            }
            $off = $h->nextTableOffset;
        }

        $algo = $this->tableHashAlgo;
        $n = \count($live);
        $numBlocks = $n === 0 ? 1 : intdiv($n + Consts::MAX_ENTRIES_PER_BLOCK - 1, Consts::MAX_ENTRIES_PER_BLOCK);

        $counts = [];
        $rem = $n;
        for ($i = 0; $i < $numBlocks; ++$i) {
            $c = min($rem, Consts::MAX_ENTRIES_PER_BLOCK);
            $counts[] = $c;
            $rem -= $c;
        }

        $blockOffsets = [];
        $o = Consts::HEADER_SIZE;
        foreach ($counts as $c) {
            $blockOffsets[] = $o;
            $o += Consts::TABLE_HEADER_SIZE + $c * Consts::ENTRY_SIZE;
        }
        $dataStart = $o;

        // Assign contiguous data offsets; trim reservations to used size.
        $d = $dataStart;
        foreach ($live as $idx => [$e, $data]) {
            $e->startOffset = $d;
            $e->usedBytes = \strlen($data);
            $e->maxLength = \strlen($data);
            // data_hash is unchanged because the content is unchanged.
            $live[$idx][0] = $e;
            $d += \strlen($data);
        }

        // Serialise.
        $header = new FileHeader(Consts::VERSION_MAJOR, Consts::VERSION_MINOR, Consts::HEADER_SIZE);
        $image = $header->toBytes();

        $cursor = 0;
        foreach ($counts as $bi => $c) {
            $next = ($bi + 1 < $numBlocks) ? $blockOffsets[$bi + 1] : 0;
            $slice = [];
            for ($k = 0; $k < $c; ++$k) {
                $slice[] = $live[$cursor + $k][0];
            }
            $th = TableBlockHeader::computeTableHash($algo, $next, $slice);
            $bh = new TableBlockHeader($c, $next, $algo, $th);
            $image .= $bh->toBytes();
            foreach ($slice as $e) {
                $image .= $e->toBytes();
            }
            $cursor += $c;
        }

        foreach ($live as [$e, $data]) {
            $image .= $data;
        }

        return $image;
    }

    /** Write a compacted copy of the container to $out. */
    public function compactInto(StorageInterface $out): void
    {
        $out->writeAt(0, $this->compactedImage());
    }

    // ---- trailer mode ------------------------------------------------------

    /**
     * Convert the file to trailer mode: append a fixed {@see Trailer} at the end
     * of the file recording the current partition-table head, then overwrite the
     * header's partition_table_offset with the {@see Consts::PT_OFFSET_TRAILER}
     * sentinel so the head is located via that trailer. The chain built by this
     * writer is forward-linked, so the trailer records {@see Consts::CHAIN_FORWARD}.
     */
    public function finalizeWithTrailer(): void
    {
        $trailer = new Trailer($this->tableHead, Consts::CHAIN_FORWARD);
        $pos = $this->storage->size();
        $this->storage->writeAt($pos, $trailer->toBytes());
        $this->header->partitionTableOffset = Consts::PT_OFFSET_TRAILER;
        $this->storage->writeAt(0, $this->header->toBytes());
        $this->chainFlags = Consts::CHAIN_FORWARD;
        $this->dataEof = $pos + Consts::TRAILER_SIZE;
    }
}
