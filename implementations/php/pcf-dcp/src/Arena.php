<?php

declare(strict_types=1);

namespace Kduma\PCFDCP;

use Kduma\PCF\Consts as PcfConsts;
use Kduma\PCF\HashAlgo;
use Kduma\PCF\PartitionEntry;
use Kduma\PCF\TableBlockHeader;

/**
 * The DCP arena: the in-memory model of one DCP container and its canonical
 * byte serialisation.
 *
 * An Arena holds a byte pool plus a list of inner partitions, each owning a list
 * of fragments. A fragment addresses a byte range in the pool; two fragments
 * addressing the same range share that extent (deduplication, spec Section
 * 10.2). Edits work on the fragment list and append new bytes to the pool, never
 * overwriting bytes a SHARED extent still names (copy-on-write, spec Section
 * 10.1). {@see Arena::toBytes()} always emits the canonical layout of the spec's
 * Section 17 test vector.
 *
 * Internally a fragment is an stdClass {offset:int, length:int, kind:int,
 * shared:bool} and an inner is an stdClass {partitionType:int, uid:string,
 * label:string, dataHashAlgo:HashAlgo, frags: list<stdClass>}.
 */
final class Arena
{
    private int $profileVersionMajor = Consts::PROFILE_VERSION_MAJOR;
    private int $profileVersionMinor = Consts::PROFILE_VERSION_MINOR;
    private int $flags = 0;
    private HashAlgo $innerTableAlgo = HashAlgo::Sha256;
    private string $blob = '';

    /** @var list<object> */
    private array $inners = [];

    /** Choose the hash algorithm used for inner Table Blocks (default SHA-256). */
    public function withInnerTableAlgo(HashAlgo $algo): self
    {
        $this->innerTableAlgo = $algo;

        return $this;
    }

    // ---- byte pool ---------------------------------------------------------

    private function appendBlob(string $data): int
    {
        $start = \strlen($this->blob);
        $this->blob .= $data;

        return $start;
    }

    private function blobSlice(int $off, int $len): string
    {
        return substr($this->blob, $off, $len);
    }

    // ---- parsing -----------------------------------------------------------

    /** Parse an arena from its on-disk bytes (spec Sections 6–8). */
    public static function parse(string $bytes): self
    {
        $header = DcpHeader::read($bytes);
        if ($header->profileVersionMajor !== Consts::PROFILE_VERSION_MAJOR) {
            throw PcfDcpException::unsupportedProfileMajor($header->profileVersionMajor);
        }
        $arenaUsed = $header->arenaUsed;

        $arena = new self();
        $arena->profileVersionMajor = $header->profileVersionMajor;
        $arena->profileVersionMinor = $header->profileVersionMinor;
        $arena->flags = $header->flags;
        $arena->blob = $bytes;

        $len = \strlen($bytes);
        $firstBlock = true;
        $off = $header->innerTableOffset;
        $budget = intdiv($len, PcfConsts::TABLE_HEADER_SIZE) + 1;
        while ($off !== Consts::ARENA_NONE) {
            if ($budget === 0) {
                throw PcfDcpException::offsetOutOfRange();
            }
            --$budget;
            if ($off + PcfConsts::TABLE_HEADER_SIZE > $len) {
                throw PcfDcpException::offsetOutOfRange();
            }
            $h = TableBlockHeader::fromBytes(substr($bytes, $off, PcfConsts::TABLE_HEADER_SIZE));
            if ($firstBlock) {
                $arena->innerTableAlgo = $h->tableHashAlgo;
                $firstBlock = false;
            }
            for ($i = 0; $i < $h->partitionCount; ++$i) {
                $eo = $off + PcfConsts::TABLE_HEADER_SIZE + $i * PcfConsts::ENTRY_SIZE;
                if ($eo + PcfConsts::ENTRY_SIZE > $len) {
                    throw PcfDcpException::offsetOutOfRange();
                }
                $entry = PartitionEntry::fromBytes(substr($bytes, $eo, PcfConsts::ENTRY_SIZE));
                $onDisk = FragmentTable::walk($bytes, $entry->startOffset);
                $frags = [];
                foreach ($onDisk as $fe) {
                    $frags[] = (object) [
                        'offset' => $fe->extentOffset,
                        'length' => $fe->extentLength,
                        'kind' => $fe->kind,
                        'shared' => $fe->isShared(),
                    ];
                }
                $arena->inners[] = (object) [
                    'partitionType' => $entry->partitionType,
                    'uid' => $entry->uid,
                    'label' => $entry->label,
                    'dataHashAlgo' => $entry->dataHashAlgo,
                    'frags' => $frags,
                ];
            }
            $off = $h->nextTableOffset;
        }

        foreach ($arena->inners as $inner) {
            foreach ($inner->frags as $f) {
                if ($f->offset + $f->length > $arenaUsed) {
                    throw PcfDcpException::offsetOutOfRange();
                }
            }
        }

        return $arena;
    }

    // ---- read-only views ---------------------------------------------------

    /** Number of inner partitions. */
    public function count(): int
    {
        return \count($this->inners);
    }

    /** Whether the arena has no inner partitions. */
    public function isEmpty(): bool
    {
        return \count($this->inners) === 0;
    }

    /**
     * The uids of all inner partitions, in stored order.
     *
     * @return list<string>
     */
    public function uids(): array
    {
        $out = [];
        foreach ($this->inners as $i) {
            $out[] = $i->uid;
        }

        return $out;
    }

    private function indexOf(string $uid): int
    {
        foreach ($this->inners as $i => $inner) {
            if ($inner->uid === $uid) {
                return $i;
            }
        }
        throw PcfDcpException::notFound();
    }

    private function innerLogicalLen(object $inner): int
    {
        $total = 0;
        foreach ($inner->frags as $f) {
            if ($f->kind === Consts::KIND_DATA) {
                $total += $f->length;
            }
        }

        return $total;
    }

    private function innerContent(object $inner): string
    {
        $out = '';
        foreach ($inner->frags as $f) {
            if ($f->kind === Consts::KIND_DATA) {
                $out .= $this->blobSlice($f->offset, $f->length);
            }
        }

        return $out;
    }

    private function innerDataHash(object $inner): string
    {
        return $inner->dataHashAlgo->compute($this->innerContent($inner));
    }

    private function view(object $inner): InnerInfo
    {
        $extents = [];
        foreach ($inner->frags as $f) {
            $extents[] = new ExtentInfo($f->offset, $f->length, $f->kind, $f->shared);
        }

        return new InnerInfo(
            $inner->partitionType,
            $inner->uid,
            PartitionEntry::decodeLabel($inner->label),
            $this->innerLogicalLen($inner),
            $inner->dataHashAlgo,
            $this->innerDataHash($inner),
            $extents,
        );
    }

    /** A read-only view of one inner partition. */
    public function innerInfo(string $uid): InnerInfo
    {
        return $this->view($this->inners[$this->indexOf($uid)]);
    }

    /**
     * Read-only views of every inner partition, in stored order.
     *
     * @return list<InnerInfo>
     */
    public function inners(): array
    {
        $out = [];
        foreach ($this->inners as $i) {
            $out[] = $this->view($i);
        }

        return $out;
    }

    /** Reconstruct an inner partition's logical content (spec Section 8.3). */
    public function content(string $uid): string
    {
        $inner = $this->inners[$this->indexOf($uid)];
        $bytes = $this->innerContent($inner);
        $declared = $this->innerLogicalLen($inner);
        if (\strlen($bytes) !== $declared) {
            throw PcfDcpException::lengthMismatch($declared, \strlen($bytes));
        }

        return $bytes;
    }

    // ---- builder -----------------------------------------------------------

    /**
     * Add an inner partition whose $content is split by $chunker into extents,
     * deduplicating against extents already present (spec Section 10.2).
     */
    public function addInner(
        int $partitionType,
        string $uid,
        string $label,
        string $content,
        HashAlgo $dataHashAlgo,
        Chunker $chunker,
    ): void {
        if ($partitionType === 0) {
            throw PcfDcpException::reservedType();
        }
        if ($partitionType === Consts::DCP_CONTAINER_TYPE) {
            throw PcfDcpException::nestedContainer();
        }
        if ($uid === PcfConsts::NIL_UID) {
            throw PcfDcpException::nilUid();
        }
        foreach ($this->inners as $i) {
            if ($i->uid === $uid) {
                throw PcfDcpException::duplicateUid();
            }
        }
        $labelBytes = PartitionEntry::encodeLabel($label);

        $frags = [];
        foreach (self::splitChunks($chunker, $content) as $chunk) {
            $hit = $this->findExtent($chunk) ?? self::findLocal($this->blob, $frags, $chunk);
            if ($hit !== null) {
                [$offset, $length] = $hit;
                $this->markShared($offset, $length);
                foreach ($frags as $f) {
                    if ($f->offset === $offset && $f->length === $length) {
                        $f->shared = true;
                    }
                }
                $frags[] = (object) ['offset' => $offset, 'length' => $length, 'kind' => Consts::KIND_DATA, 'shared' => true];
            } else {
                $offset = $this->appendBlob($chunk);
                $frags[] = (object) ['offset' => $offset, 'length' => \strlen($chunk), 'kind' => Consts::KIND_DATA, 'shared' => false];
            }
        }
        $this->inners[] = (object) [
            'partitionType' => $partitionType,
            'uid' => $uid,
            'label' => $labelBytes,
            'dataHashAlgo' => $dataHashAlgo,
            'frags' => $frags,
        ];
    }

    /**
     * @return list<string>
     */
    private static function splitChunks(Chunker $chunker, string $content): array
    {
        if ($content === '') {
            return [];
        }
        if ($chunker->isWhole) {
            return [$content];
        }

        return str_split($content, $chunker->size);
    }

    /**
     * @return array{0:int,1:int}|null
     */
    private function findExtent(string $chunk): ?array
    {
        if ($chunk === '') {
            return null;
        }
        $n = \strlen($chunk);
        foreach ($this->inners as $inner) {
            foreach ($inner->frags as $f) {
                if ($f->kind === Consts::KIND_DATA && $f->length === $n && $this->blobSlice($f->offset, $f->length) === $chunk) {
                    return [$f->offset, $f->length];
                }
            }
        }

        return null;
    }

    /**
     * @param list<object> $frags
     *
     * @return array{0:int,1:int}|null
     */
    private static function findLocal(string $blob, array $frags, string $chunk): ?array
    {
        if ($chunk === '') {
            return null;
        }
        $n = \strlen($chunk);
        foreach ($frags as $f) {
            if ($f->kind === Consts::KIND_DATA && $f->length === $n && substr($blob, $f->offset, $f->length) === $chunk) {
                return [$f->offset, $f->length];
            }
        }

        return null;
    }

    private function markShared(int $offset, int $length): void
    {
        foreach ($this->inners as $inner) {
            foreach ($inner->frags as $f) {
                if ($f->offset === $offset && $f->length === $length) {
                    $f->shared = true;
                }
            }
        }
    }

    // ---- logical edits (copy-on-write) -------------------------------------

    /** Append $bytes to an inner partition's content. */
    public function append(string $uid, string $bytes): void
    {
        $inner = $this->inners[$this->indexOf($uid)];
        if ($bytes === '') {
            return;
        }
        $offset = $this->appendBlob($bytes);
        $inner->frags[] = (object) ['offset' => $offset, 'length' => \strlen($bytes), 'kind' => Consts::KIND_DATA, 'shared' => false];
    }

    /** Overwrite the logical range [pos, pos+len) with $bytes. */
    public function overwrite(string $uid, int $pos, int $len, string $bytes): void
    {
        $this->delete($uid, $pos, $len);
        $this->insert($uid, $pos, $bytes);
    }

    /** Insert $bytes at logical position $pos. */
    public function insert(string $uid, int $pos, string $bytes): void
    {
        $idx = $this->indexOf($uid);
        $inner = $this->inners[$idx];
        $total = $this->innerLogicalLen($inner);
        if ($pos > $total) {
            throw PcfDcpException::positionOutOfRange();
        }
        if ($bytes === '') {
            return;
        }
        $split = $this->splitAt($inner, $pos);
        $offset = $this->appendBlob($bytes);
        $new = (object) ['offset' => $offset, 'length' => \strlen($bytes), 'kind' => Consts::KIND_DATA, 'shared' => false];
        array_splice($inner->frags, $split, 0, [$new]);
    }

    /** Delete the logical range [pos, pos+len). */
    public function delete(string $uid, int $pos, int $len): void
    {
        $idx = $this->indexOf($uid);
        $inner = $this->inners[$idx];
        $total = $this->innerLogicalLen($inner);
        $end = $pos + $len;
        if ($end > $total) {
            throw PcfDcpException::positionOutOfRange();
        }
        if ($len === 0) {
            return;
        }
        $lo = $this->splitAt($inner, $pos);
        $hi = $this->splitAt($inner, $end);
        array_splice($inner->frags, $lo, $hi - $lo);
    }

    /** Truncate the partition's logical content to $newLen bytes. */
    public function truncate(string $uid, int $newLen): void
    {
        $idx = $this->indexOf($uid);
        $inner = $this->inners[$idx];
        $total = $this->innerLogicalLen($inner);
        if ($newLen > $total) {
            throw PcfDcpException::positionOutOfRange();
        }
        $cut = $this->splitAt($inner, $newLen);
        $inner->frags = \array_slice($inner->frags, 0, $cut);
    }

    private function splitAt(object $inner, int $pos): int
    {
        $logical = 0;
        $i = 0;
        while ($i < \count($inner->frags)) {
            $f = $inner->frags[$i];
            $flen = $f->length;
            if ($logical === $pos) {
                return $i;
            }
            if ($pos < $logical + $flen) {
                $head = $pos - $logical;
                $left = (object) ['offset' => $f->offset, 'length' => $head, 'kind' => $f->kind, 'shared' => $f->shared];
                $right = (object) ['offset' => $f->offset + $head, 'length' => $flen - $head, 'kind' => $f->kind, 'shared' => $f->shared];
                $inner->frags[$i] = $left;
                array_splice($inner->frags, $i + 1, 0, [$right]);

                return $i + 1;
            }
            $logical += $flen;
            ++$i;
        }

        return \count($inner->frags);
    }

    // ---- promotion support -------------------------------------------------

    /**
     * Remove an inner partition, returning the pieces a promotion needs: its
     * type, label, hash algorithm, and reconstructed logical content.
     *
     * @return array{partitionType:int,label:string,dataHashAlgo:HashAlgo,content:string}
     */
    public function removeInner(string $uid): array
    {
        $idx = $this->indexOf($uid);
        $content = $this->content($uid);
        $inner = $this->inners[$idx];
        array_splice($this->inners, $idx, 1);

        return [
            'partitionType' => $inner->partitionType,
            'label' => PartitionEntry::decodeLabel($inner->label),
            'dataHashAlgo' => $inner->dataHashAlgo,
            'content' => $content,
        ];
    }

    // ---- deduplication and compaction --------------------------------------

    /**
     * Re-chunk every inner partition with $chunker and deduplicate identical
     * extents across the whole arena. Returns estimated bytes saved.
     */
    public function dedup(Chunker $chunker): int
    {
        $before = $this->canonicalExtentBytes();
        $rebuilt = new self();
        $rebuilt->profileVersionMajor = $this->profileVersionMajor;
        $rebuilt->profileVersionMinor = $this->profileVersionMinor;
        $rebuilt->flags = $this->flags;
        $rebuilt->innerTableAlgo = $this->innerTableAlgo;
        foreach ($this->inners as $inner) {
            $rebuilt->addInner(
                $inner->partitionType,
                $inner->uid,
                PartitionEntry::decodeLabel($inner->label),
                $this->innerContent($inner),
                $inner->dataHashAlgo,
                $chunker,
            );
        }
        $this->blob = $rebuilt->blob;
        $this->inners = $rebuilt->inners;
        $after = $this->canonicalExtentBytes();

        return max(0, $before - $after);
    }

    /**
     * Compact the arena (spec Section 10.3): drop unreferenced pool bytes and
     * normalise the SHARED flag, clearing it on any extent now referenced
     * exactly once (rule F2). Returns dead pool bytes reclaimed.
     */
    public function compact(): int
    {
        $refcount = [];
        foreach ($this->inners as $inner) {
            foreach ($inner->frags as $f) {
                $k = $f->offset . ':' . $f->length;
                $refcount[$k] = ($refcount[$k] ?? 0) + 1;
            }
        }
        foreach ($this->inners as $inner) {
            foreach ($inner->frags as $f) {
                if (($refcount[$f->offset . ':' . $f->length] ?? 0) <= 1) {
                    $f->shared = false;
                }
            }
        }
        $liveBytes = 0;
        foreach (array_keys($refcount) as $k) {
            $liveBytes += (int) explode(':', $k)[1];
        }
        $deadBefore = max(0, \strlen($this->blob) - $liveBytes);

        $newBlob = '';
        $remap = [];
        foreach ($this->inners as $inner) {
            foreach ($inner->frags as $f) {
                $k = $f->offset . ':' . $f->length;
                if (!isset($remap[$k])) {
                    $remap[$k] = \strlen($newBlob);
                    $newBlob .= $this->blobSlice($f->offset, $f->length);
                }
            }
        }
        foreach ($this->inners as $inner) {
            foreach ($inner->frags as $f) {
                $f->offset = $remap[$f->offset . ':' . $f->length];
            }
        }
        $this->blob = $newBlob;

        return $deadBefore;
    }

    private function canonicalExtentBytes(): int
    {
        $seen = [];
        $total = 0;
        foreach ($this->inners as $inner) {
            foreach ($inner->frags as $f) {
                $k = $f->offset . ':' . $f->length;
                if (!isset($seen[$k])) {
                    $seen[$k] = true;
                    $total += $f->length;
                }
            }
        }

        return $total;
    }

    // ---- canonical serialisation -------------------------------------------

    /** Serialise the arena into its canonical on-disk layout (spec Section 17). */
    public function toBytes(): string
    {
        // 1. distinct extents, first-reference order
        $extOrder = [];
        $extIndex = [];
        foreach ($this->inners as $inner) {
            foreach ($inner->frags as $f) {
                $k = $f->offset . ':' . $f->length;
                if (!isset($extIndex[$k])) {
                    $extIndex[$k] = \count($extOrder);
                    $extOrder[] = [$f->offset, $f->length];
                }
            }
        }

        // 2. lay out extents right after the header
        $cur = Consts::DCP_HEADER_SIZE;
        $extArenaOff = [];
        foreach ($extOrder as [$off, $len]) {
            $extArenaOff[] = $cur;
            $cur += $len;
        }

        // 3. Fragment Tables (one chain per inner)
        $fragOff = [];
        foreach ($this->inners as $inner) {
            $fragOff[] = $cur;
            $cur += self::fragtableSpan(\count($inner->frags));
        }

        // 4. Inner Table Block(s)
        $innerTableOffset = $cur;
        $counts = self::blockCounts(\count($this->inners));
        $blockOff = [];
        foreach ($counts as $c) {
            $blockOff[] = $cur;
            $cur += PcfConsts::TABLE_HEADER_SIZE + $c * PcfConsts::ENTRY_SIZE;
        }
        $arenaUsed = $cur;

        // header
        $buf = (new DcpHeader(
            $this->profileVersionMajor,
            $this->profileVersionMinor,
            $this->flags,
            $innerTableOffset,
            $arenaUsed,
        ))->toBytes();

        // extents (first-reference order)
        foreach ($extOrder as [$off, $len]) {
            $buf .= $this->blobSlice($off, $len);
        }

        // fragment tables
        foreach ($this->inners as $ii => $inner) {
            $buf .= self::writeFragmentTable($fragOff[$ii], $inner->frags, $extIndex, $extArenaOff);
        }

        // inner table block(s)
        $entries = [];
        foreach ($this->inners as $ii => $inner) {
            $used = $this->innerLogicalLen($inner);
            $entries[] = new PartitionEntry(
                $inner->partitionType,
                $inner->uid,
                $inner->label,
                $fragOff[$ii],
                $used,
                $used,
                $inner->dataHashAlgo,
                $this->innerDataHash($inner),
            );
        }

        $idx = 0;
        foreach ($counts as $b => $c) {
            $next = $b + 1 < \count($counts) ? $blockOff[$b + 1] : 0;
            $slice = \array_slice($entries, $idx, $c);
            $th = TableBlockHeader::computeTableHash($this->innerTableAlgo, $next, $slice);
            $bh = new TableBlockHeader($c, $next, $this->innerTableAlgo, $th);
            $buf .= $bh->toBytes();
            foreach ($slice as $e) {
                $buf .= $e->toBytes();
            }
            $idx += $c;
        }

        return $buf;
    }

    private static function fragtableSpan(int $n): int
    {
        $span = 0;
        foreach (self::blockCounts($n) as $c) {
            $span += Consts::FRAGTABLE_HEADER_SIZE + $c * Consts::FRAGMENT_ENTRY_SIZE;
        }

        return $span;
    }

    /**
     * @return list<int>
     */
    private static function blockCounts(int $n): array
    {
        if ($n === 0) {
            return [0];
        }
        $out = [];
        $rem = $n;
        while ($rem > 0) {
            $c = min($rem, Consts::MAX_ENTRIES_PER_BLOCK);
            $out[] = $c;
            $rem -= $c;
        }

        return $out;
    }

    /**
     * Serialise one inner partition's Fragment Table chain whose first block
     * sits at absolute arena offset $start.
     *
     * @param list<object> $frags
     * @param array<string,int> $extIndex
     * @param list<int> $extArenaOff
     */
    private static function writeFragmentTable(int $start, array $frags, array $extIndex, array $extArenaOff): string
    {
        $counts = self::blockCounts(\count($frags));
        $out = '';
        $blockStart = $start;
        $idx = 0;
        foreach ($counts as $b => $c) {
            $span = Consts::FRAGTABLE_HEADER_SIZE + $c * Consts::FRAGMENT_ENTRY_SIZE;
            $next = $b + 1 < \count($counts) ? $blockStart + $span : 0;
            $out .= (new FragTableHeader($next, $c))->toBytes();
            for ($j = 0; $j < $c; ++$j) {
                $f = $frags[$idx + $j];
                $arenaOff = $extArenaOff[$extIndex[$f->offset . ':' . $f->length]];
                $out .= (new FragmentEntry($arenaOff, $f->length, $f->kind, $f->shared ? Consts::FLAG_SHARED : 0))->toBytes();
            }
            $blockStart += $span;
            $idx += $c;
        }

        return $out;
    }
}
