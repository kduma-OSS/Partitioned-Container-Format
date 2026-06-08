<?php

declare(strict_types=1);

namespace Kduma\PCFDCP;

use Kduma\PCF\Consts as PcfConsts;
use Kduma\PCF\Container;
use Kduma\PCF\PartitionEntry;
use Kduma\PCF\Storage\StorageInterface;
use Kduma\PCF\TableBlockHeader;

/**
 * A reader for DCP containers layered over a PCF file. It works entirely through
 * the high-level {@see Container} API, so a DCP file written in trailer mode
 * reads back transparently.
 */
final class DcpReader
{
    private function __construct(
        private readonly Container $container,
    ) {
    }

    /** Open a PCF file for DCP-aware reading. */
    public static function open(StorageInterface $storage): self
    {
        return new self(Container::open($storage));
    }

    /** Borrow the underlying PCF container. */
    public function container(): Container
    {
        return $this->container;
    }

    /**
     * All top-level entries, in chain order.
     *
     * @return PartitionEntry[]
     */
    public function entries(): array
    {
        return $this->container->entries();
    }

    /**
     * The top-level DCP container entries.
     *
     * @return PartitionEntry[]
     */
    public function containers(): array
    {
        $out = [];
        foreach ($this->container->entries() as $e) {
            if ($e->partitionType === Consts::DCP_CONTAINER_TYPE) {
                $out[] = $e;
            }
        }

        return $out;
    }

    /** Parse the arena of a DCP container entry. */
    public function openArena(PartitionEntry $entry): Arena
    {
        if ($entry->partitionType !== Consts::DCP_CONTAINER_TYPE) {
            throw PcfDcpException::notADcpContainer();
        }

        return Arena::parse($this->container->readPartitionData($entry));
    }

    /**
     * Every inner partition across every DCP container, in file order.
     *
     * @return InnerLocation[]
     */
    public function innerPartitions(): array
    {
        $out = [];
        foreach ($this->containers() as $cont) {
            $arena = $this->openArena($cont);
            foreach ($arena->inners() as $info) {
                $out[] = new InnerLocation($cont->uid, $info);
            }
        }

        return $out;
    }

    /** Resolve a uid against the flattened set top-level ∪ inner (spec 2.1). */
    public function resolveUid(string $uid): Resolved
    {
        foreach ($this->container->entries() as $e) {
            if ($e->uid === $uid) {
                return Resolved::topLevel($e);
            }
        }
        foreach ($this->innerPartitions() as $loc) {
            if ($loc->info->uid === $uid) {
                return Resolved::innerPartition($loc);
            }
        }
        throw PcfDcpException::notFound();
    }

    /** Reconstruct an inner partition's logical content by uid. */
    public function readInner(string $uid): string
    {
        foreach ($this->containers() as $cont) {
            $arena = $this->openArena($cont);
            foreach ($arena->uids() as $u) {
                if ($u === $uid) {
                    return $arena->content($uid);
                }
            }
        }
        throw PcfDcpException::notFound();
    }

    /**
     * Full DCP-aware verification: PCF integrity, each inner Table Block's
     * table_hash, reconstruction length and (when algorithmic) data_hash, no
     * nested container, and file-wide uid uniqueness.
     */
    public function verify(): void
    {
        $this->container->verify();

        $seen = [];
        foreach ($this->container->entries() as $e) {
            $k = bin2hex($e->uid);
            if (isset($seen[$k])) {
                throw PcfDcpException::duplicateUid();
            }
            $seen[$k] = true;
        }

        foreach ($this->containers() as $cont) {
            $data = $this->container->readPartitionData($cont);
            self::verifyInnerTableHashes($data);

            $arena = Arena::parse($data);
            foreach ($arena->inners() as $info) {
                if ($info->partitionType === Consts::DCP_CONTAINER_TYPE) {
                    throw PcfDcpException::nestedContainer();
                }
                $k = bin2hex($info->uid);
                if (isset($seen[$k])) {
                    throw PcfDcpException::duplicateUid();
                }
                $seen[$k] = true;

                $content = $arena->content($info->uid);
                if (\strlen($content) !== $info->usedBytes) {
                    throw PcfDcpException::lengthMismatch($info->usedBytes, \strlen($content));
                }
                if (!$info->dataHashAlgo->verify($content, $info->dataHash)) {
                    throw PcfDcpException::hashMismatch();
                }
            }
        }
    }

    private static function verifyInnerTableHashes(string $arena): void
    {
        $header = DcpHeader::read($arena);
        $len = \strlen($arena);
        $off = $header->innerTableOffset;
        $budget = intdiv($len, PcfConsts::TABLE_HEADER_SIZE) + 1;
        while ($off !== 0) {
            if ($budget === 0) {
                throw PcfDcpException::offsetOutOfRange();
            }
            --$budget;
            if ($off + PcfConsts::TABLE_HEADER_SIZE > $len) {
                throw PcfDcpException::offsetOutOfRange();
            }
            $h = TableBlockHeader::fromBytes(substr($arena, $off, PcfConsts::TABLE_HEADER_SIZE));
            $entries = [];
            for ($i = 0; $i < $h->partitionCount; ++$i) {
                $eo = $off + PcfConsts::TABLE_HEADER_SIZE + $i * PcfConsts::ENTRY_SIZE;
                if ($eo + PcfConsts::ENTRY_SIZE > $len) {
                    throw PcfDcpException::offsetOutOfRange();
                }
                $entries[] = PartitionEntry::fromBytes(substr($arena, $eo, PcfConsts::ENTRY_SIZE));
            }
            if ($h->tableHashAlgo->verifies()) {
                $computed = TableBlockHeader::computeTableHash($h->tableHashAlgo, $h->nextTableOffset, $entries);
                $n = $h->tableHashAlgo->digestLen();
                if (substr($computed, 0, $n) !== substr($h->tableHash, 0, $n)) {
                    throw PcfDcpException::hashMismatch();
                }
            }
            $off = $h->nextTableOffset;
        }
    }
}
