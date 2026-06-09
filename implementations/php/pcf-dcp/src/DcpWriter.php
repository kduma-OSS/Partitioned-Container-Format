<?php

declare(strict_types=1);

namespace Kduma\PCFDCP;

use Kduma\PCF\Container;
use Kduma\PCF\HashAlgo;
use Kduma\PCF\PartitionEntry;
use Kduma\PCF\Storage\MemoryStorage;
use Kduma\PCF\Storage\StorageInterface;

/**
 * Building and rewriting PCF files that carry DCP containers. The writer keeps
 * the whole file as an in-memory list of top-level partitions and emits a fresh,
 * canonical PCF image on demand. Every mutating operation is a logical edit of
 * that list followed by a rebuild — simple and always correct for a reference
 * implementation; the result is a fully conforming PCF v1.0 file.
 *
 * Internally a top-level part is an stdClass {partitionType:int, uid:string,
 * label:string, dataHashAlgo:HashAlgo, plain:?string, arena:?Arena}.
 */
final class DcpWriter
{
    /** @var list<object> */
    private array $parts = [];
    private HashAlgo $tableHashAlgo = HashAlgo::Sha256;
    private bool $trailer = false;

    /** Load an existing PCF file into the writer's model. */
    public static function open(StorageInterface $storage): self
    {
        $c = Container::open($storage);
        $w = new self();
        foreach ($c->entries() as $e) {
            $data = $c->readPartitionData($e);
            $label = PartitionEntry::decodeLabel($e->label);
            $w->parts[] = (object) [
                'partitionType' => $e->partitionType,
                'uid' => $e->uid,
                'label' => $label,
                'dataHashAlgo' => $e->dataHashAlgo,
                'plain' => $e->partitionType === Consts::DCP_CONTAINER_TYPE ? null : $data,
                'arena' => $e->partitionType === Consts::DCP_CONTAINER_TYPE ? Arena::parse($data) : null,
            ];
        }

        return $w;
    }

    /** Finalise emitted images in trailer mode (append-only host). */
    public function setTrailer(bool $on): void
    {
        $this->trailer = $on;
    }

    private function ensureUnique(string $uid): void
    {
        foreach ($this->parts as $p) {
            if ($p->uid === $uid) {
                throw PcfDcpException::duplicateUid();
            }
        }
    }

    /** Add a DCP container partition holding $arena. */
    public function addContainer(string $uid, string $label, Arena $arena): void
    {
        $this->ensureUnique($uid);
        $this->parts[] = (object) [
            'partitionType' => Consts::DCP_CONTAINER_TYPE,
            'uid' => $uid,
            'label' => $label,
            'dataHashAlgo' => HashAlgo::None,
            'plain' => null,
            'arena' => $arena,
        ];
    }

    /** Add an ordinary top-level partition. */
    public function addPlain(int $partitionType, string $uid, string $label, string $data, HashAlgo $dataHashAlgo): void
    {
        $this->ensureUnique($uid);
        $this->parts[] = (object) [
            'partitionType' => $partitionType,
            'uid' => $uid,
            'label' => $label,
            'dataHashAlgo' => $dataHashAlgo,
            'plain' => $data,
            'arena' => null,
        ];
    }

    private function containerArena(string $uid): Arena
    {
        foreach ($this->parts as $p) {
            if ($p->uid === $uid) {
                if ($p->arena === null) {
                    throw PcfDcpException::notADcpContainer();
                }

                return $p->arena;
            }
        }
        throw PcfDcpException::notFound();
    }

    /** Borrow a container's arena for inspection or in-place editing. */
    public function arena(string $containerUid): Arena
    {
        return $this->containerArena($containerUid);
    }

    // ---- migration: promotion / demotion -----------------------------------

    /**
     * Promote an inner partition out of its DCP container to a top-level PCF
     * partition (dynamic → fixed), preserving uid, type, label, hash algorithm
     * and data_hash (the promotion invariant, spec Section 10.4).
     */
    public function promote(string $containerUid, string $innerUid): void
    {
        $arena = $this->containerArena($containerUid);
        $piece = $arena->removeInner($innerUid);
        $this->parts[] = (object) [
            'partitionType' => $piece['partitionType'],
            'uid' => $innerUid,
            'label' => $piece['label'],
            'dataHashAlgo' => $piece['dataHashAlgo'],
            'plain' => $piece['content'],
            'arena' => null,
        ];
    }

    /**
     * Demote a top-level partition into a DCP container as an inner partition
     * (fixed → dynamic), preserving uid, type, label, hash algorithm and
     * data_hash. The content becomes a single DATA extent.
     */
    public function demote(string $partUid, string $containerUid): void
    {
        $pos = -1;
        foreach ($this->parts as $i => $p) {
            if ($p->uid === $partUid) {
                $pos = $i;
                break;
            }
        }
        if ($pos < 0) {
            throw PcfDcpException::notFound();
        }
        $p = $this->parts[$pos];
        if ($p->partitionType === Consts::DCP_CONTAINER_TYPE || $p->plain === null) {
            throw PcfDcpException::nestedContainer();
        }
        $arena = $this->containerArena($containerUid);
        $arena->addInner($p->partitionType, $partUid, $p->label, $p->plain, $p->dataHashAlgo, Chunker::whole());
        array_splice($this->parts, $pos, 1);
    }

    // ---- container-level maintenance ---------------------------------------

    /** Re-chunk and deduplicate a container's inner partitions. */
    public function dedup(string $containerUid, Chunker $chunker): int
    {
        return $this->containerArena($containerUid)->dedup($chunker);
    }

    /** Compact / defragment a container's arena. Returns bytes reclaimed. */
    public function defrag(string $containerUid): int
    {
        return $this->containerArena($containerUid)->compact();
    }

    // ---- serialisation -----------------------------------------------------

    /** Build a fresh, canonical PCF image of the whole file. */
    public function toImage(): string
    {
        $cap = max(1, \count($this->parts));
        $storage = new MemoryStorage();
        $c = Container::createWith($storage, $cap, $this->tableHashAlgo);
        foreach ($this->parts as $p) {
            $data = $p->arena !== null ? $p->arena->toBytes() : $p->plain;
            $c->addPartition($p->partitionType, $p->uid, $p->label, $data, 0, $p->dataHashAlgo);
        }
        if ($this->trailer) {
            $c->finalizeWithTrailer();
        }

        return $storage->getContents();
    }
}
