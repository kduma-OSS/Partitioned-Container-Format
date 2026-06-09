<?php

declare(strict_types=1);

namespace Kduma\PCFDCP\Tests;

use Kduma\PCF\HashAlgo;
use Kduma\PCF\Storage\MemoryStorage;
use Kduma\PCFDCP\Arena;
use Kduma\PCFDCP\Chunker;
use Kduma\PCFDCP\DcpReader;
use Kduma\PCFDCP\DcpWriter;

final class RoundtripTest extends PcfDcpTestCase
{
    private function buildTwoInnerFile(): string
    {
        $arena = new Arena();
        $arena->addInner(0x10, $this->fill(0xA1), 'A', 'Hello, World!', HashAlgo::Sha256, Chunker::fixed(7));
        $arena->addInner(0x10, $this->fill(0xB2), 'B', 'World!', HashAlgo::Sha256, Chunker::whole());
        $w = new DcpWriter();
        $w->addContainer($this->fill(0xDC), 'dcp', $arena);

        return $w->toImage();
    }

    public function test_edits_reconstruct_correctly(): void
    {
        $a = new Arena();
        $a->addInner(0x10, $this->fill(1), 'f', 'Hello, World!', HashAlgo::Sha256, Chunker::fixed(7));

        $a->append($this->fill(1), '!!');
        self::assertSame('Hello, World!!!', $a->content($this->fill(1)));

        $a->insert($this->fill(1), 5, 'XYZ');
        self::assertSame('HelloXYZ, World!!!', $a->content($this->fill(1)));

        $a->delete($this->fill(1), 5, 3);
        self::assertSame('Hello, World!!!', $a->content($this->fill(1)));

        $a->overwrite($this->fill(1), 0, 5, 'HOWDY');
        self::assertSame('HOWDY, World!!!', $a->content($this->fill(1)));

        $a->truncate($this->fill(1), 5);
        self::assertSame('HOWDY', $a->content($this->fill(1)));
    }

    public function test_copy_on_write_does_not_disturb_shared_bytes(): void
    {
        $a = new Arena();
        $a->addInner(0x10, $this->fill(0xA1), 'A', 'Hello, World!', HashAlgo::Sha256, Chunker::fixed(7));
        $a->addInner(0x10, $this->fill(0xB2), 'B', 'World!', HashAlgo::Sha256, Chunker::whole());
        $a->overwrite($this->fill(0xA1), 7, 6, 'PLANET');
        self::assertSame('Hello, PLANET', $a->content($this->fill(0xA1)));
        self::assertSame('World!', $a->content($this->fill(0xB2)));
    }

    public function test_dedup_then_defrag_preserve_content(): void
    {
        $a = new Arena();
        $a->addInner(0x10, $this->fill(1), 'A', 'abcabc', HashAlgo::Sha256, Chunker::whole());
        $a->addInner(0x10, $this->fill(2), 'B', 'abcabc', HashAlgo::Sha256, Chunker::whole());
        $h1 = $a->innerInfo($this->fill(1))->dataHash;

        $saved = $a->dedup(Chunker::fixed(3));
        self::assertGreaterThan(0, $saved);
        self::assertSame('abcabc', $a->content($this->fill(1)));
        self::assertSame('abcabc', $a->content($this->fill(2)));
        self::assertSame(bin2hex($h1), bin2hex($a->innerInfo($this->fill(1))->dataHash));

        $a->compact();
        self::assertSame('abcabc', $a->content($this->fill(2)));
    }

    public function test_defrag_clears_shared_when_no_longer_aliased(): void
    {
        $a = new Arena();
        $a->addInner(0x10, $this->fill(0xA1), 'A', 'Hello, World!', HashAlgo::Sha256, Chunker::fixed(7));
        $a->addInner(0x10, $this->fill(0xB2), 'B', 'World!', HashAlgo::Sha256, Chunker::whole());
        $a->removeInner($this->fill(0xB2));
        $a->compact();
        foreach ($a->innerInfo($this->fill(0xA1))->extents as $e) {
            self::assertFalse($e->shared);
        }
        self::assertSame('Hello, World!', $a->content($this->fill(0xA1)));
    }

    public function test_promote_preserves_uid_and_data_hash(): void
    {
        $w = DcpWriter::open(new MemoryStorage($this->buildTwoInnerFile()));
        $r0 = DcpReader::open(new MemoryStorage($w->toImage()));
        $before = null;
        foreach ($r0->innerPartitions() as $loc) {
            if ($loc->info->uid === $this->fill(0xB2)) {
                $before = $loc->info->dataHash;
            }
        }
        self::assertNotNull($before);

        $w->promote($this->fill(0xDC), $this->fill(0xB2));
        $r = DcpReader::open(new MemoryStorage($w->toImage()));
        $r->verify();
        $resolved = $r->resolveUid($this->fill(0xB2));
        self::assertTrue($resolved->isTopLevel);
        self::assertSame(bin2hex($before), bin2hex($resolved->entry->dataHash));
        self::assertSame(6, $resolved->entry->usedBytes);
        self::assertSame('Hello, World!', $r->readInner($this->fill(0xA1)));
    }

    public function test_demote_then_promote_is_identity_for_content(): void
    {
        $w = DcpWriter::open(new MemoryStorage($this->buildTwoInnerFile()));
        $w->promote($this->fill(0xDC), $this->fill(0xB2));
        $w->demote($this->fill(0xB2), $this->fill(0xDC));
        $r = DcpReader::open(new MemoryStorage($w->toImage()));
        $r->verify();
        self::assertSame('World!', $r->readInner($this->fill(0xB2)));
        self::assertFalse($r->resolveUid($this->fill(0xB2))->isTopLevel);
    }

    public function test_trailer_mode_reads_back_identically(): void
    {
        $arena = new Arena();
        $arena->addInner(0x10, $this->fill(0xA1), 'A', 'Hello, World!', HashAlgo::Sha256, Chunker::fixed(7));
        $arena->addInner(0x10, $this->fill(0xB2), 'B', 'World!', HashAlgo::Sha256, Chunker::whole());
        $w = new DcpWriter();
        $w->addContainer($this->fill(0xDC), 'dcp', $arena);
        $w->setTrailer(true);
        $r = DcpReader::open(new MemoryStorage($w->toImage()));
        $r->verify();
        self::assertSame('Hello, World!', $r->readInner($this->fill(0xA1)));
        self::assertCount(2, $r->innerPartitions());
    }
}
