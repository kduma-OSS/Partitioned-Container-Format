<?php

declare(strict_types=1);

namespace Kduma\PCFDCP\Tests;

use Kduma\PCF\HashAlgo;
use Kduma\PCFDCP\Arena;
use Kduma\PCFDCP\Chunker;
use Kduma\PCFDCP\Consts;
use Kduma\PCFDCP\DcpHeader;
use Kduma\PCFDCP\FragmentEntry;
use Kduma\PCFDCP\FragTableHeader;

final class SpecComplianceTest extends PcfDcpTestCase
{
    public function test_structure_sizes_match_appendix_a(): void
    {
        self::assertSame(24, Consts::DCP_HEADER_SIZE);
        self::assertSame(9, Consts::FRAGTABLE_HEADER_SIZE);
        self::assertSame(18, Consts::FRAGMENT_ENTRY_SIZE);
        self::assertSame(0xAAAC0001, Consts::DCP_CONTAINER_TYPE);
    }

    public function test_header_round_trips_and_carries_magic(): void
    {
        $h = new DcpHeader(1, 0, 0, 109, 465);
        $b = $h->toBytes();
        self::assertSame('PDCP', substr($b, 0, 4));
        $parsed = DcpHeader::fromBytes($b);
        self::assertSame(109, $parsed->innerTableOffset);
        self::assertSame(465, $parsed->arenaUsed);
        self::assertSame(1, $parsed->profileVersionMajor);
        self::assertSame(0, $parsed->profileVersionMinor);
    }

    public function test_fragment_records_round_trip(): void
    {
        $e = new FragmentEntry(31, 6, 1, 1);
        $pe = FragmentEntry::fromBytes($e->toBytes());
        self::assertSame(31, $pe->extentOffset);
        self::assertSame(6, $pe->extentLength);
        self::assertSame(1, $pe->kind);
        self::assertTrue($pe->isShared());

        $fh = new FragTableHeader(0, 2);
        $pfh = FragTableHeader::fromBytes($fh->toBytes());
        self::assertSame(0, $pfh->nextFragtableOffset);
        self::assertSame(2, $pfh->fragmentCount);
    }

    public function test_reconstruction_equals_logical_content(): void
    {
        $a = new Arena();
        $a->addInner(0x10, $this->fill(1), 'x', 'Hello, World!', HashAlgo::Sha256, Chunker::fixed(7));
        self::assertSame('Hello, World!', $a->content($this->fill(1)));
        $info = $a->innerInfo($this->fill(1));
        self::assertSame(13, $info->usedBytes);
        self::assertCount(2, $info->extents);
    }

    public function test_data_hash_is_invariant_under_fragmentation(): void
    {
        $mk = function (Chunker $c): string {
            $a = new Arena();
            $a->addInner(0x10, $this->fill(7), 'x', 'abcdefghij', HashAlgo::Sha256, $c);

            return bin2hex($a->innerInfo($this->fill(7))->dataHash);
        };
        self::assertSame($mk(Chunker::whole()), $mk(Chunker::fixed(3)));
        self::assertSame($mk(Chunker::whole()), bin2hex(HashAlgo::Sha256->compute('abcdefghij')));
    }

    public function test_dedup_sets_shared_on_all_aliases_rule_f1(): void
    {
        $a = new Arena();
        $a->addInner(0x10, $this->fill(0xA1), 'A', 'Hello, World!', HashAlgo::Sha256, Chunker::fixed(7));
        $a->addInner(0x10, $this->fill(0xB2), 'B', 'World!', HashAlgo::Sha256, Chunker::whole());

        $ia = $a->innerInfo($this->fill(0xA1));
        $ib = $a->innerInfo($this->fill(0xB2));
        self::assertFalse($ia->extents[0]->shared);
        self::assertTrue($ia->extents[1]->shared);
        self::assertCount(1, $ib->extents);
        self::assertTrue($ib->extents[0]->shared);
        self::assertSame(bin2hex(HashAlgo::Sha256->compute('World!')), bin2hex($ib->dataHash));
    }

    public function test_parse_round_trips_canonical_arena_byte_exact(): void
    {
        $a = new Arena();
        $a->addInner(0x10, $this->fill(0xA1), 'A', 'Hello, World!', HashAlgo::Sha256, Chunker::fixed(7));
        $a->addInner(0x10, $this->fill(0xB2), 'B', 'World!', HashAlgo::Sha256, Chunker::whole());
        $bytes = $a->toBytes();
        self::assertSame(bin2hex($bytes), bin2hex(Arena::parse($bytes)->toBytes()));
    }
}
