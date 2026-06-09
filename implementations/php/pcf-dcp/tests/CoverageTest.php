<?php

declare(strict_types=1);

namespace Kduma\PCFDCP\Tests;

use Kduma\PCF\Container;
use Kduma\PCF\HashAlgo;
use Kduma\PCF\Storage\MemoryStorage;
use Kduma\PCFDCP\Arena;
use Kduma\PCFDCP\Chunker;
use Kduma\PCFDCP\DcpReader;
use Kduma\PCFDCP\DcpWriter;
use Kduma\PCFDCP\ErrorKind;
use Kduma\PCFDCP\FragmentEntry;
use Kduma\PCFDCP\FragmentTable;
use Kduma\PCFDCP\PcfDcpException;

final class CoverageTest extends PcfDcpTestCase
{
    private function kindOf(callable $fn): ErrorKind
    {
        try {
            $fn();
        } catch (PcfDcpException $e) {
            return $e->kind;
        }
        self::fail('expected a PcfDcpException');
    }

    public function test_rejects_bad_arena_magic(): void
    {
        $a = new Arena();
        $a->addInner(0x10, $this->fill(1), 'x', 'hi', HashAlgo::Sha256, Chunker::whole());
        $bytes = $a->toBytes();
        $bytes[0] = 'X';
        self::assertSame(ErrorKind::BadDcpMagic, $this->kindOf(fn () => Arena::parse($bytes)));
    }

    public function test_rejects_unsupported_profile_major(): void
    {
        $a = new Arena();
        $a->addInner(0x10, $this->fill(1), 'x', 'hi', HashAlgo::Sha256, Chunker::whole());
        $bytes = $a->toBytes();
        $bytes[4] = "\x02";
        self::assertSame(ErrorKind::UnsupportedProfileMajor, $this->kindOf(fn () => Arena::parse($bytes)));
    }

    public function test_rejects_reserved_nested_and_nil_uid(): void
    {
        $a = new Arena();
        self::assertSame(ErrorKind::ReservedType,
            $this->kindOf(fn () => $a->addInner(0, $this->fill(1), 'x', '', HashAlgo::None, Chunker::whole())));
        self::assertSame(ErrorKind::NestedContainer,
            $this->kindOf(fn () => $a->addInner(0xAAAC0001, $this->fill(1), 'x', '', HashAlgo::None, Chunker::whole())));
        self::assertSame(ErrorKind::NilUid,
            $this->kindOf(fn () => $a->addInner(0x10, str_repeat("\x00", 16), 'x', '', HashAlgo::None, Chunker::whole())));
    }

    public function test_rejects_duplicate_uid_within_arena(): void
    {
        $a = new Arena();
        $a->addInner(0x10, $this->fill(1), 'x', 'a', HashAlgo::None, Chunker::whole());
        self::assertSame(ErrorKind::DuplicateUid,
            $this->kindOf(fn () => $a->addInner(0x10, $this->fill(1), 'y', 'b', HashAlgo::None, Chunker::whole())));
    }

    public function test_rejects_bad_kind_and_out_of_range_extent(): void
    {
        self::assertSame(ErrorKind::BadFragmentKind,
            $this->kindOf(fn () => FragmentTable::reconstruct(str_repeat("\x00", 64), [new FragmentEntry(24, 1, 2, 0)], 64)));
        self::assertSame(ErrorKind::OffsetOutOfRange,
            $this->kindOf(fn () => FragmentTable::reconstruct(str_repeat("\x00", 64), [new FragmentEntry(60, 100, 1, 0)], 64)));
    }

    public function test_allows_empty_inner(): void
    {
        $a = new Arena();
        $a->addInner(0x10, $this->fill(1), 'empty', '', HashAlgo::Sha256, Chunker::whole());
        $info = $a->innerInfo($this->fill(1));
        self::assertSame(0, $info->usedBytes);
        self::assertCount(0, $info->extents);
        self::assertSame('', Arena::parse($a->toBytes())->content($this->fill(1)));
    }

    public function test_chains_inner_table_beyond_255(): void
    {
        $a = new Arena();
        for ($i = 0; $i < 300; ++$i) {
            $uid = str_repeat("\x00", 16);
            $uid[0] = \chr($i & 0xFF);
            $uid[1] = \chr(($i >> 8) & 0xFF);
            $uid[15] = "\x01";
            $a->addInner(0x10, $uid, 'n', \chr($i & 0xFF) . \chr(($i >> 8) & 0xFF), HashAlgo::Sha256, Chunker::whole());
        }
        self::assertSame(300, $a->count());
        self::assertSame(300, Arena::parse($a->toBytes())->count());

        $w = new DcpWriter();
        $w->addContainer($this->fill(0xDC), 'big', $a);
        DcpReader::open(new MemoryStorage($w->toImage()))->verify();
    }

    public function test_chains_fragment_table_beyond_255(): void
    {
        $a = new Arena();
        $distinct = '';
        for ($i = 0; $i < 300; ++$i) {
            $distinct .= \chr($i & 0xFF);
        }
        $a->addInner(0x10, $this->fill(2), 'frag', $distinct, HashAlgo::Sha256, Chunker::fixed(1));
        $parsed = Arena::parse($a->toBytes());
        self::assertSame(bin2hex($distinct), bin2hex($parsed->content($this->fill(2))));
    }

    public function test_verify_detects_file_wide_uid_collision(): void
    {
        $a = new Arena();
        $a->addInner(0x10, $this->fill(0xB2), 'B', 'World!', HashAlgo::Sha256, Chunker::whole());
        $w = new DcpWriter();
        $w->addContainer($this->fill(0xDC), 'dcp', $a);
        $w->addPlain(0x10, $this->fill(0xB2), 'dup', 'x', HashAlgo::Sha256);
        $r = DcpReader::open(new MemoryStorage($w->toImage()));
        self::assertSame(ErrorKind::DuplicateUid, $this->kindOf(fn () => $r->verify()));
    }

    public function test_open_arena_rejects_non_dcp_partition(): void
    {
        $storage = new MemoryStorage();
        $c = Container::createWith($storage, 4, HashAlgo::Sha256);
        $c->addPartition(0x10, $this->fill(7), 'plain', 'hi', 0, HashAlgo::Sha256);
        $r = DcpReader::open($storage);
        $entry = $r->entries()[0];
        self::assertSame(ErrorKind::NotADcpContainer, $this->kindOf(fn () => $r->openArena($entry)));
    }
}
