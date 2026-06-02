<?php

declare(strict_types=1);

namespace Kduma\PCF\Tests;

use Kduma\PCF\Consts;
use Kduma\PCF\ErrorKind;
use Kduma\PCF\HashAlgo;
use Kduma\PCF\TableBlockHeader;

/**
 * Table-block header and hashing tests (spec section 5.1, 8.4), porting
 * `table.rs`.
 */
final class TableTest extends PcfTestCase
{
    public function testBlockHeaderIs74Bytes(): void
    {
        self::assertSame(74, Consts::TABLE_HEADER_SIZE);
        $h = new TableBlockHeader(0, 0, HashAlgo::Sha256, str_repeat("\x00", Consts::HASH_FIELD_SIZE));
        self::assertSame(74, \strlen($h->toBytes()));
    }

    public function testHeaderRoundtrip(): void
    {
        $h = new TableBlockHeader(3, 4096, HashAlgo::Sha256, HashAlgo::Sha256->compute('abc'));
        $p = TableBlockHeader::fromBytes($h->toBytes());
        self::assertSame(3, $p->partitionCount);
        self::assertSame(4096, $p->nextTableOffset);
        self::assertSame(HashAlgo::Sha256, $p->tableHashAlgo);
        self::assertSame($h->tableHash, $p->tableHash);
    }

    public function testPartitionCountIsU8(): void
    {
        $h = new TableBlockHeader(255, 0, HashAlgo::Sha256, str_repeat("\x00", Consts::HASH_FIELD_SIZE));
        self::assertSame(255, TableBlockHeader::fromBytes($h->toBytes())->partitionCount);
    }

    public function testHeaderWithNoneHash(): void
    {
        $h = new TableBlockHeader(0, 0, HashAlgo::None, str_repeat("\x00", Consts::HASH_FIELD_SIZE));
        self::assertSame(HashAlgo::None, TableBlockHeader::fromBytes($h->toBytes())->tableHashAlgo);
    }

    public function testEmptyBlockHashIsStable(): void
    {
        $a = TableBlockHeader::computeTableHash(HashAlgo::Sha256, 0, []);
        $b = TableBlockHeader::computeTableHash(HashAlgo::Sha256, 0, []);
        self::assertSame($a, $b);
    }

    public function testTableHashChangesWithNextOffset(): void
    {
        $a = TableBlockHeader::computeTableHash(HashAlgo::Sha256, 0, []);
        $b = TableBlockHeader::computeTableHash(HashAlgo::Sha256, 4096, []);
        self::assertNotSame($a, $b);
    }

    public function testTableHashDependsOnAlgoId(): void
    {
        $sha = TableBlockHeader::computeTableHash(HashAlgo::Sha256, 0, []);
        $blake = TableBlockHeader::computeTableHash(HashAlgo::Blake3, 0, []);
        self::assertNotSame(substr($sha, 0, 32), substr($blake, 0, 32));
    }

    public function testFromBytesPropagatesUnknownAlgoId(): void
    {
        $b = str_repeat("\x00", 74);
        $b[9] = "\x64"; // 100 = unknown
        $this->assertPcfError(ErrorKind::UnknownHashAlgo, static fn () => TableBlockHeader::fromBytes($b));
    }
}
