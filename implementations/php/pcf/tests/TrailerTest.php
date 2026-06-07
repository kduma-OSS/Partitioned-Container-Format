<?php

declare(strict_types=1);

namespace Kduma\PCF\Tests;

use Kduma\PCF\Consts;
use Kduma\PCF\Container;
use Kduma\PCF\ErrorKind;
use Kduma\PCF\HashAlgo;
use Kduma\PCF\Storage\MemoryStorage;
use Kduma\PCF\Trailer;

/**
 * Tests for the optional end-of-file trailer (spec section 4, "File Trailer").
 */
final class TrailerTest extends PcfTestCase
{
    private static function build(): string
    {
        $store = new MemoryStorage();
        $c = Container::createWith($store, 4, HashAlgo::Sha256);
        $c->addPartition(0x10, self::uid(1), 'alpha', 'Hello, PCF!', 0, HashAlgo::Sha256);
        $c->addPartition(Consts::TYPE_RAW, self::uid(2), 'raw', "\x00\x01\x02", 0, HashAlgo::Crc32c);
        $c->finalizeWithTrailer();

        return $store->getContents();
    }

    public function testFinalizeWithTrailerRoundtrips(): void
    {
        $bytes = self::build();

        // Header now holds the sentinel; the last 20 bytes are a valid trailer.
        self::assertSame(Consts::PT_OFFSET_TRAILER, unpack('P', substr($bytes, 12, 8))[1]);
        $t = Trailer::fromBytes(substr($bytes, -Consts::TRAILER_SIZE));
        self::assertSame(Consts::HEADER_SIZE, $t->partitionTableOffset);
        self::assertSame(Consts::CHAIN_FORWARD, $t->chainFlags);

        $c = Container::open(new MemoryStorage($bytes));
        self::assertSame(Consts::PT_OFFSET_TRAILER, $c->header()->partitionTableOffset);
        self::assertSame(Consts::HEADER_SIZE, $c->tableHead());
        self::assertFalse($c->chainIsBackward());
        $c->verify();
        $e = $c->entries();
        self::assertCount(2, $e);
        self::assertSame('Hello, PCF!', $c->readPartitionData($e[0]));
        self::assertSame("\x00\x01\x02", $c->readPartitionData($e[1]));
    }

    public function testBackwardFlagReported(): void
    {
        $store = new MemoryStorage();
        $c = Container::create($store);
        $c->addPartition(1, self::uid(1), 'only', 'data', 0, HashAlgo::Sha256);
        $bytes = $store->getContents();

        $head = unpack('P', substr($bytes, 12, 8))[1];
        $bytes .= (new Trailer($head, Consts::CHAIN_BACKWARD))->toBytes();
        $bytes = substr_replace($bytes, pack('P', Consts::PT_OFFSET_TRAILER), 12, 8);

        $c = Container::open(new MemoryStorage($bytes));
        self::assertSame($head, $c->tableHead());
        self::assertTrue($c->chainIsBackward());
        $c->verify();
        self::assertCount(1, $c->entries());
    }

    public function testMissingTrailerRejected(): void
    {
        $store = new MemoryStorage();
        $c = Container::create($store);
        $c->addPartition(1, self::uid(1), 'p', 'x', 0, HashAlgo::Sha256);
        $bytes = $store->getContents();
        // Flag trailer mode but append no trailer.
        $bytes = substr_replace($bytes, pack('P', Consts::PT_OFFSET_TRAILER), 12, 8);

        $this->assertPcfError(ErrorKind::BadTrailer, static fn () => Container::open(new MemoryStorage($bytes)));
    }

    public function testAbortedAppendIsRecovered(): void
    {
        $bytes = self::build();
        $bytes .= str_repeat("\xAB", 500); // aborted append, no trailer magic

        $c = Container::open(new MemoryStorage($bytes));
        self::assertSame(Consts::HEADER_SIZE, $c->tableHead());
        $c->verify();
        self::assertCount(2, $c->entries());
    }

    public function testSpuriousTrailerMagicInTailIsSkipped(): void
    {
        $bytes = self::build();
        // Fake A: magic present, head into the header (offset 5) → not a block.
        $bytes .= (new Trailer(5, Consts::CHAIN_FORWARD))->toBytes();
        // Fake B at EOF: head far out of range → rejected.
        $bytes .= (new Trailer(PHP_INT_MAX, Consts::CHAIN_FORWARD))->toBytes();

        $c = Container::open(new MemoryStorage($bytes));
        self::assertSame(Consts::HEADER_SIZE, $c->tableHead());
        $c->verify();
        self::assertCount(2, $c->entries());
    }

    public function testHeaderOnlySentinelFileRejected(): void
    {
        $store = new MemoryStorage();
        $c = Container::create($store);
        $c->addPartition(1, self::uid(1), 'p', 'x', 0, HashAlgo::Sha256);
        $header = substr($store->getContents(), 0, 20);
        $header = substr_replace($header, pack('P', Consts::PT_OFFSET_TRAILER), 12, 8);

        $this->assertPcfError(ErrorKind::BadTrailer, static fn () => Container::open(new MemoryStorage($header)));
    }
}
