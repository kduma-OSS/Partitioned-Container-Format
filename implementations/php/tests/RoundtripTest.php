<?php

declare(strict_types=1);

namespace Kduma\PCF\Tests;

use Kduma\PCF\Consts;
use Kduma\PCF\Container;
use Kduma\PCF\ErrorKind;
use Kduma\PCF\HashAlgo;
use Kduma\PCF\Storage\MemoryStorage;
use Kduma\PCF\Storage\StreamStorage;

/**
 * End-to-end container tests, porting `roundtrip.rs` and `coverage.rs`.
 */
final class RoundtripTest extends PcfTestCase
{
    public function testCreateAddReadVerify(): void
    {
        $c = Container::create();
        $c->addPartition(0x10, self::uid(1), 'alpha', 'first payload', 16, HashAlgo::Sha256);
        $c->addPartition(Consts::TYPE_RAW, self::uid(2), 'blob', 'raw bytes', 0, HashAlgo::Crc32c);

        $c->verify();
        $entries = $c->entries();
        self::assertCount(2, $entries);
        self::assertSame('alpha', $entries[0]->labelString());
        self::assertSame('first payload', $c->readPartitionData($entries[0]));
        self::assertSame('raw bytes', $c->readPartitionData($entries[1]));
        self::assertSame(16, $entries[0]->freeBytes());
    }

    public function testReopenRoundtrip(): void
    {
        $store = new MemoryStorage();
        $c = Container::create($store);
        $c->addPartition(1, self::uid(1), 'one', 'aaaa', 8, HashAlgo::Sha256);
        $c->addPartition(2, self::uid(2), 'two', 'bbbbbb', 0, HashAlgo::Crc64);

        $reopened = Container::open(new MemoryStorage($store->getContents()));
        $reopened->verify();
        $e = $reopened->entries();
        self::assertCount(2, $e);
        self::assertSame('bbbbbb', $reopened->readPartitionData($e[1]));
    }

    public function testUpdateInPlaceAndCascade(): void
    {
        $c = Container::create();
        $c->addPartition(1, self::uid(1), 'p', 'short', 100, HashAlgo::Sha256);
        $c->updatePartitionData(self::uid(1), 'a longer replacement payload');
        $c->verify();
        $e = $c->entries();
        self::assertSame('a longer replacement payload', $c->readPartitionData($e[0]));

        // Exceeding the reservation must fail.
        $this->assertPcfError(
            ErrorKind::DataTooLarge,
            fn () => $c->updatePartitionData(self::uid(1), str_repeat("\x00", 1000))
        );
    }

    public function testUpdateNotFound(): void
    {
        $c = Container::create();
        $c->addPartition(1, self::uid(1), 'x', 'x', 0, HashAlgo::Sha256);
        $this->assertPcfError(
            ErrorKind::NotFound,
            fn () => $c->updatePartitionData(self::uid(99), 'y')
        );
    }

    public function testRemovePartitionWorks(): void
    {
        $c = Container::create();
        $c->addPartition(1, self::uid(1), 'a', 'AAAA', 0, HashAlgo::Sha256);
        $c->addPartition(2, self::uid(2), 'b', 'BBBB', 0, HashAlgo::Sha256);
        $c->addPartition(3, self::uid(3), 'c', 'CCCC', 0, HashAlgo::Sha256);

        $c->removePartition(self::uid(2));
        $c->verify();
        $labels = array_map(static fn ($e) => $e->labelString(), $c->entries());
        self::assertSame(['a', 'c'], $labels);

        $this->assertPcfError(ErrorKind::NotFound, fn () => $c->removePartition(self::uid(2)));
    }

    public function testOverflowChain(): void
    {
        // First block capacity of 3 forces overflow blocks for 10 partitions.
        $c = Container::createWith(new MemoryStorage(), 3, HashAlgo::Sha256);
        for ($i = 1; $i <= 10; ++$i) {
            $payload = str_repeat(\chr($i), $i + 1);
            $c->addPartition($i, self::uid($i), "part{$i}", $payload, 4, HashAlgo::Sha256);
        }
        $c->verify();
        $e = $c->entries();
        self::assertCount(10, $e);
        foreach ($e as $idx => $entry) {
            $i = $idx + 1;
            self::assertSame(str_repeat(\chr($i), $i + 1), $c->readPartitionData($entry));
        }
    }

    public function testDuplicateUidRejected(): void
    {
        $c = Container::create();
        $c->addPartition(1, self::uid(1), 'x', 'x', 0, HashAlgo::Sha256);
        $this->assertPcfError(
            ErrorKind::DuplicateUid,
            fn () => $c->addPartition(2, self::uid(1), 'y', 'y', 0, HashAlgo::Sha256)
        );
    }

    public function testReservedTypeAndNilUidRejected(): void
    {
        $c = Container::create();
        $this->assertPcfError(
            ErrorKind::ReservedType,
            fn () => $c->addPartition(0, self::uid(1), 'x', 'x', 0, HashAlgo::Sha256)
        );
        $this->assertPcfError(
            ErrorKind::NilUid,
            fn () => $c->addPartition(1, Consts::NIL_UID, 'x', 'x', 0, HashAlgo::Sha256)
        );
    }

    public function testCorruptionIsDetected(): void
    {
        $store = new MemoryStorage();
        $c = Container::create($store);
        $c->addPartition(1, self::uid(1), 'p', 'important data', 0, HashAlgo::Sha256);
        $bytes = $store->getContents();
        // Flip a byte in the partition data region (last byte of the file).
        $bytes[\strlen($bytes) - 1] = \chr(\ord($bytes[\strlen($bytes) - 1]) ^ 0xFF);

        $reopened = Container::open(new MemoryStorage($bytes));
        $this->assertPcfError(ErrorKind::DataHashMismatch, fn () => $reopened->verify());
    }

    public function testTableHashCorruptionIsDetected(): void
    {
        $store = new MemoryStorage();
        $c = Container::create($store);
        $c->addPartition(1, self::uid(1), 'p', 'payload', 0, HashAlgo::Sha256);
        $bytes = $store->getContents();
        // Flip a byte inside the table_hash field (offset HEADER_SIZE + 10).
        $pos = Consts::HEADER_SIZE + 10;
        $bytes[$pos] = \chr(\ord($bytes[$pos]) ^ 0xFF);

        $reopened = Container::open(new MemoryStorage($bytes));
        $this->assertPcfError(ErrorKind::TableHashMismatch, fn () => $reopened->verify());
    }

    public function testEmptyPartitionReadsBackAsEmpty(): void
    {
        $c = Container::create();
        $c->addPartition(7, self::uid(1), 'empty', '', 0, HashAlgo::Sha256);
        $e = $c->entries();
        self::assertSame('', $c->readPartitionData($e[0]));
        $c->verify();

        // Updating to empty data must hit the empty fast path.
        $c->updatePartitionData(self::uid(1), '');
        $c->verify();
    }

    public function testOpenRejectsBadMagicAndUnsupportedMajor(): void
    {
        $this->assertPcfError(
            ErrorKind::BadMagic,
            static fn () => Container::open(new MemoryStorage(str_repeat("\x00", 20)))
        );

        $bad = Consts::MAGIC . "\x09\x00\x00\x00" . str_repeat("\x00", 8);
        $this->assertPcfError(
            ErrorKind::UnsupportedMajor,
            static fn () => Container::open(new MemoryStorage($bad))
        );
    }

    public function testVerifyWithNoneAlgorithmSkipsHashCheck(): void
    {
        $c = Container::createWith(new MemoryStorage(), 4, HashAlgo::None);
        $c->addPartition(1, self::uid(1), 'p', 'abc', 0, HashAlgo::None);
        $c->verify();
        self::assertSame('abc', $c->readPartitionData($c->entries()[0]));
    }

    public function testCompactionReclaimsSpaceAndStaysValid(): void
    {
        $store = new MemoryStorage();
        $c = Container::createWith($store, 8, HashAlgo::Sha256);
        for ($i = 1; $i <= 5; ++$i) {
            $c->addPartition($i, self::uid($i), "f{$i}", str_repeat(\chr($i), 32), 4096, HashAlgo::Sha256);
        }
        // Remove a couple to create dead space.
        $c->removePartition(self::uid(2));
        $c->removePartition(self::uid(4));

        $compacted = $c->compactedImage();
        $c2 = Container::open(new MemoryStorage($compacted));
        $c2->verify();
        $e = $c2->entries();
        self::assertCount(3, $e);
        foreach ($e as $entry) {
            self::assertSame($entry->maxLength, $entry->usedBytes);
            self::assertSame(0, $entry->freeBytes());
        }
        self::assertSame(['f1', 'f3', 'f5'], array_map(static fn ($x) => $x->labelString(), $e));
    }

    public function testCompactionWithMoreThanOneTableBlock(): void
    {
        // 260 partitions force two table blocks in the compacted image.
        $c = Container::createWith(new MemoryStorage(), 255, HashAlgo::Sha256);
        for ($i = 0; $i < 260; ++$i) {
            $u = str_repeat("\x00", 16);
            $u = substr_replace($u, pack('V', $i), 0, 4);
            $u[15] = "\x55";
            $c->addPartition($i + 1, $u, 'p', \chr($i & 0xFF), 0, HashAlgo::Crc32);
        }
        $image = $c->compactedImage();
        $c2 = Container::open(new MemoryStorage($image));
        $c2->verify();
        self::assertCount(260, $c2->entries());
    }

    public function testCompactEmptyContainerIsValid(): void
    {
        $c = Container::create();
        $image = $c->compactedImage();
        $c2 = Container::open(new MemoryStorage($image));
        $c2->verify();
        self::assertCount(0, $c2->entries());
    }

    public function testStreamStorageFileBackedRoundtrip(): void
    {
        // Exercise the file-backed StorageInterface, not just in-memory.
        $path = tempnam(sys_get_temp_dir(), 'pcf_');
        try {
            $c = Container::create(StreamStorage::fromFile($path, 'c+'));
            $c->addPartition(1, self::uid(1), 'a', 'on-disk payload', 32, HashAlgo::Sha256);
            $c->addPartition(Consts::TYPE_RAW, self::uid(2), 'b', "\x00\x01\x02", 0, HashAlgo::Crc64);
            $c->verify();

            $reopened = Container::open(StreamStorage::fromFile($path, 'r'));
            $reopened->verify();
            $e = $reopened->entries();
            self::assertCount(2, $e);
            self::assertSame('on-disk payload', $reopened->readPartitionData($e[0]));
            self::assertSame("\x00\x01\x02", $reopened->readPartitionData($e[1]));
        } finally {
            @unlink($path);
        }
    }

    public function testCompactIntoWritesImage(): void
    {
        $c = Container::create();
        $c->addPartition(1, self::uid(1), 'p', 'data', 16, HashAlgo::Sha256);
        $out = new MemoryStorage();
        $c->compactInto($out);
        self::assertSame($c->compactedImage(), $out->getContents());
    }
}
