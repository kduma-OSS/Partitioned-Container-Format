<?php

declare(strict_types=1);

namespace Kduma\PCF\Tests;

use Kduma\PCF\Consts;
use Kduma\PCF\Container;
use Kduma\PCF\ErrorKind;
use Kduma\PCF\HashAlgo;
use Kduma\PCF\Storage\MemoryStorage;

/**
 * Spec-conformance tests — each assertion traces back to a specific MUST/SHALL
 * clause of PCF-spec-v1.0.txt. Ports `spec_compliance.rs`.
 */
final class SpecComplianceTest extends PcfTestCase
{
    // ---- Section 4 — File Header ----

    /** "A Reader MUST reject any file whose first 8 bytes do not match exactly." */
    public function testS4ReaderRejectsBadMagic(): void
    {
        $bytes = 'NOTAPCF!' . str_repeat("\x00", 12);
        $this->assertPcfError(ErrorKind::BadMagic, static fn () => Container::open(new MemoryStorage($bytes)));
    }

    /** "A Reader MUST reject a file whose version_major it does not implement." */
    public function testS4ReaderRejectsUnsupportedMajor(): void
    {
        $bytes = Consts::MAGIC . pack('v', 2) . pack('v', 0) . pack('P', 20);
        $this->assertPcfError(ErrorKind::UnsupportedMajor, static fn () => Container::open(new MemoryStorage($bytes)));
    }

    // ---- Section 5.1 — Table Block Header ----

    /** "A Reader MUST stop chain traversal when it reads 0." */
    public function testS5ChainTraversalStopsAtZero(): void
    {
        $c = Container::create();
        $c->addPartition(1, self::uid(1), 'only', 'x', 0, HashAlgo::Sha256);
        self::assertCount(1, $c->entries());
    }

    // ---- Section 5.3 — Overflow Table Blocks ----

    /** "Additional partitions are stored in further Table Blocks linked by next_table_offset." */
    public function testS5_3OverflowChain(): void
    {
        $c = Container::createWith(new MemoryStorage(), 255, HashAlgo::Sha256);
        for ($i = 0; $i < 260; ++$i) {
            $u = substr_replace(str_repeat("\x00", 16), pack('V', $i), 0, 4);
            $u[15] = "\xCC";
            $c->addPartition($i + 1, $u, 'x', \chr($i & 0xFF), 0, HashAlgo::Crc32c);
        }
        $image = $c->compactedImage();
        // First block at offset 20 reports 255 entries and a non-zero next.
        self::assertSame(255, \ord($image[20]));
        $next = unpack('P', substr($image, 21, 8))[1];
        self::assertNotSame(0, $next);
        // Second block reports the remaining 5 entries with next = 0.
        self::assertSame(5, \ord($image[$next]));
        self::assertSame(0, unpack('P', substr($image, $next + 1, 8))[1]);
    }

    /** "A block with partition_count = 0 is valid." */
    public function testS5_3EmptyBlockIsValid(): void
    {
        $c = Container::create();
        $image = $c->compactedImage();
        $c2 = Container::open(new MemoryStorage($image));
        $c2->verify();
        self::assertSame(0, \ord($image[20]));
        self::assertCount(0, $c2->entries());
    }

    // ---- Section 7.1 — Reserved Partition Types ----

    public function testS7_1TypeZeroIsRejectedByWriter(): void
    {
        $c = Container::create();
        $this->assertPcfError(
            ErrorKind::ReservedType,
            fn () => $c->addPartition(Consts::TYPE_RESERVED, self::uid(1), 'x', 'x', 0, HashAlgo::Sha256)
        );
    }

    public function testS7_1MaxApplicationTypeIsAccepted(): void
    {
        $c = Container::create();
        $c->addPartition(0xFFFF_FFFE, self::uid(1), 'edge', 'x', 0, HashAlgo::Sha256);
        $c->verify();
        self::assertSame(0xFFFF_FFFE, $c->entries()[0]->partitionType);
    }

    public function testS7_1RawTypeIsAllowed(): void
    {
        $c = Container::create();
        $c->addPartition(Consts::TYPE_RAW, self::uid(1), 'raw', "\x00\xFF", 0, HashAlgo::Crc32c);
        $c->verify();
        self::assertSame(Consts::TYPE_RAW, $c->entries()[0]->partitionType);
    }

    // ---- Section 7.2 — Reserved UID ----

    public function testS7_2NilUidIsRejected(): void
    {
        $c = Container::create();
        $this->assertPcfError(
            ErrorKind::NilUid,
            fn () => $c->addPartition(1, Consts::NIL_UID, 'x', 'x', 0, HashAlgo::Sha256)
        );
    }

    // ---- Section 8.1 — Hash Algorithm Registry ----

    public function testS8_1EveryRegisteredIdMapsBackToItself(): void
    {
        foreach ([0, 1, 2, 3, 4, 5, 16, 17, 18] as $id) {
            self::assertSame($id, HashAlgo::fromId($id)->id());
        }
    }

    public function testS8_1ReservedIdsAreRejected(): void
    {
        foreach (array_merge(range(6, 15), range(19, 30)) as $id) {
            $this->assertPcfError(ErrorKind::UnknownHashAlgo, static fn () => HashAlgo::fromId($id));
        }
    }

    // ---- Section 8.2 — Hash Field Encoding ----

    public function testS8_2HashFieldSizeIs64(): void
    {
        self::assertSame(64, Consts::HASH_FIELD_SIZE);
    }

    public function testS8_2NoneIsAllZeroAndAlwaysVerifies(): void
    {
        $f = HashAlgo::None->compute('anything');
        self::assertSame(str_repeat("\x00", 64), $f);
        $garbage = str_repeat("\xFF", 64);
        $garbage[0] = "\x00";
        self::assertTrue(HashAlgo::None->verify('data', $garbage));
    }

    // ---- Section 8.3 — Partition Data Hash ----

    public function testS8_3DataHashCoversUsedBytesOnly(): void
    {
        $c = Container::create();
        $c->addPartition(1, self::uid(1), 'p', 'hello', 1024, HashAlgo::Sha256);
        self::assertSame(HashAlgo::Sha256->compute('hello'), $c->entries()[0]->dataHash);
        $c->verify();
    }

    public function testS8_3EmptyPartitionHashesEmptyInput(): void
    {
        $c = Container::create();
        $c->addPartition(1, self::uid(1), 'p', '', 0, HashAlgo::Sha256);
        $e = $c->entries();
        self::assertSame(0, $e[0]->usedBytes);
        self::assertSame(HashAlgo::Sha256->compute(''), $e[0]->dataHash);
        $c->verify();
    }

    // ---- Section 8.5 — Hash Cascade ----

    public function testS8_5UpdateCascadesToTableHash(): void
    {
        $c = Container::create();
        $c->addPartition(1, self::uid(1), 'p', 'old', 100, HashAlgo::Sha256);
        $c->updatePartitionData(self::uid(1), 'new value');
        $c->verify(); // exercises both the new data_hash and the new table_hash
        self::assertSame('new value', $c->readPartitionData($c->entries()[0]));
    }

    // ---- Section 9 — Versioning ----

    /** "A Reader ... SHOULD accept a higher minor, ignoring features it does not understand." */
    public function testS9HigherMinorIsAccepted(): void
    {
        $bytes = Consts::MAGIC . pack('v', Consts::VERSION_MAJOR) . pack('v', 999) . pack('P', 20);
        // Empty block hashed with None — no hash verification required.
        $bytes .= "\x00" . pack('P', 0) . "\x00" . str_repeat("\x00", 64);
        $c = Container::open(new MemoryStorage($bytes));
        self::assertSame(999, $c->header()->versionMinor);
        $c->verify();
    }

    // ---- Section 10 — Labels ----

    public function testS10HighBitByteInLabelIsRejected(): void
    {
        $l = str_repeat("\x00", 32);
        $l[0] = 'a';
        $l[1] = "\xFF";
        $this->assertPcfError(
            ErrorKind::InvalidLabel,
            static fn () => \Kduma\PCF\PartitionEntry::decodeLabel($l)
        );
    }

    // ---- Section 12 — Conformance and Validation ----

    /** "C4. ... verify table_hash unless its table_hash_algo_id is 0." */
    public function testC4TableHashSkippedWhenAlgoIsNone(): void
    {
        $store = new MemoryStorage();
        $c = Container::createWith($store, 4, HashAlgo::None);
        $c->addPartition(1, self::uid(1), 'p', 'abc', 0, HashAlgo::Sha256);
        $bytes = $store->getContents();
        // Tamper with the whole table_hash field — verify() must still pass.
        for ($i = 0; $i < 64; ++$i) {
            $bytes[Consts::HEADER_SIZE + 10 + $i] = "\xFF";
        }
        $c2 = Container::open(new MemoryStorage($bytes));
        $c2->verify();
        self::assertCount(1, $c2->entries());
    }

    /** "C8. ... verify data_hash unless data_hash_algo_id is 0." */
    public function testC8DataHashSkippedWhenAlgoIsNone(): void
    {
        $c = Container::create();
        $c->addPartition(1, self::uid(1), 'p', 'original', 64, HashAlgo::None);
        $c->updatePartitionData(self::uid(1), 'different bytes');
        $c->verify();
        self::assertSame('different bytes', $c->readPartitionData($c->entries()[0]));
    }

    /** "W5. Zero-fill unused bytes of every fixed-size field (label tail, hash tail)." */
    public function testW5LabelAndHashTailsAreZeroFilled(): void
    {
        $c = Container::create();
        $c->addPartition(1, self::uid(1), 'ab', 'x', 0, HashAlgo::Crc32c);
        $image = $c->compactedImage();
        $e0 = Consts::HEADER_SIZE + Consts::TABLE_HEADER_SIZE;
        // Label tail [22..52) zero after "ab".
        self::assertSame(str_repeat("\x00", 30), substr($image, $e0 + 22, 30));
        // Hash tail [77+4 .. 77+64) zero for CRC-32C.
        self::assertSame(str_repeat("\x00", 60), substr($image, $e0 + 77 + 4, 60));
    }

    // ---- Section 15 — Test Vectors (byte-exact) ----

    /**
     * "An implementation that builds the same logical container and emits its
     *  canonical (compacted) form MUST produce these exact bytes."
     */
    public function testS15CanonicalTestVectorIsByteExact(): void
    {
        $c = Container::createWith(new MemoryStorage(), 8, HashAlgo::Sha256);
        $c->addPartition(0x0000_0010, str_repeat("\x11", 16), 'alpha', 'Hello, PCF!', 0, HashAlgo::Sha256);
        $c->addPartition(Consts::TYPE_RAW, str_repeat("\x22", 16), 'raw', "\x00\x01\x02\x03\x04\x05\x06\x07", 0, HashAlgo::Crc32c);
        $image = $c->compactedImage();

        self::assertSame(395, \strlen($image), 'spec mandates a 395-byte canonical file');
        self::assertSame($this->expectedSpecVector(), $image, 'compacted image must match spec section 15');

        // The produced file re-opens and verifies cleanly.
        $v = Container::open(new MemoryStorage($image));
        $v->verify();
    }

    // ---- Appendix A — Field Layout Summary ----

    public function testAppendixAConstsAreAuthoritative(): void
    {
        self::assertSame(16, Consts::UID_SIZE);
        self::assertSame(32, Consts::LABEL_SIZE);
        self::assertSame(64, Consts::HASH_FIELD_SIZE);
        self::assertSame(20, Consts::HEADER_SIZE);
        self::assertSame(74, Consts::TABLE_HEADER_SIZE);
        self::assertSame(141, Consts::ENTRY_SIZE);
        self::assertSame(1, Consts::VERSION_MAJOR);
        self::assertSame(0, Consts::VERSION_MINOR);
        self::assertSame(0x0000_0000, Consts::TYPE_RESERVED);
        self::assertSame(0xFFFF_FFFF, Consts::TYPE_RAW);
        self::assertSame(str_repeat("\x00", 16), Consts::NIL_UID);
    }

    /** The 395-byte expected image, transcribed from spec section 15. */
    private function expectedSpecVector(): string
    {
        $expect = str_repeat("\x00", 395);
        $put = static function (string &$buf, int $off, string $data): void {
            $buf = substr_replace($buf, $data, $off, \strlen($data));
        };

        // Header (20 B).
        $put($expect, 0, Consts::MAGIC);
        $put($expect, 8, pack('v', 1));
        $put($expect, 10, pack('v', 0));
        $put($expect, 12, pack('P', 20));
        // Table block header @ 0x14.
        $put($expect, 20, "\x02");          // partition_count
        $put($expect, 21, pack('P', 0));    // next_table_offset
        $put($expect, 29, "\x10");          // SHA-256
        $put($expect, 30, hex2bin(
            'f5ebfe8c26b170f7c97cf92ed24cf61e042bbdfac5099bc7801f0e810fc327b6'
        ));
        // Entry 0 @ 0x5E.
        $e0 = 0x5E;
        $put($expect, $e0, pack('V', 0x0000_0010));
        $put($expect, $e0 + 4, str_repeat("\x11", 16));
        $put($expect, $e0 + 20, 'alpha');
        $put($expect, $e0 + 52, pack('P', 376));
        $put($expect, $e0 + 60, pack('P', 11));
        $put($expect, $e0 + 68, pack('P', 11));
        $put($expect, $e0 + 76, "\x10"); // SHA-256
        $put($expect, $e0 + 77, hex2bin(
            'dc02cf82cec23405617ad4bf901c0975b64a4be57c303a8f5cf0a2c251cb90bc'
        ));
        // Entry 1 @ 0xEB.
        $e1 = 0xEB;
        $put($expect, $e1, pack('V', Consts::TYPE_RAW));
        $put($expect, $e1 + 4, str_repeat("\x22", 16));
        $put($expect, $e1 + 20, 'raw');
        $put($expect, $e1 + 52, pack('P', 387));
        $put($expect, $e1 + 60, pack('P', 8));
        $put($expect, $e1 + 68, pack('P', 8));
        $put($expect, $e1 + 76, "\x02"); // CRC-32C
        $put($expect, $e1 + 77, pack('V', 0x8A2C_BC3B));
        // Data region @ 0x178.
        $put($expect, 0x178, 'Hello, PCF!');
        $put($expect, 0x183, "\x00\x01\x02\x03\x04\x05\x06\x07");

        return $expect;
    }
}
