<?php

declare(strict_types=1);

namespace Kduma\PCF\Tests;

use Kduma\PCF\Consts;
use Kduma\PCF\ErrorKind;
use Kduma\PCF\HashAlgo;
use Kduma\PCF\PartitionEntry;

/**
 * Partition-entry and label tests (spec section 5.2, section 10), porting
 * `entry.rs`.
 */
final class EntryTest extends PcfTestCase
{
    private static function sample(): PartitionEntry
    {
        return new PartitionEntry(
            7,
            str_repeat("\x01", 16),
            PartitionEntry::encodeLabel('hello'),
            1024,
            4096,
            100,
            HashAlgo::Sha256,
            HashAlgo::Sha256->compute('x'),
        );
    }

    public function testEntryIs141Bytes(): void
    {
        self::assertSame(141, Consts::ENTRY_SIZE);
        self::assertSame(141, \strlen(self::sample()->toBytes()));
    }

    public function testEntryRoundtrip(): void
    {
        $e = self::sample();
        $p = PartitionEntry::fromBytes($e->toBytes());
        self::assertSame($e->partitionType, $p->partitionType);
        self::assertSame($e->uid, $p->uid);
        self::assertSame($e->label, $p->label);
        self::assertSame($e->startOffset, $p->startOffset);
        self::assertSame($e->maxLength, $p->maxLength);
        self::assertSame($e->usedBytes, $p->usedBytes);
        self::assertSame($e->dataHashAlgo, $p->dataHashAlgo);
        self::assertSame($e->dataHash, $p->dataHash);
    }

    public function testLabelRoundtrip(): void
    {
        $l = PartitionEntry::encodeLabel('config.bin');
        self::assertSame('config.bin', PartitionEntry::decodeLabel($l));
    }

    public function testFullLabelHasNoTerminator(): void
    {
        $s = str_repeat('a', 32);
        $l = PartitionEntry::encodeLabel($s);
        self::assertSame('a', $l[31]);
        self::assertSame($s, PartitionEntry::decodeLabel($l));
    }

    public function testEmptyLabelIsAllZero(): void
    {
        $l = PartitionEntry::encodeLabel('');
        self::assertSame(str_repeat("\x00", 32), $l);
        self::assertSame('', PartitionEntry::decodeLabel($l));
    }

    public function testLabelTooLong(): void
    {
        $this->assertPcfError(
            ErrorKind::InvalidLabel,
            static fn () => PartitionEntry::encodeLabel(str_repeat('a', 33))
        );
    }

    public function testEncodeLabelRejectsNulAndHighBit(): void
    {
        $this->assertPcfError(ErrorKind::InvalidLabel, static fn () => PartitionEntry::encodeLabel("a\x00b"));
        // A multi-byte UTF-8 character has a leading byte >= 0x80.
        $this->assertPcfError(ErrorKind::InvalidLabel, static fn () => PartitionEntry::encodeLabel("\xC3\xA9"));
    }

    public function testDecodeLabelRejectsHighBit(): void
    {
        $l = str_repeat("\x00", 32);
        $l[0] = 'a';
        $l[1] = "\x80"; // not 0 and >= 0x80
        $this->assertPcfError(ErrorKind::InvalidLabel, static fn () => PartitionEntry::decodeLabel($l));
    }

    public function testValidateRejectsReservedAndNil(): void
    {
        $e = self::sample();
        $e->partitionType = 0;
        $this->assertPcfError(ErrorKind::ReservedType, static fn () => $e->validate());

        $e2 = self::sample();
        $e2->uid = Consts::NIL_UID;
        $this->assertPcfError(ErrorKind::NilUid, static fn () => $e2->validate());
    }

    public function testValidateUsedExceedsMax(): void
    {
        $e = new PartitionEntry(
            1,
            self::uid(1),
            PartitionEntry::encodeLabel('x'),
            100,
            10,
            11,
            HashAlgo::None,
            str_repeat("\x00", Consts::HASH_FIELD_SIZE),
        );
        $this->assertPcfError(ErrorKind::UsedExceedsMax, static fn () => $e->validate());
        // freeBytes saturates rather than going negative.
        self::assertSame(0, $e->freeBytes());
    }

    public function testFreeBytesIsDerived(): void
    {
        $e = self::sample();
        $e->maxLength = 100;
        $e->usedBytes = 30;
        self::assertSame(70, $e->freeBytes());
    }

    public function testFromBytesPropagatesUnknownAlgoId(): void
    {
        $b = str_repeat("\x00", 141);
        $b = substr_replace($b, pack('V', 1), 0, 4); // valid type
        $b[4] = "\x01"; // non-nil uid byte
        $b[76] = "\x63"; // 99 = unknown algo
        $this->assertPcfError(ErrorKind::UnknownHashAlgo, static fn () => PartitionEntry::fromBytes($b));
    }
}
