<?php

declare(strict_types=1);

namespace Kduma\PCF\Tests;

use Kduma\PCF\Consts;
use Kduma\PCF\ErrorKind;
use Kduma\PCF\FileHeader;

/**
 * File-header tests (spec section 4), porting `header.rs`.
 */
final class HeaderTest extends PcfTestCase
{
    public function testRoundtrip(): void
    {
        $h = new FileHeader(1, 0, 20);
        $parsed = FileHeader::fromBytes($h->toBytes());
        self::assertSame(1, $parsed->versionMajor);
        self::assertSame(0, $parsed->versionMinor);
        self::assertSame(20, $parsed->partitionTableOffset);
    }

    public function testHeaderIsExactly20Bytes(): void
    {
        self::assertSame(20, Consts::HEADER_SIZE);
        self::assertSame(20, \strlen((new FileHeader(1, 0, 20))->toBytes()));
    }

    public function testRejectsBadMagic(): void
    {
        $b = (new FileHeader(1, 0, 20))->toBytes();
        $b[0] = "\x00";
        $this->assertPcfError(ErrorKind::BadMagic, static fn () => FileHeader::fromBytes($b));
    }

    public function testRejectsUnsupportedMajor(): void
    {
        $b = (new FileHeader(1, 0, 20))->toBytes();
        $b[8] = "\x02"; // bump major to 2
        $this->assertPcfError(ErrorKind::UnsupportedMajor, static fn () => FileHeader::fromBytes($b));
    }

    public function testHigherMinorIsAccepted(): void
    {
        $b = (new FileHeader(1, 0, 20))->toBytes();
        $b[10] = "\x05"; // minor = 5
        self::assertSame(5, FileHeader::fromBytes($b)->versionMinor);
    }

    public function testIntegersAreLittleEndian(): void
    {
        $h = (new FileHeader(0x0201, 0x0403, 0x0807_0605_0403_0201))->toBytes();
        self::assertSame("\x01\x02", substr($h, 8, 2));
        self::assertSame("\x03\x04", substr($h, 10, 2));
        self::assertSame("\x01\x02\x03\x04\x05\x06\x07\x08", substr($h, 12, 8));
    }
}
