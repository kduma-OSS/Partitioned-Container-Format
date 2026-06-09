<?php

declare(strict_types=1);

namespace Kduma\PCFDCP\Tests;

use Kduma\PCF\Container;
use Kduma\PCF\Storage\MemoryStorage;
use Kduma\PCFDCP\DcpReader;
use Kduma\PCFDCP\ReferenceVector;

final class CanonicalVectorTest extends PcfDcpTestCase
{
    private const EXPECTED_SHA256 =
        'b9bb59794abed008863063886d8d0daa810c44939c1c5d29449475ced8156b90';

    private static function canonical(): string
    {
        return file_get_contents(__DIR__ . '/../testdata/canonical.bin');
    }

    public function test_ships_expected_sha256_and_length(): void
    {
        $c = self::canonical();
        self::assertSame(700, \strlen($c));
        self::assertSame(self::EXPECTED_SHA256, bin2hex(hash('sha256', $c, true)));
    }

    public function test_regenerates_byte_exact(): void
    {
        $image = ReferenceVector::build();
        self::assertSame(700, \strlen($image));
        self::assertSame(self::EXPECTED_SHA256, bin2hex(hash('sha256', $image, true)));
        self::assertSame(self::canonical(), $image);
    }

    public function test_is_valid_pcf(): void
    {
        $c = Container::open(new MemoryStorage(self::canonical()));
        $c->verify();
        $entries = $c->entries();
        self::assertCount(1, $entries);
        self::assertSame(0xAAAC0001, $entries[0]->partitionType);
        self::assertSame(465, $entries[0]->usedBytes);
    }

    public function test_is_valid_dcp(): void
    {
        $r = DcpReader::open(new MemoryStorage(self::canonical()));
        $r->verify();
        self::assertSame('Hello, World!', $r->readInner($this->fill(0xA1)));
        self::assertSame('World!', $r->readInner($this->fill(0xB2)));
    }
}
