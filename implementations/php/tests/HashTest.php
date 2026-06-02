<?php

declare(strict_types=1);

namespace Kduma\PCF\Tests;

use Kduma\PCF\Blake3;
use Kduma\PCF\Consts;
use Kduma\PCF\Crc64;
use Kduma\PCF\ErrorKind;
use Kduma\PCF\HashAlgo;

/**
 * Hash-algorithm registry tests (spec section 8), porting the reference
 * implementation's `hash.rs` unit tests plus the coverage cases.
 */
final class HashTest extends PcfTestCase
{
    private static function le(string $field, int $width): int
    {
        return unpack($width === 8 ? 'P' : 'V', substr($field, 0, $width))[1];
    }

    public function testCrc32IsoHdlcCheckValue(): void
    {
        $f = HashAlgo::Crc32->compute('123456789');
        self::assertSame(0xCBF43926, self::le($f, 4));
    }

    public function testCrc32cCheckValue(): void
    {
        $f = HashAlgo::Crc32c->compute('123456789');
        self::assertSame(0xE3069283, self::le($f, 4));
    }

    public function testCrc64XzCheckValue(): void
    {
        $f = HashAlgo::Crc64->compute('123456789');
        // Check value 0x995DC9BBDF1939FA stored as a little-endian u64. Compared
        // as bytes because the value exceeds PHP_INT_MAX as a decimal literal.
        self::assertSame('fa3919dfbbc95d99', bin2hex(substr($f, 0, 8)));
        // The HashAlgo field is the direct CRC-64 bytes, zero-padded to 64.
        self::assertSame(Crc64::compute('123456789'), substr($f, 0, 8));
    }

    public function testSha256Empty(): void
    {
        $f = HashAlgo::Sha256->compute('');
        self::assertSame(
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            bin2hex(substr($f, 0, 32))
        );
        self::assertSame(str_repeat("\x00", 32), substr($f, 32));
    }

    public function testMd5Empty(): void
    {
        $f = HashAlgo::Md5->compute('');
        self::assertSame('d41d8cd98f00b204e9800998ecf8427e', bin2hex(substr($f, 0, 16)));
        self::assertSame(str_repeat("\x00", 48), substr($f, 16));
        self::assertTrue(HashAlgo::Md5->verify('', $f));
    }

    public function testSha1Empty(): void
    {
        $f = HashAlgo::Sha1->compute('');
        self::assertSame('da39a3ee5e6b4b0d3255bfef95601890afd80709', bin2hex(substr($f, 0, 20)));
        self::assertTrue(HashAlgo::Sha1->verify('', $f));
    }

    public function testSha512Empty(): void
    {
        $f = HashAlgo::Sha512->compute('');
        self::assertSame(
            'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce'
            . '47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
            bin2hex(substr($f, 0, 64))
        );
        self::assertTrue(HashAlgo::Sha512->verify('', $f));
    }

    public function testBlake3KnownVector(): void
    {
        $f = HashAlgo::Blake3->compute('');
        self::assertSame(
            'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262',
            bin2hex(substr($f, 0, 32))
        );
        self::assertSame(str_repeat("\x00", 32), substr($f, 32));
        self::assertTrue(HashAlgo::Blake3->verify('', $f));
    }

    /**
     * Multi-chunk BLAKE3 (input > 1024 bytes) exercises the chunk tree, not just
     * a single block. Vector from the official BLAKE3 test set (len 1024, 2048).
     */
    public function testBlake3MultiChunk(): void
    {
        $mk = static function (int $n): string {
            $s = '';
            for ($i = 0; $i < $n; ++$i) {
                $s .= \chr($i % 251);
            }

            return $s;
        };
        self::assertSame(
            '42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7',
            bin2hex(Blake3::hash($mk(1024)))
        );
        self::assertSame(
            'e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a',
            bin2hex(Blake3::hash($mk(2048)))
        );
    }

    public function testDigestLenMatchesRegistry(): void
    {
        self::assertSame(0, HashAlgo::None->digestLen());
        self::assertSame(4, HashAlgo::Crc32->digestLen());
        self::assertSame(4, HashAlgo::Crc32c->digestLen());
        self::assertSame(8, HashAlgo::Crc64->digestLen());
        self::assertSame(16, HashAlgo::Md5->digestLen());
        self::assertSame(20, HashAlgo::Sha1->digestLen());
        self::assertSame(32, HashAlgo::Sha256->digestLen());
        self::assertSame(64, HashAlgo::Sha512->digestLen());
        self::assertSame(32, HashAlgo::Blake3->digestLen());
    }

    public function testNoneIsAllZeroAndAlwaysVerifies(): void
    {
        $f = HashAlgo::None->compute('anything');
        self::assertSame(str_repeat("\x00", Consts::HASH_FIELD_SIZE), $f);
        // Any 64-byte field is valid under "none".
        $garbage = str_repeat("\xFF", Consts::HASH_FIELD_SIZE);
        self::assertTrue(HashAlgo::None->verify('data', $garbage));
    }

    public function testVerifyRejectsWrongData(): void
    {
        $stored = HashAlgo::Sha256->compute('correct');
        self::assertFalse(HashAlgo::Sha256->verify('tampered', $stored));
    }

    public function testVerifyComparesOnlySignificantBytes(): void
    {
        $f = HashAlgo::Crc32c->compute('hello');
        $f[10] = "\x99"; // garbage in the unused tail
        self::assertTrue(HashAlgo::Crc32c->verify('hello', $f));
    }

    public function testUnknownIdIsError(): void
    {
        $this->assertPcfError(ErrorKind::UnknownHashAlgo, static fn () => HashAlgo::fromId(99));
    }

    public function testRoundtripIds(): void
    {
        foreach ([0, 1, 2, 3, 4, 5, 16, 17, 18] as $id) {
            self::assertSame($id, HashAlgo::fromId($id)->id());
        }
    }

    public function testReservedIdsAreRejected(): void
    {
        foreach (array_merge(range(6, 15), range(19, 30)) as $id) {
            $this->assertPcfError(ErrorKind::UnknownHashAlgo, static fn () => HashAlgo::fromId($id));
        }
    }

    public function testDigestsAreLeftAlignedAndZeroPadded(): void
    {
        foreach ([HashAlgo::Md5, HashAlgo::Sha1, HashAlgo::Sha256, HashAlgo::Sha512, HashAlgo::Blake3] as $algo) {
            $f = $algo->compute('some content');
            self::assertSame(Consts::HASH_FIELD_SIZE, \strlen($f));
            $n = $algo->digestLen();
            self::assertSame(str_repeat("\x00", Consts::HASH_FIELD_SIZE - $n), substr($f, $n));
        }
    }

    public function testCrcsAreLittleEndianLeftAlignedAndZeroPadded(): void
    {
        foreach ([[HashAlgo::Crc32, 4], [HashAlgo::Crc32c, 4], [HashAlgo::Crc64, 8]] as [$algo, $w]) {
            $f = $algo->compute('abc');
            self::assertSame(str_repeat("\x00", Consts::HASH_FIELD_SIZE - $w), substr($f, $w));
        }
    }
}
