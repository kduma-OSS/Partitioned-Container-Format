<?php

declare(strict_types=1);

namespace Kduma\PCFSIG\Tests;

use Kduma\PCF\Container;
use Kduma\PCF\HashAlgo;
use Kduma\PCF\Storage\MemoryStorage;
use Kduma\PCFSIG\EntryVerdict;
use Kduma\PCFSIG\ManifestVerdict;
use Kduma\PCFSIG\SignPartitions;
use Kduma\PCFSIG\SigningMaterial;
use Kduma\PCFSIG\Verify;

final class CanonicalVectorTest extends PcfSigTestCase
{
    private const EXPECTED_SHA256 =
        'b158e2f5b160d72cea3226af2041f8d18aa75b3db6cb85faeca5df7879871307';

    private static function canonical(): string
    {
        return file_get_contents(__DIR__ . '/../testdata/canonical.bin');
    }

    public function test_ships_expected_sha256(): void
    {
        self::assertSame(
            self::EXPECTED_SHA256,
            bin2hex(hash('sha256', self::canonical(), true)),
        );
    }

    public function test_opens_and_verifies_pcf_and_pcfsig(): void
    {
        $c = Container::open(new MemoryStorage(self::canonical()));
        $c->verify();
        $reports = Verify::allWithRecheck($c);
        self::assertCount(1, $reports);
        self::assertSame(ManifestVerdict::Valid, $reports[0]->verdict);
        self::assertCount(1, $reports[0]->entries);
        self::assertSame(EntryVerdict::Valid, $reports[0]->entries[0]->verdict);
    }

    public function test_regenerates_byte_exact_from_deterministic_seed(): void
    {
        $seed = '';
        for ($i = 0; $i < 32; ++$i) {
            $seed .= \chr($i);
        }
        $signer = SigningMaterial::ed25519FromSeed($seed);

        $c = Container::createWith(new MemoryStorage(), 8, HashAlgo::Sha256);
        $c->addPartition(
            0x10,
            str_repeat("\x11", 16),
            'alpha',
            'Hello, PCF-SIG!',
            0,
            HashAlgo::Sha256,
        );
        SignPartitions::run(
            $c,
            $signer,
            [str_repeat("\x11", 16)],
            str_repeat("\x33", 16),
            str_repeat("\x22", 16),
            0,
            'pcfsig',
            'pcfkey',
        );
        $image = $c->compactedImage();
        self::assertSame(\strlen(self::canonical()), \strlen($image));
        self::assertSame(
            self::EXPECTED_SHA256,
            bin2hex(hash('sha256', $image, true)),
        );
    }
}
