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

final class RelocationTest extends PcfSigTestCase
{
    public function test_signature_survives_pcf_compaction(): void
    {
        $c = Container::create();
        $c->addPartition(0x10, $this->uid(1), 'alpha', 'alpha payload', 1024, HashAlgo::Sha256);
        $c->addPartition(0x11, $this->uid(2), 'beta', 'beta payload', 1024, HashAlgo::Sha512);
        $c->addPartition(0x12, $this->uid(3), 'gamma', 'gamma payload', 1024, HashAlgo::Blake3);
        $signer = SigningMaterial::ed25519FromSeed(str_repeat("\x10", 32));
        SignPartitions::run(
            $c, $signer, [$this->uid(1), $this->uid(2), $this->uid(3)],
            $this->uid(0xA1), $this->uid(0xA0),
            0, 'sig', 'key',
        );

        $compacted = $c->compactedImage();
        $c2 = Container::open(new MemoryStorage($compacted));
        $c2->verify();

        $alpha = null;
        foreach ($c2->entries() as $e) {
            if (\ord($e->uid[0]) === 1) {
                $alpha = $e;
                break;
            }
        }
        self::assertNotNull($alpha);
        self::assertSame(13, $alpha->usedBytes);
        self::assertSame(13, $alpha->maxLength);

        $reports = Verify::allWithRecheck($c2);
        self::assertSame(ManifestVerdict::Valid, $reports[0]->verdict);
        self::assertCount(3, $reports[0]->entries);
        foreach ($reports[0]->entries as $er) {
            self::assertSame(EntryVerdict::Valid, $er->verdict);
        }
    }

    public function test_signature_survives_chain_growth(): void
    {
        $c = Container::createWith(new MemoryStorage(), 2, HashAlgo::Sha256);
        $c->addPartition(0x10, $this->uid(1), 'alpha', 'alpha', 0, HashAlgo::Sha256);
        $signer = SigningMaterial::ed25519FromSeed(str_repeat("\x20", 32));
        SignPartitions::run(
            $c, $signer, [$this->uid(1)],
            $this->uid(0xA1), $this->uid(0xA0),
            0, 'sig', 'key',
        );
        for ($i = 0; $i < 6; ++$i) {
            $c->addPartition(0x20, $this->uid(0x40 + $i), 'extra', str_repeat(\chr($i), 4), 0, HashAlgo::Sha256);
        }
        $c->verify();
        $reports = Verify::allWithRecheck($c);
        self::assertSame(ManifestVerdict::Valid, $reports[0]->verdict);
        self::assertSame(EntryVerdict::Valid, $reports[0]->entries[0]->verdict);
    }

    public function test_signature_survives_unrelated_update(): void
    {
        $c = Container::create();
        $c->addPartition(0x10, $this->uid(1), 'signed', 'locked', 0, HashAlgo::Sha256);
        $c->addPartition(0x11, $this->uid(2), 'free', 'original', 64, HashAlgo::Sha256);
        $signer = SigningMaterial::ed25519FromSeed(str_repeat("\x30", 32));
        SignPartitions::run(
            $c, $signer, [$this->uid(1)],
            $this->uid(0xA1), $this->uid(0xA0),
            0, 'sig', 'key',
        );
        $c->updatePartitionData($this->uid(2), 'replaced payload data');
        $c->verify();
        $reports = Verify::allWithRecheck($c);
        self::assertSame(ManifestVerdict::Valid, $reports[0]->verdict);
        self::assertSame(EntryVerdict::Valid, $reports[0]->entries[0]->verdict);
    }
}
