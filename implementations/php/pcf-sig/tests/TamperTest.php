<?php

declare(strict_types=1);

namespace Kduma\PCFSIG\Tests;

use Kduma\PCF\Container;
use Kduma\PCF\HashAlgo;
use Kduma\PCF\Storage\MemoryStorage;
use Kduma\PCFSIG\Consts;
use Kduma\PCFSIG\EntryVerdict;
use Kduma\PCFSIG\ManifestVerdict;
use Kduma\PCFSIG\SignPartitions;
use Kduma\PCFSIG\SigningMaterial;
use Kduma\PCFSIG\Verify;

final class TamperTest extends PcfSigTestCase
{
    /** @return array{0: Container, 1: string} */
    private function build(): array
    {
        $c = Container::create();
        $alpha = $this->uid(1);
        $c->addPartition(0x10, $alpha, 'alpha', 'original payload', 64, HashAlgo::Sha256);
        $signer = SigningMaterial::ed25519FromSeed(str_repeat("\x33", 32));
        SignPartitions::run(
            $c, $signer, [$alpha],
            $this->uid(0xA1), $this->uid(0xA0),
            0, 'sig', 'key',
        );

        return [$c, $alpha];
    }

    public function test_baseline_verifies(): void
    {
        [$c] = $this->build();
        $reports = Verify::allWithRecheck($c);
        self::assertSame(ManifestVerdict::Valid, $reports[0]->verdict);
        self::assertSame(EntryVerdict::Valid, $reports[0]->entries[0]->verdict);
    }

    public function test_data_update_invalidates_entry(): void
    {
        [$c, $alpha] = $this->build();
        $c->updatePartitionData($alpha, 'forged payload');
        $reports = Verify::allWithRecheck($c);
        self::assertSame(ManifestVerdict::Valid, $reports[0]->verdict);
        self::assertSame(
            EntryVerdict::ProtectedFieldMismatch,
            $reports[0]->entries[0]->verdict,
        );
    }

    public function test_removed_covered_partition_reported_missing(): void
    {
        [$c, $alpha] = $this->build();
        $c->removePartition($alpha);
        $reports = Verify::allWithRecheck($c);
        self::assertSame(ManifestVerdict::Valid, $reports[0]->verdict);
        self::assertSame(
            EntryVerdict::MissingPartition,
            $reports[0]->entries[0]->verdict,
        );
    }

    public function test_flipping_signature_byte_invalidates_manifest(): void
    {
        [$c] = $this->build();
        $bytes = $c->compactedImage();
        $c2 = Container::open(new MemoryStorage($bytes));
        $sig = null;
        foreach ($c2->entries() as $e) {
            if ($e->partitionType === Consts::TYPE_PCFSIG_SIG) {
                $sig = $e;
                break;
            }
        }
        self::assertNotNull($sig);
        $last = $sig->startOffset + $sig->usedBytes - 8;
        $bytes[$last] = \chr(\ord($bytes[$last]) ^ 0x01);
        $c3 = Container::open(new MemoryStorage($bytes));
        $reports = Verify::allWithRecheck($c3);
        self::assertSame(ManifestVerdict::Invalid, $reports[0]->verdict);
    }
}
