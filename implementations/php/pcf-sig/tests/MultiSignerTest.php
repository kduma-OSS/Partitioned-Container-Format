<?php

declare(strict_types=1);

namespace Kduma\PCFSIG\Tests;

use Kduma\PCF\Container;
use Kduma\PCF\HashAlgo;
use Kduma\PCFSIG\Consts;
use Kduma\PCFSIG\DataRecheck;
use Kduma\PCFSIG\EntryVerdict;
use Kduma\PCFSIG\ManifestVerdict;
use Kduma\PCFSIG\SignPartitions;
use Kduma\PCFSIG\SigningMaterial;
use Kduma\PCFSIG\Verify;

final class MultiSignerTest extends PcfSigTestCase
{
    public function test_two_signers_each_sign_own_partition(): void
    {
        $c = Container::create();
        $c->addPartition(0x10, $this->uid(1), 'alpha', 'alpha', 0, HashAlgo::Sha256);
        $c->addPartition(0x11, $this->uid(2), 'beta', 'beta', 0, HashAlgo::Sha256);

        $a = SigningMaterial::ed25519FromSeed(str_repeat("\x01", 32));
        $b = SigningMaterial::ed25519FromSeed(str_repeat("\x02", 32));

        SignPartitions::run($c, $a, [$this->uid(1)], $this->uid(0xA1), $this->uid(0xA0), 0, 'sigA', 'keyA');
        SignPartitions::run($c, $b, [$this->uid(2)], $this->uid(0xB1), $this->uid(0xB0), 0, 'sigB', 'keyB');

        $reports = Verify::all($c, DataRecheck::Skip);
        self::assertCount(2, $reports);
        foreach ($reports as $r) {
            self::assertSame(ManifestVerdict::Valid, $r->verdict);
            self::assertCount(1, $r->entries);
            self::assertSame(EntryVerdict::Valid, $r->entries[0]->verdict);
        }
    }

    public function test_same_signer_dedupes_key_partition(): void
    {
        $c = Container::create();
        $c->addPartition(0x10, $this->uid(1), 'alpha', 'a', 0, HashAlgo::Sha256);
        $c->addPartition(0x11, $this->uid(2), 'beta', 'b', 0, HashAlgo::Sha256);
        $signer = SigningMaterial::ed25519FromSeed(str_repeat("\xAA", 32));
        SignPartitions::run($c, $signer, [$this->uid(1)], $this->uid(0xA1), $this->uid(0xA0), 0, 'sig1', 'key');
        SignPartitions::run($c, $signer, [$this->uid(2)], $this->uid(0xA2), $this->uid(0xA3), 0, 'sig2', 'key');

        $keyParts = array_values(array_filter(
            $c->entries(),
            fn($e) => $e->partitionType === Consts::TYPE_PCFSIG_KEY,
        ));
        self::assertCount(1, $keyParts);
        self::assertSame($this->uid(0xA0), $keyParts[0]->uid);
    }
}
