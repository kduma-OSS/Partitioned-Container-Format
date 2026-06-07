<?php

declare(strict_types=1);

namespace Kduma\PCFSIG\Tests;

use Kduma\PCF\Container;
use Kduma\PCF\HashAlgo;
use Kduma\PCF\Storage\MemoryStorage;
use Kduma\PCFSIG\Consts;
use Kduma\PCFSIG\DataRecheck;
use Kduma\PCFSIG\EntryVerdict;
use Kduma\PCFSIG\ErrorKind;
use Kduma\PCFSIG\ManifestVerdict;
use Kduma\PCFSIG\PcfSigException;
use Kduma\PCFSIG\SigningMaterial;
use Kduma\PCFSIG\SignPartitions;
use Kduma\PCFSIG\Verify;

final class RoundtripTest extends PcfSigTestCase
{
    public function test_sign_and_verify_single_partition(): void
    {
        $c = Container::create();
        $alpha = $this->uid(1);
        $c->addPartition(0x10, $alpha, 'alpha', 'hello', 0, HashAlgo::Sha256);

        $signer = SigningMaterial::ed25519FromSeed(str_repeat("\x42", 32));
        SignPartitions::run(
            $c, $signer, [$alpha],
            $this->uid(0xA1), $this->uid(0xA0),
            1_700_000_000, 'pcfsig', 'pcfkey',
        );

        $c->verify();
        $reports = Verify::all($c, DataRecheck::Skip);
        self::assertCount(1, $reports);
        self::assertSame(ManifestVerdict::Valid, $reports[0]->verdict);
        self::assertCount(1, $reports[0]->entries);
        self::assertSame(EntryVerdict::Valid, $reports[0]->entries[0]->verdict);
        self::assertSame(1_700_000_000, $reports[0]->signedAtUnixSeconds);
        self::assertSame($signer->fingerprint(), $reports[0]->signerKeyFingerprint);
    }

    public function test_reopen_after_serialise_and_verify(): void
    {
        $c = Container::create();
        $c->addPartition(0x10, $this->uid(1), 'alpha', 'hello', 0, HashAlgo::Sha256);
        $c->addPartition(0x11, $this->uid(2), 'beta', 'world', 0, HashAlgo::Blake3);
        $signer = SigningMaterial::ed25519FromSeed(str_repeat("\x01", 32));
        SignPartitions::run(
            $c, $signer, [$this->uid(1), $this->uid(2)],
            $this->uid(0xA1), $this->uid(0xA0),
            0, 'sig', 'key',
        );
        $bytes = $c->compactedImage();
        $c2 = Container::open(new MemoryStorage($bytes));
        $c2->verify();
        $reports = Verify::allWithRecheck($c2);
        self::assertSame(ManifestVerdict::Valid, $reports[0]->verdict);
        self::assertCount(2, $reports[0]->entries);
        foreach ($reports[0]->entries as $er) {
            self::assertSame(EntryVerdict::Valid, $er->verdict);
        }
    }

    public function test_deduplicates_key_partitions(): void
    {
        $c = Container::create();
        $c->addPartition(0x10, $this->uid(1), 'a', 'a', 0, HashAlgo::Sha256);
        $c->addPartition(0x10, $this->uid(2), 'b', 'b', 0, HashAlgo::Sha256);
        $signer = SigningMaterial::ed25519FromSeed(str_repeat("\x03", 32));
        SignPartitions::run(
            $c, $signer, [$this->uid(1)],
            $this->uid(0xA1), $this->uid(0xA0),
            0, 'sig1', 'k',
        );
        SignPartitions::run(
            $c, $signer, [$this->uid(2)],
            $this->uid(0xA2), $this->uid(0xA3),
            0, 'sig2', 'k2',
        );

        $keyPartitions = array_values(array_filter(
            $c->entries(),
            fn($e) => $e->partitionType === Consts::TYPE_PCFSIG_KEY,
        ));
        self::assertCount(1, $keyPartitions);
        self::assertSame($this->uid(0xA0), $keyPartitions[0]->uid);

        $reports = Verify::all($c, DataRecheck::Skip);
        self::assertCount(2, $reports);
        foreach ($reports as $r) {
            self::assertSame(ManifestVerdict::Valid, $r->verdict);
        }
    }

    public function test_refuses_weakly_hashed_target(): void
    {
        $c = Container::create();
        $alpha = $this->uid(1);
        $c->addPartition(0x10, $alpha, 'alpha', 'x', 0, HashAlgo::Crc32c);
        $signer = SigningMaterial::ed25519FromSeed(str_repeat("\x04", 32));
        try {
            SignPartitions::run(
                $c, $signer, [$alpha],
                $this->uid(0xA1), $this->uid(0xA0),
                0, 'sig', 'key',
            );
            self::fail('expected NonCryptoTargetHash');
        } catch (PcfSigException $e) {
            self::assertSame(ErrorKind::NonCryptoTargetHash, $e->kind);
        }
    }

    public function test_refuses_self_reference(): void
    {
        $c = Container::create();
        $alpha = $this->uid(1);
        $c->addPartition(0x10, $alpha, 'alpha', 'x', 0, HashAlgo::Sha256);
        $signer = SigningMaterial::ed25519FromSeed(str_repeat("\x05", 32));
        $sigUid = $this->uid(0xA1);
        try {
            SignPartitions::run(
                $c, $signer, [$alpha, $sigUid],
                $sigUid, $this->uid(0xA0),
                0, 'sig', 'key',
            );
            self::fail('expected SelfSignedEntry');
        } catch (PcfSigException $e) {
            self::assertSame(ErrorKind::SelfSignedEntry, $e->kind);
        }
    }
}
