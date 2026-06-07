<?php

declare(strict_types=1);

namespace Kduma\PCFSIG;

use Kduma\PCF\Container;
use Kduma\PCF\HashAlgo;
use Kduma\PCF\PartitionEntry;

/** High-level signing API (spec Section 10). */
final class SignPartitions
{
    /**
     * Look up an existing PCFSIG_KEY partition by fingerprint, or, if none
     * exists, add a fresh one carrying $signer's public material. Returns
     * the PCF uid of the chosen partition.
     */
    public static function ensureKeyPartition(
        Container $container,
        SigningMaterial $signer,
        string $keyUidSeed,
        string $label,
    ): string {
        $fp = $signer->fingerprint();
        foreach ($container->entries() as $e) {
            if ($e->partitionType === Consts::TYPE_PCFSIG_KEY) {
                try {
                    $rec = KeyRecord::fromBytes($container->readPartitionData($e));
                    if (hash_equals($rec->fingerprint, $fp)) {
                        return $e->uid;
                    }
                } catch (PcfSigException) {
                    // skip malformed key records
                }
            }
        }
        $container->addPartition(
            Consts::TYPE_PCFSIG_KEY,
            $keyUidSeed,
            $label,
            $signer->toKeyRecordBytes(),
            0,
            HashAlgo::Sha256,
        );

        return $keyUidSeed;
    }

    /** Build a SignedEntry mirroring a PCF PartitionEntry. */
    public static function signedEntryFromPartition(PartitionEntry $e): SignedEntry
    {
        if (!Manifest::isCryptoHash($e->dataHashAlgo)) {
            throw PcfSigException::nonCryptoTargetHash();
        }

        return new SignedEntry(
            $e->uid,
            $e->partitionType,
            $e->label,
            $e->usedBytes,
            $e->dataHashAlgo,
            $e->dataHash,
        );
    }

    /**
     * Sign a chosen set of partitions and write the resulting PCFSIG_SIG
     * partition into $container.
     *
     * @param string[] $targetUids
     */
    public static function run(
        Container $container,
        SigningMaterial $signer,
        array $targetUids,
        string $sigPartitionUid,
        string $keyPartitionUid,
        int $signedAtUnixSeconds,
        string $sigLabel,
        string $keyLabel,
    ): string {
        if ($targetUids === []) {
            throw PcfSigException::emptyManifest();
        }
        foreach ($targetUids as $u) {
            if ($u === $sigPartitionUid) {
                throw PcfSigException::selfSignedEntry();
            }
        }
        $seen = [];
        foreach ($targetUids as $u) {
            $k = bin2hex($u);
            if (isset($seen[$k])) {
                throw PcfSigException::duplicateSignedUid();
            }
            $seen[$k] = true;
        }

        self::ensureKeyPartition($container, $signer, $keyPartitionUid, $keyLabel);

        $entries = $container->entries();
        $signedEntries = [];
        foreach ($targetUids as $uid) {
            $found = null;
            foreach ($entries as $e) {
                if ($e->uid === $uid) {
                    $found = $e;
                    break;
                }
            }
            if ($found === null) {
                throw PcfSigException::targetPartitionMissing();
            }
            $signedEntries[] = self::signedEntryFromPartition($found);
        }

        $manifestHash = $signer->sigAlgo->requiredManifestHash();
        if ($manifestHash === null) {
            throw new \LogicException('signer algorithm has no fixed manifest hash binding');
        }
        $manifest = Manifest::make(
            $signer->sigAlgo,
            $manifestHash,
            $signer->fingerprint(),
            $signedAtUnixSeconds,
            $signedEntries,
        );
        $manifestBytes = $manifest->toBytes();
        $signature = $signer->sign($manifestBytes);
        $partition = new SignaturePartition($manifest, $manifestBytes, $signature, '');
        $container->addPartition(
            Consts::TYPE_PCFSIG_SIG,
            $sigPartitionUid,
            $sigLabel,
            $partition->toBytes(),
            0,
            HashAlgo::Sha256,
        );

        return $sigPartitionUid;
    }
}
