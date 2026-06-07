<?php

declare(strict_types=1);

namespace Kduma\PCFSIG;

use Kduma\PCF\Container;
use Kduma\PCF\PartitionEntry;

/** Verdict on one SignedEntry inside a Manifest (spec Section 11, V7). */
enum EntryVerdict: string
{
    case Valid = 'Valid';
    case MissingPartition = 'MissingPartition';
    case ProtectedFieldMismatch = 'ProtectedFieldMismatch';
    case DataHashRecomputationMismatch = 'DataHashRecomputationMismatch';
    case WeakHash = 'WeakHash';
}

/** Verdict on a whole PCFSIG_SIG partition (spec Section 11, V8). */
enum ManifestVerdict: string
{
    case Valid = 'Valid';
    case Invalid = 'Invalid';
    case Unverifiable = 'Unverifiable';
}

/** Why a manifest could not be verified. */
enum UnverifiableReason: string
{
    case NoMatchingKey = 'NoMatchingKey';
    case UnsupportedSigAlgo = 'UnsupportedSigAlgo';
    case UnsupportedKeyFormat = 'UnsupportedKeyFormat';
    case MalformedKey = 'MalformedKey';
    case SignatureLengthMismatch = 'SignatureLengthMismatch';
}

/** Per-entry report. */
final class EntryReport
{
    public function __construct(
        public readonly string $uid,
        public EntryVerdict $verdict,
    ) {
    }
}

/** Report for one PCFSIG_SIG partition. */
final class SignatureReport
{
    /** @param EntryReport[] $entries */
    public function __construct(
        public readonly string $sigPartitionUid,
        public readonly string $signerKeyFingerprint,
        public readonly int $signedAtUnixSeconds,
        public ManifestVerdict $verdict,
        public ?UnverifiableReason $unverifiableReason,
        public ?int $unverifiableId,
        public array $entries,
    ) {
    }
}

/** Whether to independently re-hash each covered partition during verification. */
enum DataRecheck: string
{
    case Skip = 'Skip';
    case Recompute = 'Recompute';
}

/** High-level verification API (spec Section 11). */
final class Verify
{
    /**
     * Verify every PCFSIG_SIG partition in $container and return one report
     * each.
     *
     * @return SignatureReport[]
     */
    public static function all(
        Container $container,
        DataRecheck $recheck = DataRecheck::Skip,
    ): array {
        $entries = $container->entries();

        /** @var array<array{record: KeyRecord, uid: string}> $keys */
        $keys = [];
        foreach ($entries as $e) {
            if ($e->partitionType === Consts::TYPE_PCFSIG_KEY) {
                try {
                    $rec = KeyRecord::fromBytes($container->readPartitionData($e));
                    $keys[] = ['record' => $rec, 'uid' => $e->uid];
                } catch (PcfSigException) {
                    // skip
                }
            }
        }

        /** @var SignatureReport[] $reports */
        $reports = [];
        foreach ($entries as $e) {
            if ($e->partitionType !== Consts::TYPE_PCFSIG_SIG) {
                continue;
            }
            $data = $container->readPartitionData($e);
            $reports[] = self::verifyOne($entries, $keys, $e, $data);
        }

        if ($recheck === DataRecheck::Recompute) {
            foreach ($reports as $r) {
                foreach ($r->entries as $er) {
                    if ($er->verdict !== EntryVerdict::Valid) {
                        continue;
                    }
                    $p = null;
                    foreach ($entries as $x) {
                        if ($x->uid === $er->uid) {
                            $p = $x;
                            break;
                        }
                    }
                    if ($p !== null) {
                        $bytes = $container->readPartitionData($p);
                        $computed = $p->dataHashAlgo->compute($bytes);
                        if (!hash_equals($computed, $p->dataHash)) {
                            $er->verdict = EntryVerdict::DataHashRecomputationMismatch;
                        }
                    }
                }
            }
        }

        return $reports;
    }

    /** @return SignatureReport[] */
    public static function allWithRecheck(Container $container): array
    {
        return self::all($container, DataRecheck::Recompute);
    }

    /**
     * @param PartitionEntry[]                                $entries
     * @param array<array{record: KeyRecord, uid: string}>    $keys
     */
    private static function verifyOne(
        array $entries,
        array $keys,
        PartitionEntry $sigEntry,
        string $data,
    ): SignatureReport {
        try {
            $parsed = SignaturePartition::fromBytes($data);
        } catch (PcfSigException) {
            return new SignatureReport(
                $sigEntry->uid,
                str_repeat("\x00", Consts::FINGERPRINT_SIZE),
                0,
                ManifestVerdict::Unverifiable,
                UnverifiableReason::MalformedKey,
                null,
                [],
            );
        }

        $report = new SignatureReport(
            $sigEntry->uid,
            $parsed->manifest->signerKeyFingerprint,
            $parsed->manifest->signedAtUnixSeconds,
            ManifestVerdict::Valid,
            null,
            null,
            [],
        );

        // Self-reference check (spec Section 7.2).
        foreach ($parsed->manifest->signedEntries as $e) {
            if ($e->uid === $sigEntry->uid) {
                $report->verdict = ManifestVerdict::Invalid;

                return $report;
            }
        }

        if (!$parsed->manifest->sigAlgo->isImplemented()) {
            $report->verdict = ManifestVerdict::Unverifiable;
            $report->unverifiableReason = UnverifiableReason::UnsupportedSigAlgo;
            $report->unverifiableId = $parsed->manifest->sigAlgo->id();

            return $report;
        }

        $key = null;
        foreach ($keys as $k) {
            if (hash_equals(
                $k['record']->fingerprint,
                $parsed->manifest->signerKeyFingerprint,
            )) {
                $key = $k;
                break;
            }
        }
        if ($key === null) {
            $report->verdict = ManifestVerdict::Unverifiable;
            $report->unverifiableReason = UnverifiableReason::NoMatchingKey;

            return $report;
        }

        $keyRecord = $key['record'];
        if (!$keyRecord->keyFormat->isImplemented()) {
            $report->verdict = ManifestVerdict::Unverifiable;
            $report->unverifiableReason = UnverifiableReason::UnsupportedKeyFormat;
            $report->unverifiableId = $keyRecord->keyFormat->id();

            return $report;
        }

        if (
            $parsed->manifest->sigAlgo === SigAlgo::Ed25519
            && $keyRecord->keyFormat === KeyFormat::Ed25519Raw
        ) {
            if (\strlen($parsed->signature) !== Consts::ED25519_SIGNATURE_LEN) {
                $report->verdict = ManifestVerdict::Unverifiable;
                $report->unverifiableReason = UnverifiableReason::SignatureLengthMismatch;

                return $report;
            }
            if (\strlen($keyRecord->keyData) !== Consts::ED25519_PUBLIC_KEY_LEN) {
                $report->verdict = ManifestVerdict::Unverifiable;
                $report->unverifiableReason = UnverifiableReason::MalformedKey;

                return $report;
            }
            try {
                $ok = sodium_crypto_sign_verify_detached(
                    $parsed->signature,
                    $parsed->manifestBytes,
                    $keyRecord->keyData,
                );
            } catch (\SodiumException) {
                $ok = false;
            }
            if (!$ok) {
                $report->verdict = ManifestVerdict::Invalid;

                return $report;
            }
        } else {
            $report->verdict = ManifestVerdict::Unverifiable;
            $report->unverifiableReason = UnverifiableReason::UnsupportedSigAlgo;
            $report->unverifiableId = $parsed->manifest->sigAlgo->id();

            return $report;
        }

        foreach ($parsed->manifest->signedEntries as $se) {
            $p = null;
            foreach ($entries as $x) {
                if ($x->uid === $se->uid) {
                    $p = $x;
                    break;
                }
            }
            if ($p === null) {
                $report->entries[] = new EntryReport($se->uid, EntryVerdict::MissingPartition);

                continue;
            }
            if (!Manifest::isCryptoHash($se->dataHashAlgo)) {
                $report->entries[] = new EntryReport($se->uid, EntryVerdict::WeakHash);

                continue;
            }
            if (
                $p->partitionType !== $se->partitionType
                || $p->label !== $se->label
                || $p->usedBytes !== $se->usedBytes
                || $p->dataHashAlgo !== $se->dataHashAlgo
                || !hash_equals($p->dataHash, $se->dataHash)
            ) {
                $report->entries[] = new EntryReport(
                    $se->uid,
                    EntryVerdict::ProtectedFieldMismatch,
                );

                continue;
            }
            $report->entries[] = new EntryReport($se->uid, EntryVerdict::Valid);
        }

        return $report;
    }
}
