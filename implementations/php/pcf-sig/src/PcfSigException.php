<?php

declare(strict_types=1);

namespace Kduma\PCFSIG;

/**
 * The single exception type raised by this library. The {@see ErrorKind}
 * carried in {@see PcfSigException::$kind} identifies the precise failure.
 */
final class PcfSigException extends \RuntimeException
{
    public function __construct(
        public readonly ErrorKind $kind,
        string $message,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    public static function badKeyMagic(): self
    {
        return new self(ErrorKind::BadKeyMagic, 'bad PCFSIG_KEY magic');
    }

    public static function badManifestMagic(): self
    {
        return new self(ErrorKind::BadManifestMagic, 'bad PCFSIG_SIG manifest magic');
    }

    public static function unsupportedMajor(int $v): self
    {
        return new self(ErrorKind::UnsupportedMajor, "unsupported PCF-SIG major version {$v}");
    }

    public static function unknownKeyFormat(int $id): self
    {
        return new self(ErrorKind::UnknownKeyFormat, "unknown key_format_id {$id}");
    }

    public static function emptyKeyData(): self
    {
        return new self(ErrorKind::EmptyKeyData, 'key_data_length is zero');
    }

    public static function nonZeroKeyReserved(): self
    {
        return new self(ErrorKind::NonZeroKeyReserved, 'key record reserved bytes are non-zero');
    }

    public static function fingerprintMismatch(): self
    {
        return new self(
            ErrorKind::FingerprintMismatch,
            'stored key fingerprint does not match SHA-256(key_data)',
        );
    }

    public static function unknownSigAlgo(int $id): self
    {
        return new self(ErrorKind::UnknownSigAlgo, "unknown or reserved sig_algo_id {$id}");
    }

    public static function nonCryptoManifestHash(int $id): self
    {
        return new self(
            ErrorKind::NonCryptoManifestHash,
            "manifest_hash_algo_id {$id} is not cryptographic",
        );
    }

    public static function hashAlgoBindingMismatch(): self
    {
        return new self(
            ErrorKind::HashAlgoBindingMismatch,
            'manifest_hash_algo_id does not match the binding required by sig_algo_id',
        );
    }

    public static function nonZeroFlags(): self
    {
        return new self(ErrorKind::NonZeroFlags, 'manifest flags are non-zero in v1.0');
    }

    public static function emptyManifest(): self
    {
        return new self(ErrorKind::EmptyManifest, 'manifest signed_count is 0');
    }

    public static function nonZeroTrailer(): self
    {
        return new self(ErrorKind::NonZeroTrailer, 'trailer_length is non-zero in v1.0');
    }

    public static function nonZeroEntryReserved(): self
    {
        return new self(
            ErrorKind::NonZeroEntryReserved,
            'SignedEntry reserved span contains non-zero bytes',
        );
    }

    public static function nonCryptoEntryHash(int $id): self
    {
        return new self(
            ErrorKind::NonCryptoEntryHash,
            "SignedEntry data_hash_algo_id {$id} is not cryptographic",
        );
    }

    public static function entryNilUid(): self
    {
        return new self(ErrorKind::EntryNilUid, 'SignedEntry uses the NIL UID');
    }

    public static function entryReservedType(): self
    {
        return new self(
            ErrorKind::EntryReservedType,
            'SignedEntry uses PCF reserved type 0x00000000',
        );
    }

    public static function duplicateSignedUid(): self
    {
        return new self(ErrorKind::DuplicateSignedUid, 'duplicate uid in manifest');
    }

    public static function selfSignedEntry(): self
    {
        return new self(
            ErrorKind::SelfSignedEntry,
            'SignedEntry references the PCFSIG_SIG partition itself',
        );
    }

    public static function malformedSignaturePartition(): self
    {
        return new self(
            ErrorKind::MalformedSignaturePartition,
            'PCFSIG_SIG partition layout is malformed',
        );
    }

    public static function signatureLengthMismatch(): self
    {
        return new self(
            ErrorKind::SignatureLengthMismatch,
            'sig_bytes length does not match the algorithm',
        );
    }

    public static function nonCryptoTargetHash(): self
    {
        return new self(
            ErrorKind::NonCryptoTargetHash,
            'cannot sign a partition whose data_hash_algo_id is not cryptographic',
        );
    }

    public static function targetPartitionMissing(): self
    {
        return new self(
            ErrorKind::TargetPartitionMissing,
            'partition to sign is not present in the container',
        );
    }
}
