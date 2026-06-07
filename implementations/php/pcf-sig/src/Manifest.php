<?php

declare(strict_types=1);

namespace Kduma\PCFSIG;

use Kduma\PCF\HashAlgo;

/** A parsed Manifest (spec Section 7.1). */
final class Manifest
{
    /**
     * @param SignedEntry[] $signedEntries
     */
    public function __construct(
        public readonly int $versionMajor,
        public readonly int $versionMinor,
        public readonly SigAlgo $sigAlgo,
        public readonly HashAlgo $manifestHashAlgo,
        public readonly int $flags,
        public readonly string $signerKeyFingerprint,
        public readonly int $signedAtUnixSeconds,
        public readonly array $signedEntries,
    ) {
    }

    /**
     * Build a Manifest from its component parts.
     *
     * @param SignedEntry[] $signedEntries
     */
    public static function make(
        SigAlgo $sigAlgo,
        HashAlgo $manifestHashAlgo,
        string $signerKeyFingerprint,
        int $signedAtUnixSeconds,
        array $signedEntries,
    ): self {
        return new self(
            Consts::PROFILE_VERSION_MAJOR,
            Consts::PROFILE_VERSION_MINOR,
            $sigAlgo,
            $manifestHashAlgo,
            0,
            $signerKeyFingerprint,
            $signedAtUnixSeconds,
            $signedEntries,
        );
    }

    /** Serialised length in bytes. */
    public function byteLen(): int
    {
        return Consts::MANIFEST_PREFIX_SIZE
            + Consts::SIGNED_ENTRY_SIZE * \count($this->signedEntries);
    }

    /** Serialise to the on-disk byte layout (spec Section 7.1). */
    public function toBytes(): string
    {
        $out = Consts::SIG_MAGIC;
        $out .= pack('v', $this->versionMajor);
        $out .= pack('v', $this->versionMinor);
        $out .= \chr($this->sigAlgo->id());
        $out .= \chr($this->manifestHashAlgo->id());
        $out .= pack('v', $this->flags);
        $out .= str_pad(substr($this->signerKeyFingerprint, 0, Consts::FINGERPRINT_SIZE), Consts::FINGERPRINT_SIZE, "\x00");
        $out .= pack('q', $this->signedAtUnixSeconds); // i64 LE
        $out .= pack('V', \count($this->signedEntries));
        foreach ($this->signedEntries as $e) {
            $out .= $e->toBytes();
        }

        return $out;
    }

    /**
     * Parse from the on-disk byte layout. Validates: magic, major version,
     * algorithm registry membership, hash-algo binding (Section 8),
     * cryptographic hash requirement (Section 9), reserved flags, non-empty
     * signed_count, per-entry reserved spans (Section 7.2). Does NOT validate
     * duplicate uids or self-reference; the verifier does that with context
     * from the enclosing partition.
     */
    public static function fromBytes(string $b): self
    {
        if (\strlen($b) < Consts::MANIFEST_PREFIX_SIZE) {
            throw PcfSigException::malformedSignaturePartition();
        }
        if (substr($b, 0, 8) !== Consts::SIG_MAGIC) {
            throw PcfSigException::badManifestMagic();
        }
        $versionMajor = unpack('v', substr($b, 8, 2))[1];
        $versionMinor = unpack('v', substr($b, 10, 2))[1];
        if ($versionMajor !== Consts::PROFILE_VERSION_MAJOR) {
            throw PcfSigException::unsupportedMajor($versionMajor);
        }
        $sigAlgo = SigAlgo::fromId(\ord($b[12]));
        $manifestHashId = \ord($b[13]);
        $manifestHashAlgo = HashAlgo::fromId($manifestHashId);
        if (!self::isCryptoHash($manifestHashAlgo)) {
            throw PcfSigException::nonCryptoManifestHash($manifestHashId);
        }
        $required = $sigAlgo->requiredManifestHash();
        if ($required !== null && $required !== $manifestHashAlgo) {
            throw PcfSigException::hashAlgoBindingMismatch();
        }
        $flags = unpack('v', substr($b, 14, 2))[1];
        if ($flags !== 0) {
            throw PcfSigException::nonZeroFlags();
        }
        $signerKeyFingerprint = substr($b, 16, Consts::FINGERPRINT_SIZE);
        $signedAtUnixSeconds = unpack('q', substr($b, 48, 8))[1];
        $signedCount = unpack('V', substr($b, 56, 4))[1];
        if ($signedCount === 0) {
            throw PcfSigException::emptyManifest();
        }
        $expected = Consts::MANIFEST_PREFIX_SIZE + Consts::SIGNED_ENTRY_SIZE * $signedCount;
        if (\strlen($b) < $expected) {
            throw PcfSigException::malformedSignaturePartition();
        }
        $entries = [];
        $seen = [];
        for ($i = 0; $i < $signedCount; ++$i) {
            $off = Consts::MANIFEST_PREFIX_SIZE + $i * Consts::SIGNED_ENTRY_SIZE;
            $e = SignedEntry::fromBytes(substr($b, $off, Consts::SIGNED_ENTRY_SIZE));
            $key = bin2hex($e->uid);
            if (isset($seen[$key])) {
                throw PcfSigException::duplicateSignedUid();
            }
            $seen[$key] = true;
            $entries[] = $e;
        }

        return new self(
            $versionMajor,
            $versionMinor,
            $sigAlgo,
            $manifestHashAlgo,
            $flags,
            $signerKeyFingerprint,
            $signedAtUnixSeconds,
            $entries,
        );
    }

    /** Whether a PCF hash algorithm id is cryptographic (spec Section 9). */
    public static function isCryptoHash(HashAlgo $algo): bool
    {
        return $algo === HashAlgo::Sha256
            || $algo === HashAlgo::Sha512
            || $algo === HashAlgo::Blake3;
    }
}
