<?php

declare(strict_types=1);

namespace Kduma\PCFSIG;

/**
 * The Key Record stored in a `PCFSIG_KEY` partition (spec Section 6).
 *
 * A Key Record is a fixed prefix ({@see Consts::KEY_PREFIX_SIZE} bytes)
 * carrying the 32-byte SHA-256 fingerprint plus a length-prefixed key_data
 * blob, then an optional Type-Length-Value metadata stream that runs to
 * used_bytes.
 */
final class KeyRecord
{
    /**
     * @param KeyMetadata[] $metadata
     */
    public function __construct(
        public readonly int $versionMajor,
        public readonly int $versionMinor,
        public readonly KeyFormat $keyFormat,
        public readonly string $fingerprint,
        public readonly string $keyData,
        public readonly array $metadata,
    ) {
    }

    /**
     * Build a Key Record from raw key bytes; fills in version and fingerprint
     * deterministically.
     *
     * @param KeyMetadata[] $metadata
     */
    public static function make(
        KeyFormat $keyFormat,
        string $keyData,
        array $metadata = [],
    ): self {
        if ($keyData === '') {
            throw PcfSigException::emptyKeyData();
        }

        return new self(
            Consts::PROFILE_VERSION_MAJOR,
            Consts::PROFILE_VERSION_MINOR,
            $keyFormat,
            self::computeFingerprint($keyData),
            $keyData,
            $metadata,
        );
    }

    /** Serialise to the on-disk byte layout (spec Section 6.1). */
    public function toBytes(): string
    {
        $out = Consts::KEY_MAGIC;
        $out .= pack('v', $this->versionMajor);
        $out .= pack('v', $this->versionMinor);
        $out .= \chr($this->keyFormat->id());
        $out .= "\x00\x00\x00"; // reserved
        $out .= str_pad(substr($this->fingerprint, 0, Consts::FINGERPRINT_SIZE), Consts::FINGERPRINT_SIZE, "\x00");
        $out .= pack('V', \strlen($this->keyData));
        $out .= $this->keyData;
        foreach ($this->metadata as $m) {
            $out .= pack('v', $m->tag);
            $out .= pack('V', \strlen($m->value));
            $out .= $m->value;
        }

        return $out;
    }

    /** Parse from the on-disk byte layout (spec Section 6.1). */
    public static function fromBytes(string $b): self
    {
        if (\strlen($b) < Consts::KEY_PREFIX_SIZE) {
            throw PcfSigException::malformedSignaturePartition();
        }
        if (substr($b, 0, 8) !== Consts::KEY_MAGIC) {
            throw PcfSigException::badKeyMagic();
        }
        $versionMajor = unpack('v', substr($b, 8, 2))[1];
        $versionMinor = unpack('v', substr($b, 10, 2))[1];
        if ($versionMajor !== Consts::PROFILE_VERSION_MAJOR) {
            throw PcfSigException::unsupportedMajor($versionMajor);
        }
        $keyFormat = KeyFormat::fromId(\ord($b[12]));
        if ($b[13] !== "\x00" || $b[14] !== "\x00" || $b[15] !== "\x00") {
            throw PcfSigException::nonZeroKeyReserved();
        }
        $fingerprint = substr($b, 16, Consts::FINGERPRINT_SIZE);
        $keyDataLength = unpack('V', substr($b, 48, 4))[1];
        if ($keyDataLength === 0) {
            throw PcfSigException::emptyKeyData();
        }
        $keyEnd = Consts::KEY_PREFIX_SIZE + $keyDataLength;
        if (\strlen($b) < $keyEnd) {
            throw PcfSigException::malformedSignaturePartition();
        }
        $keyData = substr($b, Consts::KEY_PREFIX_SIZE, $keyDataLength);

        $recomputed = self::computeFingerprint($keyData);
        if (!hash_equals($recomputed, $fingerprint)) {
            throw PcfSigException::fingerprintMismatch();
        }

        $metadata = [];
        $cur = $keyEnd;
        $len = \strlen($b);
        while ($cur < $len) {
            if ($len - $cur < 6) {
                throw PcfSigException::malformedSignaturePartition();
            }
            $tag = unpack('v', substr($b, $cur, 2))[1];
            $valueLen = unpack('V', substr($b, $cur + 2, 4))[1];
            $valueStart = $cur + 6;
            $valueEnd = $valueStart + $valueLen;
            if ($valueEnd > $len) {
                throw PcfSigException::malformedSignaturePartition();
            }
            $metadata[] = new KeyMetadata($tag, substr($b, $valueStart, $valueLen));
            $cur = $valueEnd;
        }

        return new self(
            $versionMajor,
            $versionMinor,
            $keyFormat,
            $fingerprint,
            $keyData,
            $metadata,
        );
    }

    /** Compute the SHA-256 fingerprint of a key's key_data (spec Section 6.3). */
    public static function computeFingerprint(string $keyData): string
    {
        return hash('sha256', $keyData, true);
    }
}
