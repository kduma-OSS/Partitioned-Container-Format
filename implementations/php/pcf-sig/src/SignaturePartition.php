<?php

declare(strict_types=1);

namespace Kduma\PCFSIG;

/**
 * The byte payload of a `PCFSIG_SIG` partition: Manifest, length-prefixed
 * signature bytes, length-prefixed trailer (spec Section 7.3).
 */
final class SignaturePartition
{
    public function __construct(
        public readonly Manifest $manifest,
        public readonly string $manifestBytes,
        public readonly string $signature,
        public readonly string $trailer,
    ) {
    }

    /** Compose a partition payload from manifest + signature (trailer is empty in v1.0). */
    public static function make(Manifest $manifest, string $signature): self
    {
        return new self($manifest, $manifest->toBytes(), $signature, '');
    }

    /** Serialise to the on-disk byte layout (spec Section 7). */
    public function toBytes(): string
    {
        return $this->manifestBytes
            . pack('V', \strlen($this->signature))
            . $this->signature
            . pack('V', \strlen($this->trailer))
            . $this->trailer;
    }

    /**
     * Parse the on-disk byte layout. Validates manifest, sig_length presence,
     * sig_bytes availability, trailer_length presence and 0 in v1.0, and total
     * length consistency.
     */
    public static function fromBytes(string $b): self
    {
        if (\strlen($b) < Consts::MANIFEST_PREFIX_SIZE) {
            throw PcfSigException::malformedSignaturePartition();
        }
        $manifest = Manifest::fromBytes($b);
        $manifestLen = $manifest->byteLen();
        if (\strlen($b) < $manifestLen + 4) {
            throw PcfSigException::malformedSignaturePartition();
        }
        $sigLength = unpack('V', substr($b, $manifestLen, 4))[1];
        if ($sigLength === 0) {
            throw PcfSigException::signatureLengthMismatch();
        }
        $sigStart = $manifestLen + 4;
        $sigEnd = $sigStart + $sigLength;
        if (\strlen($b) < $sigEnd + 4) {
            throw PcfSigException::malformedSignaturePartition();
        }
        $signature = substr($b, $sigStart, $sigLength);
        $trailerLength = unpack('V', substr($b, $sigEnd, 4))[1];
        if ($trailerLength !== 0) {
            throw PcfSigException::nonZeroTrailer();
        }
        $totalEnd = $sigEnd + 4 + $trailerLength;
        if (\strlen($b) !== $totalEnd) {
            throw PcfSigException::malformedSignaturePartition();
        }
        $manifestBytes = substr($b, 0, $manifestLen);

        return new self($manifest, $manifestBytes, $signature, '');
    }
}
