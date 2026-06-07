<?php

declare(strict_types=1);

namespace Kduma\PCFSIG;

use Kduma\PCF\HashAlgo;

/**
 * Signature algorithm registry (spec Section 8).
 *
 * This library implements Ed25519 as the MUST-support baseline. All other
 * registry entries are recognised by id so that a Reader can correctly
 * report "unsupported" without misclassifying a well-formed file as
 * malformed (spec Section 15, R9).
 */
enum SigAlgo: int
{
    /** 1 — Ed25519 (RFC 8032). Manifest hash is intrinsically SHA-512. */
    case Ed25519 = 1;
    /** 2 — RSA-PSS-SHA-256. Recognised but not implemented. */
    case RsaPssSha256 = 2;
    /** 4 — RSA-PSS-SHA-512. Recognised but not implemented. */
    case RsaPssSha512 = 4;
    /** 5 — RSA-PKCS1v15-SHA-256. Recognised but not implemented. */
    case RsaPkcs1v15Sha256 = 5;
    /** 7 — RSA-PKCS1v15-SHA-512. Recognised but not implemented. */
    case RsaPkcs1v15Sha512 = 7;
    /** 16 — ECDSA-P256-SHA-256. Recognised but not implemented. */
    case EcdsaP256Sha256 = 16;
    /** 18 — ECDSA-P521-SHA-512. Recognised but not implemented. */
    case EcdsaP521Sha512 = 18;
    /** 32 — X.509 chain. Recognised but not implemented. */
    case X509Chain = 32;

    /** Map a registry id byte to a signature algorithm. */
    public static function fromId(int $id): self
    {
        $algo = self::tryFrom($id);
        if ($algo === null) {
            throw PcfSigException::unknownSigAlgo($id);
        }

        return $algo;
    }

    /** The registry id byte for this algorithm. */
    public function id(): int
    {
        return $this->value;
    }

    /**
     * The manifest_hash_algo_id an implementation MUST require for this
     * algorithm (spec Section 8). `null` for X.509 chain (binding follows
     * the leaf certificate).
     */
    public function requiredManifestHash(): ?HashAlgo
    {
        return match ($this) {
            self::Ed25519,
            self::RsaPssSha512,
            self::RsaPkcs1v15Sha512,
            self::EcdsaP521Sha512 => HashAlgo::Sha512,
            self::RsaPssSha256,
            self::RsaPkcs1v15Sha256,
            self::EcdsaP256Sha256 => HashAlgo::Sha256,
            self::X509Chain => null,
        };
    }

    /** Whether this library implements signing and verification for the algorithm. */
    public function isImplemented(): bool
    {
        return $this === self::Ed25519;
    }
}
