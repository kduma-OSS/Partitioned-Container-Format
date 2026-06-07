<?php

declare(strict_types=1);

namespace Kduma\PCFSIG;

/** Key format registry (spec Section 6.2). */
enum KeyFormat: int
{
    /** 1 — Ed25519 raw public key (32 bytes, RFC 8032). */
    case Ed25519Raw = 1;
    /** 2 — RSA SPKI DER. Recognised but not implemented. */
    case RsaSpkiDer = 2;
    /** 3 — ECDSA SPKI DER. Recognised but not implemented. */
    case EcdsaSpkiDer = 3;
    /** 16 — X.509 single certificate (DER). Recognised but not implemented. */
    case X509Cert = 16;
    /** 17 — X.509 length-prefixed chain. Recognised but not implemented. */
    case X509Chain = 17;

    public static function fromId(int $id): self
    {
        $fmt = self::tryFrom($id);
        if ($fmt === null) {
            throw PcfSigException::unknownKeyFormat($id);
        }

        return $fmt;
    }

    public function id(): int
    {
        return $this->value;
    }

    /** Whether this library can extract a verification key from records of this format. */
    public function isImplemented(): bool
    {
        return $this === self::Ed25519Raw;
    }
}
