<?php

declare(strict_types=1);

namespace Kduma\PCFSIG;

/**
 * A signing key wired to one algorithm.
 *
 * v1.0 covers Ed25519, the MUST-support baseline. The library uses PHP's
 * bundled libsodium ({@see sodium_crypto_sign_detached}) for signing and
 * verification.
 */
final class SigningMaterial
{
    private function __construct(
        public readonly SigAlgo $sigAlgo,
        public readonly KeyFormat $keyFormat,
        private readonly string $sodiumKeypair,
        public readonly string $publicKeyBytes,
    ) {
    }

    /** Construct an Ed25519 signer from a 32-byte secret seed. */
    public static function ed25519FromSeed(string $seed): self
    {
        if (\strlen($seed) !== 32) {
            throw new \InvalidArgumentException('Ed25519 seed must be exactly 32 bytes');
        }
        $keypair = sodium_crypto_sign_seed_keypair($seed);
        $publicKey = sodium_crypto_sign_publickey($keypair);

        return new self(SigAlgo::Ed25519, KeyFormat::Ed25519Raw, $keypair, $publicKey);
    }

    /** SHA-256 fingerprint of the signer's public-key bytes. */
    public function fingerprint(): string
    {
        return KeyRecord::computeFingerprint($this->publicKeyBytes);
    }

    /** Sign $message and return the raw signature bytes. */
    public function sign(string $message): string
    {
        return match ($this->sigAlgo) {
            SigAlgo::Ed25519 => sodium_crypto_sign_detached(
                $message,
                sodium_crypto_sign_secretkey($this->sodiumKeypair),
            ),
            default => throw new \LogicException("sig_algo_id {$this->sigAlgo->id()} is not implemented"),
        };
    }

    /** Bytes of a Key Record representing this signer. */
    public function toKeyRecordBytes(): string
    {
        return KeyRecord::make($this->keyFormat, $this->publicKeyBytes)->toBytes();
    }
}
