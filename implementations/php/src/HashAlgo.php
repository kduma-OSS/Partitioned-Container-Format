<?php

declare(strict_types=1);

namespace Kduma\PCF;

use Tourze\Blake3\Blake3;

/**
 * Hash-algorithm registry (spec section 8).
 *
 * Each hash field in the format is a fixed 64-byte field accompanied by a u8
 * algorithm identifier. Digests are stored left-aligned and zero-padded; CRC
 * values are stored as little-endian integers, left-aligned and zero-padded
 * (spec section 8.2).
 */
enum HashAlgo: int
{
    /** 0 — no verification. */
    case None = 0;
    /** 1 — CRC-32/ISO-HDLC. */
    case Crc32 = 1;
    /** 2 — CRC-32C (Castagnoli). */
    case Crc32c = 2;
    /** 3 — CRC-64/XZ. */
    case Crc64 = 3;
    /** 4 — MD5 (checksum use only). */
    case Md5 = 4;
    /** 5 — SHA-1 (checksum use only). */
    case Sha1 = 5;
    /** 16 — SHA-256 (default). */
    case Sha256 = 16;
    /** 17 — SHA-512. */
    case Sha512 = 17;
    /** 18 — BLAKE3. */
    case Blake3 = 18;

    /** Map a registry id byte to an algorithm (spec section 8.1). */
    public static function fromId(int $id): self
    {
        $algo = self::tryFrom($id);
        if ($algo === null) {
            throw PcfException::unknownHashAlgo($id);
        }

        return $algo;
    }

    /** The registry id byte for this algorithm. */
    public function id(): int
    {
        return $this->value;
    }

    /** Number of significant bytes this algorithm writes into a hash field. */
    public function digestLen(): int
    {
        return match ($this) {
            self::None => 0,
            self::Crc32, self::Crc32c => 4,
            self::Crc64 => 8,
            self::Md5 => 16,
            self::Sha1 => 20,
            self::Sha256, self::Blake3 => 32,
            self::Sha512 => 64,
        };
    }

    /** Whether this algorithm performs any verification (everything but None). */
    public function verifies(): bool
    {
        return $this !== self::None;
    }

    /**
     * Compute the full 64-byte hash field for $data per spec section 8.2:
     * the meaningful digest is written left-aligned and the remainder is 0x00.
     */
    public function compute(string $data): string
    {
        $digest = match ($this) {
            self::None => '',
            // PHP's "crc32b" is CRC-32/ISO-HDLC; raw output is big-endian, so it
            // is reversed to the little-endian on-disk encoding (spec 8.2).
            self::Crc32 => strrev(hash('crc32b', $data, true)),
            self::Crc32c => strrev(hash('crc32c', $data, true)),
            self::Crc64 => Crc64::compute($data), // already little-endian
            self::Md5 => hash('md5', $data, true),
            self::Sha1 => hash('sha1', $data, true),
            self::Sha256 => hash('sha256', $data, true),
            self::Sha512 => hash('sha512', $data, true),
            self::Blake3 => self::blake3($data),
        };

        return str_pad($digest, Consts::HASH_FIELD_SIZE, "\x00");
    }

    private static function blake3(string $data): string
    {
        $hasher = Blake3::newInstance();
        $hasher->update($data);

        return $hasher->finalize();
    }

    /**
     * Verify $data against a stored 64-byte hash field. None always succeeds
     * (no verification). Only the significant prefix is compared (spec 8.2).
     */
    public function verify(string $data, string $stored): bool
    {
        if (!$this->verifies()) {
            return true;
        }
        $n = $this->digestLen();
        $computed = $this->compute($data);

        return hash_equals(substr($computed, 0, $n), substr($stored, 0, $n));
    }
}
