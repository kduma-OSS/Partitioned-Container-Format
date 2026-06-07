<?php

declare(strict_types=1);

namespace Kduma\PCFSIG\Tests;

use Kduma\PCF\Consts as PcfConsts;
use Kduma\PCF\HashAlgo;
use Kduma\PCFSIG\Consts;
use Kduma\PCFSIG\ErrorKind;
use Kduma\PCFSIG\KeyFormat;
use Kduma\PCFSIG\KeyRecord;
use Kduma\PCFSIG\Manifest;
use Kduma\PCFSIG\PcfSigException;
use Kduma\PCFSIG\SigAlgo;
use Kduma\PCFSIG\SignaturePartition;
use Kduma\PCFSIG\SignedEntry;

final class SpecComplianceTest extends PcfSigTestCase
{
    public function test_s5_reserved_type_values(): void
    {
        self::assertSame(0xAAAB_0001, Consts::TYPE_PCFSIG_KEY);
        self::assertSame(0xAAAB_0002, Consts::TYPE_PCFSIG_SIG);
    }

    public function test_s6_1_key_magic(): void
    {
        self::assertSame("PCFKEY\x00\x00", Consts::KEY_MAGIC);
    }

    public function test_s6_1_profile_version_constants(): void
    {
        self::assertSame(1, Consts::PROFILE_VERSION_MAJOR);
        self::assertSame(0, Consts::PROFILE_VERSION_MINOR);
    }

    public function test_s6_1_reader_rejects_bad_key_magic(): void
    {
        $bytes = KeyRecord::make(KeyFormat::Ed25519Raw, str_repeat("\x10", 32))->toBytes();
        $bytes[0] = 'X';
        try {
            KeyRecord::fromBytes($bytes);
            self::fail('expected BadKeyMagic');
        } catch (PcfSigException $e) {
            self::assertSame(ErrorKind::BadKeyMagic, $e->kind);
        }
    }

    public function test_s6_1_reader_rejects_unknown_major(): void
    {
        $bytes = KeyRecord::make(KeyFormat::Ed25519Raw, str_repeat("\x10", 32))->toBytes();
        $bytes[8] = \chr(2);
        try {
            KeyRecord::fromBytes($bytes);
            self::fail('expected UnsupportedMajor');
        } catch (PcfSigException $e) {
            self::assertSame(ErrorKind::UnsupportedMajor, $e->kind);
        }
    }

    public function test_s6_1_reader_rejects_non_zero_reserved(): void
    {
        $bytes = KeyRecord::make(KeyFormat::Ed25519Raw, str_repeat("\x10", 32))->toBytes();
        $bytes[13] = "\xFF";
        try {
            KeyRecord::fromBytes($bytes);
            self::fail('expected NonZeroKeyReserved');
        } catch (PcfSigException $e) {
            self::assertSame(ErrorKind::NonZeroKeyReserved, $e->kind);
        }
    }

    public function test_s6_3_fingerprint_is_sha256(): void
    {
        $key = str_repeat("\xAA", 32);
        $rec = KeyRecord::make(KeyFormat::Ed25519Raw, $key);
        self::assertSame(KeyRecord::computeFingerprint($key), $rec->fingerprint);
        self::assertSame(32, Consts::FINGERPRINT_SIZE);
    }

    public function test_s6_3_reader_rejects_fingerprint_mismatch(): void
    {
        $bytes = KeyRecord::make(KeyFormat::Ed25519Raw, str_repeat("\x10", 32))->toBytes();
        $bytes[16] = \chr(\ord($bytes[16]) ^ 0x01);
        try {
            KeyRecord::fromBytes($bytes);
            self::fail('expected FingerprintMismatch');
        } catch (PcfSigException $e) {
            self::assertSame(ErrorKind::FingerprintMismatch, $e->kind);
        }
    }

    public function test_s7_1_sig_magic(): void
    {
        self::assertSame("PCFSIG\x00\x00", Consts::SIG_MAGIC);
    }

    public function test_s7_1_byte_layout_sizes(): void
    {
        self::assertSame(60, Consts::MANIFEST_PREFIX_SIZE);
        self::assertSame(218, Consts::SIGNED_ENTRY_SIZE);
    }

    public function test_s8_ed25519_binds_sha512(): void
    {
        self::assertSame(HashAlgo::Sha512, SigAlgo::Ed25519->requiredManifestHash());
    }

    public function test_s8_ed25519_is_implemented(): void
    {
        self::assertTrue(SigAlgo::Ed25519->isImplemented());
    }

    public function test_s9_crypto_hash_check(): void
    {
        self::assertTrue(Manifest::isCryptoHash(HashAlgo::Sha256));
        self::assertTrue(Manifest::isCryptoHash(HashAlgo::Sha512));
        self::assertTrue(Manifest::isCryptoHash(HashAlgo::Blake3));
        self::assertFalse(Manifest::isCryptoHash(HashAlgo::Crc32c));
        self::assertFalse(Manifest::isCryptoHash(HashAlgo::Md5));
        self::assertFalse(Manifest::isCryptoHash(HashAlgo::Sha1));
    }

    public function test_s7_2_nil_uid_entry_rejected(): void
    {
        // Build a SignedEntry by hand with NIL UID and otherwise valid fields.
        $bytes = str_repeat("\x00", Consts::SIGNED_ENTRY_SIZE);
        $bytes = substr_replace($bytes, pack('V', 0x10), 16, 4);
        $bytes[60] = \chr(HashAlgo::Sha256->id());
        try {
            SignedEntry::fromBytes($bytes);
            self::fail('expected EntryNilUid');
        } catch (PcfSigException $e) {
            self::assertSame(ErrorKind::EntryNilUid, $e->kind);
        }
    }

    public function test_s7_2_weak_data_hash_rejected(): void
    {
        $bytes = str_repeat("\x00", Consts::SIGNED_ENTRY_SIZE);
        $bytes[0] = "\x01";
        $bytes = substr_replace($bytes, pack('V', 0x10), 16, 4);
        $bytes[60] = \chr(HashAlgo::Crc32c->id());
        try {
            SignedEntry::fromBytes($bytes);
            self::fail('expected NonCryptoEntryHash');
        } catch (PcfSigException $e) {
            self::assertSame(ErrorKind::NonCryptoEntryHash, $e->kind);
        }
    }

    public function test_s7_3_non_zero_trailer_rejected(): void
    {
        $entry = new SignedEntry(
            $this->uid(1),
            0x10,
            str_repeat("\x00", PcfConsts::LABEL_SIZE),
            0,
            HashAlgo::Sha256,
            str_repeat("\x00", PcfConsts::HASH_FIELD_SIZE),
        );
        $manifest = Manifest::make(
            SigAlgo::Ed25519,
            HashAlgo::Sha512,
            str_repeat("\x00", Consts::FINGERPRINT_SIZE),
            0,
            [$entry],
        );
        $mb = $manifest->toBytes();
        $tail = $mb
            . pack('V', 64)
            . str_repeat("\x00", 64)
            . pack('V', 1)      // non-zero trailer length
            . "\x00";

        try {
            SignaturePartition::fromBytes($tail);
            self::fail('expected NonZeroTrailer');
        } catch (PcfSigException $e) {
            self::assertSame(ErrorKind::NonZeroTrailer, $e->kind);
        }
    }

    public function test_s7_2_signed_entry_roundtrip(): void
    {
        $entry = new SignedEntry(
            $this->uid(1),
            0x10,
            str_pad('alpha', PcfConsts::LABEL_SIZE, "\x00"),
            15,
            HashAlgo::Sha256,
            str_pad(str_repeat("\x7F", 32), PcfConsts::HASH_FIELD_SIZE, "\x00"),
        );
        $bytes = $entry->toBytes();
        self::assertSame(Consts::SIGNED_ENTRY_SIZE, \strlen($bytes));
        $parsed = SignedEntry::fromBytes($bytes);
        self::assertSame($entry->partitionType, $parsed->partitionType);
        self::assertSame($entry->usedBytes, $parsed->usedBytes);
        self::assertSame($entry->dataHashAlgo, $parsed->dataHashAlgo);
    }
}
