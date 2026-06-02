<?php

declare(strict_types=1);

namespace Kduma\PCF;

/**
 * The single exception type raised by this library. The {@see ErrorKind}
 * carried in {@see PcfException::$kind} identifies the precise failure, so
 * callers can `catch (PcfException $e)` and branch on `$e->kind`.
 */
final class PcfException extends \RuntimeException
{
    public function __construct(
        public readonly ErrorKind $kind,
        string $message,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    public static function badMagic(): self
    {
        return new self(ErrorKind::BadMagic, 'bad magic: not a PCF file');
    }

    public static function unsupportedMajor(int $version): self
    {
        return new self(ErrorKind::UnsupportedMajor, "unsupported major version {$version}");
    }

    public static function unknownHashAlgo(int $id): self
    {
        return new self(ErrorKind::UnknownHashAlgo, "unknown hash algorithm id {$id}");
    }

    public static function reservedType(): self
    {
        return new self(ErrorKind::ReservedType, 'reserved partition type used for a live entry');
    }

    public static function nilUid(): self
    {
        return new self(ErrorKind::NilUid, 'NIL UID used for a live entry');
    }

    public static function usedExceedsMax(): self
    {
        return new self(ErrorKind::UsedExceedsMax, 'used_bytes exceeds max_length');
    }

    public static function invalidLabel(): self
    {
        return new self(ErrorKind::InvalidLabel, 'invalid label');
    }

    public static function tableHashMismatch(): self
    {
        return new self(ErrorKind::TableHashMismatch, 'table block hash mismatch');
    }

    public static function dataHashMismatch(): self
    {
        return new self(ErrorKind::DataHashMismatch, 'partition data hash mismatch');
    }

    public static function dataTooLarge(): self
    {
        return new self(ErrorKind::DataTooLarge, 'data larger than partition reservation');
    }

    public static function notFound(): self
    {
        return new self(ErrorKind::NotFound, 'partition not found');
    }

    public static function duplicateUid(): self
    {
        return new self(ErrorKind::DuplicateUid, 'duplicate UID');
    }

    public static function io(string $message, ?\Throwable $previous = null): self
    {
        return new self(ErrorKind::Io, "i/o error: {$message}", $previous);
    }
}
