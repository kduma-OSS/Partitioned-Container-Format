<?php

declare(strict_types=1);

namespace Kduma\PCFDCP;

/**
 * The single exception type raised by this library. The {@see ErrorKind}
 * carried in {@see PcfDcpException::$kind} identifies the precise failure.
 */
final class PcfDcpException extends \RuntimeException
{
    public function __construct(
        public readonly ErrorKind $kind,
        string $message,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    public static function badDcpMagic(): self
    {
        return new self(ErrorKind::BadDcpMagic, 'arena does not begin with "PDCP" magic');
    }

    public static function unsupportedProfileMajor(int $v): self
    {
        return new self(ErrorKind::UnsupportedProfileMajor, "unsupported PCF-DCP profile major version {$v}");
    }

    public static function badFragmentKind(int $k): self
    {
        return new self(ErrorKind::BadFragmentKind, "unsupported fragment kind {$k}");
    }

    public static function offsetOutOfRange(): self
    {
        return new self(ErrorKind::OffsetOutOfRange, 'extent range escapes the arena');
    }

    public static function lengthMismatch(int $expected, int $got): self
    {
        return new self(ErrorKind::LengthMismatch, "logical length mismatch: expected {$expected}, got {$got}");
    }

    public static function hashMismatch(): self
    {
        return new self(ErrorKind::HashMismatch, 'stored hash does not verify');
    }

    public static function notFound(): self
    {
        return new self(ErrorKind::NotFound, 'no partition with that uid');
    }

    public static function duplicateUid(): self
    {
        return new self(ErrorKind::DuplicateUid, 'uid is not unique file-wide');
    }

    public static function nestedContainer(): self
    {
        return new self(ErrorKind::NestedContainer, 'an inner partition may not be a DCP container');
    }

    public static function nilUid(): self
    {
        return new self(ErrorKind::NilUid, 'uid is the NIL uid');
    }

    public static function reservedType(): self
    {
        return new self(ErrorKind::ReservedType, 'partition type is the reserved type 0x00000000');
    }

    public static function notADcpContainer(): self
    {
        return new self(ErrorKind::NotADcpContainer, 'partition is not a DCP container');
    }

    public static function positionOutOfRange(): self
    {
        return new self(ErrorKind::PositionOutOfRange, 'logical position is past end of content');
    }
}
