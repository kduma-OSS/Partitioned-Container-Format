<?php

declare(strict_types=1);

namespace Kduma\PCFDCP;

/** Discriminant identifying which kind of {@see PcfDcpException} occurred. */
enum ErrorKind: string
{
    case BadDcpMagic = 'BadDcpMagic';
    case UnsupportedProfileMajor = 'UnsupportedProfileMajor';
    case BadFragmentKind = 'BadFragmentKind';
    case OffsetOutOfRange = 'OffsetOutOfRange';
    case LengthMismatch = 'LengthMismatch';
    case HashMismatch = 'HashMismatch';
    case NotFound = 'NotFound';
    case DuplicateUid = 'DuplicateUid';
    case NestedContainer = 'NestedContainer';
    case NilUid = 'NilUid';
    case ReservedType = 'ReservedType';
    case NotADcpContainer = 'NotADcpContainer';
    case PositionOutOfRange = 'PositionOutOfRange';
}
