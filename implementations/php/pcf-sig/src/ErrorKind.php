<?php

declare(strict_types=1);

namespace Kduma\PCFSIG;

/** Discriminant identifying which kind of {@see PcfSigException} occurred. */
enum ErrorKind: string
{
    case BadKeyMagic = 'BadKeyMagic';
    case BadManifestMagic = 'BadManifestMagic';
    case UnsupportedMajor = 'UnsupportedMajor';
    case UnknownKeyFormat = 'UnknownKeyFormat';
    case EmptyKeyData = 'EmptyKeyData';
    case NonZeroKeyReserved = 'NonZeroKeyReserved';
    case FingerprintMismatch = 'FingerprintMismatch';
    case UnknownSigAlgo = 'UnknownSigAlgo';
    case NonCryptoManifestHash = 'NonCryptoManifestHash';
    case HashAlgoBindingMismatch = 'HashAlgoBindingMismatch';
    case NonZeroFlags = 'NonZeroFlags';
    case EmptyManifest = 'EmptyManifest';
    case NonZeroTrailer = 'NonZeroTrailer';
    case NonZeroEntryReserved = 'NonZeroEntryReserved';
    case NonCryptoEntryHash = 'NonCryptoEntryHash';
    case EntryNilUid = 'EntryNilUid';
    case EntryReservedType = 'EntryReservedType';
    case DuplicateSignedUid = 'DuplicateSignedUid';
    case SelfSignedEntry = 'SelfSignedEntry';
    case MalformedSignaturePartition = 'MalformedSignaturePartition';
    case SignatureLengthMismatch = 'SignatureLengthMismatch';
    case NonCryptoTargetHash = 'NonCryptoTargetHash';
    case TargetPartitionMissing = 'TargetPartitionMissing';
}
