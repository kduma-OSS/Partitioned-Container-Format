<?php

declare(strict_types=1);

namespace Kduma\PCFSIG;

use Kduma\PCF\Consts as PcfConsts;
use Kduma\PCF\HashAlgo;

/** One Signed Entry inside a Manifest (spec Section 7.2). */
final class SignedEntry
{
    public function __construct(
        public readonly string $uid,
        public readonly int $partitionType,
        public readonly string $label,
        public readonly int $usedBytes,
        public readonly HashAlgo $dataHashAlgo,
        public readonly string $dataHash,
    ) {
    }

    /** Serialise to the on-disk 218-byte layout (spec Section 7.2). */
    public function toBytes(): string
    {
        $out = str_pad(substr($this->uid, 0, PcfConsts::UID_SIZE), PcfConsts::UID_SIZE, "\x00");
        $out .= pack('V', $this->partitionType);
        $out .= str_pad(substr($this->label, 0, PcfConsts::LABEL_SIZE), PcfConsts::LABEL_SIZE, "\x00");
        $out .= pack('P', $this->usedBytes);
        $out .= \chr($this->dataHashAlgo->id());
        $out .= "\x00"; // reserved 1 B
        $out .= str_pad(substr($this->dataHash, 0, PcfConsts::HASH_FIELD_SIZE), PcfConsts::HASH_FIELD_SIZE, "\x00");
        $out .= str_repeat("\x00", 92); // reserved 92 B

        return $out;
    }

    /**
     * Parse from the on-disk 218-byte layout. Validates reserved spans, the
     * cryptographic-hash constraint (Section 9), and the PCF reserved-value
     * guards (Section 11, V7).
     */
    public static function fromBytes(string $b): self
    {
        if (\strlen($b) !== Consts::SIGNED_ENTRY_SIZE) {
            throw PcfSigException::malformedSignaturePartition();
        }
        if ($b[61] !== "\x00") {
            throw PcfSigException::nonZeroEntryReserved();
        }
        for ($i = 126; $i < 218; ++$i) {
            if ($b[$i] !== "\x00") {
                throw PcfSigException::nonZeroEntryReserved();
            }
        }
        $uid = substr($b, 0, PcfConsts::UID_SIZE);
        if ($uid === PcfConsts::NIL_UID) {
            throw PcfSigException::entryNilUid();
        }
        $partitionType = unpack('V', substr($b, 16, 4))[1];
        if ($partitionType === PcfConsts::TYPE_RESERVED) {
            throw PcfSigException::entryReservedType();
        }
        $label = substr($b, 20, PcfConsts::LABEL_SIZE);
        $usedBytes = unpack('P', substr($b, 52, 8))[1];
        $dataHashAlgo = HashAlgo::fromId(\ord($b[60]));
        if (!Manifest::isCryptoHash($dataHashAlgo)) {
            throw PcfSigException::nonCryptoEntryHash($dataHashAlgo->id());
        }
        $dataHash = substr($b, 62, PcfConsts::HASH_FIELD_SIZE);

        return new self(
            $uid,
            $partitionType,
            $label,
            $usedBytes,
            $dataHashAlgo,
            $dataHash,
        );
    }
}
