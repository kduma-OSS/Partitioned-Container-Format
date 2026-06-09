<?php

declare(strict_types=1);

namespace Kduma\PCFDCP;

use Kduma\PCF\HashAlgo;

/** A read-only view of one inner partition. */
final class InnerInfo
{
    /**
     * @param ExtentInfo[] $extents
     */
    public function __construct(
        public int $partitionType,
        public string $uid,
        public string $label,
        public int $usedBytes,
        public HashAlgo $dataHashAlgo,
        public string $dataHash,
        public array $extents,
    ) {
    }
}
