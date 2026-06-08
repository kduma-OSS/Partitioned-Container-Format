<?php

declare(strict_types=1);

namespace Kduma\PCFDCP;

/** A read-only view of one extent, for tooling and tests. */
final class ExtentInfo
{
    public function __construct(
        public int $extentOffset,
        public int $extentLength,
        public int $kind,
        public bool $shared,
    ) {
    }
}
