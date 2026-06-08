<?php

declare(strict_types=1);

namespace Kduma\PCFDCP;

/** An inner partition together with the container that holds it. */
final class InnerLocation
{
    public function __construct(
        public string $containerUid,
        public InnerInfo $info,
    ) {
    }
}
