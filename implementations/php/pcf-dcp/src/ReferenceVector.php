<?php

declare(strict_types=1);

namespace Kduma\PCFDCP;

use Kduma\PCF\HashAlgo;

/** The canonical PCF-DCP v1.0 test vector (spec Section 17). */
final class ReferenceVector
{
    private function __construct()
    {
    }

    /**
     * Build the byte-exact 700-byte reference file from spec Section 17: one DCP
     * container ("dcp", uid 16×0xDC) holding inner "A" ("Hello, World!" as two
     * extents, the second shared) and inner "B" ("World!" deduplicated onto A's
     * second extent). Building this logical container and emitting the canonical
     * layout MUST reproduce these exact bytes.
     */
    public static function build(): string
    {
        $arena = new Arena();
        $arena->addInner(0x0000_0010, str_repeat("\xA1", 16), 'A', 'Hello, World!', HashAlgo::Sha256, Chunker::fixed(7));
        $arena->addInner(0x0000_0010, str_repeat("\xB2", 16), 'B', 'World!', HashAlgo::Sha256, Chunker::whole());

        $w = new DcpWriter();
        $w->addContainer(str_repeat("\xDC", 16), 'dcp', $arena);

        return $w->toImage();
    }
}
