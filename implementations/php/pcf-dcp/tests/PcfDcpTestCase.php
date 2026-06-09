<?php

declare(strict_types=1);

namespace Kduma\PCFDCP\Tests;

use PHPUnit\Framework\TestCase;

abstract class PcfDcpTestCase extends TestCase
{
    /** A 16-byte uid all equal to $b. */
    protected function fill(int $b): string
    {
        return str_repeat(\chr($b), 16);
    }
}
