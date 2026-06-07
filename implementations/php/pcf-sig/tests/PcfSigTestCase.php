<?php

declare(strict_types=1);

namespace Kduma\PCFSIG\Tests;

use PHPUnit\Framework\TestCase;

abstract class PcfSigTestCase extends TestCase
{
    protected function uid(int $n): string
    {
        $u = str_repeat("\x00", 16);
        $u[0] = \chr($n);
        $u[15] = "\xAA";

        return $u;
    }
}
