<?php

declare(strict_types=1);

namespace Kduma\PCF\Tests;

use Kduma\PCF\ErrorKind;
use Kduma\PCF\PcfException;
use PHPUnit\Framework\TestCase;

/**
 * Shared helpers for the PCF test suites.
 */
abstract class PcfTestCase extends TestCase
{
    /** A non-NIL 16-byte UID seeded from $n (matches the reference test helper). */
    protected static function uid(int $n): string
    {
        $u = str_repeat("\x00", 16);
        $u[0] = \chr($n & 0xFF);
        $u[15] = "\xAA"; // ensure non-nil even if n == 0

        return $u;
    }

    /**
     * Assert that $fn throws a {@see PcfException} whose kind is $expected.
     */
    protected function assertPcfError(ErrorKind $expected, callable $fn): void
    {
        try {
            $fn();
        } catch (PcfException $e) {
            self::assertSame(
                $expected,
                $e->kind,
                "expected error kind {$expected->name}, got {$e->kind->name}: {$e->getMessage()}"
            );

            return;
        }
        self::fail("expected a PcfException of kind {$expected->name}, but none was thrown");
    }
}
