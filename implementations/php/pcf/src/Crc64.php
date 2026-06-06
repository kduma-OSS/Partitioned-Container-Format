<?php

declare(strict_types=1);

namespace Kduma\PCF;

/**
 * Pure-PHP CRC-64/XZ (spec section 8.1, hash algorithm id 3).
 *
 * width=64, reflected poly 0x42F0E1EBA9EA3693, init=all-ones, refin=true,
 * refout=true, xorout=all-ones. This is the CRC-64 used by xz/liblzma and by
 * .NET System.IO.Hashing.Crc64. The check value for the ASCII input "123456789"
 * is 0x995DC9BBDF1939FA.
 *
 * PHP integers are 64-bit two's complement, so the reflected polynomial pattern
 * is built from two 32-bit halves and `>> 1` is masked to behave as a logical
 * (unsigned) shift.
 */
final class Crc64
{
    /** Reflected polynomial 0xC96C5795D7870F42, as a signed 64-bit pattern. */
    private const POLY = (0xC96C5795 << 32) | 0xD7870F42;

    /** @var int[]|null Lazily built 256-entry lookup table. */
    private static ?array $table = null;

    private function __construct()
    {
    }

    /**
     * Compute the CRC-64/XZ of $data and return it as an 8-byte little-endian
     * string (the on-disk encoding used by PCF hash fields).
     */
    public static function compute(string $data): string
    {
        $table = self::table();
        $crc = ~0; // init = 0xFFFFFFFFFFFFFFFF (all bits set)
        $len = \strlen($data);
        for ($i = 0; $i < $len; ++$i) {
            $idx = ($crc ^ \ord($data[$i])) & 0xFF;
            $crc = $table[$idx] ^ (($crc >> 8) & 0x00FFFFFFFFFFFFFF);
        }
        $crc ^= ~0; // xorout = all bits set

        return pack('P', $crc);
    }

    /** @return int[] */
    private static function table(): array
    {
        if (self::$table !== null) {
            return self::$table;
        }
        $table = [];
        for ($n = 0; $n < 256; ++$n) {
            $crc = $n;
            for ($k = 0; $k < 8; ++$k) {
                if (($crc & 1) !== 0) {
                    // Mask the sign-extended top bit so >> behaves as logical.
                    $crc = (($crc >> 1) & PHP_INT_MAX) ^ self::POLY;
                } else {
                    $crc = ($crc >> 1) & PHP_INT_MAX;
                }
            }
            $table[$n] = $crc;
        }

        return self::$table = $table;
    }
}
