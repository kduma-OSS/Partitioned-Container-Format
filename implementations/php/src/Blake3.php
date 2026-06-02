<?php

declare(strict_types=1);

namespace Kduma\PCF;

/**
 * Pure-PHP BLAKE3 (spec section 8.1, hash algorithm id 18).
 *
 * A direct port of the official BLAKE3 reference implementation
 * (https://github.com/BLAKE3-team/BLAKE3/blob/master/reference_impl), restricted
 * to the plain (un-keyed) hash that PCF uses. It supports arbitrary-length input
 * via the chunk tree, so it is correct for partition data and table blocks of any
 * size, not just a single 1024-byte chunk.
 *
 * All arithmetic is on 32-bit unsigned words held in PHP ints masked to
 * [0, 2^32).
 */
final class Blake3
{
    private const OUT_LEN = 32;
    private const BLOCK_LEN = 64;
    private const CHUNK_LEN = 1024;

    private const CHUNK_START = 1 << 0;
    private const CHUNK_END = 1 << 1;
    private const PARENT = 1 << 2;
    private const ROOT = 1 << 3;

    private const MASK32 = 0xFFFFFFFF;

    /** @var int[] */
    private const IV = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ];

    /** @var int[] */
    private const MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

    private function __construct()
    {
    }

    /** Hash $input and return a raw binary digest of $outLen bytes (default 32). */
    public static function hash(string $input, int $outLen = self::OUT_LEN): string
    {
        // Incremental hasher state (plain hash: key = IV, flags = 0).
        $key = self::IV;
        $flags = 0;

        $cvStack = [];                 // stack of 8-word chaining values
        $chunk = self::newChunkState($key, 0, $flags);

        $len = \strlen($input);
        $pos = 0;
        while ($pos < $len) {
            if (self::chunkLen($chunk) === self::CHUNK_LEN) {
                $chunkCv = self::outputChainingValue(self::chunkOutput($chunk));
                $totalChunks = $chunk['counter'] + 1;
                // Merge completed subtrees: while total_chunks is even, pop+merge.
                while (($totalChunks & 1) === 0) {
                    $right = $chunkCv;
                    $leftCv = array_pop($cvStack);
                    $chunkCv = self::outputChainingValue(
                        self::parentOutput($leftCv, $right, $key, $flags)
                    );
                    $totalChunks >>= 1;
                }
                $cvStack[] = $chunkCv;
                $chunk = self::newChunkState($key, $chunk['counter'] + 1, $flags);
            }
            $want = self::CHUNK_LEN - self::chunkLen($chunk);
            $take = min($want, $len - $pos);
            self::chunkUpdate($chunk, substr($input, $pos, $take));
            $pos += $take;
        }

        // Finalize: fold the chunk output up through the remaining parent stack.
        $output = self::chunkOutput($chunk);
        for ($i = \count($cvStack) - 1; $i >= 0; --$i) {
            $output = self::parentOutput(
                $cvStack[$i],
                self::outputChainingValue($output),
                $key,
                $flags
            );
        }

        return self::rootOutputBytes($output, $outLen);
    }

    // ---- chunk state -------------------------------------------------------

    /**
     * @param int[] $key
     * @return array{cv:int[],counter:int,buf:string,blocksCompressed:int,flags:int}
     */
    private static function newChunkState(array $key, int $counter, int $flags): array
    {
        return [
            'cv' => $key,
            'counter' => $counter,
            'buf' => '',
            'blocksCompressed' => 0,
            'flags' => $flags,
        ];
    }

    /** @param array{cv:int[],counter:int,buf:string,blocksCompressed:int,flags:int} $chunk */
    private static function chunkLen(array $chunk): int
    {
        return self::BLOCK_LEN * $chunk['blocksCompressed'] + \strlen($chunk['buf']);
    }

    /** @param array{cv:int[],counter:int,buf:string,blocksCompressed:int,flags:int} $chunk */
    private static function chunkStartFlag(array $chunk): int
    {
        return $chunk['blocksCompressed'] === 0 ? self::CHUNK_START : 0;
    }

    /**
     * @param array{cv:int[],counter:int,buf:string,blocksCompressed:int,flags:int} $chunk
     */
    private static function chunkUpdate(array &$chunk, string $input): void
    {
        $pos = 0;
        $len = \strlen($input);
        while ($pos < $len) {
            if (\strlen($chunk['buf']) === self::BLOCK_LEN) {
                $blockWords = self::wordsFromLe($chunk['buf']);
                $chunk['cv'] = self::first8(self::compress(
                    $chunk['cv'],
                    $blockWords,
                    $chunk['counter'],
                    self::BLOCK_LEN,
                    $chunk['flags'] | self::chunkStartFlag($chunk)
                ));
                $chunk['blocksCompressed']++;
                $chunk['buf'] = '';
            }
            $want = self::BLOCK_LEN - \strlen($chunk['buf']);
            $take = min($want, $len - $pos);
            $chunk['buf'] .= substr($input, $pos, $take);
            $pos += $take;
        }
    }

    /**
     * @param array{cv:int[],counter:int,buf:string,blocksCompressed:int,flags:int} $chunk
     * @return array{cv:int[],block:int[],counter:int,blockLen:int,flags:int}
     */
    private static function chunkOutput(array $chunk): array
    {
        return [
            'cv' => $chunk['cv'],
            'block' => self::wordsFromLe($chunk['buf']),
            'counter' => $chunk['counter'],
            'blockLen' => \strlen($chunk['buf']),
            'flags' => $chunk['flags'] | self::CHUNK_END | self::chunkStartFlag($chunk),
        ];
    }

    // ---- output nodes ------------------------------------------------------

    /**
     * @param int[] $leftCv
     * @param int[] $rightCv
     * @param int[] $key
     * @return array{cv:int[],block:int[],counter:int,blockLen:int,flags:int}
     */
    private static function parentOutput(array $leftCv, array $rightCv, array $key, int $flags): array
    {
        return [
            'cv' => $key,
            'block' => array_merge($leftCv, $rightCv),
            'counter' => 0,
            'blockLen' => self::BLOCK_LEN,
            'flags' => self::PARENT | $flags,
        ];
    }

    /**
     * @param array{cv:int[],block:int[],counter:int,blockLen:int,flags:int} $output
     * @return int[] 8-word chaining value
     */
    private static function outputChainingValue(array $output): array
    {
        return self::first8(self::compress(
            $output['cv'],
            $output['block'],
            $output['counter'],
            $output['blockLen'],
            $output['flags']
        ));
    }

    /**
     * @param array{cv:int[],block:int[],counter:int,blockLen:int,flags:int} $output
     */
    private static function rootOutputBytes(array $output, int $outLen): string
    {
        $result = '';
        $counter = 0;
        while (\strlen($result) < $outLen) {
            $words = self::compress(
                $output['cv'],
                $output['block'],
                $counter,
                $output['blockLen'],
                $output['flags'] | self::ROOT
            );
            foreach ($words as $w) {
                $result .= pack('V', $w);
                if (\strlen($result) >= $outLen) {
                    break;
                }
            }
            $counter++;
        }

        return substr($result, 0, $outLen);
    }

    // ---- compression -------------------------------------------------------

    /**
     * @param int[] $cv 8 words
     * @param int[] $blockWords 16 words
     * @return int[] 16-word compression output
     */
    private static function compress(array $cv, array $blockWords, int $counter, int $blockLen, int $flags): array
    {
        $counterLow = $counter & self::MASK32;
        $counterHigh = ($counter >> 32) & self::MASK32;

        $state = [
            $cv[0], $cv[1], $cv[2], $cv[3], $cv[4], $cv[5], $cv[6], $cv[7],
            self::IV[0], self::IV[1], self::IV[2], self::IV[3],
            $counterLow, $counterHigh, $blockLen & self::MASK32, $flags & self::MASK32,
        ];

        $block = $blockWords;
        for ($r = 0; $r < 7; ++$r) {
            self::round($state, $block);
            if ($r < 6) {
                $block = self::permute($block);
            }
        }

        for ($i = 0; $i < 8; ++$i) {
            $state[$i] ^= $state[$i + 8];
            $state[$i + 8] ^= $cv[$i];
        }

        return $state;
    }

    /**
     * @param int[] $state 16 words (by reference)
     * @param int[] $m 16 message words
     */
    private static function round(array &$state, array $m): void
    {
        // Columns.
        self::g($state, 0, 4, 8, 12, $m[0], $m[1]);
        self::g($state, 1, 5, 9, 13, $m[2], $m[3]);
        self::g($state, 2, 6, 10, 14, $m[4], $m[5]);
        self::g($state, 3, 7, 11, 15, $m[6], $m[7]);
        // Diagonals.
        self::g($state, 0, 5, 10, 15, $m[8], $m[9]);
        self::g($state, 1, 6, 11, 12, $m[10], $m[11]);
        self::g($state, 2, 7, 8, 13, $m[12], $m[13]);
        self::g($state, 3, 4, 9, 14, $m[14], $m[15]);
    }

    /**
     * @param int[] $state 16 words (by reference)
     */
    private static function g(array &$state, int $a, int $b, int $c, int $d, int $mx, int $my): void
    {
        $state[$a] = ($state[$a] + $state[$b] + $mx) & self::MASK32;
        $state[$d] = self::rotr($state[$d] ^ $state[$a], 16);
        $state[$c] = ($state[$c] + $state[$d]) & self::MASK32;
        $state[$b] = self::rotr($state[$b] ^ $state[$c], 12);
        $state[$a] = ($state[$a] + $state[$b] + $my) & self::MASK32;
        $state[$d] = self::rotr($state[$d] ^ $state[$a], 8);
        $state[$c] = ($state[$c] + $state[$d]) & self::MASK32;
        $state[$b] = self::rotr($state[$b] ^ $state[$c], 7);
    }

    private static function rotr(int $x, int $n): int
    {
        $x &= self::MASK32;

        return (($x >> $n) | ($x << (32 - $n))) & self::MASK32;
    }

    /**
     * @param int[] $m 16 words
     * @return int[] permuted 16 words
     */
    private static function permute(array $m): array
    {
        $out = [];
        foreach (self::MSG_PERMUTATION as $i) {
            $out[] = $m[$i];
        }

        return $out;
    }

    /**
     * @param int[] $words 16 words
     * @return int[] first 8 words
     */
    private static function first8(array $words): array
    {
        return \array_slice($words, 0, 8);
    }

    /**
     * Convert a block of up to 64 bytes into 16 little-endian u32 words,
     * zero-padding a short final block.
     *
     * @return int[] 16 words
     */
    private static function wordsFromLe(string $block): array
    {
        $block = str_pad($block, self::BLOCK_LEN, "\x00");

        return array_values(unpack('V16', $block));
    }
}
