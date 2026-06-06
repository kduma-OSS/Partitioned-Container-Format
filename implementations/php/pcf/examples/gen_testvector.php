<?php

/**
 * Generates the canonical PCF v1.0 test-vector file used in spec section 15.
 *
 * Run with: php examples/gen_testvector.php [output-path]
 * (defaults to ./pcf_testvector.bin). Everything is fixed and deterministic so
 * that ports can reproduce the file byte-for-byte.
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Kduma\PCF\Container;
use Kduma\PCF\HashAlgo;
use Kduma\PCF\Storage\MemoryStorage;

$path = $argv[1] ?? 'pcf_testvector.bin';

$c = Container::createWith(new MemoryStorage(), 8, HashAlgo::Sha256);

// Partition 0: a SHA-256-protected text region.
$c->addPartition(0x0000_0010, str_repeat("\x11", 16), 'alpha', 'Hello, PCF!', 0, HashAlgo::Sha256);

// Partition 1: a RAW region protected by CRC-32C.
$c->addPartition(0xFFFF_FFFF, str_repeat("\x22", 16), 'raw', "\x00\x01\x02\x03\x04\x05\x06\x07", 0, HashAlgo::Crc32c);

// Compact to the canonical, tightly-packed layout.
$image = $c->compactedImage();
file_put_contents($path, $image);

// Re-open the produced bytes and verify, then print a short report.
$v = Container::open(new MemoryStorage($image));
$v->verify();

fwrite(STDERR, sprintf("wrote %s (%d bytes)\n", $path, \strlen($image)));
foreach ($v->entries() as $e) {
    $n = $e->dataHashAlgo->digestLen();
    $hex = bin2hex(substr($e->dataHash, 0, $n));
    fwrite(STDERR, sprintf(
        "  %-6s type=0x%08X algo=%s start=%d used=%d data_hash=%s\n",
        $e->labelString(),
        $e->partitionType,
        $e->dataHashAlgo->name,
        $e->startOffset,
        $e->usedBytes,
        $hex
    ));
}
