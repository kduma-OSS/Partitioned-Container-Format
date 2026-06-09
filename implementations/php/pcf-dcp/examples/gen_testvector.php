<?php

declare(strict_types=1);

/**
 * Generates the canonical PCF-DCP v1.0 test-vector file (spec Section 17). Run
 * with `php examples/gen_testvector.php <output-path>` (defaults to
 * ./pcf_dcp_testvector.bin). Everything is fixed and deterministic so that
 * independent implementations can reproduce the file byte-for-byte.
 */

require __DIR__ . '/../vendor/autoload.php';

use Kduma\PCF\Container;
use Kduma\PCF\Storage\MemoryStorage;
use Kduma\PCFDCP\DcpReader;
use Kduma\PCFDCP\ReferenceVector;

$path = $argv[1] ?? 'pcf_dcp_testvector.bin';

$image = ReferenceVector::build();
file_put_contents($path, $image);

// It is a conforming PCF v1.0 file ...
Container::open(new MemoryStorage($image))->verify();

// ... and a conforming DCP file.
DcpReader::open(new MemoryStorage($image))->verify();

fwrite(STDERR, sprintf("wrote %s (%d bytes)\n", $path, \strlen($image)));
fwrite(STDERR, 'sha256 = ' . bin2hex(hash('sha256', $image, true)) . "\n");
