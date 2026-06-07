<?php

declare(strict_types=1);

/**
 * Generates the canonical PCF-SIG v1.0 test-vector file. Run with
 * `php examples/gen_testvector.php <output-path>` (defaults to
 * ./pcfsig_testvector.bin).
 *
 * The Ed25519 keypair is generated deterministically from a fixed 32-byte seed
 * of 0x00..0x1F, so independent implementations can reproduce the file
 * byte-for-byte.
 */

require __DIR__ . '/../vendor/autoload.php';

use Kduma\PCF\Container;
use Kduma\PCF\HashAlgo;
use Kduma\PCF\Storage\MemoryStorage;
use Kduma\PCFSIG\ManifestVerdict;
use Kduma\PCFSIG\SignPartitions;
use Kduma\PCFSIG\SigningMaterial;
use Kduma\PCFSIG\Verify;

$path = $argv[1] ?? 'pcfsig_testvector.bin';

$seed = '';
for ($i = 0; $i < 32; ++$i) {
    $seed .= chr($i);
}
$signer = SigningMaterial::ed25519FromSeed($seed);

$c = Container::createWith(new MemoryStorage(), 8, HashAlgo::Sha256);
$c->addPartition(
    0x10,
    str_repeat("\x11", 16),
    'alpha',
    'Hello, PCF-SIG!',
    0,
    HashAlgo::Sha256,
);
SignPartitions::run(
    $c,
    $signer,
    [str_repeat("\x11", 16)],
    str_repeat("\x33", 16),
    str_repeat("\x22", 16),
    0,
    'pcfsig',
    'pcfkey',
);

$image = $c->compactedImage();
file_put_contents($path, $image);

$verifier = Container::open(new MemoryStorage($image));
$verifier->verify();
$reports = Verify::allWithRecheck($verifier);
if (count($reports) !== 1 || $reports[0]->verdict !== ManifestVerdict::Valid) {
    fwrite(STDERR, "generated vector does not self-verify\n");
    exit(1);
}

fprintf(STDERR, "wrote %s (%d bytes)\n", $path, strlen($image));
fprintf(STDERR, "sha256 = %s\n", bin2hex(hash('sha256', $image, true)));
fprintf(STDERR, "signer fingerprint = %s\n", bin2hex($signer->fingerprint()));
