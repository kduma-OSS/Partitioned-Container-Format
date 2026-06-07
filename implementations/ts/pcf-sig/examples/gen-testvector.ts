/**
 * Generates the canonical PCF-SIG v1.0 test-vector file. Run with
 * `npm run gen-testvector -- <output-path>` (defaults to ./pcfsig_testvector.bin).
 *
 * The Ed25519 keypair is generated deterministically from a fixed 32-byte seed
 * of 0x00..0x1F, so independent implementations can reproduce the file
 * byte-for-byte.
 */

import { writeFileSync } from "node:fs";

import { Container, HashAlgo, MemoryStorage } from "@kduma-oss/pcf";
import { sha256 } from "@noble/hashes/sha2";

import {
  ManifestVerdict,
  SigningMaterial,
  signPartitions,
  verifyAllWithRecheck,
} from "../src/index.js";

const path = process.argv[2] ?? "pcfsig_testvector.bin";

const seed = new Uint8Array(32);
for (let i = 0; i < 32; i++) seed[i] = i;
const signer = SigningMaterial.ed25519FromSeed(seed);

const c = Container.createWith(new MemoryStorage(), 8, HashAlgo.Sha256);

c.addPartition(
  0x10,
  new Uint8Array(16).fill(0x11),
  "alpha",
  new TextEncoder().encode("Hello, PCF-SIG!"),
  0,
  HashAlgo.Sha256,
);

signPartitions(c, signer, {
  targetUids: [new Uint8Array(16).fill(0x11)],
  sigPartitionUid: new Uint8Array(16).fill(0x33),
  keyPartitionUid: new Uint8Array(16).fill(0x22),
  signedAtUnixSeconds: 0n,
  sigLabel: "pcfsig",
  keyLabel: "pcfkey",
});

const image = c.compactedImage();
writeFileSync(path, image);

const verifier = Container.open(new MemoryStorage(image));
verifier.verify();
const reports = verifyAllWithRecheck(verifier);
if (reports.length !== 1 || reports[0]!.verdict !== ManifestVerdict.Valid) {
  throw new Error("generated vector does not self-verify");
}

const digest = Array.from(sha256(image), (b) =>
  b.toString(16).padStart(2, "0"),
).join("");
const fingerprint = Array.from(signer.fingerprint(), (b) =>
  b.toString(16).padStart(2, "0"),
).join("");

console.error(`wrote ${path} (${image.length} bytes)`);
console.error(`sha256 = ${digest}`);
console.error(`signer fingerprint = ${fingerprint}`);
