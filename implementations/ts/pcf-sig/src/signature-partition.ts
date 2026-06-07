/**
 * The byte payload of a `PCFSIG_SIG` partition: Manifest, length-prefixed
 * signature bytes, length-prefixed trailer (spec Section 7.3).
 */

import { MANIFEST_PREFIX_SIZE } from "./consts.js";
import { PcfSigError } from "./errors.js";
import {
  type Manifest,
  manifestByteLen,
  manifestFromBytes,
  manifestToBytes,
} from "./manifest.js";

/** One PCFSIG_SIG partition's full payload (spec Section 7). */
export interface SignaturePartition {
  /** Parsed Manifest. */
  manifest: Manifest;
  /** Raw bytes of the Manifest as serialised in the partition (signing input). */
  manifestBytes: Uint8Array;
  /** Raw signature bytes. */
  signature: Uint8Array;
  /** Trailer bytes; MUST be empty in v1.0. */
  trailer: Uint8Array;
}

/** Compose a partition payload from a manifest + signature. */
export function makeSignaturePartition(
  manifest: Manifest,
  signature: Uint8Array,
): SignaturePartition {
  return {
    manifest,
    manifestBytes: manifestToBytes(manifest),
    signature: new Uint8Array(signature),
    trailer: new Uint8Array(0),
  };
}

/** Serialise the partition to the on-disk byte layout (spec Section 7). */
export function signaturePartitionToBytes(p: SignaturePartition): Uint8Array {
  const total =
    p.manifestBytes.length + 4 + p.signature.length + 4 + p.trailer.length;
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  out.set(p.manifestBytes, 0);
  view.setUint32(p.manifestBytes.length, p.signature.length, true);
  out.set(p.signature, p.manifestBytes.length + 4);
  view.setUint32(
    p.manifestBytes.length + 4 + p.signature.length,
    p.trailer.length,
    true,
  );
  out.set(p.trailer, p.manifestBytes.length + 4 + p.signature.length + 4);
  return out;
}

/**
 * Parse the on-disk byte layout. Validates: manifest, sig_length present,
 * sig_bytes available, trailer_length present and 0 in v1.0, total length
 * equals partition `used_bytes`. Signature verification itself is done by the
 * Verifier, not here.
 */
export function signaturePartitionFromBytes(b: Uint8Array): SignaturePartition {
  if (b.length < MANIFEST_PREFIX_SIZE) {
    throw PcfSigError.malformedSignaturePartition();
  }
  const manifest = manifestFromBytes(b);
  const manifestLen = manifestByteLen(manifest);
  if (b.length < manifestLen + 4) {
    throw PcfSigError.malformedSignaturePartition();
  }
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const sigLength = view.getUint32(manifestLen, true);
  if (sigLength === 0) {
    throw PcfSigError.signatureLengthMismatch();
  }
  const sigStart = manifestLen + 4;
  const sigEnd = sigStart + sigLength;
  if (b.length < sigEnd + 4) {
    throw PcfSigError.malformedSignaturePartition();
  }
  const signature = b.slice(sigStart, sigEnd);
  const trailerLength = view.getUint32(sigEnd, true);
  if (trailerLength !== 0) {
    throw PcfSigError.nonZeroTrailer();
  }
  const totalEnd = sigEnd + 4 + trailerLength;
  if (b.length !== totalEnd) {
    throw PcfSigError.malformedSignaturePartition();
  }
  const manifestBytes = b.slice(0, manifestLen);
  return {
    manifest,
    manifestBytes,
    signature,
    trailer: new Uint8Array(0),
  };
}
