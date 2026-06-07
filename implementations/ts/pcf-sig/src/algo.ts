/**
 * Signature algorithm registry (spec Section 8) and key-format registry
 * (spec Section 6.2).
 *
 * This library implements `Ed25519` as the MUST-support baseline. All other
 * registry entries are recognised by id so that a Reader can correctly
 * report "unsupported" without misclassifying a well-formed file as
 * malformed (spec Section 15, R9).
 */

import { HashAlgo } from "@kduma-oss/pcf";

import { PcfSigError } from "./errors.js";

/** A signature algorithm id (spec Section 8, Appendix B). */
export enum SigAlgo {
  /** `1` — Ed25519 (RFC 8032). Manifest hash is intrinsically SHA-512. */
  Ed25519 = 1,
  /** `2` — RSA-PSS-SHA-256. Recognised but not implemented in this library. */
  RsaPssSha256 = 2,
  /** `4` — RSA-PSS-SHA-512. Recognised but not implemented in this library. */
  RsaPssSha512 = 4,
  /** `5` — RSA-PKCS1v15-SHA-256. Recognised but not implemented. */
  RsaPkcs1v15Sha256 = 5,
  /** `7` — RSA-PKCS1v15-SHA-512. Recognised but not implemented. */
  RsaPkcs1v15Sha512 = 7,
  /** `16` — ECDSA-P256-SHA-256. Recognised but not implemented. */
  EcdsaP256Sha256 = 16,
  /** `18` — ECDSA-P521-SHA-512. Recognised but not implemented. */
  EcdsaP521Sha512 = 18,
  /** `32` — X.509 chain. Recognised but not implemented. */
  X509Chain = 32,
}

const KNOWN_SIG_IDS: ReadonlySet<number> = new Set([1, 2, 4, 5, 7, 16, 18, 32]);

/** Map a registry id byte to a signature algorithm. */
export function sigAlgoFromId(id: number): SigAlgo {
  if (id === 0 || !KNOWN_SIG_IDS.has(id)) {
    throw PcfSigError.unknownSigAlgo(id);
  }
  return id as SigAlgo;
}

/** The registry id byte for a signature algorithm. */
export function sigAlgoId(algo: SigAlgo): number {
  return algo;
}

/**
 * The `manifest_hash_algo_id` an implementation MUST require for this
 * algorithm (spec Section 8). `null` means the binding is not fixed by this
 * library's registry view (the X.509 chain case, where the leaf certificate
 * names the actual hash).
 */
export function requiredManifestHash(algo: SigAlgo): HashAlgo | null {
  switch (algo) {
    case SigAlgo.Ed25519:
    case SigAlgo.RsaPssSha512:
    case SigAlgo.RsaPkcs1v15Sha512:
    case SigAlgo.EcdsaP521Sha512:
      return HashAlgo.Sha512;
    case SigAlgo.RsaPssSha256:
    case SigAlgo.RsaPkcs1v15Sha256:
    case SigAlgo.EcdsaP256Sha256:
      return HashAlgo.Sha256;
    case SigAlgo.X509Chain:
      return null;
  }
}

/**
 * Whether this library implements signing and verification for the algorithm.
 * In v1.0, only Ed25519 is implemented; the remaining entries are listed for
 * correct id-level recognition.
 */
export function sigAlgoIsImplemented(algo: SigAlgo): boolean {
  return algo === SigAlgo.Ed25519;
}

/** A key-format id (spec Section 6.2, Appendix B). */
export enum KeyFormat {
  /** `1` — Ed25519 raw public key (32 bytes, RFC 8032). */
  Ed25519Raw = 1,
  /** `2` — RSA SPKI DER. Recognised but not implemented in this library. */
  RsaSpkiDer = 2,
  /** `3` — ECDSA SPKI DER. Recognised but not implemented. */
  EcdsaSpkiDer = 3,
  /** `16` — X.509 single certificate (DER). Recognised but not implemented. */
  X509Cert = 16,
  /** `17` — X.509 length-prefixed chain. Recognised but not implemented. */
  X509Chain = 17,
}

const KNOWN_KEY_FORMAT_IDS: ReadonlySet<number> = new Set([1, 2, 3, 16, 17]);

/** Map a registry id byte to a key format. */
export function keyFormatFromId(id: number): KeyFormat {
  if (id === 0 || !KNOWN_KEY_FORMAT_IDS.has(id)) {
    throw PcfSigError.unknownKeyFormat(id);
  }
  return id as KeyFormat;
}

/** The registry id byte for a key format. */
export function keyFormatId(fmt: KeyFormat): number {
  return fmt;
}

/**
 * Whether this library can extract a verification key from records using
 * this format. Only `Ed25519Raw` is implemented in v1.0 of this library.
 */
export function keyFormatIsImplemented(fmt: KeyFormat): boolean {
  return fmt === KeyFormat.Ed25519Raw;
}
