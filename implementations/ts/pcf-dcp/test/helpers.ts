import { createHash } from "node:crypto";

import { expect } from "vitest";

import { PcfDcpError, type PcfDcpErrorKind } from "../src/index.js";

/** A 16-byte uid all equal to `b`. */
export function fill(b: number): Uint8Array {
  return new Uint8Array(16).fill(b);
}

/** ASCII/UTF-8 string to bytes. */
export function enc(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/** Bytes to string. */
export function dec(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}

/** Lowercase hex of a byte array. */
export function hex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

/** SHA-256 of `b` as lowercase hex. */
export function sha256hex(b: Uint8Array): string {
  return createHash("sha256").update(b).digest("hex");
}

/** Assert that `fn` throws a {@link PcfDcpError} of the given `kind`. */
export function expectKind(fn: () => unknown, kind: PcfDcpErrorKind): void {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(PcfDcpError);
    expect((e as PcfDcpError).kind).toBe(kind);
    return;
  }
  throw new Error(`expected a PcfDcpError of kind ${kind}, but nothing was thrown`);
}
