import { expect } from "vitest";

import { MemoryStorage, PcfError, type PcfErrorKind } from "../src/index.js";

/** A 16-byte UID derived from `n` (non-NIL even when `n === 0`). */
export function uid(n: number): Uint8Array {
  const u = new Uint8Array(16);
  u[0] = n;
  u[15] = 0xaa;
  return u;
}

/** ASCII/UTF-8 string to bytes. */
export function bytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/** Bytes to string. */
export function str(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}

/** Snapshot the raw bytes of an in-memory storage. */
export function snapshot(s: unknown): Uint8Array {
  return (s as MemoryStorage).toUint8Array();
}

/** Assert that `fn` throws a {@link PcfError} of the given `kind`. */
export function expectKind(fn: () => unknown, kind: PcfErrorKind): void {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(PcfError);
    expect((e as PcfError).kind).toBe(kind);
    return;
  }
  throw new Error(`expected a PcfError of kind ${kind}, but nothing was thrown`);
}
