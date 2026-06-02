/**
 * Synchronous random-access storage backing a {@link "./container".Container}.
 *
 * This mirrors the reference implementation's `Read + Write + Seek` bound: the
 * container only needs to read and write byte ranges at absolute offsets and to
 * learn the current size. Two implementations are provided: an in-memory
 * growable buffer (the analogue of the reference's `Cursor<Vec<u8>>`) and a
 * Node file-descriptor backed store.
 *
 * Offsets are plain `number` byte positions. The on-disk format preserves full
 * `u64` fidelity (offsets are encoded as little-endian `u64` via `DataView`);
 * any real file fits comfortably below `Number.MAX_SAFE_INTEGER`.
 */

import { PcfError, PcfErrorKind } from "./errors.js";

/** Random-access byte store. */
export interface Storage {
  /** Read exactly `length` bytes starting at `offset`. */
  readAt(offset: number, length: number): Uint8Array;
  /** Write `data` starting at `offset`, growing the store as needed. */
  writeAt(offset: number, data: Uint8Array): void;
  /** Current logical size, in bytes. */
  size(): number;
}

/** In-memory growable storage (the `Cursor<Vec<u8>>` analogue). */
export class MemoryStorage implements Storage {
  private buf: Uint8Array;
  private len: number;

  constructor(initial?: Uint8Array) {
    if (initial && initial.length > 0) {
      this.buf = initial.slice();
      this.len = initial.length;
    } else {
      this.buf = new Uint8Array(64);
      this.len = 0;
    }
  }

  private ensureCapacity(needed: number): void {
    if (needed <= this.buf.length) {
      return;
    }
    let cap = this.buf.length === 0 ? 64 : this.buf.length;
    while (cap < needed) {
      cap *= 2;
    }
    const next = new Uint8Array(cap);
    next.set(this.buf.subarray(0, this.len), 0);
    this.buf = next;
  }

  readAt(offset: number, length: number): Uint8Array {
    if (offset < 0 || offset + length > this.len) {
      throw new PcfError(
        PcfErrorKind.Io,
        `read out of bounds: offset ${offset}, length ${length}, size ${this.len}`,
      );
    }
    return this.buf.slice(offset, offset + length);
  }

  writeAt(offset: number, data: Uint8Array): void {
    if (offset < 0) {
      throw new PcfError(PcfErrorKind.Io, `negative write offset ${offset}`);
    }
    const end = offset + data.length;
    this.ensureCapacity(end);
    this.buf.set(data, offset);
    if (end > this.len) {
      this.len = end;
    }
  }

  size(): number {
    return this.len;
  }

  /** Return a copy of the logical contents (the analogue of `into_inner`). */
  toUint8Array(): Uint8Array {
    return this.buf.slice(0, this.len);
  }
}
