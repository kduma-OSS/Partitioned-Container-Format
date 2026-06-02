/**
 * A {@link Storage} implementation backed by a Node file descriptor, the
 * analogue of using `std::fs::File` with the reference implementation.
 *
 * This module imports `node:fs` and is therefore Node-only; the rest of the
 * library is runtime-agnostic.
 */

import {
  closeSync,
  fstatSync,
  openSync,
  readSync,
  writeSync,
} from "node:fs";

import type { Storage } from "./storage.js";

/** File-descriptor backed random-access storage. */
export class NodeFileStorage implements Storage {
  private fd: number;

  private constructor(fd: number) {
    this.fd = fd;
  }

  /**
   * Open `path` for reading and writing, creating it if necessary (mode
   * `"r+"`-like with creation). Use `truncate` to start from an empty file.
   */
  static open(path: string, truncate = false): NodeFileStorage {
    // "w+" truncates+creates for read/write; "a+"/"r+" otherwise.
    const flags = truncate ? "w+" : "a+";
    const fd = openSync(path, flags);
    return new NodeFileStorage(fd);
  }

  readAt(offset: number, length: number): Uint8Array {
    const buf = new Uint8Array(length);
    let read = 0;
    while (read < length) {
      const n = readSync(this.fd, buf, read, length - read, offset + read);
      if (n === 0) {
        throw new Error(
          `unexpected EOF: wanted ${length} bytes at offset ${offset}`,
        );
      }
      read += n;
    }
    return buf;
  }

  writeAt(offset: number, data: Uint8Array): void {
    let written = 0;
    while (written < data.length) {
      const n = writeSync(
        this.fd,
        data,
        written,
        data.length - written,
        offset + written,
      );
      written += n;
    }
  }

  size(): number {
    return fstatSync(this.fd).size;
  }

  /** Close the underlying file descriptor. */
  close(): void {
    closeSync(this.fd);
  }
}
