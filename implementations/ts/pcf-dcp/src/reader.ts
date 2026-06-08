/**
 * {@link DcpReader}: reading DCP containers from a PCF file.
 *
 * The reader works entirely through the high-level {@link Container} API, so a
 * DCP file written in trailer mode (append-only host) reads back transparently
 * — this code never assumes the header's `partitionTableOffset` is a real
 * offset (spec Section 2, "Compatibility with the PCF File Trailer").
 */

import {
  computeTableHash,
  Container,
  digestLen,
  entryFromBytes,
  ENTRY_SIZE,
  type PartitionEntry,
  type Storage,
  TABLE_HEADER_SIZE,
  tableHeaderFromBytes,
  verifies,
  verifyHashField,
} from "@kduma-oss/pcf";

import { Arena, type InnerInfo } from "./arena.js";
import { DCP_CONTAINER_TYPE } from "./consts.js";
import { PcfDcpError } from "./errors.js";
import { readHeader } from "./header.js";

/** An inner partition together with the container that holds it. */
export interface InnerLocation {
  /** uid of the enclosing DCP container partition. */
  containerUid: Uint8Array;
  /** The inner partition's metadata and extents. */
  info: InnerInfo;
}

/** The result of resolving a uid against top-level ∪ inner (spec 2.1). */
export type Resolved =
  | { kind: "top-level"; entry: PartitionEntry }
  | { kind: "inner"; location: InnerLocation };

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

/** A reader for DCP containers layered over a PCF file. */
export class DcpReader {
  private c: Container;

  private constructor(c: Container) {
    this.c = c;
  }

  /** Open a PCF file for DCP-aware reading. */
  static open(storage: Storage): DcpReader {
    return new DcpReader(Container.open(storage));
  }

  /** Borrow the underlying PCF container. */
  container(): Container {
    return this.c;
  }

  /** All top-level entries, in chain order. */
  entries(): PartitionEntry[] {
    return this.c.entries();
  }

  /** The top-level DCP container entries. */
  containers(): PartitionEntry[] {
    return this.c.entries().filter((e) => e.partitionType === DCP_CONTAINER_TYPE);
  }

  /** Parse the arena of a DCP container entry. */
  openArena(entry: PartitionEntry): Arena {
    if (entry.partitionType !== DCP_CONTAINER_TYPE) {
      throw PcfDcpError.notADcpContainer();
    }
    return Arena.parse(this.c.readPartitionData(entry));
  }

  /** Every inner partition across every DCP container, in file order. */
  innerPartitions(): InnerLocation[] {
    const out: InnerLocation[] = [];
    for (const cont of this.containers()) {
      const arena = this.openArena(cont);
      for (const info of arena.innerInfos()) {
        out.push({ containerUid: cont.uid.slice(), info });
      }
    }
    return out;
  }

  /** Resolve a uid against the flattened set top-level ∪ inner (spec 2.1). */
  resolveUid(uid: Uint8Array): Resolved {
    const top = this.c.entries().find((e) => bytesEqual(e.uid, uid));
    if (top) {
      return { kind: "top-level", entry: top };
    }
    for (const loc of this.innerPartitions()) {
      if (bytesEqual(loc.info.uid, uid)) {
        return { kind: "inner", location: loc };
      }
    }
    throw PcfDcpError.notFound();
  }

  /** Reconstruct an inner partition's logical content by uid. */
  readInner(uid: Uint8Array): Uint8Array {
    for (const cont of this.containers()) {
      const arena = this.openArena(cont);
      if (arena.uids().some((u) => bytesEqual(u, uid))) {
        return arena.content(uid);
      }
    }
    throw PcfDcpError.notFound();
  }

  /**
   * Full DCP-aware verification: PCF integrity, each inner Table Block's
   * `table_hash`, reconstruction length and (when algorithmic) `data_hash`, no
   * nested container, and file-wide uid uniqueness.
   */
  verify(): void {
    this.c.verify();

    const seen = new Set<string>();
    const seenHex = (uid: Uint8Array): string =>
      Array.from(uid, (b) => b.toString(16).padStart(2, "0")).join("");
    for (const e of this.c.entries()) {
      const k = seenHex(e.uid);
      if (seen.has(k)) {
        throw PcfDcpError.duplicateUid();
      }
      seen.add(k);
    }

    for (const cont of this.containers()) {
      const data = this.c.readPartitionData(cont);
      verifyInnerTableHashes(data);

      const arena = Arena.parse(data);
      for (const info of arena.innerInfos()) {
        if (info.partitionType === DCP_CONTAINER_TYPE) {
          throw PcfDcpError.nestedContainer();
        }
        const k = seenHex(info.uid);
        if (seen.has(k)) {
          throw PcfDcpError.duplicateUid();
        }
        seen.add(k);

        const content = arena.content(info.uid);
        if (content.length !== info.usedBytes) {
          throw PcfDcpError.lengthMismatch(info.usedBytes, content.length);
        }
        if (!verifyHashField(info.dataHashAlgo, content, info.dataHash)) {
          throw PcfDcpError.hashMismatch();
        }
      }
    }
  }
}

/**
 * Walk the inner Table Block chain in an arena and recompute each block's
 * `table_hash`, exactly as PCF does (spec Section 9.2).
 */
function verifyInnerTableHashes(arena: Uint8Array): void {
  const header = readHeader(arena);
  let off = header.innerTableOffset;
  let budget = Math.floor(arena.length / TABLE_HEADER_SIZE) + 1;
  while (off !== 0) {
    if (budget === 0) {
      throw PcfDcpError.offsetOutOfRange();
    }
    budget -= 1;
    if (off + TABLE_HEADER_SIZE > arena.length) {
      throw PcfDcpError.offsetOutOfRange();
    }
    const h = tableHeaderFromBytes(arena.subarray(off, off + TABLE_HEADER_SIZE));
    const entries: PartitionEntry[] = [];
    for (let i = 0; i < h.partitionCount; i++) {
      const eo = off + TABLE_HEADER_SIZE + i * ENTRY_SIZE;
      if (eo + ENTRY_SIZE > arena.length) {
        throw PcfDcpError.offsetOutOfRange();
      }
      entries.push(entryFromBytes(arena.subarray(eo, eo + ENTRY_SIZE)));
    }
    if (verifies(h.tableHashAlgo)) {
      const computed = computeTableHash(h.tableHashAlgo, h.nextTableOffset, entries);
      const n = digestLen(h.tableHashAlgo);
      for (let i = 0; i < n; i++) {
        if (computed[i] !== h.tableHash[i]) {
          throw PcfDcpError.hashMismatch();
        }
      }
    }
    off = Number(h.nextTableOffset);
  }
}
