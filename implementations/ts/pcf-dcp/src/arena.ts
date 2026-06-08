/**
 * The DCP arena: the in-memory model of one DCP container and its canonical
 * byte serialisation.
 *
 * An {@link Arena} holds a byte pool (`blob`) plus a list of inner partitions,
 * each owning a list of fragments. A fragment addresses a byte range in the
 * pool; two fragments addressing the *same* range share that extent
 * (deduplication, spec Section 10.2). Editing operations work purely on the
 * fragment list and append new bytes to the pool, never overwriting bytes a
 * `SHARED` extent still names (copy-on-write, spec Section 10.1).
 *
 * {@link Arena.toBytes} always emits the *canonical* layout of the spec's test
 * vector (Section 17): `DCP Header || data extents || Fragment Tables || Inner
 * Table Block(s)`, with each distinct extent emitted exactly once.
 */

import {
  computeHashField,
  decodeLabel,
  encodeLabel,
  entryFromBytes,
  entryToBytes,
  ENTRY_SIZE,
  HashAlgo,
  NIL_UID,
  type PartitionEntry,
  TABLE_HEADER_SIZE,
  tableHeaderFromBytes,
  tableHeaderToBytes,
  type TableBlockHeader,
  computeTableHash,
} from "@kduma-oss/pcf";

import {
  ARENA_NONE,
  DCP_CONTAINER_TYPE,
  DCP_HEADER_SIZE,
  FLAG_SHARED,
  FRAGMENT_ENTRY_SIZE,
  FRAGTABLE_HEADER_SIZE,
  KIND_DATA,
  MAX_ENTRIES_PER_BLOCK,
  PROFILE_VERSION_MAJOR,
  PROFILE_VERSION_MINOR,
} from "./consts.js";
import { PcfDcpError } from "./errors.js";
import {
  type DcpHeader,
  dcpHeaderToBytes,
  readHeader,
} from "./header.js";
import {
  fragTableHeaderToBytes,
  fragmentEntryToBytes,
  walkFragmentTable,
} from "./fragment.js";

/**
 * How a Writer splits an inner partition's content into extents (spec Section
 * 10.2; chunking is writer-side policy).
 */
export type Chunker = { type: "whole" } | { type: "fixed"; size: number };

/** Chunker constructors. */
export const Chunker = {
  /** One extent for the whole content. */
  whole(): Chunker {
    return { type: "whole" };
  },
  /** Fixed-size chunks of `n` bytes (final chunk may be shorter; 0 = whole). */
  fixed(n: number): Chunker {
    return { type: "fixed", size: n };
  },
};

function splitChunks(chunker: Chunker, content: Uint8Array): Uint8Array[] {
  if (content.length === 0) {
    return [];
  }
  if (chunker.type === "whole" || chunker.size <= 0) {
    return [content];
  }
  const out: Uint8Array[] = [];
  for (let i = 0; i < content.length; i += chunker.size) {
    out.push(content.subarray(i, Math.min(i + chunker.size, content.length)));
  }
  return out;
}

/** One extent reference inside an inner partition (`offset`/`length` → blob). */
interface Frag {
  offset: number;
  length: number;
  kind: number;
  shared: boolean;
}

/** One inner partition. */
interface Inner {
  partitionType: number;
  uid: Uint8Array;
  label: Uint8Array;
  dataHashAlgo: HashAlgo;
  frags: Frag[];
}

/** A read-only view of one extent, for tooling and tests. */
export interface ExtentInfo {
  extentOffset: number;
  extentLength: number;
  kind: number;
  shared: boolean;
}

/** A read-only view of one inner partition. */
export interface InnerInfo {
  partitionType: number;
  uid: Uint8Array;
  label: string;
  usedBytes: number;
  dataHashAlgo: HashAlgo;
  dataHash: Uint8Array;
  extents: ExtentInfo[];
}

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

const extKey = (off: number, len: number): string => `${off}:${len}`;

/** The in-memory model of one DCP container. */
export class Arena {
  private profileVersionMajor = PROFILE_VERSION_MAJOR;
  private profileVersionMinor = PROFILE_VERSION_MINOR;
  private flags = 0;
  private innerTableAlgo: HashAlgo = HashAlgo.Sha256;
  private blob = new Uint8Array(0);
  private blobLen = 0;
  private inners: Inner[] = [];

  /** Choose the hash algorithm used for inner Table Blocks (default SHA-256). */
  withInnerTableAlgo(algo: HashAlgo): this {
    this.innerTableAlgo = algo;
    return this;
  }

  // ---- byte pool ---------------------------------------------------------

  private appendBlob(data: Uint8Array): number {
    const start = this.blobLen;
    const end = start + data.length;
    if (end > this.blob.length) {
      let cap = this.blob.length === 0 ? 64 : this.blob.length;
      while (cap < end) {
        cap *= 2;
      }
      const next = new Uint8Array(cap);
      next.set(this.blob.subarray(0, this.blobLen), 0);
      this.blob = next;
    }
    this.blob.set(data, start);
    this.blobLen = end;
    return start;
  }

  private blobSlice(off: number, len: number): Uint8Array {
    return this.blob.subarray(off, off + len);
  }

  // ---- parsing -----------------------------------------------------------

  /** Parse an arena from its on-disk bytes (spec Sections 6–8). */
  static parse(bytes: Uint8Array): Arena {
    const header = readHeader(bytes);
    if (header.profileVersionMajor !== PROFILE_VERSION_MAJOR) {
      throw PcfDcpError.unsupportedProfileMajor(header.profileVersionMajor);
    }
    const arenaUsed = header.arenaUsed;

    const arena = new Arena();
    arena.profileVersionMajor = header.profileVersionMajor;
    arena.profileVersionMinor = header.profileVersionMinor;
    arena.flags = header.flags;
    arena.blob = bytes.slice();
    arena.blobLen = bytes.length;

    let firstBlock = true;
    let off = header.innerTableOffset;
    let budget = Math.floor(bytes.length / TABLE_HEADER_SIZE) + 1;
    while (off !== ARENA_NONE) {
      if (budget === 0) {
        throw PcfDcpError.offsetOutOfRange();
      }
      budget -= 1;
      if (off + TABLE_HEADER_SIZE > bytes.length) {
        throw PcfDcpError.offsetOutOfRange();
      }
      const h = tableHeaderFromBytes(bytes.subarray(off, off + TABLE_HEADER_SIZE));
      if (firstBlock) {
        arena.innerTableAlgo = h.tableHashAlgo;
        firstBlock = false;
      }
      for (let i = 0; i < h.partitionCount; i++) {
        const eo = off + TABLE_HEADER_SIZE + i * ENTRY_SIZE;
        if (eo + ENTRY_SIZE > bytes.length) {
          throw PcfDcpError.offsetOutOfRange();
        }
        const entry = entryFromBytes(bytes.subarray(eo, eo + ENTRY_SIZE));
        const onDisk = walkFragmentTable(bytes, Number(entry.startOffset));
        const frags: Frag[] = onDisk.map((fe) => ({
          offset: fe.extentOffset,
          length: fe.extentLength,
          kind: fe.kind,
          shared: (fe.flags & FLAG_SHARED) !== 0,
        }));
        arena.inners.push({
          partitionType: entry.partitionType,
          uid: entry.uid,
          label: entry.label,
          dataHashAlgo: entry.dataHashAlgo,
          frags,
        });
      }
      off = Number(h.nextTableOffset);
    }

    // Bound every extent by the declared arena_used.
    for (const inner of arena.inners) {
      for (const f of inner.frags) {
        if (f.offset + f.length > arenaUsed) {
          throw PcfDcpError.offsetOutOfRange();
        }
      }
    }
    return arena;
  }

  // ---- read-only views ---------------------------------------------------

  /** Number of inner partitions. */
  len(): number {
    return this.inners.length;
  }

  /** Whether the arena has no inner partitions. */
  isEmpty(): boolean {
    return this.inners.length === 0;
  }

  /** The uids of all inner partitions, in stored order. */
  uids(): Uint8Array[] {
    return this.inners.map((i) => i.uid.slice());
  }

  private indexOf(uid: Uint8Array): number {
    const i = this.inners.findIndex((inner) => bytesEqual(inner.uid, uid));
    if (i < 0) {
      throw PcfDcpError.notFound();
    }
    return i;
  }

  private innerLogicalLen(inner: Inner): number {
    let total = 0;
    for (const f of inner.frags) {
      if (f.kind === KIND_DATA) {
        total += f.length;
      }
    }
    return total;
  }

  private innerContent(inner: Inner): Uint8Array {
    const out = new Uint8Array(this.innerLogicalLen(inner));
    let p = 0;
    for (const f of inner.frags) {
      if (f.kind === KIND_DATA) {
        out.set(this.blobSlice(f.offset, f.length), p);
        p += f.length;
      }
    }
    return out;
  }

  private innerDataHash(inner: Inner): Uint8Array {
    return computeHashField(inner.dataHashAlgo, this.innerContent(inner));
  }

  private view(inner: Inner): InnerInfo {
    return {
      partitionType: inner.partitionType,
      uid: inner.uid.slice(),
      label: decodeLabel(inner.label),
      usedBytes: this.innerLogicalLen(inner),
      dataHashAlgo: inner.dataHashAlgo,
      dataHash: this.innerDataHash(inner),
      extents: inner.frags.map((f) => ({
        extentOffset: f.offset,
        extentLength: f.length,
        kind: f.kind,
        shared: f.shared,
      })),
    };
  }

  /** A read-only view of one inner partition. */
  innerInfo(uid: Uint8Array): InnerInfo {
    return this.view(this.inners[this.indexOf(uid)]!);
  }

  /** Read-only views of every inner partition, in stored order. */
  innerInfos(): InnerInfo[] {
    return this.inners.map((i) => this.view(i));
  }

  /** Reconstruct an inner partition's logical content (spec Section 8.3). */
  content(uid: Uint8Array): Uint8Array {
    const inner = this.inners[this.indexOf(uid)]!;
    const bytes = this.innerContent(inner);
    const declared = this.innerLogicalLen(inner);
    if (bytes.length !== declared) {
      throw PcfDcpError.lengthMismatch(declared, bytes.length);
    }
    return bytes;
  }

  // ---- builder -----------------------------------------------------------

  /**
   * Add an inner partition whose `content` is split by `chunker` into extents,
   * deduplicating against extents already present (spec Section 10.2).
   */
  addInner(
    partitionType: number,
    uid: Uint8Array,
    label: string,
    content: Uint8Array,
    dataHashAlgo: HashAlgo,
    chunker: Chunker,
  ): void {
    if ((partitionType >>> 0) === 0) {
      throw PcfDcpError.reservedType();
    }
    if ((partitionType >>> 0) === DCP_CONTAINER_TYPE) {
      throw PcfDcpError.nestedContainer();
    }
    if (bytesEqual(uid, NIL_UID)) {
      throw PcfDcpError.nilUid();
    }
    if (this.inners.some((i) => bytesEqual(i.uid, uid))) {
      throw PcfDcpError.duplicateUid();
    }
    const labelBytes = encodeLabel(label);

    const frags: Frag[] = [];
    for (const chunk of splitChunks(chunker, content)) {
      const hit =
        this.findExtent(chunk) ?? this.findLocal(frags, chunk);
      if (hit) {
        const [offset, length] = hit;
        this.markShared(offset, length);
        for (const f of frags) {
          if (f.offset === offset && f.length === length) {
            f.shared = true;
          }
        }
        frags.push({ offset, length, kind: KIND_DATA, shared: true });
      } else {
        const offset = this.appendBlob(chunk);
        frags.push({ offset, length: chunk.length, kind: KIND_DATA, shared: false });
      }
    }
    this.inners.push({
      partitionType: partitionType >>> 0,
      uid: uid.slice(),
      label: labelBytes,
      dataHashAlgo,
      frags,
    });
  }

  private findExtent(chunk: Uint8Array): [number, number] | undefined {
    if (chunk.length === 0) {
      return undefined;
    }
    for (const inner of this.inners) {
      for (const f of inner.frags) {
        if (
          f.kind === KIND_DATA &&
          f.length === chunk.length &&
          bytesEqual(this.blobSlice(f.offset, f.length), chunk)
        ) {
          return [f.offset, f.length];
        }
      }
    }
    return undefined;
  }

  private findLocal(frags: readonly Frag[], chunk: Uint8Array): [number, number] | undefined {
    if (chunk.length === 0) {
      return undefined;
    }
    for (const f of frags) {
      if (
        f.kind === KIND_DATA &&
        f.length === chunk.length &&
        bytesEqual(this.blobSlice(f.offset, f.length), chunk)
      ) {
        return [f.offset, f.length];
      }
    }
    return undefined;
  }

  private markShared(offset: number, length: number): void {
    for (const inner of this.inners) {
      for (const f of inner.frags) {
        if (f.offset === offset && f.length === length) {
          f.shared = true;
        }
      }
    }
  }

  // ---- logical edits (copy-on-write) -------------------------------------

  /** Append `bytes` to the end of an inner partition's logical content. */
  append(uid: Uint8Array, bytes: Uint8Array): void {
    const idx = this.indexOf(uid);
    if (bytes.length === 0) {
      return;
    }
    const offset = this.appendBlob(bytes);
    this.inners[idx]!.frags.push({
      offset,
      length: bytes.length,
      kind: KIND_DATA,
      shared: false,
    });
  }

  /** Overwrite the logical range `[pos, pos+len)` with `bytes`. */
  overwrite(uid: Uint8Array, pos: number, len: number, bytes: Uint8Array): void {
    this.delete(uid, pos, len);
    this.insert(uid, pos, bytes);
  }

  /** Insert `bytes` at logical position `pos` (`pos == length` appends). */
  insert(uid: Uint8Array, pos: number, bytes: Uint8Array): void {
    const idx = this.indexOf(uid);
    const total = this.innerLogicalLen(this.inners[idx]!);
    if (pos > total) {
      throw PcfDcpError.positionOutOfRange();
    }
    if (bytes.length === 0) {
      return;
    }
    const split = this.splitAt(idx, pos);
    const offset = this.appendBlob(bytes);
    this.inners[idx]!.frags.splice(split, 0, {
      offset,
      length: bytes.length,
      kind: KIND_DATA,
      shared: false,
    });
  }

  /** Delete the logical range `[pos, pos+len)`. */
  delete(uid: Uint8Array, pos: number, len: number): void {
    const idx = this.indexOf(uid);
    const total = this.innerLogicalLen(this.inners[idx]!);
    const end = pos + len;
    if (end > total) {
      throw PcfDcpError.positionOutOfRange();
    }
    if (len === 0) {
      return;
    }
    const lo = this.splitAt(idx, pos);
    const hi = this.splitAt(idx, end);
    this.inners[idx]!.frags.splice(lo, hi - lo);
  }

  /** Truncate the partition's logical content to `newLen` bytes. */
  truncate(uid: Uint8Array, newLen: number): void {
    const idx = this.indexOf(uid);
    const total = this.innerLogicalLen(this.inners[idx]!);
    if (newLen > total) {
      throw PcfDcpError.positionOutOfRange();
    }
    const cut = this.splitAt(idx, newLen);
    this.inners[idx]!.frags.length = cut;
  }

  /**
   * Ensure a fragment boundary exists at logical position `pos` in inner `idx`,
   * splitting the straddling fragment if needed. Splitting copies no bytes.
   */
  private splitAt(idx: number, pos: number): number {
    const frags = this.inners[idx]!.frags;
    let logical = 0;
    let i = 0;
    while (i < frags.length) {
      const f = frags[i]!;
      const flen = f.length;
      if (logical === pos) {
        return i;
      }
      if (pos < logical + flen) {
        const head = pos - logical;
        const left: Frag = { offset: f.offset, length: head, kind: f.kind, shared: f.shared };
        const right: Frag = {
          offset: f.offset + head,
          length: flen - head,
          kind: f.kind,
          shared: f.shared,
        };
        frags[i] = left;
        frags.splice(i + 1, 0, right);
        return i + 1;
      }
      logical += flen;
      i += 1;
    }
    return frags.length;
  }

  // ---- promotion support -------------------------------------------------

  /**
   * Remove an inner partition, returning the pieces a promotion needs: its
   * type, label, hash algorithm, and reconstructed logical content.
   */
  removeInner(uid: Uint8Array): {
    partitionType: number;
    label: string;
    dataHashAlgo: HashAlgo;
    content: Uint8Array;
  } {
    const idx = this.indexOf(uid);
    const content = this.content(uid);
    const inner = this.inners.splice(idx, 1)[0]!;
    return {
      partitionType: inner.partitionType,
      label: decodeLabel(inner.label),
      dataHashAlgo: inner.dataHashAlgo,
      content,
    };
  }

  // ---- deduplication and compaction --------------------------------------

  /**
   * Re-chunk every inner partition with `chunker` and deduplicate identical
   * extents across the whole arena (spec Section 10.2). Returns the estimated
   * number of bytes the pool shrank by once re-serialised.
   */
  dedup(chunker: Chunker): number {
    const before = this.canonicalExtentBytes();
    const rebuilt = new Arena();
    rebuilt.profileVersionMajor = this.profileVersionMajor;
    rebuilt.profileVersionMinor = this.profileVersionMinor;
    rebuilt.flags = this.flags;
    rebuilt.innerTableAlgo = this.innerTableAlgo;
    for (const inner of this.inners) {
      rebuilt.addInner(
        inner.partitionType,
        inner.uid,
        decodeLabel(inner.label),
        this.innerContent(inner),
        inner.dataHashAlgo,
        chunker,
      );
    }
    this.adopt(rebuilt);
    const after = this.canonicalExtentBytes();
    return Math.max(0, before - after);
  }

  /**
   * Compact the arena (spec Section 10.3): drop unreferenced pool bytes and
   * normalise the SHARED flag, clearing it on any extent now referenced exactly
   * once (rule F2). Returns the number of dead pool bytes reclaimed.
   */
  compact(): number {
    const refcount = new Map<string, number>();
    for (const inner of this.inners) {
      for (const f of inner.frags) {
        const k = extKey(f.offset, f.length);
        refcount.set(k, (refcount.get(k) ?? 0) + 1);
      }
    }
    for (const inner of this.inners) {
      for (const f of inner.frags) {
        if ((refcount.get(extKey(f.offset, f.length)) ?? 0) <= 1) {
          f.shared = false;
        }
      }
    }
    let liveBytes = 0;
    for (const [k] of refcount) {
      liveBytes += Number(k.split(":")[1]);
    }
    const deadBefore = Math.max(0, this.blobLen - liveBytes);

    const newPool = new Arena();
    newPool.innerTableAlgo = this.innerTableAlgo;
    const remap = new Map<string, number>();
    for (const inner of this.inners) {
      for (const f of inner.frags) {
        const k = extKey(f.offset, f.length);
        if (!remap.has(k)) {
          remap.set(k, newPool.appendBlob(this.blobSlice(f.offset, f.length)));
        }
      }
    }
    for (const inner of this.inners) {
      for (const f of inner.frags) {
        f.offset = remap.get(extKey(f.offset, f.length))!;
      }
    }
    this.blob = newPool.blob;
    this.blobLen = newPool.blobLen;
    return deadBefore;
  }

  private canonicalExtentBytes(): number {
    const seen = new Set<string>();
    let total = 0;
    for (const inner of this.inners) {
      for (const f of inner.frags) {
        const k = extKey(f.offset, f.length);
        if (!seen.has(k)) {
          seen.add(k);
          total += f.length;
        }
      }
    }
    return total;
  }

  private adopt(other: Arena): void {
    this.profileVersionMajor = other.profileVersionMajor;
    this.profileVersionMinor = other.profileVersionMinor;
    this.flags = other.flags;
    this.innerTableAlgo = other.innerTableAlgo;
    this.blob = other.blob;
    this.blobLen = other.blobLen;
    this.inners = other.inners;
  }

  // ---- canonical serialisation -------------------------------------------

  /** Serialise the arena into its canonical on-disk layout (spec Section 17). */
  toBytes(): Uint8Array {
    // 1. distinct extents, first-reference order
    const extOrder: Array<[number, number]> = [];
    const extIndex = new Map<string, number>();
    for (const inner of this.inners) {
      for (const f of inner.frags) {
        const k = extKey(f.offset, f.length);
        if (!extIndex.has(k)) {
          extIndex.set(k, extOrder.length);
          extOrder.push([f.offset, f.length]);
        }
      }
    }

    // 2. lay out extents right after the header
    let cur = DCP_HEADER_SIZE;
    const extArenaOff: number[] = [];
    for (const [, len] of extOrder) {
      extArenaOff.push(cur);
      cur += len;
    }

    // 3. Fragment Tables (one chain per inner)
    const fragOff: number[] = [];
    for (const inner of this.inners) {
      fragOff.push(cur);
      cur += fragtableSpan(inner.frags.length);
    }

    // 4. Inner Table Block(s)
    const innerTableOffset = cur;
    const counts = blockCounts(this.inners.length);
    const blockOff: number[] = [];
    for (const c of counts) {
      blockOff.push(cur);
      cur += TABLE_HEADER_SIZE + c * ENTRY_SIZE;
    }
    const arenaUsed = cur;

    const buf = new Uint8Array(arenaUsed);

    const header: DcpHeader = {
      profileVersionMajor: this.profileVersionMajor,
      profileVersionMinor: this.profileVersionMinor,
      flags: this.flags,
      innerTableOffset,
      arenaUsed,
    };
    buf.set(dcpHeaderToBytes(header), 0);

    for (let i = 0; i < extOrder.length; i++) {
      const [boff, len] = extOrder[i]!;
      buf.set(this.blobSlice(boff, len), extArenaOff[i]!);
    }

    for (let ii = 0; ii < this.inners.length; ii++) {
      writeFragmentTable(buf, fragOff[ii]!, this.inners[ii]!.frags, extIndex, extArenaOff);
    }

    const entries: PartitionEntry[] = this.inners.map((inner, ii) => {
      const used = this.innerLogicalLen(inner);
      return {
        partitionType: inner.partitionType,
        uid: inner.uid.slice(),
        label: inner.label.slice(),
        startOffset: BigInt(fragOff[ii]!),
        maxLength: BigInt(used),
        usedBytes: BigInt(used),
        dataHashAlgo: inner.dataHashAlgo,
        dataHash: this.innerDataHash(inner),
      };
    });

    let idx = 0;
    for (let b = 0; b < counts.length; b++) {
      const c = counts[b]!;
      const next = b + 1 < counts.length ? blockOff[b + 1]! : 0;
      const slice = entries.slice(idx, idx + c);
      const th = computeTableHash(this.innerTableAlgo, BigInt(next), slice);
      const bh: TableBlockHeader = {
        partitionCount: c,
        nextTableOffset: BigInt(next),
        tableHashAlgo: this.innerTableAlgo,
        tableHash: th,
      };
      let p = blockOff[b]!;
      buf.set(tableHeaderToBytes(bh), p);
      p += TABLE_HEADER_SIZE;
      for (const e of slice) {
        buf.set(entryToBytes(e), p);
        p += ENTRY_SIZE;
      }
      idx += c;
    }

    return buf;
  }
}

/** Span of an inner partition's Fragment Table chain holding `n` extents. */
function fragtableSpan(n: number): number {
  let span = 0;
  for (const c of blockCounts(n)) {
    span += FRAGTABLE_HEADER_SIZE + c * FRAGMENT_ENTRY_SIZE;
  }
  return span;
}

/** Split `n` items into blocks of at most 255 (always at least one block). */
function blockCounts(n: number): number[] {
  if (n === 0) {
    return [0];
  }
  const out: number[] = [];
  let rem = n;
  while (rem > 0) {
    const c = Math.min(rem, MAX_ENTRIES_PER_BLOCK);
    out.push(c);
    rem -= c;
  }
  return out;
}

/** Write one inner partition's Fragment Table chain at `start`. */
function writeFragmentTable(
  buf: Uint8Array,
  start: number,
  frags: readonly Frag[],
  extIndex: Map<string, number>,
  extArenaOff: number[],
): void {
  const counts = blockCounts(frags.length);
  let blockStart = start;
  let idx = 0;
  for (let b = 0; b < counts.length; b++) {
    const c = counts[b]!;
    const span = FRAGTABLE_HEADER_SIZE + c * FRAGMENT_ENTRY_SIZE;
    const next = b + 1 < counts.length ? blockStart + span : 0;
    buf.set(
      fragTableHeaderToBytes({ nextFragtableOffset: next, fragmentCount: c }),
      blockStart,
    );
    for (let j = 0; j < c; j++) {
      const f = frags[idx + j]!;
      const arenaOff = extArenaOff[extIndex.get(extKey(f.offset, f.length))!]!;
      buf.set(
        fragmentEntryToBytes({
          extentOffset: arenaOff,
          extentLength: f.length,
          kind: f.kind,
          flags: f.shared ? FLAG_SHARED : 0,
        }),
        blockStart + FRAGTABLE_HEADER_SIZE + j * FRAGMENT_ENTRY_SIZE,
      );
    }
    blockStart += span;
    idx += c;
  }
}
