/**
 * The high-level {@link Container} type: reading and writing whole PCF files.
 *
 * `Container` is backed by any {@link Storage}, so it works equally with an
 * in-memory {@link MemoryStorage} and a file-backed `NodeFileStorage`.
 *
 * # Reader vs. writer scope
 *
 * The *reader* side (`open`, `entries`, `readPartitionData`, `verify`) is fully
 * general: it accepts any conforming file, including arbitrary region placement
 * and overflow-block chains.
 *
 * The *writer* side implements one documented placement strategy (the format
 * deliberately leaves layout to the writer, spec section 12 / A7, A9):
 *
 * - The first table block sits immediately after the header and is created with
 *   reserved capacity for `firstBlockCapacity` entries, so entries can be
 *   appended in place without moving data.
 * - Partition data is appended at a growing end-of-data cursor; each partition
 *   may reserve `extraReserve` spare bytes for later in-place growth.
 * - When every known block is full, a new overflow block is appended and linked
 *   into the chain.
 * - Block capacity is *not* stored in the file (spec A9); it is tracked only in
 *   memory for the lifetime of this handle. After {@link Container.open}, blocks
 *   are treated as having no spare capacity, so subsequent additions go into
 *   fresh overflow blocks. {@link Container.compactedImage} rebuilds a tightly
 *   packed file.
 */

import {
  CHAIN_FORWARD,
  ENTRY_SIZE,
  HEADER_SIZE,
  MAX_ENTRIES_PER_BLOCK,
  NIL_UID,
  PT_OFFSET_TRAILER,
  TABLE_HEADER_SIZE,
  TRAILER_MAGIC,
  TRAILER_SIZE,
  TYPE_RESERVED,
  VERSION_MAJOR,
  VERSION_MINOR,
} from "./consts.js";
import {
  encodeLabel,
  entryFromBytes,
  entryToBytes,
  type PartitionEntry,
  validateEntry,
} from "./entry.js";
import { PcfError } from "./errors.js";
import { computeHashField, digestLen, HashAlgo, verifies } from "./hash.js";
import {
  type FileHeader,
  headerFromBytes,
  headerToBytes,
} from "./header.js";
import { MemoryStorage, type Storage } from "./storage.js";
import {
  computeTableHash,
  tableHeaderFromBytes,
  tableHeaderToBytes,
  type TableBlockHeader,
} from "./table.js";
import { type Trailer, trailerFromBytes, trailerToBytes } from "./trailer.js";

/** In-memory bookkeeping for one table block (not stored on disk). */
interface BlockInfo {
  offset: number;
  capacity: number;
  count: number;
  algo: HashAlgo;
  next: number;
}

/**
 * One table block read from disk: its absolute `offset`, its parsed
 * {@link TableBlockHeader} (including `tableHash` and `nextTableOffset`), and
 * its {@link PartitionEntry} list.
 *
 * Returned by {@link Container.readBlockAt}. It lets code layered on PCF group
 * blocks, inspect each block's `tableHash`, and follow non-default
 * `nextTableOffset` chains, instead of {@link Container.entries} which flattens
 * the whole chain.
 */
export interface BlockView {
  /** Absolute file offset of the table block. */
  offset: number;
  /** Parsed 74-byte block header. */
  header: TableBlockHeader;
  /** The block's entries, in stored order. */
  entries: PartitionEntry[];
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

/** A PCF container backed by a {@link Storage}. */
export class Container {
  private storage: Storage;
  private fileHeader: FileHeader;
  private blocks: BlockInfo[];
  private dataEof: number;
  private defaultCapacity: number;
  private tableHashAlgo: HashAlgo;
  /**
   * Resolved absolute offset of the partition-table head: the header pointer
   * for a classic file, or the offset from the file trailer when the header
   * holds {@link PT_OFFSET_TRAILER}. 0 denotes an empty table.
   */
  private tableHeadOffset = HEADER_SIZE;
  /** Chain-direction flags resolved at open time (see {@link Trailer}). */
  private chainFlags = CHAIN_FORWARD;

  private constructor(
    storage: Storage,
    fileHeader: FileHeader,
    blocks: BlockInfo[],
    dataEof: number,
    defaultCapacity: number,
    tableHashAlgo: HashAlgo,
  ) {
    this.storage = storage;
    this.fileHeader = fileHeader;
    this.blocks = blocks;
    this.dataEof = dataEof;
    this.defaultCapacity = defaultCapacity;
    this.tableHashAlgo = tableHashAlgo;
  }

  // ---- construction ------------------------------------------------------

  /**
   * Create an empty container with sensible defaults (first block capacity 16,
   * table hashing with SHA-256). Defaults to an in-memory store.
   */
  static create(storage: Storage = new MemoryStorage()): Container {
    return Container.createWith(storage, 16, HashAlgo.Sha256);
  }

  /**
   * Create an empty container, choosing the first block's reserved capacity and
   * the table-hash algorithm.
   */
  static createWith(
    storage: Storage,
    firstBlockCapacity: number,
    tableHashAlgo: HashAlgo,
  ): Container {
    const cap = Math.min(
      Math.max(firstBlockCapacity, 1),
      MAX_ENTRIES_PER_BLOCK,
    );
    const header: FileHeader = {
      versionMajor: VERSION_MAJOR,
      versionMinor: VERSION_MINOR,
      partitionTableOffset: BigInt(HEADER_SIZE),
    };
    storage.writeAt(0, headerToBytes(header));

    const th = computeTableHash(tableHashAlgo, 0n, []);
    const bh: TableBlockHeader = {
      partitionCount: 0,
      nextTableOffset: 0n,
      tableHashAlgo,
      tableHash: th,
    };
    storage.writeAt(HEADER_SIZE, tableHeaderToBytes(bh));

    const dataEof = HEADER_SIZE + TABLE_HEADER_SIZE + cap * ENTRY_SIZE;
    const blocks: BlockInfo[] = [
      { offset: HEADER_SIZE, capacity: cap, count: 0, algo: tableHashAlgo, next: 0 },
    ];
    return new Container(storage, header, blocks, dataEof, cap, tableHashAlgo);
  }

  /**
   * Open an existing container, validating the header (spec C1, C2).
   *
   * When the header's `partitionTableOffset` is the {@link PT_OFFSET_TRAILER}
   * sentinel, the partition-table head and chain direction are read from the
   * file trailer (located by scanning backward from the end of the file). Chain
   * traversal is identical in both directions (follow `nextTableOffset` until
   * 0); the direction only conveys which end is newest, exposed via
   * {@link Container.chainIsBackward}.
   */
  static open(storage: Storage): Container {
    const hb = storage.readAt(0, HEADER_SIZE);
    const header = headerFromBytes(hb);

    const me = new Container(storage, header, [], 0, 16, HashAlgo.Sha256);
    if (header.partitionTableOffset === PT_OFFSET_TRAILER) {
      [me.tableHeadOffset, me.chainFlags] = Container.locateTrailer(storage);
    } else {
      me.tableHeadOffset = Number(header.partitionTableOffset);
      me.chainFlags = CHAIN_FORWARD;
    }

    const blocks: BlockInfo[] = [];
    let off = me.tableHeadOffset;
    while (off !== 0) {
      const [h] = me.readBlock(off);
      blocks.push({
        offset: off,
        capacity: h.partitionCount, // no known spare after open
        count: h.partitionCount,
        algo: h.tableHashAlgo,
        next: Number(h.nextTableOffset),
      });
      off = Number(h.nextTableOffset);
    }
    if (blocks.length > 0) {
      me.tableHashAlgo = blocks[0]!.algo;
    }
    me.blocks = blocks;
    me.dataEof = storage.size();
    return me;
  }

  /** Consume the container and return the backing store. */
  intoStorage(): Storage {
    return this.storage;
  }

  /**
   * The parsed file header. In trailer mode its `partitionTableOffset` holds
   * the {@link PT_OFFSET_TRAILER} sentinel; use {@link Container.tableHead} for
   * the resolved head.
   */
  header(): FileHeader {
    return this.fileHeader;
  }

  /**
   * The resolved absolute offset of the partition-table head (0 if empty). This
   * is the value to follow regardless of header-pointer vs trailer mode.
   */
  tableHead(): number {
    return this.tableHeadOffset;
  }

  /**
   * Whether the chain is backward-linked (head = newest block,
   * `nextTableOffset` points at the previous/older block). Classic
   * header-pointer files are always forward.
   */
  chainIsBackward(): boolean {
    return (this.chainFlags & 1) !== 0;
  }

  /**
   * Locate the most recent valid file trailer by scanning backward from the end
   * of the file for the last 20-byte window ending in {@link TRAILER_MAGIC}
   * whose recorded head is empty (0) or references a parseable table block.
   * Bytes after that trailer — an incomplete or aborted append — are ignored,
   * which gives append-only writers crash recovery for free. In the clean case
   * the trailer is the final {@link TRAILER_SIZE} bytes.
   */
  private static locateTrailer(storage: Storage): [number, number] {
    let end = storage.size();
    while (end >= TRAILER_SIZE) {
      const start = end - TRAILER_SIZE;
      const window = storage.readAt(start, TRAILER_SIZE);
      let magicOk = true;
      for (let i = 0; i < TRAILER_MAGIC.length; i++) {
        if (window[12 + i] !== TRAILER_MAGIC[i]) {
          magicOk = false;
          break;
        }
      }
      if (magicOk) {
        const t = trailerFromBytes(window);
        if (t.partitionTableOffset === 0n) {
          return [0, t.chainFlags];
        }
        const head = Number(t.partitionTableOffset);
        if (t.partitionTableOffset > 0n && head + TABLE_HEADER_SIZE <= start) {
          try {
            tableHeaderFromBytes(storage.readAt(head, TABLE_HEADER_SIZE));
            return [head, t.chainFlags];
          } catch (e) {
            if (!(e instanceof PcfError)) {
              throw e;
            }
            // Spurious magic in an aborted tail; keep scanning.
          }
        }
      }
      end -= 1;
    }
    throw PcfError.badTrailer();
  }

  // ---- low-level I/O ------------------------------------------------------

  private readBlock(off: number): [TableBlockHeader, PartitionEntry[]] {
    const hb = this.storage.readAt(off, TABLE_HEADER_SIZE);
    const h = tableHeaderFromBytes(hb);
    const entries: PartitionEntry[] = [];
    for (let i = 0; i < h.partitionCount; i++) {
      const eb = this.storage.readAt(
        off + TABLE_HEADER_SIZE + i * ENTRY_SIZE,
        ENTRY_SIZE,
      );
      entries.push(entryFromBytes(eb));
    }
    return [h, entries];
  }

  private writeBlock(
    off: number,
    next: number,
    algo: HashAlgo,
    entries: readonly PartitionEntry[],
  ): void {
    const hash = computeTableHash(algo, BigInt(next), entries);
    const header: TableBlockHeader = {
      partitionCount: entries.length,
      nextTableOffset: BigInt(next),
      tableHashAlgo: algo,
      tableHash: hash,
    };
    this.storage.writeAt(off, tableHeaderToBytes(header));
    const buf = new Uint8Array(entries.length * ENTRY_SIZE);
    let p = 0;
    for (const e of entries) {
      buf.set(entryToBytes(e), p);
      p += ENTRY_SIZE;
    }
    this.storage.writeAt(off + TABLE_HEADER_SIZE, buf);
  }

  // ---- reading -----------------------------------------------------------

  /** All live partition entries, in chain order. */
  entries(): PartitionEntry[] {
    const out: PartitionEntry[] = [];
    let off = this.tableHeadOffset;
    while (off !== 0) {
      const [h, entries] = this.readBlock(off);
      out.push(...entries);
      off = Number(h.nextTableOffset);
    }
    return out;
  }

  /**
   * Read a single table block at an absolute `offset`, returning its parsed
   * header (including `tableHash`) and entries. Unlike {@link entries}, which
   * flattens the whole chain, this exposes one block at a time so a caller can
   * follow an arbitrary `nextTableOffset` chain and inspect each block's
   * `tableHash`. It is a read-only operation and does not alter the container.
   */
  readBlockAt(offset: number): BlockView {
    const [header, entries] = this.readBlock(offset);
    return { offset, header, entries };
  }

  /** Read a partition's used data. */
  readPartitionData(entry: PartitionEntry): Uint8Array {
    const used = Number(entry.usedBytes);
    if (used === 0) {
      return new Uint8Array(0);
    }
    return this.storage.readAt(Number(entry.startOffset), used);
  }

  private locate(uid: Uint8Array): [number, number, PartitionEntry] {
    let off = this.tableHeadOffset;
    while (off !== 0) {
      const [h, entries] = this.readBlock(off);
      for (let i = 0; i < entries.length; i++) {
        if (bytesEqual(entries[i]!.uid, uid)) {
          return [off, i, entries[i]!];
        }
      }
      off = Number(h.nextTableOffset);
    }
    throw PcfError.notFound();
  }

  private blockIndex(offset: number): number {
    const i = this.blocks.findIndex((b) => b.offset === offset);
    if (i < 0) {
      throw new Error("block offset must be tracked");
    }
    return i;
  }

  // ---- writing -----------------------------------------------------------

  /**
   * Add a new partition. The data is appended at the end-of-data cursor and
   * reserves `extraReserve` spare bytes for later in-place growth.
   */
  addPartition(
    partitionType: number,
    uid: Uint8Array,
    label: string,
    data: Uint8Array,
    extraReserve: number | bigint = 0,
    dataHashAlgo: HashAlgo = HashAlgo.Sha256,
  ): void {
    if ((partitionType >>> 0) === TYPE_RESERVED) {
      throw PcfError.reservedType();
    }
    if (bytesEqual(uid, NIL_UID)) {
      throw PcfError.nilUid();
    }
    if (this.entries().some((e) => bytesEqual(e.uid, uid))) {
      throw PcfError.duplicateUid();
    }

    const labelBytes = encodeLabel(label);
    const used = data.length;
    const max = used + Number(extraReserve);
    const start = this.dataEof;
    if (used > 0) {
      this.storage.writeAt(start, data);
    }
    this.dataEof += max;
    const dataHash = computeHashField(dataHashAlgo, data);

    const entry: PartitionEntry = {
      partitionType: partitionType >>> 0,
      uid: uid.slice(),
      label: labelBytes,
      startOffset: BigInt(start),
      maxLength: BigInt(max),
      usedBytes: BigInt(used),
      dataHashAlgo,
      dataHash,
    };

    // Find an existing block with reserved room.
    const target = this.blocks.findIndex(
      (b) => b.count < b.capacity && b.count < MAX_ENTRIES_PER_BLOCK,
    );

    if (target >= 0) {
      const boff = this.blocks[target]!.offset;
      const [, entries] = this.readBlock(boff);
      entries.push(entry);
      const algo = this.blocks[target]!.algo;
      const next = this.blocks[target]!.next;
      this.writeBlock(boff, next, algo, entries);
      this.blocks[target]!.count += 1;
    } else {
      // Allocate a new overflow block at the end-of-data cursor.
      const newOff = this.dataEof;
      const cap = Math.min(
        Math.max(this.defaultCapacity, 1),
        MAX_ENTRIES_PER_BLOCK,
      );
      this.dataEof = newOff + TABLE_HEADER_SIZE + cap * ENTRY_SIZE;
      const algo = this.tableHashAlgo;
      this.writeBlock(newOff, 0, algo, [entry]);

      // Re-link the previous tail block to point at the new block.
      const tail = this.blocks[this.blocks.length - 1]!;
      const [, tentries] = this.readBlock(tail.offset);
      this.writeBlock(tail.offset, newOff, tail.algo, tentries);
      tail.next = newOff;
      this.blocks.push({
        offset: newOff,
        capacity: cap,
        count: 1,
        algo,
        next: 0,
      });
    }
  }

  /**
   * Replace a partition's data in place (spec section 8.5, hash cascade).
   * Fails if `newData` exceeds the partition's reservation.
   */
  updatePartitionData(uid: Uint8Array, newData: Uint8Array): void {
    const [boff, slot, entry] = this.locate(uid);
    if (BigInt(newData.length) > entry.maxLength) {
      throw PcfError.dataTooLarge();
    }
    if (newData.length > 0) {
      this.storage.writeAt(Number(entry.startOffset), newData);
    }
    entry.usedBytes = BigInt(newData.length);
    entry.dataHash = computeHashField(entry.dataHashAlgo, newData);

    const [, entries] = this.readBlock(boff);
    entries[slot] = entry;
    const bi = this.blockIndex(boff);
    const next = this.blocks[bi]!.next;
    const algo = this.blocks[bi]!.algo;
    this.writeBlock(boff, next, algo, entries);
  }

  /**
   * Remove a partition. Entries after it in the same block shift down; the
   * freed data region becomes dead space until {@link Container.compactedImage}
   * reclaims it (spec section 11.4).
   */
  removePartition(uid: Uint8Array): void {
    const [boff, slot] = this.locate(uid);
    const [, entries] = this.readBlock(boff);
    entries.splice(slot, 1);
    const bi = this.blockIndex(boff);
    const next = this.blocks[bi]!.next;
    const algo = this.blocks[bi]!.algo;
    this.writeBlock(boff, next, algo, entries);
    this.blocks[bi]!.count -= 1;
  }

  // ---- integrity ---------------------------------------------------------

  /**
   * Verify every table block and every partition's data against its stored
   * hash, and run the per-entry conformance checks (spec section 12).
   */
  verify(): void {
    let off = this.tableHeadOffset;
    while (off !== 0) {
      const [h, entries] = this.readBlock(off);
      if (verifies(h.tableHashAlgo)) {
        const computed = computeTableHash(
          h.tableHashAlgo,
          h.nextTableOffset,
          entries,
        );
        const n = digestLen(h.tableHashAlgo);
        for (let i = 0; i < n; i++) {
          if (computed[i] !== h.tableHash[i]) {
            throw PcfError.tableHashMismatch();
          }
        }
      }
      for (const e of entries) {
        validateEntry(e);
        const data = this.readPartitionData(e);
        if (!verifyDataHash(e, data)) {
          throw PcfError.dataHashMismatch();
        }
      }
      off = Number(h.nextTableOffset);
    }
  }

  // ---- compaction --------------------------------------------------------

  /**
   * Build a freshly compacted image: all dead space removed, every `maxLength`
   * trimmed to `usedBytes`, partitions placed contiguously after a tightly
   * packed table (spec section 11.5). The current handle is left unchanged;
   * write the bytes to a new store and re-open it.
   */
  compactedImage(): Uint8Array {
    // Gather live entries and their data, in chain order.
    const live: Array<{ entry: PartitionEntry; data: Uint8Array }> = [];
    let off = this.tableHeadOffset;
    while (off !== 0) {
      const [h, entries] = this.readBlock(off);
      for (const e of entries) {
        live.push({ entry: e, data: this.readPartitionData(e) });
      }
      off = Number(h.nextTableOffset);
    }

    const algo = this.tableHashAlgo;
    const n = live.length;
    const numBlocks = n === 0 ? 1 : Math.ceil(n / MAX_ENTRIES_PER_BLOCK);

    const counts: number[] = [];
    let rem = n;
    for (let i = 0; i < numBlocks; i++) {
      const c = Math.min(rem, MAX_ENTRIES_PER_BLOCK);
      counts.push(c);
      rem -= c;
    }

    const blockOffsets: number[] = [];
    let o = HEADER_SIZE;
    for (const c of counts) {
      blockOffsets.push(o);
      o += TABLE_HEADER_SIZE + c * ENTRY_SIZE;
    }
    const dataStart = o;

    // Assign contiguous data offsets; trim reservations to used size.
    let d = dataStart;
    for (const item of live) {
      const len = item.data.length;
      item.entry = {
        ...item.entry,
        startOffset: BigInt(d),
        usedBytes: BigInt(len),
        maxLength: BigInt(len),
        // dataHash is unchanged because the content is unchanged.
      };
      d += len;
    }

    // Serialise.
    const image = new Uint8Array(d);
    const header: FileHeader = {
      versionMajor: VERSION_MAJOR,
      versionMinor: VERSION_MINOR,
      partitionTableOffset: BigInt(HEADER_SIZE),
    };
    image.set(headerToBytes(header), 0);

    let idx = 0;
    for (let bi = 0; bi < counts.length; bi++) {
      const c = counts[bi]!;
      const next = bi + 1 < numBlocks ? blockOffsets[bi + 1]! : 0;
      const slice = live.slice(idx, idx + c).map((x) => x.entry);
      const th = computeTableHash(algo, BigInt(next), slice);
      const bh: TableBlockHeader = {
        partitionCount: c,
        nextTableOffset: BigInt(next),
        tableHashAlgo: algo,
        tableHash: th,
      };
      let p = blockOffsets[bi]!;
      image.set(tableHeaderToBytes(bh), p);
      p += TABLE_HEADER_SIZE;
      for (const e of slice) {
        image.set(entryToBytes(e), p);
        p += ENTRY_SIZE;
      }
      idx += c;
    }

    let dp = dataStart;
    for (const item of live) {
      image.set(item.data, dp);
      dp += item.data.length;
    }
    return image;
  }

  /** Write a compacted copy of the container to `out`. */
  compactInto(out: Storage): void {
    out.writeAt(0, this.compactedImage());
  }

  // ---- trailer mode ------------------------------------------------------

  /**
   * Convert the file to trailer mode: append a fixed trailer at the end of the
   * file recording the current partition-table head, then overwrite the
   * header's `partitionTableOffset` with the {@link PT_OFFSET_TRAILER} sentinel
   * so the head is located via that trailer. The chain built by this writer is
   * forward-linked, so the trailer records {@link CHAIN_FORWARD}.
   */
  finalizeWithTrailer(): void {
    const trailer: Trailer = {
      partitionTableOffset: BigInt(this.tableHeadOffset),
      chainFlags: CHAIN_FORWARD,
    };
    const pos = this.storage.size();
    this.storage.writeAt(pos, trailerToBytes(trailer));
    this.fileHeader = {
      ...this.fileHeader,
      partitionTableOffset: PT_OFFSET_TRAILER,
    };
    this.storage.writeAt(0, headerToBytes(this.fileHeader));
    this.chainFlags = CHAIN_FORWARD;
    this.dataEof = pos + TRAILER_SIZE;
  }
}

function verifyDataHash(e: PartitionEntry, data: Uint8Array): boolean {
  if (!verifies(e.dataHashAlgo)) {
    return true;
  }
  const computed = computeHashField(e.dataHashAlgo, data);
  const n = digestLen(e.dataHashAlgo);
  for (let i = 0; i < n; i++) {
    if (computed[i] !== e.dataHash[i]) {
      return false;
    }
  }
  return true;
}
