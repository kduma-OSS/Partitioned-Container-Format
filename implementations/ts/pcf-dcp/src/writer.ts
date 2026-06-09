/**
 * {@link DcpWriter}: building and rewriting PCF files that carry DCP containers.
 *
 * The writer keeps the whole file as an in-memory list of top-level partitions
 * (plain partitions and DCP containers) and emits a fresh, canonical PCF image
 * on demand. Every mutating operation is a logical edit of that list followed
 * by a rebuild — deliberately simple and always correct for a reference
 * implementation; the resulting file is a fully conforming PCF v1.0 file.
 */

import {
  Container,
  decodeLabel,
  HashAlgo,
  MemoryStorage,
  type Storage,
} from "@kduma-oss/pcf";

import { Arena, type Chunker } from "./arena.js";
import { DCP_CONTAINER_TYPE } from "./consts.js";
import { PcfDcpError } from "./errors.js";

type Body =
  | { kind: "plain"; data: Uint8Array }
  | { kind: "container"; arena: Arena };

interface TopPart {
  partitionType: number;
  uid: Uint8Array;
  label: string;
  dataHashAlgo: HashAlgo;
  body: Body;
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

/** A writer that assembles a PCF file containing DCP containers. */
export class DcpWriter {
  private parts: TopPart[] = [];
  private tableHashAlgo: HashAlgo = HashAlgo.Sha256;
  private trailer = false;

  /** Load an existing PCF file into the writer's model. */
  static open(storage: Storage): DcpWriter {
    const c = Container.open(storage);
    const w = new DcpWriter();
    for (const e of c.entries()) {
      const data = c.readPartitionData(e);
      const label = decodeLabel(e.label);
      const body: Body =
        e.partitionType === DCP_CONTAINER_TYPE
          ? { kind: "container", arena: Arena.parse(data) }
          : { kind: "plain", data };
      w.parts.push({
        partitionType: e.partitionType,
        uid: e.uid.slice(),
        label,
        dataHashAlgo: e.dataHashAlgo,
        body,
      });
    }
    return w;
  }

  /** Finalise emitted images in trailer mode (append-only host). */
  setTrailer(on: boolean): void {
    this.trailer = on;
  }

  private ensureUnique(uid: Uint8Array): void {
    if (this.parts.some((p) => bytesEqual(p.uid, uid))) {
      throw PcfDcpError.duplicateUid();
    }
  }

  /** Add a DCP container partition holding `arena` (data hash algo 0). */
  addContainer(uid: Uint8Array, label: string, arena: Arena): void {
    this.ensureUnique(uid);
    this.parts.push({
      partitionType: DCP_CONTAINER_TYPE,
      uid: uid.slice(),
      label,
      dataHashAlgo: HashAlgo.None,
      body: { kind: "container", arena },
    });
  }

  /** Add an ordinary top-level partition. */
  addPlain(
    partitionType: number,
    uid: Uint8Array,
    label: string,
    data: Uint8Array,
    dataHashAlgo: HashAlgo,
  ): void {
    this.ensureUnique(uid);
    this.parts.push({
      partitionType: partitionType >>> 0,
      uid: uid.slice(),
      label,
      dataHashAlgo,
      body: { kind: "plain", data },
    });
  }

  private containerArena(uid: Uint8Array): Arena {
    for (const p of this.parts) {
      if (bytesEqual(p.uid, uid)) {
        if (p.body.kind !== "container") {
          throw PcfDcpError.notADcpContainer();
        }
        return p.body.arena;
      }
    }
    throw PcfDcpError.notFound();
  }

  /** Borrow a container's arena for inspection or in-place editing. */
  arena(containerUid: Uint8Array): Arena {
    return this.containerArena(containerUid);
  }

  // ---- migration: promotion / demotion -----------------------------------

  /**
   * Promote an inner partition out of its DCP container to a top-level PCF
   * partition (dynamic → fixed), preserving uid, type, label, hash algorithm
   * and `data_hash` (the promotion invariant, spec Section 10.4).
   */
  promote(containerUid: Uint8Array, innerUid: Uint8Array): void {
    const arena = this.containerArena(containerUid);
    const { partitionType, label, dataHashAlgo, content } = arena.removeInner(innerUid);
    this.parts.push({
      partitionType,
      uid: innerUid.slice(),
      label,
      dataHashAlgo,
      body: { kind: "plain", data: content },
    });
  }

  /**
   * Demote a top-level partition into a DCP container as an inner partition
   * (fixed → dynamic), preserving uid, type, label, hash algorithm and
   * `data_hash`. The content becomes a single DATA extent.
   */
  demote(partUid: Uint8Array, containerUid: Uint8Array): void {
    const pos = this.parts.findIndex((p) => bytesEqual(p.uid, partUid));
    if (pos < 0) {
      throw PcfDcpError.notFound();
    }
    const p = this.parts[pos]!;
    if (p.partitionType === DCP_CONTAINER_TYPE || p.body.kind !== "plain") {
      throw PcfDcpError.nestedContainer();
    }
    const { partitionType, label, dataHashAlgo, body } = p;
    const content = body.data;
    const arena = this.containerArena(containerUid);
    arena.addInner(partitionType, partUid, label, content, dataHashAlgo, {
      type: "whole",
    });
    this.parts.splice(pos, 1);
  }

  // ---- container-level maintenance ---------------------------------------

  /** Re-chunk and deduplicate a container's inner partitions. */
  dedup(containerUid: Uint8Array, chunker: Chunker): number {
    return this.containerArena(containerUid).dedup(chunker);
  }

  /** Compact / defragment a container's arena. Returns bytes reclaimed. */
  defrag(containerUid: Uint8Array): number {
    return this.containerArena(containerUid).compact();
  }

  // ---- serialisation -----------------------------------------------------

  /** Build a fresh, canonical PCF image of the whole file. */
  toImage(): Uint8Array {
    const cap = Math.max(1, this.parts.length);
    const c = Container.createWith(new MemoryStorage(), cap, this.tableHashAlgo);
    for (const p of this.parts) {
      const data = p.body.kind === "plain" ? p.body.data : p.body.arena.toBytes();
      c.addPartition(p.partitionType, p.uid, p.label, data, 0, p.dataHashAlgo);
    }
    if (this.trailer) {
      c.finalizeWithTrailer();
    }
    return (c.intoStorage() as MemoryStorage).toUint8Array();
  }
}
