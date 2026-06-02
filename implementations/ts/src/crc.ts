/**
 * Pure-TypeScript CRC implementations used by the PCF hash registry
 * (spec section 8.1). `@noble/hashes` does not provide CRCs, so the three
 * registered variants are implemented here from their normative parameters.
 *
 * All three are *reflected* CRCs (refin = refout = true), so the table-driven
 * form processes the low byte and shifts right, using the reflected polynomial.
 */

const MASK32 = 0xffff_ffff;
const MASK64 = (1n << 64n) - 1n;

function makeTable32(reflectedPoly: number): Uint32Array {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? reflectedPoly ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
}

function makeTable64(reflectedPoly: bigint): BigUint64Array {
  const table = new BigUint64Array(256);
  for (let n = 0n; n < 256n; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1n ? reflectedPoly ^ (c >> 1n) : c >> 1n;
    }
    table[Number(n)] = c & MASK64;
  }
  return table;
}

// Reflected polynomials for each registered CRC (spec section 8.1).
const CRC32_TABLE = makeTable32(0xedb88320); // CRC-32/ISO-HDLC
const CRC32C_TABLE = makeTable32(0x82f63b78); // CRC-32C (Castagnoli)
// CRC-64/XZ: normal poly 0x42F0E1EBA9EA3693, reflected 0xC96C5795D7870F42.
const CRC64_TABLE = makeTable64(0xc96c5795d7870f42n);

function crc32With(table: Uint32Array, data: Uint8Array): number {
  let crc = MASK32;
  for (let i = 0; i < data.length; i++) {
    crc = (crc >>> 8) ^ table[(crc ^ data[i]!) & 0xff]!;
  }
  return (crc ^ MASK32) >>> 0;
}

/** CRC-32/ISO-HDLC (the CRC used by zlib, gzip, and PNG). */
export function crc32(data: Uint8Array): number {
  return crc32With(CRC32_TABLE, data);
}

/** CRC-32C (Castagnoli). */
export function crc32c(data: Uint8Array): number {
  return crc32With(CRC32C_TABLE, data);
}

/** CRC-64/XZ. */
export function crc64(data: Uint8Array): bigint {
  let crc = MASK64;
  for (let i = 0; i < data.length; i++) {
    const idx = Number((crc ^ BigInt(data[i]!)) & 0xffn);
    crc = (crc >> 8n) ^ CRC64_TABLE[idx]!;
  }
  return (crc ^ MASK64) & MASK64;
}
