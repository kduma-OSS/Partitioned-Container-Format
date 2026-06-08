//! The Fragment Table: its 9-byte block header and 18-byte entries
//! (spec Section 8).

use crate::consts::{
    ARENA_NONE, FLAG_SHARED, FRAGMENT_ENTRY_SIZE, FRAGTABLE_HEADER_SIZE, KIND_DATA,
};
use crate::error::{Error, Result};

/// One Fragment Entry: a single extent of an inner partition (spec Section 8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentEntry {
    /// Arena-relative start of the extent's bytes.
    pub extent_offset: u64,
    /// Length of the extent in bytes.
    pub extent_length: u64,
    /// Extent kind (`1` = DATA; `0` invalid; `2`/`3` reserved).
    pub kind: u8,
    /// `flags` byte (bit 0 = SHARED; others reserved 0).
    pub flags: u8,
}

impl FragmentEntry {
    /// Serialise to the on-disk 18-byte layout.
    pub fn to_bytes(&self) -> [u8; 18] {
        let mut b = [0u8; 18];
        b[0..8].copy_from_slice(&self.extent_offset.to_le_bytes());
        b[8..16].copy_from_slice(&self.extent_length.to_le_bytes());
        b[16] = self.kind;
        b[17] = self.flags;
        b
    }

    /// Parse from the on-disk 18-byte layout.
    pub fn from_bytes(b: &[u8; 18]) -> Self {
        FragmentEntry {
            extent_offset: u64::from_le_bytes(b[0..8].try_into().unwrap()),
            extent_length: u64::from_le_bytes(b[8..16].try_into().unwrap()),
            kind: b[16],
            flags: b[17],
        }
    }

    /// Whether this entry's `kind` is DATA (the only v1.0 content kind).
    pub fn is_data(&self) -> bool {
        self.kind == KIND_DATA
    }

    /// Whether the SHARED flag (bit 0) is set.
    pub fn is_shared(&self) -> bool {
        self.flags & FLAG_SHARED != 0
    }
}

/// The 9-byte header that begins each Fragment Table block (spec Section 8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragTableHeader {
    /// Arena-relative offset of the next Fragment Table block of this
    /// partition, or 0 if this is the last block.
    pub next_fragtable_offset: u64,
    /// Number of Fragment Entries packed immediately after this header.
    pub fragment_count: u8,
}

impl FragTableHeader {
    /// Serialise to the on-disk 9-byte layout.
    pub fn to_bytes(&self) -> [u8; 9] {
        let mut b = [0u8; 9];
        b[0..8].copy_from_slice(&self.next_fragtable_offset.to_le_bytes());
        b[8] = self.fragment_count;
        b
    }

    /// Parse from the on-disk 9-byte layout.
    pub fn from_bytes(b: &[u8; 9]) -> Self {
        FragTableHeader {
            next_fragtable_offset: u64::from_le_bytes(b[0..8].try_into().unwrap()),
            fragment_count: b[8],
        }
    }
}

/// Walk an inner partition's Fragment Table chain starting at arena-relative
/// `first_off`, returning its Fragment Entries in logical order across the
/// whole chain (spec Section 8.3). `first_off == 0` yields an empty list.
pub fn walk_fragment_table(arena: &[u8], first_off: u64) -> Result<Vec<FragmentEntry>> {
    let mut out = Vec::new();
    let mut off = first_off;
    // A simple cycle guard: a well-formed chain only ever moves forward, but a
    // corrupt file could loop. Bound the walk by the arena length.
    let mut budget = arena.len() / FRAGTABLE_HEADER_SIZE as usize + 1;
    while off != ARENA_NONE {
        if budget == 0 {
            return Err(Error::OffsetOutOfRange);
        }
        budget -= 1;
        let base = off as usize;
        let hb: [u8; 9] = arena
            .get(base..base + FRAGTABLE_HEADER_SIZE as usize)
            .ok_or(Error::OffsetOutOfRange)?
            .try_into()
            .unwrap();
        let h = FragTableHeader::from_bytes(&hb);
        let mut eo = base + FRAGTABLE_HEADER_SIZE as usize;
        for _ in 0..h.fragment_count {
            let eb: [u8; 18] = arena
                .get(eo..eo + FRAGMENT_ENTRY_SIZE as usize)
                .ok_or(Error::OffsetOutOfRange)?
                .try_into()
                .unwrap();
            out.push(FragmentEntry::from_bytes(&eb));
            eo += FRAGMENT_ENTRY_SIZE as usize;
        }
        off = h.next_fragtable_offset;
    }
    Ok(out)
}

/// Reconstruct the logical content of a partition from its Fragment Entries
/// (spec Section 8.3): concatenate the bytes of its DATA extents in order.
///
/// `arena_used` bounds every extent range; a reserved (non-DATA) kind makes the
/// partition unreadable to a v1.0 reader (spec Section 8.2).
pub fn reconstruct(arena: &[u8], frags: &[FragmentEntry], arena_used: u64) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for f in frags {
        if !f.is_data() {
            return Err(Error::BadFragmentKind(f.kind));
        }
        let end = f
            .extent_offset
            .checked_add(f.extent_length)
            .ok_or(Error::OffsetOutOfRange)?;
        if end > arena_used || end > arena.len() as u64 {
            return Err(Error::OffsetOutOfRange);
        }
        out.extend_from_slice(&arena[f.extent_offset as usize..end as usize]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_roundtrip() {
        let e = FragmentEntry {
            extent_offset: 31,
            extent_length: 6,
            kind: KIND_DATA,
            flags: FLAG_SHARED,
        };
        assert_eq!(FragmentEntry::from_bytes(&e.to_bytes()), e);
        assert!(e.is_data());
        assert!(e.is_shared());
    }

    #[test]
    fn header_roundtrip() {
        let h = FragTableHeader {
            next_fragtable_offset: 0,
            fragment_count: 2,
        };
        assert_eq!(FragTableHeader::from_bytes(&h.to_bytes()), h);
    }
}
