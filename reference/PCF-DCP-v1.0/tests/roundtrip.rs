//! End-to-end round-trips: build, edit, dedup/defrag, promote/demote.

use std::io::Cursor;

use pcf::HashAlgo;
use pcf_dcp::{Arena, Chunker, DcpReader, DcpWriter, Resolved};

fn build_two_inner_file() -> Vec<u8> {
    let mut arena = Arena::new();
    arena
        .add_inner(
            0x10,
            [0xA1; 16],
            "A",
            b"Hello, World!",
            HashAlgo::Sha256,
            Chunker::Fixed(7),
        )
        .unwrap();
    arena
        .add_inner(
            0x10,
            [0xB2; 16],
            "B",
            b"World!",
            HashAlgo::Sha256,
            Chunker::Whole,
        )
        .unwrap();
    let mut w = DcpWriter::new();
    w.add_container([0xDC; 16], "dcp", arena).unwrap();
    w.to_image().unwrap()
}

#[test]
fn edits_reconstruct_correctly() {
    let mut arena = Arena::new();
    arena
        .add_inner(
            0x10,
            [1; 16],
            "f",
            b"Hello, World!",
            HashAlgo::Sha256,
            Chunker::Fixed(7),
        )
        .unwrap();

    arena.append(&[1; 16], b"!!").unwrap();
    assert_eq!(arena.content(&[1; 16]).unwrap(), b"Hello, World!!!");

    arena.insert(&[1; 16], 5, b"XYZ").unwrap();
    assert_eq!(arena.content(&[1; 16]).unwrap(), b"HelloXYZ, World!!!");

    arena.delete(&[1; 16], 5, 3).unwrap();
    assert_eq!(arena.content(&[1; 16]).unwrap(), b"Hello, World!!!");

    arena.overwrite(&[1; 16], 0, 5, b"HOWDY").unwrap();
    assert_eq!(arena.content(&[1; 16]).unwrap(), b"HOWDY, World!!!");

    arena.truncate(&[1; 16], 5).unwrap();
    assert_eq!(arena.content(&[1; 16]).unwrap(), b"HOWDY");
}

#[test]
fn cow_does_not_disturb_shared_bytes() {
    // A and B share "World!"; overwriting A's copy must not change B.
    let mut arena = Arena::new();
    arena
        .add_inner(
            0x10,
            [0xA1; 16],
            "A",
            b"Hello, World!",
            HashAlgo::Sha256,
            Chunker::Fixed(7),
        )
        .unwrap();
    arena
        .add_inner(
            0x10,
            [0xB2; 16],
            "B",
            b"World!",
            HashAlgo::Sha256,
            Chunker::Whole,
        )
        .unwrap();
    // Overwrite the "World!" part of A (logical [7,13)).
    arena.overwrite(&[0xA1; 16], 7, 6, b"PLANET").unwrap();
    assert_eq!(arena.content(&[0xA1; 16]).unwrap(), b"Hello, PLANET");
    assert_eq!(arena.content(&[0xB2; 16]).unwrap(), b"World!");
}

#[test]
fn dedup_then_defrag_preserve_content() {
    // Two inners with no initial sharing; dedup should fold the identical chunk.
    let mut arena = Arena::new();
    arena
        .add_inner(
            0x10,
            [1; 16],
            "A",
            b"abcabc",
            HashAlgo::Sha256,
            Chunker::Whole,
        )
        .unwrap();
    arena
        .add_inner(
            0x10,
            [2; 16],
            "B",
            b"abcabc",
            HashAlgo::Sha256,
            Chunker::Whole,
        )
        .unwrap();
    let h1 = arena.inner_info(&[1; 16]).unwrap().data_hash;

    let saved = arena.dedup(Chunker::Fixed(3));
    assert!(saved > 0, "identical chunks should dedup");
    // Content and hash unchanged.
    assert_eq!(arena.content(&[1; 16]).unwrap(), b"abcabc");
    assert_eq!(arena.content(&[2; 16]).unwrap(), b"abcabc");
    assert_eq!(arena.inner_info(&[1; 16]).unwrap().data_hash, h1);

    arena.compact();
    assert_eq!(arena.content(&[2; 16]).unwrap(), b"abcabc");
}

#[test]
fn defrag_clears_shared_when_no_longer_aliased() {
    let mut arena = Arena::new();
    arena
        .add_inner(
            0x10,
            [0xA1; 16],
            "A",
            b"Hello, World!",
            HashAlgo::Sha256,
            Chunker::Fixed(7),
        )
        .unwrap();
    arena
        .add_inner(
            0x10,
            [0xB2; 16],
            "B",
            b"World!",
            HashAlgo::Sha256,
            Chunker::Whole,
        )
        .unwrap();
    // Remove B, so "World!" is referenced only by A now.
    arena.remove_inner(&[0xB2; 16]).unwrap();
    arena.compact();
    let a = arena.inner_info(&[0xA1; 16]).unwrap();
    assert!(
        a.extents.iter().all(|e| !e.shared),
        "F2: shared cleared at compaction"
    );
    assert_eq!(arena.content(&[0xA1; 16]).unwrap(), b"Hello, World!");
}

#[test]
fn promote_preserves_uid_and_data_hash() {
    let image = build_two_inner_file();
    let mut w = DcpWriter::open(Cursor::new(image)).unwrap();

    // data_hash of inner B before promotion.
    let before = {
        let bytes = w.to_image().unwrap();
        let mut r = DcpReader::open(Cursor::new(bytes)).unwrap();
        let inner = r
            .inner_partitions()
            .unwrap()
            .into_iter()
            .find(|l| l.info.uid == [0xB2; 16])
            .unwrap();
        inner.info.data_hash
    };

    w.promote(&[0xDC; 16], &[0xB2; 16]).unwrap();
    let image = w.to_image().unwrap();

    let mut r = DcpReader::open(Cursor::new(image)).unwrap();
    r.verify().unwrap();
    match r.resolve_uid(&[0xB2; 16]).unwrap() {
        Resolved::TopLevel(e) => {
            assert_eq!(e.uid, [0xB2; 16]);
            assert_eq!(
                e.data_hash, before,
                "promotion invariant: data_hash unchanged"
            );
            assert_eq!(e.used_bytes, 6);
        }
        _ => panic!("B should now be top-level"),
    }
    // The promoted partition reads back as "World!".
    assert_eq!(r.read_inner(&[0xA1; 16]).unwrap(), b"Hello, World!");
}

#[test]
fn demote_then_promote_is_identity_for_content() {
    let image = build_two_inner_file();
    let mut w = DcpWriter::open(Cursor::new(image)).unwrap();
    w.promote(&[0xDC; 16], &[0xB2; 16]).unwrap();
    // Now B is top-level; demote it back into the container.
    w.demote(&[0xB2; 16], &[0xDC; 16]).unwrap();
    let image = w.to_image().unwrap();

    let mut r = DcpReader::open(Cursor::new(image)).unwrap();
    r.verify().unwrap();
    assert_eq!(r.read_inner(&[0xB2; 16]).unwrap(), b"World!");
    // And it is an inner partition again.
    assert!(matches!(
        r.resolve_uid(&[0xB2; 16]).unwrap(),
        Resolved::Inner(_)
    ));
}

#[test]
fn trailer_mode_reads_back_identically() {
    // Build the same file in trailer mode (append-only host); the reader must
    // resolve the table head from the trailer and expose every inner partition.
    let mut arena = Arena::new();
    arena
        .add_inner(
            0x10,
            [0xA1; 16],
            "A",
            b"Hello, World!",
            HashAlgo::Sha256,
            Chunker::Fixed(7),
        )
        .unwrap();
    arena
        .add_inner(
            0x10,
            [0xB2; 16],
            "B",
            b"World!",
            HashAlgo::Sha256,
            Chunker::Whole,
        )
        .unwrap();
    let mut w = DcpWriter::new();
    w.add_container([0xDC; 16], "dcp", arena).unwrap();
    w.set_trailer(true);
    let image = w.to_image().unwrap();

    let mut r = DcpReader::open(Cursor::new(image)).unwrap();
    r.verify().unwrap();
    assert_eq!(r.read_inner(&[0xA1; 16]).unwrap(), b"Hello, World!");
    assert_eq!(r.read_inner(&[0xB2; 16]).unwrap(), b"World!");
    assert_eq!(r.inner_partitions().unwrap().len(), 2);
}
