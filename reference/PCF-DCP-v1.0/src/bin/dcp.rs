//! `dcp` — a small command-line tool for DCP containers.
//!
//! Subcommands (arguments parsed by hand, in the style of the other reference
//! tools):
//!
//! ```text
//! dcp info    <file>
//! dcp dedup   <file> [--fixed N] [--trailer]
//! dcp defrag  <file> [--trailer]
//! dcp promote <file> <container-uid> <inner-uid> [--trailer]
//! dcp demote  <file> <part-uid> <container-uid> [--trailer]
//! ```
//!
//! UIDs are given as 32 hex digits (16 bytes), or as `0xNN` to mean a uid of 16
//! identical bytes (e.g. `0xDC` = 16×0xDC), matching the test vector's notation.
//! Every mutating command rewrites the file and then re-verifies it.

use std::io::Cursor;
use std::process::ExitCode;

use pcf_dcp::{Chunker, DcpReader, DcpWriter, UID_SIZE};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage();
        return ExitCode::FAILURE;
    }
    let cmd = args[0].as_str();
    let rest = &args[1..];
    let result = match cmd {
        "info" => cmd_info(rest),
        "dedup" => cmd_dedup(rest),
        "defrag" => cmd_defrag(rest),
        "promote" => cmd_promote(rest),
        "demote" => cmd_demote(rest),
        "-h" | "--help" | "help" => {
            usage();
            return ExitCode::SUCCESS;
        }
        other => Err(format!("unknown command '{other}'")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("dcp: {e}");
            ExitCode::FAILURE
        }
    }
}

fn usage() {
    eprintln!(
        "usage:\n  dcp info    <file>\n  dcp dedup   <file> [--fixed N] [--trailer]\n  \
         dcp defrag  <file> [--trailer]\n  dcp promote <file> <container-uid> <inner-uid> [--trailer]\n  \
         dcp demote  <file> <part-uid> <container-uid> [--trailer]"
    );
}

// ---- commands -------------------------------------------------------------

fn cmd_info(args: &[String]) -> Result<(), String> {
    let path = args.first().ok_or("info: missing <file>")?;
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut r = DcpReader::open(Cursor::new(bytes)).map_err(de)?;
    r.verify().map_err(de)?;
    let containers = r.containers().map_err(de)?;
    println!("{}: {} DCP container(s)", path, containers.len());
    for c in containers {
        let arena = r.open_arena(&c).map_err(de)?;
        println!(
            "  container {} (uid {}) used={} inner={}",
            c.label_string().unwrap_or_default(),
            hex(&c.uid),
            c.used_bytes,
            arena.len()
        );
        for info in arena.inners() {
            let n = info.data_hash_algo.digest_len();
            let dh: String = info.data_hash[..n]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let shared = info.extents.iter().filter(|e| e.shared).count();
            println!(
                "    inner {} (uid {}) type=0x{:08X} used={} extents={} shared={} algo={:?} data_hash={}",
                info.label,
                hex(&info.uid),
                info.partition_type,
                info.used_bytes,
                info.extents.len(),
                shared,
                info.data_hash_algo,
                dh
            );
        }
    }
    Ok(())
}

fn cmd_dedup(args: &[String]) -> Result<(), String> {
    let opts = Opts::parse(args, 1)?;
    let path = &opts.positional[0];
    let chunker = match opts.fixed {
        Some(n) => Chunker::Fixed(n),
        None => Chunker::Whole,
    };
    let mut w = open_writer(path, opts.trailer)?;
    let containers = container_uids(path)?;
    let mut saved = 0u64;
    for uid in &containers {
        saved += w.dedup(uid, chunker).map_err(de)?;
    }
    commit(path, &w)?;
    println!(
        "deduplicated {} container(s); ~{} bytes saved",
        containers.len(),
        saved
    );
    Ok(())
}

fn cmd_defrag(args: &[String]) -> Result<(), String> {
    let opts = Opts::parse(args, 1)?;
    let path = &opts.positional[0];
    let mut w = open_writer(path, opts.trailer)?;
    let containers = container_uids(path)?;
    let mut reclaimed = 0u64;
    for uid in &containers {
        reclaimed += w.defrag(uid).map_err(de)?;
    }
    commit(path, &w)?;
    println!(
        "defragmented {} container(s); {} dead bytes reclaimed",
        containers.len(),
        reclaimed
    );
    Ok(())
}

fn cmd_promote(args: &[String]) -> Result<(), String> {
    let opts = Opts::parse(args, 3)?;
    let path = &opts.positional[0];
    let cuid = parse_uid(&opts.positional[1])?;
    let iuid = parse_uid(&opts.positional[2])?;
    let mut w = open_writer(path, opts.trailer)?;
    w.promote(&cuid, &iuid).map_err(de)?;
    commit(path, &w)?;
    println!(
        "promoted inner {} out of container {}",
        hex(&iuid),
        hex(&cuid)
    );
    Ok(())
}

fn cmd_demote(args: &[String]) -> Result<(), String> {
    let opts = Opts::parse(args, 3)?;
    let path = &opts.positional[0];
    let puid = parse_uid(&opts.positional[1])?;
    let cuid = parse_uid(&opts.positional[2])?;
    let mut w = open_writer(path, opts.trailer)?;
    w.demote(&puid, &cuid).map_err(de)?;
    commit(path, &w)?;
    println!(
        "demoted partition {} into container {}",
        hex(&puid),
        hex(&cuid)
    );
    Ok(())
}

// ---- helpers --------------------------------------------------------------

fn open_writer(path: &str, trailer: bool) -> Result<DcpWriter, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut w = DcpWriter::open(Cursor::new(bytes)).map_err(de)?;
    w.set_trailer(trailer);
    Ok(w)
}

fn container_uids(path: &str) -> Result<Vec<[u8; UID_SIZE]>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut r = DcpReader::open(Cursor::new(bytes)).map_err(de)?;
    Ok(r.containers()
        .map_err(de)?
        .into_iter()
        .map(|c| c.uid)
        .collect())
}

fn commit(path: &str, w: &DcpWriter) -> Result<(), String> {
    let image = w.to_image().map_err(de)?;
    // Re-verify before overwriting the file on disk.
    let mut r = DcpReader::open(Cursor::new(image.clone())).map_err(de)?;
    r.verify().map_err(de)?;
    std::fs::write(path, &image).map_err(|e| format!("write {path}: {e}"))?;
    Ok(())
}

fn de<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

fn hex(uid: &[u8; UID_SIZE]) -> String {
    uid.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse a uid: either 32 hex digits, or `0xNN` meaning 16 identical bytes.
fn parse_uid(s: &str) -> Result<[u8; UID_SIZE], String> {
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if rest.len() == 2 {
            let b = u8::from_str_radix(rest, 16).map_err(|_| format!("bad uid byte '{s}'"))?;
            return Ok([b; UID_SIZE]);
        }
    }
    let clean: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    if clean.len() != 32 {
        return Err(format!("uid '{s}' must be 32 hex digits or 0xNN"));
    }
    let mut uid = [0u8; UID_SIZE];
    for (i, byte) in uid.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!("bad hex in uid '{s}'"))?;
    }
    Ok(uid)
}

/// Parsed options common to the subcommands.
struct Opts {
    positional: Vec<String>,
    fixed: Option<usize>,
    trailer: bool,
}

impl Opts {
    fn parse(args: &[String], need: usize) -> Result<Opts, String> {
        let mut positional = Vec::new();
        let mut fixed = None;
        let mut trailer = false;
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--trailer" => trailer = true,
                "--fixed" => {
                    i += 1;
                    let n = args.get(i).ok_or("--fixed needs a value")?;
                    fixed = Some(n.parse().map_err(|_| format!("bad --fixed value '{n}'"))?);
                }
                other => positional.push(other.to_string()),
            }
            i += 1;
        }
        if positional.len() < need {
            return Err(format!(
                "expected {need} positional argument(s), got {}",
                positional.len()
            ));
        }
        Ok(Opts {
            positional,
            fixed,
            trailer,
        })
    }
}
