//! `pfs` — a small demo CLI for the PFS-MS reference implementation.
//!
//! Each mutating subcommand opens the file, commits exactly one session, and
//! flushes; read subcommands reconstruct the filesystem at the head.
//!
//! ```text
//! pfs mkfs   <file>
//! pfs mkdir  <file> <path>
//! pfs put    <file> <path> [<src|->] [--store]   # default reads stdin
//! pfs mv     <file> <src> <dst>
//! pfs rm     <file> <path>
//! pfs ls     <file> [<path>]
//! pfs cat    <file> <path>
//! pfs get    <file> <path> <out>
//! pfs log    <file>
//! pfs verify <file>
//! ```

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::process::ExitCode;

use pcf::HashAlgo;
use pfs_ms::{FsReader, FsWriter, Tree, ROOT_NODE_ID};

type CliResult = Result<(), String>;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("pfs: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> CliResult {
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("");
    let rest = if args.is_empty() {
        &args[0..0]
    } else {
        &args[1..]
    };
    match cmd {
        "mkfs" => cmd_mkfs(rest),
        "mkdir" => cmd_mkdir(rest),
        "put" => cmd_put(rest),
        "mv" => cmd_mv(rest),
        "rm" => cmd_rm(rest),
        "ls" => cmd_ls(rest),
        "cat" => cmd_cat(rest),
        "get" => cmd_get(rest),
        "log" => cmd_log(rest),
        "verify" => cmd_verify(rest),
        "" | "help" | "-h" | "--help" => {
            print_usage();
            Ok(())
        }
        other => Err(format!("unknown command '{other}' (try `pfs help`)")),
    }
}

fn print_usage() {
    eprintln!(
        "usage:\n  pfs mkfs   <file>\n  pfs mkdir  <file> <path>\n  pfs put    <file> <path> [<src|->] [--store]\n  pfs mv     <file> <src> <dst>\n  pfs rm     <file> <path>\n  pfs ls     <file> [<path>]\n  pfs cat    <file> <path>\n  pfs get    <file> <path> <out>\n  pfs log    <file>\n  pfs verify <file>"
    );
}

fn arg<'a>(args: &'a [String], i: usize, what: &str) -> Result<&'a str, String> {
    args.get(i)
        .map(|s| s.as_str())
        .ok_or_else(|| format!("missing argument: {what}"))
}

fn open_rw(path: &str) -> Result<File, String> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| format!("cannot open '{path}': {e}"))
}

fn open_writer(path: &str) -> Result<FsWriter<File>, String> {
    FsWriter::open(open_rw(path)?).map_err(|e| e.to_string())
}

fn open_reader(path: &str) -> Result<FsReader<File>, String> {
    FsReader::open(open_rw(path)?).map_err(|e| e.to_string())
}

fn cmd_mkfs(a: &[String]) -> CliResult {
    let file = arg(a, 0, "<file>")?;
    let f = File::create(file).map_err(|e| format!("cannot create '{file}': {e}"))?;
    FsWriter::mkfs(f, HashAlgo::Sha256).map_err(|e| e.to_string())?;
    Ok(())
}

fn cmd_mkdir(a: &[String]) -> CliResult {
    let file = arg(a, 0, "<file>")?;
    let path = arg(a, 1, "<path>")?;
    open_writer(file)?.mkdir(path).map_err(|e| e.to_string())
}

fn cmd_put(a: &[String]) -> CliResult {
    // `--store` (anywhere after the file) disables compression for this write.
    let store = a.iter().any(|s| s == "--store");
    let positional: Vec<&str> = a
        .iter()
        .map(|s| s.as_str())
        .filter(|s| *s != "--store")
        .collect();
    let file = positional
        .first()
        .copied()
        .ok_or("missing argument: <file>")?;
    let path = positional
        .get(1)
        .copied()
        .ok_or("missing argument: <path>")?;
    let src = positional.get(2).copied().unwrap_or("-");
    let data = if src == "-" {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| e.to_string())?;
        buf
    } else {
        std::fs::read(src).map_err(|e| format!("cannot read '{src}': {e}"))?
    };
    let mut w = open_writer(file)?;
    w.set_compression(!store);
    w.put_file(path, &data).map_err(|e| e.to_string())
}

fn cmd_mv(a: &[String]) -> CliResult {
    let file = arg(a, 0, "<file>")?;
    let src = arg(a, 1, "<src>")?;
    let dst = arg(a, 2, "<dst>")?;
    open_writer(file)?.mv(src, dst).map_err(|e| e.to_string())
}

fn cmd_rm(a: &[String]) -> CliResult {
    let file = arg(a, 0, "<file>")?;
    let path = arg(a, 1, "<path>")?;
    open_writer(file)?.rm(path).map_err(|e| e.to_string())
}

fn cmd_ls(a: &[String]) -> CliResult {
    let file = arg(a, 0, "<file>")?;
    let base = a.get(1).map(|s| s.as_str()).unwrap_or("");
    let mut r = open_reader(file)?;
    let tree = r.tree().map_err(|e| e.to_string())?;
    let start = pfs_ms::resolve_path(&tree, base).map_err(|e| e.to_string())?;
    print_tree(&tree, start, 0);
    Ok(())
}

fn print_tree(tree: &Tree, id: [u8; 16], depth: usize) {
    if let Some(rec) = tree.nodes.get(&id) {
        if id == ROOT_NODE_ID {
            println!("/");
        } else {
            let suffix = if rec.is_dir() { "/" } else { "" };
            println!("{}{}{}", "  ".repeat(depth), rec.name_str(), suffix);
        }
    }
    if let Some(kids) = tree.children.get(&id) {
        for &k in kids {
            print_tree(tree, k, depth + 1);
        }
    }
}

fn cmd_cat(a: &[String]) -> CliResult {
    let file = arg(a, 0, "<file>")?;
    let path = arg(a, 1, "<path>")?;
    let data = open_reader(file)?
        .read_path(path)
        .map_err(|e| e.to_string())?;
    std::io::stdout()
        .write_all(&data)
        .map_err(|e| e.to_string())
}

fn cmd_get(a: &[String]) -> CliResult {
    let file = arg(a, 0, "<file>")?;
    let path = arg(a, 1, "<path>")?;
    let out = arg(a, 2, "<out>")?;
    let data = open_reader(file)?
        .read_path(path)
        .map_err(|e| e.to_string())?;
    std::fs::write(out, &data).map_err(|e| format!("cannot write '{out}': {e}"))
}

fn cmd_log(a: &[String]) -> CliResult {
    let file = arg(a, 0, "<file>")?;
    let sessions = open_reader(file)?
        .list_sessions()
        .map_err(|e| e.to_string())?;
    for s in &sessions {
        let writer = String::from_utf8_lossy(&s.writer);
        println!(
            "seq {:<4} blocks {:<3} changes {:<4} ts {:<14} writer {}",
            s.session_seq, s.block_count, s.change_count, s.timestamp_unix_ms, writer
        );
    }
    Ok(())
}

fn cmd_verify(a: &[String]) -> CliResult {
    let file = arg(a, 0, "<file>")?;
    open_reader(file)?.verify().map_err(|e| e.to_string())?;
    println!("ok");
    Ok(())
}
