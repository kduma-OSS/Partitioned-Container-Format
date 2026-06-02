//! Command-line parsing for `pcf-debug`.
//!
//! Hand-written on top of [`std::env::args`] to keep the tool free of any
//! argument-parsing dependency (matching the reference crate's minimal-deps
//! posture). The grammar is:
//!
//! ```text
//! pcf-debug <FILE> [subcommand] [flags]
//! ```

use std::path::PathBuf;

/// Whether to colour the output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorChoice {
    Auto,
    Never,
}

/// A byte range for `hexdump --range start[:len]`.
#[derive(Debug, Clone, Copy)]
pub struct ByteRange {
    pub start: u64,
    pub len: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct HexOpts {
    pub region: Option<String>,
    pub range: Option<ByteRange>,
    pub max_bytes: usize,
}

#[derive(Debug, Clone, Default)]
pub struct DecodeOpts {
    pub uid: Option<String>,
    pub label: Option<String>,
    pub decoder: Option<String>,
}

#[derive(Debug, Clone)]
pub enum Command {
    Inspect,
    Layout,
    Table,
    Chain,
    Hexdump(HexOpts),
    Decode(DecodeOpts),
}

#[derive(Debug, Clone)]
pub struct Args {
    pub file: PathBuf,
    pub command: Command,
    pub html: Option<PathBuf>,
    pub color: ColorChoice,
    pub verify: bool,
}

const HELP: &str = "\
pcf-debug — inspect and visualise Partitioned Container Format (PCF) files

USAGE:
    pcf-debug <FILE> [SUBCOMMAND] [FLAGS]

SUBCOMMANDS:
    inspect   (default) byte map + layout + partition table + chain + diagnostics
    layout    physical region map only
    table     partition table only
    chain     table-block chain tree only
    hexdump   hexdump regions or an explicit byte range
    decode    run partition decoders and print field trees

GLOBAL FLAGS:
    --html <FILE>     also write a self-contained HTML report
    --no-color        disable ANSI colour (auto-off when stdout is not a TTY)
    --verify          compute and check hashes (default for inspect)
    --no-verify       skip hashing
    -h, --help        show this help

HEXDUMP FLAGS:
    --region <NAME>   limit to regions matching a kind/label/uid substring
    --range <S[:L]>   hexdump bytes [S, S+L) (decimal or 0x-hex); L defaults to EOF
    --max-bytes <N>   cap bytes shown per region (default 512)

DECODE FLAGS:
    --uid <HEX>       decode only the partition with this UID (hex prefix)
    --label <S>       decode only partitions whose label contains S
    --decoder <NAME>  force a specific decoder (e.g. pfs-node, pfs-session, raw)
";

/// Parse a number that may be decimal or `0x`-prefixed hex.
fn parse_u64(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let r = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        s.parse::<u64>()
    };
    r.map_err(|_| format!("invalid number: {s:?}"))
}

fn parse_range(s: &str) -> Result<ByteRange, String> {
    match s.split_once(':') {
        Some((a, b)) => Ok(ByteRange {
            start: parse_u64(a)?,
            len: Some(parse_u64(b)?),
        }),
        None => Ok(ByteRange {
            start: parse_u64(s)?,
            len: None,
        }),
    }
}

/// Outcome of parsing: either runnable args, or a message to print and exit.
pub enum Parsed {
    Run(Args),
    Help,
}

/// Parse arguments (excluding `argv[0]`).
pub fn parse(argv: &[String]) -> Result<Parsed, String> {
    let mut positionals: Vec<String> = Vec::new();
    let mut html: Option<PathBuf> = None;
    let mut color = ColorChoice::Auto;
    let mut verify = true;
    let mut hex = HexOpts {
        max_bytes: 512,
        ..Default::default()
    };
    let mut dec = DecodeOpts::default();

    // Take the value following a flag, advancing the cursor.
    fn value(argv: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
        *i += 1;
        argv.get(*i)
            .cloned()
            .ok_or_else(|| format!("flag {flag} needs a value"))
    }

    let mut i = 0;
    while i < argv.len() {
        let a = argv[i].clone();
        match a.as_str() {
            "-h" | "--help" => return Ok(Parsed::Help),
            "--no-color" => color = ColorChoice::Never,
            "--verify" => verify = true,
            "--no-verify" => verify = false,
            "--html" => html = Some(PathBuf::from(value(argv, &mut i, &a)?)),
            "--region" => hex.region = Some(value(argv, &mut i, &a)?),
            "--range" => hex.range = Some(parse_range(&value(argv, &mut i, &a)?)?),
            "--max-bytes" => hex.max_bytes = parse_u64(&value(argv, &mut i, &a)?)? as usize,
            "--uid" => dec.uid = Some(value(argv, &mut i, &a)?),
            "--label" => dec.label = Some(value(argv, &mut i, &a)?),
            "--decoder" => dec.decoder = Some(value(argv, &mut i, &a)?),
            other if other.starts_with('-') => {
                return Err(format!("unknown flag: {other}"));
            }
            _ => positionals.push(a.clone()),
        }
        i += 1;
    }

    if positionals.is_empty() {
        return Err("missing FILE argument".into());
    }
    let file = PathBuf::from(&positionals[0]);
    let command = match positionals.get(1).map(|s| s.as_str()) {
        None | Some("inspect") => Command::Inspect,
        Some("layout") => Command::Layout,
        Some("table") => Command::Table,
        Some("chain") => Command::Chain,
        Some("hexdump") => Command::Hexdump(hex),
        Some("decode") => Command::Decode(dec),
        Some(other) => return Err(format!("unknown subcommand: {other}")),
    };

    Ok(Parsed::Run(Args {
        file,
        command,
        html,
        color,
        verify,
    }))
}

/// The full help text.
pub fn help() -> &'static str {
    HELP
}
