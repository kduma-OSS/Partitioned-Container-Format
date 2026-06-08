//! Command-line parsing for `pcf-compact`.
//!
//! Hand-written on top of [`std::env::args`] to keep the tool free of any
//! argument-parsing dependency (matching the reference crate's minimal-deps
//! posture). Grammar:
//!
//! ```text
//! pcf-compact <FILE> [FLAGS]
//! ```

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Args {
    pub file: PathBuf,
    pub output: Option<PathBuf>,
    pub verify: bool,
    pub quiet: bool,
    pub force: bool,
    pub allow_pfs: bool,
}

#[derive(Debug)]
pub enum Parsed {
    Run(Args),
    Help,
}

const HELP: &str = "\
pcf-compact — rebuild a Partitioned Container Format (PCF) file with all dead
space and per-partition reservations removed (spec section 11.5).

USAGE:
    pcf-compact <FILE> [FLAGS]

FLAGS:
    -o, --output <PATH>   write the compacted file to PATH instead of
                          overwriting <FILE> in place
        --no-verify       skip integrity verification before and after
                          compaction (default: verify both)
        --force           overwrite an existing --output path
        --allow-pfs       compact a PFS-MS file anyway (produces a plain PCF;
                          DISCARDS the multi-session filesystem structure)
    -q, --quiet           suppress the savings report on stderr
    -h, --help            show this help

By default the tool overwrites <FILE> atomically: it writes the compacted
image to a sibling temp file, fsyncs it, and then renames it into place.
";

pub fn help() -> &'static str {
    HELP
}

/// Parse arguments (excluding `argv[0]`).
pub fn parse(argv: &[String]) -> Result<Parsed, String> {
    let mut positionals: Vec<String> = Vec::new();
    let mut output: Option<PathBuf> = None;
    let mut verify = true;
    let mut quiet = false;
    let mut force = false;
    let mut allow_pfs = false;

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
            "-o" | "--output" => output = Some(PathBuf::from(value(argv, &mut i, &a)?)),
            "--no-verify" => verify = false,
            "--force" => force = true,
            "--allow-pfs" => allow_pfs = true,
            "-q" | "--quiet" => quiet = true,
            other if other.starts_with('-') => {
                return Err(format!("unknown flag: {other}"));
            }
            _ => positionals.push(a),
        }
        i += 1;
    }

    if positionals.is_empty() {
        return Err("missing FILE argument".into());
    }
    if positionals.len() > 1 {
        return Err(format!(
            "unexpected positional argument: {:?}",
            positionals[1]
        ));
    }
    let file = PathBuf::from(&positionals[0]);

    Ok(Parsed::Run(Args {
        file,
        output,
        verify,
        quiet,
        force,
        allow_pfs,
    }))
}
