//! Binary entry point for `pcf-compact`.

use std::path::PathBuf;
use std::process::ExitCode;

use pcf_compact::cli::{self, Args, Parsed};
use pcf_compact::{atomic_write, compact_bytes, format_size, CompactError};

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match cli::parse(&argv) {
        Ok(Parsed::Help) => {
            print!("{}", cli::help());
            ExitCode::SUCCESS
        }
        Ok(Parsed::Run(args)) => match run(args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("pcf-compact: {e}");
                ExitCode::FAILURE
            }
        },
        Err(e) => {
            eprintln!("pcf-compact: {e}\n\n{}", cli::help());
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Result<(), CompactError> {
    let input_bytes = std::fs::read(&args.file).map_err(|e| CompactError::Read {
        path: args.file.clone(),
        source: e,
    })?;
    let input_len = input_bytes.len() as u64;

    let compacted = compact_bytes(&input_bytes, args.verify, args.verify)?;

    let target: PathBuf = match &args.output {
        Some(out) => {
            // Reject "--output" that points at the same underlying file as
            // the input (after symlink resolution) — almost certainly a typo.
            if let (Ok(a), Ok(b)) = (
                std::fs::canonicalize(&args.file),
                std::fs::canonicalize(out),
            ) {
                if a == b {
                    return Err(CompactError::SameInputOutput(out.clone()));
                }
            }
            if out.exists() && !args.force {
                return Err(CompactError::OutputExists(out.clone()));
            }
            out.clone()
        }
        None => args.file.clone(),
    };

    atomic_write(&target, &compacted)?;

    if !args.quiet {
        let new_len = compacted.len() as u64;
        let saved = input_len.saturating_sub(new_len);
        let pct = saved
            .checked_mul(100)
            .and_then(|n| n.checked_div(input_len))
            .unwrap_or(0);
        eprintln!(
            "Compacted {}: {} -> {} (saved {}, {}%)",
            args.file.display(),
            format_size(input_len),
            format_size(new_len),
            format_size(saved),
            pct,
        );
    }

    Ok(())
}
