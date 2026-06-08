//! `pcf-sig` — sign and verify PCF files with PCF-SIG (Ed25519) signatures.
//!
//! ```text
//! pcf-sig keygen <priv_out> <pub_out>
//! pcf-sig sign   <file.pcf> --key <priv> [--uid <hex16>]... [--resign] [--sig-label <s>] [--key-label <s>]
//! pcf-sig verify <file.pcf> [--key <trusted_pub>] [--no-recheck]
//! pcf-sig keys   <file.pcf>
//! ```
//!
//! A PFS-MS archive is a PCF file, so `verify` and `keys` work on it directly;
//! `sign`, however, refuses PFS-MS files (use `pfs sign`, which commits a
//! signature session). Signatures cover partition content (uid, type, label,
//! used_bytes, data_hash) but not byte offsets, so `pcf-compact` preserves them.

use std::path::Path;
use std::process::ExitCode;

use pcf_sig_cli::{
    all_valid, format_keys, format_sign, format_verify, keygen, list_keys, parse_hex_uid,
    sign_file, verify_file, CliResult,
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("");
    let rest = if args.is_empty() {
        &args[0..0]
    } else {
        &args[1..]
    };
    let result = match cmd {
        "keygen" => cmd_keygen(rest),
        "sign" => return finish(cmd_sign(rest)),
        "verify" => return cmd_verify(rest),
        "keys" => cmd_keys(rest),
        "" | "help" | "-h" | "--help" => {
            print_usage();
            return ExitCode::SUCCESS;
        }
        other => Err(pcf_sig_cli::CliError::Msg(format!(
            "unknown command '{other}' (try `pcf-sig help`)"
        ))),
    };
    finish(result)
}

fn finish(r: CliResult<()>) -> ExitCode {
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pcf-sig: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    eprintln!(
        "usage:\n  pcf-sig keygen <priv_out> <pub_out>\n  pcf-sig sign   <file.pcf> --key <priv> [--uid <hex16>]... [--resign] [--sig-label <s>] [--key-label <s>]\n  pcf-sig verify <file.pcf> [--key <trusted_pub>] [--no-recheck]\n  pcf-sig keys   <file.pcf>"
    );
}

/// Minimal argument model: positionals, boolean flags, single-value flags, and
/// the repeatable `--uid` flag.
struct Args {
    positional: Vec<String>,
    bools: std::collections::HashSet<String>,
    values: std::collections::HashMap<String, String>,
    uids: Vec<String>,
}

fn parse(args: &[String], value_flags: &[&str], bool_flags: &[&str]) -> CliResult<Args> {
    let mut out = Args {
        positional: Vec::new(),
        bools: std::collections::HashSet::new(),
        values: std::collections::HashMap::new(),
        uids: Vec::new(),
    };
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(name) = a.strip_prefix("--") {
            if name == "uid" {
                let v = next_value(args, i, name)?;
                out.uids.push(v);
                i += 2;
            } else if value_flags.contains(&name) {
                let v = next_value(args, i, name)?;
                out.values.insert(name.to_string(), v);
                i += 2;
            } else if bool_flags.contains(&name) {
                out.bools.insert(name.to_string());
                i += 1;
            } else {
                return Err(pcf_sig_cli::CliError::Msg(format!("unknown flag --{name}")));
            }
        } else {
            out.positional.push(a.clone());
            i += 1;
        }
    }
    Ok(out)
}

fn next_value(args: &[String], i: usize, name: &str) -> CliResult<String> {
    args.get(i + 1)
        .cloned()
        .ok_or_else(|| pcf_sig_cli::CliError::Msg(format!("flag --{name} needs a value")))
}

fn positional<'a>(a: &'a Args, i: usize, what: &str) -> CliResult<&'a str> {
    a.positional
        .get(i)
        .map(|s| s.as_str())
        .ok_or_else(|| pcf_sig_cli::CliError::Msg(format!("missing argument: {what}")))
}

fn cmd_keygen(args: &[String]) -> CliResult<()> {
    let a = parse(args, &[], &[])?;
    let priv_out = positional(&a, 0, "<priv_out>")?;
    let pub_out = positional(&a, 1, "<pub_out>")?;
    let s = keygen(priv_out, pub_out)?;
    println!(
        "wrote private key {priv_out} and public key {pub_out}\nfingerprint {}",
        pcf_sig_cli::hex(&s.fingerprint)
    );
    Ok(())
}

fn cmd_sign(args: &[String]) -> CliResult<()> {
    let a = parse(args, &["key", "sig-label", "key-label"], &["resign"])?;
    let file = positional(&a, 0, "<file.pcf>")?;
    let key = a
        .values
        .get("key")
        .ok_or_else(|| pcf_sig_cli::CliError::Msg("missing required flag --key".into()))?;
    let select = if a.uids.is_empty() {
        None
    } else {
        let mut uids = Vec::with_capacity(a.uids.len());
        for u in &a.uids {
            uids.push(parse_hex_uid(u)?);
        }
        Some(uids)
    };
    let sig_label = a
        .values
        .get("sig-label")
        .map(|s| s.as_str())
        .unwrap_or("pcfsig");
    let key_label = a
        .values
        .get("key-label")
        .map(|s| s.as_str())
        .unwrap_or("pcfkey");
    let summary = sign_file(
        file,
        key,
        select,
        a.bools.contains("resign"),
        sig_label,
        key_label,
    )?;
    println!("{}", format_sign(&summary));
    Ok(())
}

fn cmd_verify(args: &[String]) -> ExitCode {
    let result = (|| -> CliResult<bool> {
        let a = parse(args, &["key"], &["no-recheck"])?;
        let file = positional(&a, 0, "<file.pcf>")?;
        let trusted = a.values.get("key").map(Path::new);
        let recheck = !a.bools.contains("no-recheck");
        let summary = verify_file(file, trusted, recheck)?;
        print!("{}", format_verify(&summary));
        // Success only if every signature is fully valid and, when a trusted
        // key was supplied, it matched.
        Ok(all_valid(&summary) && (summary.trusted_fingerprint.is_none() || summary.trusted_match))
    })();
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("pcf-sig: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_keys(args: &[String]) -> CliResult<()> {
    let a = parse(args, &[], &[])?;
    let file = positional(&a, 0, "<file.pcf>")?;
    let keys = list_keys(file)?;
    print!("{}", format_keys(&keys));
    Ok(())
}
