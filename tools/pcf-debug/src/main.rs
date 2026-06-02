//! Binary entry point: parse arguments, build the report, and render it.

use std::io::IsTerminal;
use std::process::ExitCode;

use pcf_debug::cli::{self, ColorChoice, Command, DecodeOpts, HexOpts, Parsed};
use pcf_debug::plugin::{DecoderRegistry, PartitionMeta};
use pcf_debug::render::color::Palette;
use pcf_debug::render::{hexdump, html, text, Report};
use pcf_debug::{build_report, model};

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
                eprintln!("pcf-debug: {e}");
                ExitCode::FAILURE
            }
        },
        Err(e) => {
            eprintln!("pcf-debug: {e}\n\n{}", cli::help());
            ExitCode::FAILURE
        }
    }
}

fn color_enabled(choice: ColorChoice) -> bool {
    match choice {
        ColorChoice::Never => false,
        ColorChoice::Auto => {
            std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
        }
    }
}

fn run(args: cli::Args) -> Result<(), String> {
    let data = std::fs::read(&args.file)
        .map_err(|e| format!("cannot read {}: {e}", args.file.display()))?;
    let registry = DecoderRegistry::with_builtins();
    let report = build_report(&data, args.verify, &registry);
    let pal = Palette::new(color_enabled(args.color));

    // Optional HTML report is written regardless of the chosen text view.
    if let Some(path) = &args.html {
        let title = args
            .file
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "pcf".into());
        std::fs::write(path, html::render(&report, &title))
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        eprintln!("pcf-debug: wrote HTML report to {}", path.display());
    }

    let out = match &args.command {
        Command::Inspect => text::inspect(&report, pal),
        Command::Layout => text::layout(&report.layout, pal),
        Command::Table => text::table(&report.layout, pal),
        Command::Chain => text::chain(&report.layout, pal),
        Command::Hexdump(opts) => render_hexdump(&data, &report, opts, pal),
        Command::Decode(opts) => {
            let filtered = filter_decode(&data, &report, &registry, opts);
            text::decode(&filtered, pal)
        }
    };
    print!("{out}");
    if !out.ends_with('\n') {
        println!();
    }
    Ok(())
}

/// Hexdump regions (optionally filtered) or an explicit byte range.
fn render_hexdump(data: &[u8], report: &Report, opts: &HexOpts, pal: Palette) -> String {
    if let Some(range) = opts.range {
        let start = range.start.min(data.len() as u64) as usize;
        let end = match range.len {
            Some(l) => (range.start + l).min(data.len() as u64) as usize,
            None => data.len(),
        };
        return format!(
            "{}\n{}\n",
            pal.bold(&format!("hexdump {:#x}..{:#x}", start, end)),
            hexdump::dump(&data[start..end], start as u64, opts.max_bytes, pal)
        );
    }

    let mut out = String::new();
    for r in &report.layout.regions {
        if let Some(filter) = &opts.region {
            let uid_hit = match &r.kind {
                model::RegionKind::PartitionData { uid, .. } | model::RegionKind::Slack { uid } => {
                    pcf_debug::render::uid_hex(uid).starts_with(filter)
                }
                _ => false,
            };
            if r.kind.short() != filter && !r.label.contains(filter.as_str()) && !uid_hit {
                continue;
            }
        }
        let start = r.start as usize;
        let end = r.end().min(data.len() as u64) as usize;
        out.push_str(&pal.bold(&format!(
            "{:#x}..{:#x}  {}  {}\n",
            r.start,
            r.end(),
            r.kind.short(),
            r.label
        )));
        if start < end {
            out.push_str(&hexdump::dump(
                &data[start..end],
                r.start,
                opts.max_bytes,
                pal,
            ));
        }
        out.push_str("\n\n");
    }
    out
}

/// Build a report whose decoded list is filtered (and optionally re-decoded with
/// a forced decoder) per the `decode` subcommand options.
fn filter_decode(
    data: &[u8],
    report: &Report,
    registry: &DecoderRegistry,
    opts: &DecodeOpts,
) -> Report {
    let mut decoded = Vec::new();
    for b in &report.layout.blocks {
        for ev in &b.entries {
            let e = &ev.entry;
            let label = e.label_string().unwrap_or_default();
            if let Some(uf) = &opts.uid {
                if !pcf_debug::render::uid_hex(&e.uid).starts_with(uf) {
                    continue;
                }
            }
            if let Some(lf) = &opts.label {
                if !label.contains(lf.as_str()) {
                    continue;
                }
            }
            let bytes = if ev.data_in_bounds && e.used_bytes > 0 {
                data[e.start_offset as usize..(e.start_offset + e.used_bytes) as usize].to_vec()
            } else {
                Vec::new()
            };
            let meta = PartitionMeta {
                partition_type: e.partition_type,
                uid: &e.uid,
                label: &label,
            };
            let dec = match &opts.decoder {
                Some(name) => registry
                    .decode_with(name, &meta, &bytes)
                    .unwrap_or_else(|| registry.decode(&meta, &bytes)),
                None => registry.decode(&meta, &bytes),
            };
            decoded.push((e.uid, dec));
        }
    }
    Report {
        layout: report.layout.clone(),
        decoded,
    }
}
