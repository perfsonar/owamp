//! `owstats` mode — port of the `owstats` branch in `owping.c` `main()`.
//!
//! Same binary as owping (argv[0] / progname); prints stats for session files.

use std::fs::File;
use std::process::ExitCode;

use clap::Parser;
use tracing::error;

use crate::owpingP::{usage_for_mode, Args, ProgMode};
use crate::parse::validate_units;
use crate::stats_io::do_stats;

/// Entry for `owstats` progname.
pub fn run() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    let mode = ProgMode::Owstats;
    let mut args = match Args::try_parse_from(std::env::args_os()) {
        Ok(a) => a,
        Err(e) => {
            if e.kind() == clap::error::ErrorKind::DisplayHelp {
                usage_for_mode(mode, None);
                return ExitCode::SUCCESS;
            }
            usage_for_mode(mode, Some("Invalid arguments."));
            return ExitCode::from(1);
        },
    };

    if args.help {
        usage_for_mode(mode, None);
        return ExitCode::SUCCESS;
    }

    if let Err(e) = normalize_output_opts(&mut args) {
        error!("{e}");
        usage_for_mode(mode, Some(&e));
        return ExitCode::from(1);
    }

    let files = args.positionals.clone();
    if files.is_empty() {
        usage_for_mode(mode, None);
        return ExitCode::from(1);
    }

    for path in &files {
        let mut fp = match File::open(path) {
            Ok(f) => f,
            Err(e) => {
                error!("fopen({path}): {e}");
                return ExitCode::from(1);
            },
        };
        if do_stats(&mut fp, None, None, None, &args, false).is_err() {
            error!("do_stats() failed.");
            return ExitCode::from(1);
        }
    }
    ExitCode::SUCCESS
}

fn normalize_output_opts(args: &mut Args) -> Result<(), String> {
    if args.bucket_width <= 0.0 {
        return Err("Invalid '-b' value. Positive float expected".into());
    }
    validate_units(args.units)?;
    if let Some(ref a) = args.percentiles {
        let _ = crate::parse::parse_percentiles(a)?;
    }
    if args.raw {
        args.quiet = true;
    }
    if args.records.is_some() && args.quiet {
        tracing::warn!("Ignoring '-v', '-Q' set");
        args.records = None;
    }
    if args.machine && args.quiet {
        tracing::warn!("Ignoring '-M', '-Q' set");
        args.machine = false;
    }
    if args.records.is_some() && args.machine {
        tracing::warn!("Ignoring '-v', '-M' set");
        args.records = None;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_raw_implies_quiet() {
        let mut a = Args::parse_from(["owstats", "-R", "file.owp"]);
        normalize_output_opts(&mut a).unwrap();
        assert!(a.quiet);
    }
}
