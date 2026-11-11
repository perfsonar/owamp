//! `owfetch` mode — port of the `owfetch` branch in `owping.c` `main()`.
//!
//! Usage: `owfetch [conn/out args] servaddr [SID savefile]+`

use std::process::ExitCode;

use clap::Parser;
use tracing::error;

use owamp::capi::control_open_interface;
use owamp::context::{Addr, Context, Control, ErrSeverity};
use owamp::owampP::{OWP_IPV4_ONLY, OWP_IPV6_ONLY};

use crate::auth::set_auth;
use crate::hex::sid_hex_decode;
use crate::owpingP::{usage_for_mode, Args, ProgMode};
use crate::parse::validate_units;
use crate::stats_io::{do_stats, owp_fetch_sid};

/// Entry for `owfetch` progname.
pub fn run() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    let mode = ProgMode::Owfetch;
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

    if let Err(e) = normalize(&mut args) {
        error!("{e}");
        usage_for_mode(mode, Some(&e));
        return ExitCode::from(1);
    }

    // positionals: servaddr SID savefile [SID savefile]...
    let pos = &args.positionals;
    if pos.len() < 3 || pos.len() % 2 == 0 {
        usage_for_mode(mode, None);
        return ExitCode::from(1);
    }

    let remote_serv = &pos[0];
    let pairs = &pos[1..];

    match run_fetch(&args, remote_serv, pairs) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => ExitCode::from(code),
    }
}

fn normalize(args: &mut Args) -> Result<(), String> {
    if args.v4only && args.v6only {
        return Err("-4 and -6 flags cannot be set together".into());
    }
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

fn run_fetch(args: &Args, remote_serv: &str, pairs: &[String]) -> Result<(), u8> {
    let ctx = Context::create().ok_or_else(|| {
        error!("Unable to initialize OWP library.");
        1u8
    })?;

    if args.v4only {
        let _ = ctx.config_set_v(OWP_IPV4_ONLY, 1);
    }
    if args.v6only {
        let _ = ctx.config_set_v(OWP_IPV6_ONLY, 1);
    }

    let (auth_mode, identity) = set_auth(&ctx, args, false).map_err(|e| {
        error!("{e}");
        1u8
    })?;

    let server = Addr::by_node(remote_serv, None);
    let mut err_ret = ErrSeverity::Ok;
    let Some(cntrl_rc) = control_open_interface(
        &ctx,
        args.srcaddr.as_deref(),
        args.interface.as_deref(),
        server,
        auth_mode,
        identity.as_deref(),
        None,
        &mut err_ret,
    ) else {
        error!("Unable to open control connection to {remote_serv}.");
        return Err(1);
    };

    let result = {
        let mut cntrl = cntrl_rc.borrow_mut();
        fetch_pairs(&mut cntrl, args, pairs)
    };

    let _ = Control::close_rc(cntrl_rc);
    ctx.free();
    result
}

fn fetch_pairs(cntrl: &mut Control, args: &Args, pairs: &[String]) -> Result<(), u8> {
    let mut i = 0;
    while i + 1 < pairs.len() {
        let sname = &pairs[i];
        let fname = &pairs[i + 1];
        i += 2;

        let sid = sid_hex_decode(sname).map_err(|e| {
            error!("{e}");
            1u8
        })?;

        match owp_fetch_sid(Some(std::path::Path::new(fname)), cntrl, &sid) {
            None => error!("Unable to fetch sid({sname})"),
            Some(mut fp) => {
                if (!args.quiet || args.raw)
                    && do_stats(&mut fp, None, None, None, args, false).is_err()
                {
                    error!("do_stats() failed.");
                }
            },
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn argc_rule_odd_and_at_least_three() {
        // C: (argc%2 == 0) || (argc < 3) → usage; valid: servaddr + N*(SID,file)
        fn valid(argc: usize) -> bool {
            argc >= 3 && argc % 2 == 1
        }
        assert!(!valid(0));
        assert!(!valid(1));
        assert!(!valid(2));
        assert!(valid(3));
        assert!(!valid(4));
        assert!(valid(5));
    }
}
