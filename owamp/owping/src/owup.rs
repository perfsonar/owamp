//! `owup` mode — port of the `owup` branch in `owping.c` `main()`.
//!
//! Prints server “up since” timestamp from the `ServerStart` control handshake.

use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use tracing::error;

use owamp::capi::control_open_interface;
use owamp::context::{Addr, Context, Control, ErrSeverity};
use owamp::owamp::{OwampNum64, OwampTimeStamp};
use owamp::owampP::{OWP_IPV4_ONLY, OWP_IPV6_ONLY};
use owamp::time::timestamp_to_timeval;

use crate::auth::set_auth;
use crate::owpingP::{usage_for_mode, Args, ProgMode};

/// Entry for `owup` progname.
pub fn run() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    let mode = ProgMode::Owup;
    let args = match Args::try_parse_from(std::env::args_os()) {
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

    if args.v4only && args.v6only {
        error!("-4 and -6 flags cannot be set together");
        return ExitCode::from(1);
    }

    if args.positionals.len() != 1 {
        usage_for_mode(mode, None);
        return ExitCode::from(1);
    }

    let remote_serv = &args.positionals[0];
    match run_up(&args, remote_serv) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => ExitCode::from(code),
    }
}

fn run_up(args: &Args, remote_serv: &str) -> Result<(), u8> {
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
    let mut uptime = OwampNum64(0);
    let Some(cntrl_rc) = control_open_interface(
        &ctx,
        args.srcaddr.as_deref(),
        args.interface.as_deref(),
        server,
        auth_mode,
        identity.as_deref(),
        Some(&mut uptime),
        &mut err_ret,
    ) else {
        error!("Unable to open control connection to {remote_serv}.");
        return Err(1);
    };

    let _ = Control::close_rc(cntrl_rc);
    ctx.free();

    let tstamp = OwampTimeStamp {
        owptime: uptime,
        sync: true,
        multiplier: 1,
        scale: 0,
    };
    print_up_since(&tstamp)?;
    Ok(())
}

fn print_up_since(tstamp: &OwampTimeStamp) -> Result<(), u8> {
    let Some(tv) = timestamp_to_timeval(tstamp) else {
        error!("Unable to convert timestamp to timeval.");
        return Err(1);
    };
    let secs = tv.tv_sec;
    let usecs = tv.tv_usec;
    if secs < 0 {
        error!("Unable to convert timestamp to timeval.");
        return Err(1);
    }
    let st = UNIX_EPOCH + Duration::new(secs as u64, (usecs.max(0) as u32) * 1_000);
    let datetime = format_local(st, usecs.max(0) as u32 / 1_000);
    eprint!("{datetime}");
    Ok(())
}

fn format_local(st: SystemTime, msec: u32) -> String {
    // Best-effort local formatting without chrono dependency.
    // C: strftime("Server Up Since: %Y-%m-%dT%H:%M:%S.%%03d%Z\n", ...)
    let Ok(dur) = st.duration_since(UNIX_EPOCH) else {
        return "Server Up Since: (invalid)\n".to_string();
    };
    let total = dur.as_secs() as i64;
    // Use libc localtime_r for timezone-correct wall clock.
    unsafe {
        let t = total as libc::time_t;
        let mut trec: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut trec).is_null() {
            return "Server Up Since: (localtime failed)\n".to_string();
        }
        let mut buf = [0i8; 128];
        let fmt = c"Server Up Since: %Y-%m-%dT%H:%M:%S.";
        let n = libc::strftime(buf.as_mut_ptr(), buf.len(), fmt.as_ptr(), &trec);
        if n == 0 {
            return "Server Up Since: (strftime failed)\n".to_string();
        }
        let prefix = std::ffi::CStr::from_ptr(buf.as_ptr())
            .to_string_lossy()
            .into_owned();
        // Append msec + timezone abbrev.
        let mut zbuf = [0i8; 16];
        let zn = libc::strftime(zbuf.as_mut_ptr(), zbuf.len(), c"%Z".as_ptr(), &trec);
        let zone = if zn > 0 {
            std::ffi::CStr::from_ptr(zbuf.as_ptr())
                .to_string_lossy()
                .into_owned()
        } else {
            String::new()
        };
        format!("{prefix}{msec:03}{zone}\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_up_since_nonempty() {
        let tstamp = OwampTimeStamp {
            owptime: OwampNum64(0x83aa_7e80_0000_0000), // roughly NTP epoch offset area
            sync: true,
            multiplier: 1,
            scale: 0,
        };
        let s = format_local(UNIX_EPOCH + Duration::from_secs(1_000_000_000), 123);
        assert!(s.contains("Server Up Since:"));
        assert!(s.contains("123"));
        let _ = tstamp;
    }
}
