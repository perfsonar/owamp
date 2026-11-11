//! Main client flow — port of `main()` in `owping.c` for owping/twping.

use std::process::ExitCode;

use clap::Parser;
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::path::Path;

use owamp::api::{self, parse_port_range, stop_sessions_wait};
use owamp::arithm64::{double_to_num64, num64_mult, num64_to_double, ulong_to_num64};
use owamp::capi::{
    control_open_interface, session_request, session_request_ex, start_sessions,
    twp_control_open_interface,
};
use owamp::context::{
    get_time_of_day, AcceptType, Addr, Context, Control, ErrSeverity, PortRange, Slot, SlotType,
    TestSpec, OWP_INTERRUPT_IO,
};
use owamp::owampP::{
    OWP_CHILD_WAIT, OWP_DETACH_PROCESSES, OWP_END_DELAY, OWP_IPV4_ONLY, OWP_IPV6_ONLY,
    OWP_NAME_SEP, OWP_PATH_SEPARATOR, OWP_TEST_PORT_RANGE, OWP_TSTAMPCHARS,
};
use tracing::{error, info, warn};

use crate::auth::set_auth;
use crate::owpingP::{
    usage, usage_for_mode, Args, ProgMode, OWPING_DEF_EXT, OWPING_INC_EXT, OWPING_SUM_EXT,
};
use crate::parse::{
    max_padding_size, parse_percentiles, parse_slots, parse_type_p, validate_units,
};
use crate::stats_io::{do_stats, open_from_fp, owp_fetch_sid, report_fetch_fail};

const PADDING_UNSET: u32 = u32::MAX;
const DEFAULT_PORT_LOW: u16 = 8_760;
const DEFAULT_PORT_HIGH: u16 = 9_960;
const DEFAULT_MEAN_WAIT: f64 = 0.1;
const PATH_MAX: usize = 1_024;

/// Dispatch by argv[0] like C (same binary: owping/twping/owstats/owfetch/owup).
#[must_use]
pub fn run_by_progname() -> ExitCode {
    let prog = std::env::args().next().unwrap_or_else(|| "owping".into());
    match ProgMode::from_progname(&prog) {
        ProgMode::Twping => run(true),
        ProgMode::Owstats => crate::owstats::run(),
        ProgMode::Owfetch => crate::owfetch::run(),
        ProgMode::Owup => crate::owup::run(),
        ProgMode::Owping => run(false),
    }
}

/// Entry used by `owping` (`twoway=false`) and `twping` (`twoway=true`).
pub fn run(twoway: bool) -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    let mode = if twoway {
        ProgMode::Twping
    } else {
        ProgMode::Owping
    };
    let prog = mode.name();

    let mut args = match Args::try_parse() {
        Ok(a) => a,
        Err(e) => {
            let rendered = e.to_string();
            if rendered.contains("help") || e.kind() == clap::error::ErrorKind::DisplayHelp {
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

    // C: argc is 1 or 2 after options (testaddr [servaddr]).
    if args.positionals.is_empty() || args.positionals.len() > 2 {
        usage_for_mode(mode, None);
        return ExitCode::from(1);
    }

    if let Err(e) = validate_and_normalize(&mut args, twoway) {
        error!("{e}");
        usage(prog, Some(&e), twoway);
        return ExitCode::from(1);
    }

    match run_ping(&args, twoway) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => ExitCode::from(code),
    }
}

fn validate_and_normalize(args: &mut Args, twoway: bool) -> Result<(), String> {
    if args.v4only && args.v6only {
        return Err("-4 and -6 flags cannot be set together".into());
    }
    if args.loss_threshold < 0.0 {
        return Err("Invalid '-L' value. Positive float expected".into());
    }
    if args.delay_start < 0.0 {
        return Err("Invalid '-z' value. Positive float expected".into());
    }
    if args.bucket_width <= 0.0 {
        return Err("Invalid '-b' value. Positive float expected".into());
    }
    if let Some(ed) = args.end_delay {
        if ed < 0.0 {
            return Err("Invalid '-E' value. Positive float expected".into());
        }
    }
    validate_units(args.units)?;
    if let Some(ref a) = args.percentiles {
        let _ = parse_percentiles(a)?;
    }
    if let Some(ref i) = args.interval {
        let _ = parse_slots(i)?;
    }
    if let Some(ref d) = args.dscp {
        let _ = parse_type_p(d)?;
    }

    // savedir path length check (C: fname_len + dir must fit PATH_MAX).
    let fname_len = (2 * OWP_TSTAMPCHARS)
        + OWP_NAME_SEP.len()
        + OWPING_DEF_EXT.len().max(OWPING_SUM_EXT.len())
        + OWPING_INC_EXT.len();
    if let Some(ref dir) = args.savedir {
        if dir.len() + OWP_PATH_SEPARATOR.len() + fname_len + 1 > PATH_MAX {
            return Err("-d: pathname too long.".into());
        }
    }

    // TMPDIR length check (C: tmpdir + sep + owamp.XXXXXX).
    let tmpdir = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
    if tmpdir.len() + OWP_PATH_SEPARATOR.len() + "owamp.XXXXXX".len() > PATH_MAX {
        return Err("TMPDIR too long".into());
    }

    if args.raw {
        args.quiet = true;
    }
    if args.records.is_some() && args.quiet {
        warn!("Ignoring '-v', '-Q' set");
        args.records = None;
    }
    if args.machine && args.quiet {
        warn!("Ignoring '-M', '-Q' set");
        args.machine = false;
    }
    if args.records.is_some() && args.machine {
        warn!("Ignoring '-v', '-M' set");
        args.records = None;
    }

    // TWAMP: -f/-t not used the same way; -F still saves reflected results.
    if twoway {
        if args.to || args.save_to_test.is_some() {
            // C twping has no -t/-T; ignore if somehow set.
            args.to = false;
            args.save_to_test = None;
        }
        args.from = true;
    }

    // C: -F implies from; -T implies to (fall-through in getopt).
    if args.save_from_test.is_some() {
        args.from = true;
    }
    if args.save_to_test.is_some() {
        args.to = true;
    }

    Ok(())
}

fn run_ping(args: &Args, twoway: bool) -> Result<(), u8> {
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

    // Interrupt flag shared with lib I/O (C: owp_intr).
    let mut owp_intr: i32 = 0;
    let _ = ctx.config_set_v(OWP_INTERRUPT_IO, &mut owp_intr as *mut i32 as usize);
    install_signal_handlers(&mut owp_intr);

    let (auth_mode, identity) = set_auth(&ctx, args, twoway).map_err(|e| {
        error!("{e}");
        1u8
    })?;

    let type_p = if let Some(ref d) = args.dscp {
        parse_type_p(d).map_err(|e| {
            error!("{e}");
            1u8
        })?
    } else {
        0
    };

    let mut padding = args.padding.unwrap_or(PADDING_UNSET);
    if padding == PADDING_UNSET {
        if twoway {
            // Match sender payload to reflector response size (C TWAMP default).
            padding = api::test_tw_payload_size(auth_mode, 0)
                .saturating_sub(api::test_payload_size(auth_mode, 0));
        } else {
            padding = 0;
        }
    }
    if padding > max_padding_size() {
        padding = max_padding_size();
    }

    let slots: Vec<Slot> = if let Some(ref sched) = args.interval {
        parse_slots(sched).map_err(|e| {
            error!("{e}");
            1u8
        })?
    } else {
        vec![Slot {
            slot_type: SlotType::RandExp,
            time: double_to_num64(DEFAULT_MEAN_WAIT),
        }]
    };

    let mut portrec = PortRange {
        low: DEFAULT_PORT_LOW,
        high: DEFAULT_PORT_HIGH,
    };
    if let Some(ref pr) = args.port_range {
        if pr == "0" {
            portrec.low = 0;
            portrec.high = 0;
        } else if !parse_port_range(pr, &mut portrec) {
            error!("Invalid test port range specified.");
            return Err(1);
        } else if portrec.high != 0
            && portrec.low != 0
            && (i32::from(portrec.high) - i32::from(portrec.low) + 1) < 1
        {
            error!("Invalid test port range specified: must contain at least 2 ports.");
            return Err(1);
        }
    }
    if !ctx.config_set_v(OWP_TEST_PORT_RANGE, &portrec as *const PortRange as usize) {
        error!("OWPContextConfigSetV(): Unable to set OWPTestPortRange?!");
        return Err(1);
    }

    let end_delay_storage = args.end_delay.unwrap_or(0.0);
    if args.end_delay.is_some()
        && !ctx.config_set_v(OWP_END_DELAY, &end_delay_storage as *const f64 as usize)
    {
        error!("Unable to set Context var: OWPEndDelay");
        return Err(1);
    }

    if !ctx.config_set_v(OWP_DETACH_PROCESSES, 1) {
        error!("Unable to set Context var: OWPDetachProcesses");
        return Err(1);
    }

    if args.childwait && !ctx.config_set_v(OWP_CHILD_WAIT, 1) {
        error!("OWPContextConfigSetV(): Unable to set OWPChildWait?!");
        return Err(1);
    }

    let do_from = args.effective_from(twoway);
    let do_to = args.effective_to(twoway);

    let server = Addr::by_node(args.remote_serv(), None);
    let mut err_ret = ErrSeverity::Ok;
    let cntrl_rc = if twoway {
        twp_control_open_interface(
            &ctx,
            args.srcaddr.as_deref(),
            args.interface.as_deref(),
            server,
            auth_mode,
            identity.as_deref(),
            None,
            &mut err_ret,
        )
    } else {
        control_open_interface(
            &ctx,
            args.srcaddr.as_deref(),
            args.interface.as_deref(),
            server,
            auth_mode,
            identity.as_deref(),
            None,
            &mut err_ret,
        )
    };

    let Some(cntrl_rc) = cntrl_rc else {
        error!(
            "Unable to open control connection to {}.",
            args.remote_serv()
        );
        return Err(1);
    };

    let result = {
        let mut cntrl = cntrl_rc.borrow_mut();
        run_sessions(
            &ctx,
            &mut cntrl,
            args,
            twoway,
            do_from,
            do_to,
            auth_mode,
            type_p,
            padding,
            &slots,
            &mut owp_intr,
        )
    };

    let _ = Control::close_rc(cntrl_rc);
    ctx.free();
    result
}

#[allow(clippy::too_many_arguments)]
fn run_sessions(
    ctx: &Context,
    cntrl: &mut Control,
    args: &Args,
    twoway: bool,
    do_from: bool,
    do_to: bool,
    _auth_mode: u32,
    type_p: u32,
    padding: u32,
    slots: &[Slot],
    owp_intr: &mut i32,
) -> Result<(), u8> {
    let rtt_bound = api::get_rtt_bound(cntrl);
    let mut loss_threshold = args.loss_threshold;
    if loss_threshold <= 0.0 {
        loss_threshold = num64_to_double(rtt_bound) + 2.0;
    }
    if loss_threshold < args.bucket_width {
        error!(
            "Invalid test specification: LossThreshold({loss_threshold}) '-L' < BucketWidth ({}) '-b'",
            args.bucket_width
        );
        return Err(1);
    }

    let curr_time = get_time_of_day(ctx).ok_or_else(|| {
        error!("Unable to get current time");
        1u8
    })?;

    let mut num_rtt: u32 = 1; // StartSessions
    if do_to {
        num_rtt += 1;
    }
    if do_from {
        num_rtt += 1;
    }

    // num_rtt * rtt_bound + margin. C uses +1s; Rust debug AES handshake for
    // Authenticated/Encrypted (two sessions) can exceed that on a loaded
    // loopback host, so keep a 3s floor before first send.
    let mut start_time = num64_mult(rtt_bound, ulong_to_num64(num_rtt)) + ulong_to_num64(3);

    let delay_start = if args.delay_start > 0.0 {
        double_to_num64(args.delay_start)
    } else {
        ulong_to_num64(0)
    };
    if delay_start.cmp_num(start_time) > 0 {
        start_time = delay_start;
    }
    start_time = start_time + curr_time.owptime;

    let tspec = TestSpec {
        start_time,
        loss_timeout: double_to_num64(loss_threshold),
        type_p,
        packet_size_padding: padding,
        npackets: args.num_packets,
        nslots: slots.len() as u32,
        slots: slots.to_vec(),
    };

    if *owp_intr != 0 {
        return Err(2);
    }

    let mut to_sid = [0u8; 16];
    let mut from_sid = [0u8; 16];
    let mut err_ret = ErrSeverity::Ok;
    let zero_addr = args.zero_addr;

    // Local receive-side results file (C `fromfp`), attached via session_request_ex.
    let mut from_fp: Option<File> = None;

    let test_host = args.test_host();

    if twoway {
        from_fp = open_from_fp(args.save_from_test.as_deref());
        if from_fp.is_none() {
            return Err(1);
        }
        // Test endpoints use host only (UDP port 0); never the control TCP port.
        let receiver = Addr::by_test_node(test_host);
        if !session_request_ex(
            cntrl,
            None,
            false,
            Some(receiver),
            true,
            zero_addr,
            &tspec,
            from_fp.as_ref(),
            &mut from_sid,
            &mut err_ret,
        ) {
            fail_session();
            return Err(1);
        }
    } else {
        if do_to {
            let receiver = Addr::by_test_node(test_host);
            if !session_request(
                cntrl,
                None,
                false,
                Some(receiver),
                true,
                zero_addr,
                &tspec,
                &mut to_sid,
                &mut err_ret,
            ) {
                fail_session();
                return Err(1);
            }
        }
        if *owp_intr != 0 {
            return Err(2);
        }
        if do_from {
            from_fp = open_from_fp(args.save_from_test.as_deref());
            if from_fp.is_none() {
                return Err(1);
            }
            let sender = Addr::by_test_node(test_host);
            if !session_request_ex(
                cntrl,
                Some(sender),
                true,
                None,
                false,
                zero_addr,
                &tspec,
                from_fp.as_ref(),
                &mut from_sid,
                &mut err_ret,
            ) {
                fail_session();
                return Err(1);
            }
        }
    }

    if start_sessions(cntrl) < ErrSeverity::Info {
        fail_session();
        return Err(1);
    }

    // Estimate for user message only (C prints duration; wait uses wake=NULL).
    if !args.quiet {
        let wake = estimate_end(ctx, &tspec, loss_threshold, rtt_bound);
        if let Some(now) = get_time_of_day(ctx) {
            let endtime = num64_to_double(wake) - num64_to_double(now.owptime);
            println!("Approximately {endtime:.1} seconds until results available");
        }
    }

    if *owp_intr != 0 {
        return Err(2);
    }

    let mut acceptval = AcceptType::Accept;
    let mut err = ErrSeverity::Ok;
    // C: OWPStopSessionsWait(cntrl, NULL, &owp_intr, &acceptval, &err)
    // wake=NULL → block on sessions_active / control fd until complete.
    let ch = stop_sessions_wait(cntrl, None, Some(owp_intr), &mut acceptval, &mut err);
    if ch < 0 || acceptval != AcceptType::Accept {
        error!("Test session(s) Failed...");
        if let Some(ref path) = args.save_from_test {
            let _ = std::fs::remove_file(path);
        }
        return Err(1);
    }
    if ch == 2 {
        // Early termination request (signal) — send StopSessions.
        let stop_err = api::stop_sessions(cntrl, Some(owp_intr), &mut acceptval);
        if stop_err < ErrSeverity::Warning || acceptval != AcceptType::Accept {
            error!("Test session(s) Failed...");
            if let Some(ref path) = args.save_from_test {
                let _ = std::fs::remove_file(path);
            }
            return Err(2);
        }
    }
    if *owp_intr > 1 {
        return Err(2);
    }

    let (local, remote) = if !args.quiet || args.raw {
        let local = cntrl.local_addr.as_ref().and_then(|a| {
            a.node
                .clone()
                .or_else(|| a.saddr().map(|s| s.ip().to_string()))
        });
        let remote = Some(test_host.to_string());
        if !args.quiet {
            info!(
                local = local.as_deref().unwrap_or("?"),
                remote = remote.as_deref().unwrap_or("?"),
                "session complete"
            );
        }
        (local, remote)
    } else {
        (None, None)
    };

    if !twoway && do_to && (args.save_to_test.is_some() || !args.quiet || args.raw) {
        let save = args.save_to_test.as_ref().map(Path::new);
        match owp_fetch_sid(save, cntrl, &to_sid) {
            None => report_fetch_fail(&to_sid),
            Some(mut tofp) => {
                if (!args.quiet || args.raw)
                    && do_stats(
                        &mut tofp,
                        local.as_deref(),
                        remote.as_deref(),
                        None,
                        args,
                        false,
                    )
                    .is_err()
                {
                    error!("do_stats(\"to\" session)");
                }
            },
        }
    }

    if *owp_intr > 1 {
        return Err(2);
    }

    if let Some(mut fp) = from_fp.take() {
        if !args.quiet || args.raw {
            let _ = fp.seek(SeekFrom::Start(0));
            let (from_h, to_h) = if twoway {
                (local.as_deref(), remote.as_deref())
            } else {
                (remote.as_deref(), local.as_deref())
            };
            if do_stats(&mut fp, from_h, to_h, Some(&tspec), args, twoway).is_err() {
                if args.save_from_test.is_some() {
                    warn!("do_stats(\"from\" session): no usable session data yet");
                } else {
                    error!("do_stats(\"from\" session)");
                }
            }
        }
    }

    let _ = from_sid;
    Ok(())
}

fn estimate_end(
    ctx: &Context,
    tspec: &TestSpec,
    loss_threshold: f64,
    rtt_bound: owamp::OwampNum64,
) -> owamp::OwampNum64 {
    let rate = api::test_packet_rate(ctx, tspec);
    let mut duration = if rate <= 0.0 {
        0.0
    } else {
        f64::from(tspec.npackets) / rate
    };
    duration += loss_threshold;
    duration += num64_to_double(rtt_bound);
    owamp::OwampNum64(tspec.start_time.0.wrapping_add(double_to_num64(duration).0))
}

fn fail_session() {
    error!("Session Failed!");
    let _ = std::io::Write::flush(&mut std::io::stderr());
}

fn install_signal_handlers(owp_intr: &mut i32) {
    // Store pointer for signal handler (process-global, as in C).
    unsafe {
        INTR_PTR = owp_intr as *mut i32;
        let mut setact: libc::sigaction = std::mem::zeroed();
        setact.sa_sigaction = signal_catch as *const () as usize;
        libc::sigemptyset(&mut setact.sa_mask);
        libc::sigaction(libc::SIGTERM, &setact, std::ptr::null_mut());
        libc::sigaction(libc::SIGHUP, &setact, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &setact, std::ptr::null_mut());
    }
}

static mut INTR_PTR: *mut i32 = std::ptr::null_mut();

extern "C" fn signal_catch(signo: libc::c_int) {
    match signo {
        libc::SIGINT | libc::SIGTERM | libc::SIGHUP => {},
        _ => {
            unsafe { libc::_exit(-1) };
        },
    }
    unsafe {
        if !INTR_PTR.is_null() {
            *INTR_PTR += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_v4_and_v6() {
        let mut a = Args::parse_from(["owping", "-4", "-6", "h"]);
        assert!(validate_and_normalize(&mut a, false).is_err());
    }

    #[test]
    fn save_from_implies_from_flag() {
        let mut a = Args::parse_from(["owping", "-F", "/tmp/x.owp", "h"]);
        validate_and_normalize(&mut a, false).unwrap();
        assert!(a.from);
        assert!(a.effective_from(false));
    }

    #[test]
    fn estimate_end_after_start() {
        let ctx = Context::create().unwrap();
        let tspec = TestSpec {
            start_time: ulong_to_num64(100),
            loss_timeout: double_to_num64(1.0),
            type_p: 0,
            packet_size_padding: 0,
            npackets: 10,
            nslots: 1,
            slots: vec![Slot {
                slot_type: SlotType::Literal,
                time: double_to_num64(0.1),
            }],
        };
        let end = estimate_end(&ctx, &tspec, 1.0, ulong_to_num64(1));
        assert!(end.cmp_num(tspec.start_time) > 0);
        ctx.free();
    }
}
