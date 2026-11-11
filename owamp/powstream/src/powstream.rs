//! Continuous OWAMP streamer — port of `powstream/powstream.c`.

use std::path::PathBuf;

use clap::{Arg, ArgAction, Command};
use owamp::api::stop_sessions;
use owamp::context::{ulong_to_num64, AcceptType, Context, Control, ErrSeverity};
use owamp::OwampNum64;
use owamp::{OWP_NAME_SEP, OWP_PATH_SEPARATOR, OWP_TSTAMPCHARS};
use tracing::{error, info, warn};

use crate::powstreamP::{format_tstamp, AppCtx, Options, POW_INC_EXT, POW_SUM_EXT, SETUP_ESTIMATE};
use crate::session::{
    build_tspec, close_sessions, collect_summary, configure_context, lock_savedir, parse_port_opt,
    reset_session, setup_session, stop_sessions_wait, wait_until, write_session, PowCntrl,
    StreamState,
};

const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Port of C `print_conn_args` / `print_test_args` / `print_output_args` / `usage`.
fn usage_help() -> String {
    format!(
        "\
usage: powstream [arguments] testaddr [servaddr]
[arguments] are as follows:

   -h             print this message and exit

              [Test Args]

   -t             sets the tests direction from client to server
   -c count       number of test packets (per complete session)
   -E endDelay    time to wait before sending stop-session message
   -i wait        mean average time between packets (seconds)
   -L timeout     maximum time to wait for a packet (seconds)
   -P portrange   test port range to use (must contain at least 2 ports)
   -s padding     size of the padding added to each packet (bytes)
   -z delayStart  time to wait before starting first test (seconds)

              [Connection Args]

   -4             use IPv4 only
   -6             use IPv6 only
   -A authmode    requested modes: [A]uthenticated, [E]ncrypted, [O]pen
   -k pffile      pass-phrase file to use with Authenticated/Encrypted modes
   -S srcaddr     specify the local address or interface for control connection and tests
   -B interface   specify the interface to use for control connection and tests
   -u username    username to use with Authenticated/Encrypted modes
   -I retryDelay  time to wait between failed connections (default: 60 seconds)

              [Output Args]

   -b bucketWidth create summary files with buckets(seconds)
   -d dir         directory to save session file in
   -e facility    syslog facility to log to
   -g loglevel    severity log messages to report to syslog Valid values: NONE, FATAL, WARN, INFO, DEBUG, ALL
   -N count       number of test packets (per sub-session)
   -p             print filenames to stdout
   -R             Only send messages to syslog (not STDERR)
   -v             include more verbose output
   -U             Adds UNIX timestamps to summary results

Version: {PACKAGE_VERSION}

Continuous one-way latency streaming. Runs perpetual overlapping
test sessions until SIGTERM/SIGINT. SIGHUP re-opens connections."
    )
}

fn build_cli() -> Command {
    Command::new("powstream")
        .about("Continuous OWAMP streamer (port of Internet2/perfSONAR powstream)")
        .version(PACKAGE_VERSION)
        .disable_help_flag(true)
        .override_usage("powstream [arguments] testaddr [servaddr]")
        .after_help(usage_help())
        .arg(
            Arg::new("help")
                .short('h')
                .long("help")
                .action(ArgAction::Help)
                .help("print this message and exit"),
        )
        .arg(
            Arg::new("testaddr")
                .required(true)
                .help("Test address (OWAMP peer for the test packets)"),
        )
        .arg(
            Arg::new("servaddr")
                .required(false)
                .help("Control-server address (defaults to testaddr)"),
        )
        // [Connection Args]
        .arg(Arg::new("v4").short('4').action(ArgAction::SetTrue).help("use IPv4 only"))
        .arg(Arg::new("v6").short('6').action(ArgAction::SetTrue).help("use IPv6 only"))
        .arg(
            Arg::new("authmode")
                .short('A')
                .help("requested modes: [A]uthenticated, [E]ncrypted, [O]pen"),
        )
        .arg(
            Arg::new("pffile")
                .short('k')
                .help("pass-phrase file to use with Authenticated/Encrypted modes"),
        )
        .arg(
            Arg::new("srcaddr")
                .short('S')
                .help("specify the local address or interface for control connection and tests"),
        )
        .arg(
            Arg::new("interface")
                .short('B')
                .help("specify the interface to use for control connection and tests"),
        )
        .arg(
            Arg::new("identity")
                .short('u')
                .help("username to use with Authenticated/Encrypted modes"),
        )
        .arg(
            Arg::new("retryDelay")
                .short('I')
                .default_value("60")
                .help("time to wait between failed connections (default: 60 seconds)"),
        )
        // [Test Args]
        .arg(
            Arg::new("sender")
                .short('t')
                .action(ArgAction::SetTrue)
                .help("sets the tests direction from client to server"),
        )
        .arg(
            Arg::new("count")
                .short('c')
                .default_value("300")
                .help("number of test packets (per complete session)"),
        )
        .arg(
            Arg::new("endDelay")
                .short('E')
                .help("time to wait before sending stop-session message"),
        )
        .arg(
            Arg::new("wait")
                .short('i')
                .default_value("0.1")
                .help("mean average time between packets (seconds)"),
        )
        .arg(
            Arg::new("timeout")
                .short('L')
                .default_value("10.0")
                .help("maximum time to wait for a packet (seconds)"),
        )
        .arg(
            Arg::new("portrange")
                .short('P')
                .default_value("8760-9960")
                .help("test port range to use (must contain at least 2 ports)"),
        )
        .arg(
            Arg::new("padding")
                .short('s')
                .default_value("0")
                .help("size of the padding added to each packet (bytes)"),
        )
        .arg(
            Arg::new("delayStart")
                .short('z')
                .default_value("0")
                .help("time to wait before starting first test (seconds)"),
        )
        // [Output Args]
        .arg(
            Arg::new("bucketWidth")
                .short('b')
                .default_value("0.0001")
                .help("create summary files with buckets(seconds)"),
        )
        .arg(Arg::new("dir").short('d').help("directory to save session file in"))
        .arg(Arg::new("facility").short('e').help("syslog facility to log to"))
        .arg(
            Arg::new("loglevel")
                .short('g')
                .help("severity log messages to report to syslog Valid values: NONE, FATAL, WARN, INFO, DEBUG, ALL"),
        )
        .arg(
            Arg::new("bucketCount")
                .short('N')
                .help("number of test packets (per sub-session)"),
        )
        .arg(
            Arg::new("printfiles")
                .short('p')
                .action(ArgAction::SetTrue)
                .help("print filenames to stdout"),
        )
        .arg(
            Arg::new("syslog_only")
                .short('R')
                .action(ArgAction::SetTrue)
                .help("Only send messages to syslog (not STDERR)"),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .action(ArgAction::Count)
                .help("include more verbose output"),
        )
        .arg(
            Arg::new("unix_ts")
                .short('U')
                .action(ArgAction::SetTrue)
                .help("Adds UNIX timestamps to summary results"),
        )
        .arg(
            Arg::new("childwait")
                .short('w')
                .action(ArgAction::SetTrue)
                .help("DEBUG: pause endpoint workers so a debugger can attach (OWPChildWait)"),
        )
}

fn parse_options() -> AppCtx {
    let matches = build_cli().get_matches();

    let retry_delay = matches
        .get_one::<String>("retryDelay")
        .unwrap()
        .parse()
        .unwrap_or_else(|_| {
            eprintln!("Invalid (-I) value. Positive integer expected");
            std::process::exit(1);
        });
    let num_packets = matches
        .get_one::<String>("count")
        .unwrap()
        .parse()
        .unwrap_or_else(|_| {
            eprintln!("Invalid value. Positive integer expected");
            std::process::exit(1);
        });
    let mut set_end_delay = false;
    let mut end_delay = 0.0;
    if let Some(ed) = matches.get_one::<String>("endDelay") {
        let v: f64 = ed.parse().unwrap_or_else(|_| {
            eprintln!("Invalid (-E) value. Positive float expected");
            std::process::exit(1);
        });
        if v <= 0.0 {
            eprintln!("Invalid (-E) value. Positive float expected");
            std::process::exit(1);
        }
        end_delay = v;
        set_end_delay = true;
    }
    let mean_wait = matches
        .get_one::<String>("wait")
        .unwrap()
        .parse()
        .unwrap_or_else(|_| {
            eprintln!("Invalid value. Positive float expected");
            std::process::exit(1);
        });
    let loss_threshold = matches
        .get_one::<String>("timeout")
        .unwrap()
        .parse()
        .unwrap_or_else(|_| {
            eprintln!("Invalid (-L) value. Positive float expected");
            std::process::exit(1);
        });
    if loss_threshold <= 0.0 {
        eprintln!("Invalid (-L) value. Positive float expected");
        std::process::exit(1);
    }
    let padding = matches
        .get_one::<String>("padding")
        .unwrap()
        .parse()
        .unwrap_or_else(|_| {
            eprintln!("Invalid value. Positive integer expected");
            std::process::exit(1);
        });
    let delay_start = matches
        .get_one::<String>("delayStart")
        .unwrap()
        .parse()
        .unwrap_or_else(|_| {
            eprintln!("Invalid (-z) value. Positive integer expected");
            std::process::exit(1);
        });
    let mut port_range = Options::default().port_range;
    let pr = matches.get_one::<String>("portrange").unwrap();
    if let Err(e) = parse_port_opt(pr, &mut port_range) {
        eprintln!("{e}");
        std::process::exit(1);
    }
    let bucket_width = matches
        .get_one::<String>("bucketWidth")
        .unwrap()
        .parse()
        .unwrap_or_else(|_| {
            eprintln!("Invalid (-b) value. Positive float expected");
            std::process::exit(1);
        });
    if bucket_width <= 0.0 {
        eprintln!("Invalid (-b) value. Positive float expected");
        std::process::exit(1);
    }
    let num_bucket_packets = matches.get_one::<String>("bucketCount").map_or(0u32, |n| {
        n.parse().unwrap_or_else(|_| {
            eprintln!("Invalid (-N) value. Positive integer expected");
            std::process::exit(1);
        })
    });
    let mut syslog_facility = Options::default().syslog_facility;
    if let Some(fac) = matches.get_one::<String>("facility") {
        if let Some(f) = owamp::syslog_facility_by_name(fac) {
            syslog_facility = f;
        } else {
            eprintln!("Invalid -e: Syslog facility \"{fac}\" unknown");
            std::process::exit(1);
        }
    }
    let mut syslog_report_level = None;
    if let Some(lvl) = matches.get_one::<String>("loglevel") {
        if let Some(l) = owamp::report_level_by_name(lvl) {
            syslog_report_level = Some(l);
        } else {
            eprintln!("Log level \"{lvl}\" invalid");
            std::process::exit(1);
        }
    }

    let opt = Options {
        v4only: matches.get_flag("v4"),
        v6only: matches.get_flag("v6"),
        authmode: matches.get_one::<String>("authmode").cloned(),
        pffile: matches.get_one::<String>("pffile").cloned(),
        srcaddr: matches.get_one::<String>("srcaddr").cloned(),
        interface: matches.get_one::<String>("interface").cloned(),
        identity: matches.get_one::<String>("identity").cloned(),
        retry_delay,
        sender: matches.get_flag("sender"),
        num_packets,
        set_end_delay,
        end_delay,
        mean_wait,
        loss_threshold,
        padding,
        delay_start,
        port_range,
        bucket_width,
        savedir: matches.get_one::<String>("dir").cloned(),
        num_bucket_packets,
        printfiles: matches.get_flag("printfiles"),
        display_unix_ts: matches.get_flag("unix_ts"),
        verbose: u32::from(matches.get_count("verbose")),
        syslog_only: matches.get_flag("syslog_only"),
        syslog_facility,
        syslog_report_level,
        childwait: matches.get_flag("childwait"),
    };

    let remote_test = matches.get_one::<String>("testaddr").unwrap().clone();
    let remote_serv = matches
        .get_one::<String>("servaddr")
        .cloned()
        .unwrap_or_else(|| remote_test.clone());

    AppCtx::new(opt, remote_test, remote_serv)
}

/// Call `setup_session` configuring `q_idx`, with `p_idx` as the peer.
fn setup_pair(
    state: &mut StreamState,
    pcntrl: &mut [PowCntrl; 2],
    q_idx: usize,
    p_idx: usize,
    stop: Option<OwampNum64>,
) -> i32 {
    let (left, right) = pcntrl.split_at_mut(1);
    if q_idx == 0 {
        // q = left[0], p = right[0]
        let p = if p_idx == 1 {
            &mut right[0]
        } else {
            unreachable!()
        };
        setup_session(state, &mut left[0], p, stop)
    } else {
        // q = right[0], p = left[0]
        setup_session(state, &mut right[0], &mut left[0], stop)
    }
}

fn reset_pair(state: &StreamState, pcntrl: &mut [PowCntrl; 2], q_idx: usize, p_idx: usize) {
    let (left, right) = pcntrl.split_at_mut(1);
    if q_idx == 0 {
        reset_session(&mut left[0], &mut right[0], state);
        let _ = p_idx;
    } else {
        reset_session(&mut right[0], &mut left[0], state);
    }
}

/// Init tracing + optional syslog (`-e`/`-g`/`-R`), port of `I2ErrLogSyslog` setup.
fn init_logging(opt: &Options) {
    let ident = std::ffi::CString::new("powstream").unwrap_or_default();
    let mut logopt = libc::LOG_PID;
    if !opt.syslog_only {
        logopt |= libc::LOG_PERROR;
    }
    if opt.verbose > 1 {
        logopt |= libc::LOG_PID;
    }
    unsafe {
        libc::openlog(ident.as_ptr(), logopt, opt.syslog_facility);
    }

    let filter = if opt.verbose > 1 {
        "trace".to_string()
    } else if opt.verbose == 1 {
        "debug".to_string()
    } else if let Some(lvl) = opt.syslog_report_level {
        // Map OWPErr* / report-level ints onto tracing filters.
        match lvl {
            0 => "off".into(),       // none
            3 => "error".into(),     // fatal
            4 => "warn".into(),      // warning
            7 | 8 => "debug".into(), // debug / all
            _ => "info".into(),      // info / default
        }
    } else {
        "info".into()
    };

    let env = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter));

    if opt.syslog_only {
        // STDERR off (`~LOG_PERROR`); tracing still emits via a syslog writer.
        tracing_subscriber::fmt()
            .with_env_filter(env)
            .with_writer(|| SyslogWriter)
            .with_ansi(false)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(env)
            .with_writer(std::io::stderr)
            .init();
    }
}

/// Minimal `MakeWriter` that forwards lines to `syslog(3)`.
struct SyslogWriter;

impl std::io::Write for SyslogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let msg = String::from_utf8_lossy(buf);
        let trimmed = msg.trim_end_matches(['\n', '\r']);
        if let Ok(c) = std::ffi::CString::new(trimmed) {
            unsafe {
                libc::syslog(
                    libc::LOG_ERR,
                    c"%s".as_ptr() as *const libc::c_char,
                    c.as_ptr(),
                );
            }
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn run() {
    let mut app = parse_options();
    init_logging(&app.opt);

    let fname_len = (2 * OWP_TSTAMPCHARS)
        + OWP_NAME_SEP.len()
        + POW_SUM_EXT.len().max(owamp::OWP_FILE_EXT.len())
        + POW_INC_EXT.len();
    let mut dirpath = PathBuf::new();
    if let Some(ref d) = app.opt.savedir {
        if d.len() + OWP_PATH_SEPARATOR.len() + fname_len + 1 > 4_096 {
            eprintln!("-d: pathname too long.");
            std::process::exit(1);
        }
        dirpath.push(d);
        if !dirpath.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(&dirpath);
        }
    }
    let file_offset = dirpath.as_os_str().len();
    let tstamp_offset = file_offset + OWP_TSTAMPCHARS;
    let ext_offset = tstamp_offset + OWP_TSTAMPCHARS + OWP_NAME_SEP.len();

    let _lock = match lock_savedir(&dirpath) {
        Ok(f) => f,
        Err(e) => {
            error!("{e}");
            std::process::exit(1);
        },
    };

    let num_summaries = if app.opt.num_bucket_packets == 0 {
        app.opt.num_bucket_packets = app.opt.num_packets;
        0
    } else {
        if app.opt.num_packets < app.opt.num_bucket_packets
            || !app
                .opt
                .num_packets
                .is_multiple_of(app.opt.num_bucket_packets)
        {
            error!(
                "Number of summary packets (-N {}) must be a divisor of the number of session packets (-c {}).",
                app.opt.num_bucket_packets, app.opt.num_packets
            );
            std::process::exit(1);
        }
        app.opt.num_packets / app.opt.num_bucket_packets
    };

    let session_time = (f64::from(app.opt.num_packets) * app.opt.mean_wait) as u32;
    if f64::from(session_time) < f64::from(SETUP_ESTIMATE) + app.opt.loss_threshold {
        warn!(
            "Warning: Holes in data are likely because lossThreshold({}) is too large a fraction of approx summary session duration({session_time})",
            app.opt.loss_threshold
        );
    }
    if session_time < app.opt.retry_delay {
        app.opt.retry_delay = session_time;
    }

    let tspec = build_tspec(&app.opt);
    let Some(ctx) = Context::create() else {
        error!("Unable to initialize OWP library.");
        std::process::exit(1);
    };
    crate::auth::owp_set_auth(&ctx, &mut app);

    let iotime = app.opt.mean_wait.max(1.0) as u32 + 2;

    let mut state = StreamState {
        app,
        ctx: ctx.clone(),
        tspec,
        dirpath,
        file_offset,
        ext_offset,
        num_summaries,
        iotime,
        first_time: true,
    };

    if let Err(e) = configure_context(&mut state) {
        error!("{e}");
        std::process::exit(1);
    }

    if let Err(e) = crate::signals::install_handlers() {
        error!("sigaction(): {e}");
        std::process::exit(1);
    }

    let mut pcntrl = [PowCntrl::new(ctx.clone()), PowCntrl::new(ctx)];
    let mut which: usize = 0;

    info!(
        "powstream starting: test={} serv={} packets={} mean_wait={} summaries={}",
        state.app.remote_test,
        state.app.remote_serv,
        state.app.opt.num_packets,
        state.app.opt.mean_wait,
        state.num_summaries
    );

    // Perpetual overlapping dual-control loop (C `while(1)` / NextConnection).
    loop {
        if crate::signals::sig_check(|| close_sessions(&mut pcntrl, &state)) {
            continue;
        }

        // p = pcntrl[which++]; which %= 2; q = pcntrl[which];
        let p_idx = which;
        which = (which + 1) % 2;
        let q_idx = which;

        if pcntrl[p_idx].num_packets == 0 {
            // SetupSession(ctx, q, p, NULL) — configure the peer first.
            let _ = setup_pair(&mut state, &mut pcntrl, q_idx, p_idx, None);
            continue;
        }

        pcntrl[p_idx].current_session_start_num = pcntrl[p_idx].next_session_start_num;
        pcntrl[p_idx].current_session_end_num = pcntrl[p_idx].next_session_end_num;

        if state.app.opt.verbose > 1 {
            eprintln!(
                "Starting session [{} - {}] v={}",
                format_tstamp(pcntrl[p_idx].current_session_start_num),
                format_tstamp(pcntrl[p_idx].current_session_end_num),
                state.app.opt.verbose
            );
        }

        let mut aval = AcceptType::Accept;
        let mut sum_done = 0u32;

        if state.num_summaries == 0 {
            if setup_pair(&mut state, &mut pcntrl, q_idx, p_idx, None) != 0 {
                continue;
            }
            pcntrl[p_idx].session_started = true;
            // C: OWPStopSessionsWait(p->cntrl, NULL, &pow_intr, ...) — block until
            // sessions_active completes (live endpoints), no artificial wake.
            loop {
                let rc = {
                    let Some(ref rc) = pcntrl[p_idx].cntrl else {
                        break;
                    };
                    let mut c = rc.borrow_mut();
                    stop_sessions_wait(&mut c, None, &mut aval)
                };
                if rc < 0 {
                    pcntrl[p_idx].call_stop = false;
                    close_sessions(&mut pcntrl, &state);
                    break;
                } else if rc == 2 {
                    if crate::signals::sig_check(|| close_sessions(&mut pcntrl, &state)) {
                        break;
                    }
                    continue; // wait_again
                }
                // Session over (rc==0); wake=NULL never returns 1.
                pcntrl[p_idx].call_stop = false;
                break;
            }
        } else {
            let mut lastnum = OwampNum64::ZERO;
            for sum in 0..state.num_summaries {
                if crate::signals::sig_check(|| close_sessions(&mut pcntrl, &state)) {
                    break;
                }
                let startnum = OwampNum64(
                    pcntrl[p_idx]
                        .current_session_start_num
                        .0
                        .wrapping_add(lastnum.0),
                );
                if let Some(ref mut sctx) = pcntrl[p_idx].sctx {
                    for _ in 0..state.app.opt.num_bucket_packets {
                        match sctx.generate_next_delta() {
                            Ok(d) => lastnum = OwampNum64(lastnum.0.wrapping_add(d.0)),
                            Err(e) => {
                                error!("schedule: {e}");
                                break;
                            },
                        }
                    }
                }
                let localstop = OwampNum64(
                    pcntrl[p_idx]
                        .current_session_start_num
                        .0
                        .wrapping_add(lastnum.0),
                );
                let stopnum = OwampNum64(
                    localstop
                        .0
                        .wrapping_add(state.tspec.loss_timeout.0)
                        .wrapping_add(ulong_to_num64(state.iotime).0),
                );

                if setup_pair(&mut state, &mut pcntrl, q_idx, p_idx, Some(stopnum)) != 0 {
                    break;
                }

                let mut reset_conn = false;
                let rc = if pcntrl[p_idx].call_stop {
                    pcntrl[p_idx].cntrl.clone().map_or_else(
                        || wait_until(stopnum),
                        |crc| {
                            let mut c = crc.borrow_mut();
                            // C AGAIN: on interrupt, if sessions still active retry wait.
                            let mut rc = stop_sessions_wait(&mut c, Some(&stopnum), &mut aval);
                            while rc == 2 {
                                if crate::signals::sig_check(|| close_sessions(&mut pcntrl, &state))
                                {
                                    reset_conn = true;
                                    break;
                                }
                                let (active, _) = owamp::api::sessions_active(&c);
                                if active == 0 {
                                    rc = 1; // fall through as time-up
                                    break;
                                }
                                rc = stop_sessions_wait(&mut c, Some(&stopnum), &mut aval);
                            }
                            rc
                        },
                    )
                } else {
                    1
                };
                if reset_conn {
                    break;
                }

                if rc < 0 {
                    if let Some(rc) = pcntrl[p_idx].cntrl.take() {
                        let _ = Control::close_rc(rc);
                    }
                    break;
                }
                if rc == 0 {
                    pcntrl[p_idx].call_stop = false;
                    if aval != AcceptType::Accept {
                        break;
                    }
                }
                if rc == 2 {
                    // Unexpected residual interrupt — treat like C NextConnection.
                    if crate::signals::sig_check(|| close_sessions(&mut pcntrl, &state)) {
                        break;
                    }
                    continue;
                }

                pcntrl[p_idx].session_started = true;
                collect_summary(&state, &mut pcntrl[p_idx], sum, startnum, localstop);
                sum_done = sum + 1;

                if pcntrl[p_idx].cntrl.is_none() {
                    break;
                }
            }
        }

        if pcntrl[p_idx].cntrl.is_some() && pcntrl[p_idx].call_stop {
            if let Some(ref rc) = pcntrl[p_idx].cntrl.clone() {
                let mut c = rc.borrow_mut();
                if (stop_sessions(&mut c, Some(crate::signals::intr_ref()), &mut aval) as i32)
                    < (ErrSeverity::Warning as i32)
                {
                    drop(c);
                    if let Some(rc) = pcntrl[p_idx].cntrl.take() {
                        let _ = Control::close_rc(rc);
                    }
                }
            }
        }

        write_session(&state, &mut pcntrl[p_idx], aval, false);

        pcntrl[p_idx].num_packets = 0;
        pcntrl[p_idx].fp = None;
        pcntrl[p_idx].testfp = None;

        if state.num_summaries > 0 && sum_done < state.num_summaries {
            reset_pair(&state, &mut pcntrl, q_idx, p_idx);
        }
    }
}
