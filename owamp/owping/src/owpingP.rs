//! Command-line options — mirrors `owpingP.h` / getopt in `owping.c`.

use clap::{ArgAction, Parser};
use std::io::Write;
use std::path::Path;

pub const OWPING_SUM_EXT: &str = ".sum";
pub const OWPING_DEF_EXT: &str = ".txt";
pub const OWPING_INC_EXT: &str = ".i";

pub const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Program personality selected by argv[0] (C uses the same binary under several names).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgMode {
    Owping,
    Twping,
    Owstats,
    Owfetch,
    Owup,
}

impl ProgMode {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Owping => "owping",
            Self::Twping => "twping",
            Self::Owstats => "owstats",
            Self::Owfetch => "owfetch",
            Self::Owup => "owup",
        }
    }

    #[must_use]
    pub fn from_progname(prog: &str) -> Self {
        let base = Path::new(prog)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(prog);
        match base {
            "twping" => Self::Twping,
            "owstats" => Self::Owstats,
            "owfetch" => Self::Owfetch,
            "owup" => Self::Owup,
            _ => Self::Owping,
        }
    }

    #[must_use]
    pub const fn twoway(self) -> bool {
        matches!(self, Self::Twping)
    }
}

/// OWAMP / TWAMP client options (shared across owping/twping/owstats/owfetch/owup).
#[derive(Debug, Clone, Parser)]
#[command(
    name = "owping",
    about = "One-way / two-way active delay measurement client",
    disable_help_flag = true,
    override_usage = "owping [arguments] testaddr [servaddr]"
)]
pub struct Args {
    /// Print this message and exit
    #[arg(short = 'h', long = "help", action = ArgAction::SetTrue)]
    pub help: bool,

    // --- Connection ---
    /// Connect using IPv4 addresses only
    #[arg(short = '4')]
    pub v4only: bool,

    /// Connect using IPv6 addresses only
    #[arg(short = '6')]
    pub v6only: bool,

    /// Requested modes: [A]uthenticated, [E]ncrypted, [O]pen (, [M]ixed for TWAMP)
    #[arg(short = 'A', long = "authmode", value_name = "authmode")]
    pub authmode: Option<String>,

    /// Passphrase file for Authenticated/Encrypted(/Mixed) modes
    #[arg(short = 'k', long = "passphrasefile", value_name = "file")]
    pub pffile: Option<String>,

    /// Local address or interface for control connection and tests
    #[arg(short = 'S', long = "srcaddr", value_name = "srcaddr")]
    pub srcaddr: Option<String>,

    /// Interface for control connection and tests
    #[arg(short = 'B', long = "interface", value_name = "interface")]
    pub interface: Option<String>,

    /// Username for Authenticated/Encrypted(/Mixed) modes
    #[arg(short = 'u', long = "username", value_name = "username")]
    pub identity: Option<String>,

    /// Do not specify IP addresses for test packets (NAT traversal; TWAMP)
    #[arg(short = 'Z')]
    pub zero_addr: bool,

    // --- Test ---
    /// Number of test packets
    #[arg(
        short = 'c',
        long = "count",
        value_name = "count",
        default_value_t = 100
    )]
    pub num_packets: u32,

    /// RFC 2474 style DSCP value for TOS byte
    #[arg(short = 'D', long = "dscp", value_name = "DSCP")]
    pub dscp: Option<String>,

    /// End delay after last packet (seconds)
    #[arg(short = 'E', long = "end-delay", value_name = "seconds")]
    pub end_delay: Option<f64>,

    /// Perform one-way test from testhost (OWAMP); with `-F` also saves results
    #[arg(short = 'f')]
    pub from: bool,

    /// Save "from" session results to file
    #[arg(short = 'F', long = "save-from", value_name = "file")]
    pub save_from_test: Option<String>,

    /// Mean average time between packets / schedule (seconds[,…])
    #[arg(short = 'i', long = "interval", value_name = "wait")]
    pub interval: Option<String>,

    /// Maximum time to wait for a packet before declaring it lost (seconds)
    #[arg(
        short = 'L',
        long = "timeout",
        value_name = "seconds",
        default_value_t = 0.0
    )]
    pub loss_threshold: f64,

    /// Port range to use during the test (e.g. 8760-9960 or 0)
    #[arg(short = 'P', long = "portrange", value_name = "portrange")]
    pub port_range: Option<String>,

    /// Padding added to each packet (bytes)
    #[arg(short = 's', long = "padding", value_name = "bytes")]
    pub padding: Option<u32>,

    /// Perform one-way test to testhost (OWAMP)
    #[arg(short = 't')]
    pub to: bool,

    /// Save "to" session results to file (OWAMP)
    #[arg(short = 'T', long = "save-to", value_name = "file")]
    pub save_to_test: Option<String>,

    /// Time to wait before executing test (seconds)
    #[arg(
        short = 'z',
        long = "delay-start",
        value_name = "seconds",
        default_value_t = 0.0
    )]
    pub delay_start: f64,

    // --- Output ---
    /// Additional percentile level(s) for delays (comma-separated)
    #[arg(short = 'a', long = "alpha", value_name = "alpha")]
    pub percentiles: Option<String>,

    /// Bin size for histogram calculations
    #[arg(
        short = 'b',
        long = "bucketwidth",
        value_name = "width",
        default_value_t = 0.0001
    )]
    pub bucket_width: f64,

    /// Directory for saved session files
    #[arg(short = 'd', long = "savedir", value_name = "dir")]
    pub savedir: Option<String>,

    /// Print machine (perl) readable summary
    #[arg(short = 'M')]
    pub machine: bool,

    /// Units: n, u, m, or s
    #[arg(short = 'n', long = "units", value_name = "units", default_value = "m")]
    pub units: char,

    /// Number of test packets to summarize per sub-session
    #[arg(
        short = 'N',
        long = "bucket-packets",
        value_name = "count",
        default_value_t = 0
    )]
    pub num_bucket_packets: u32,

    /// Print filenames of saved data
    #[arg(short = 'p')]
    pub printfiles: bool,

    /// Run the test and exit without reporting statistics
    #[arg(short = 'Q')]
    pub quiet: bool,

    /// Print RAW delay records
    #[arg(short = 'R')]
    pub raw: bool,

    /// Print individual delays; optional N limits to first N packets
    #[arg(short = 'v', long = "verbose", num_args = 0..=1, default_missing_value = "0")]
    pub records: Option<u64>,

    /// Add UNIX timestamps when printing individual delays
    #[arg(short = 'U')]
    pub display_unix_ts: bool,

    /// DEBUG: pause endpoint workers so a debugger can attach (`OWPChildWait`)
    #[arg(short = 'w', action = ArgAction::SetTrue)]
    pub childwait: bool,

    /// Remaining positionals (testaddr/servaddr, session files, SID/savefile pairs, …).
    #[arg(
        value_name = "ARGS",
        trailing_var_arg = true,
        allow_hyphen_values = false
    )]
    pub positionals: Vec<String>,
}

impl Args {
    #[must_use]
    pub const fn progname(twoway: bool) -> &'static str {
        if twoway {
            "twping"
        } else {
            "owping"
        }
    }

    #[must_use]
    pub const fn effective_from(&self, twoway: bool) -> bool {
        if twoway {
            // TWAMP always runs a reflected session (C: save_from / fromfp path).
            true
        } else if !self.to
            && !self.from
            && self.save_to_test.is_none()
            && self.save_from_test.is_none()
        {
            true
        } else {
            self.from || self.save_from_test.is_some()
        }
    }

    #[must_use]
    pub const fn effective_to(&self, twoway: bool) -> bool {
        if twoway {
            false
        } else if !self.to
            && !self.from
            && self.save_to_test.is_none()
            && self.save_from_test.is_none()
        {
            true
        } else {
            self.to || self.save_to_test.is_some()
        }
    }

    pub fn remote_serv(&self) -> &str {
        self.positionals
            .get(1)
            .map(String::as_str)
            .or_else(|| self.positionals.first().map(String::as_str))
            .unwrap_or("")
    }

    pub fn test_host(&self) -> &str {
        self.positionals.first().map_or("", String::as_str)
    }

    /// `-v` without N → unlimited; `-vN` → limit N; absent → no individual records.
    #[must_use]
    pub const fn rec_limit(&self) -> Option<u64> {
        self.records
    }
}

/// `print_conn_args` from `owping.c`.
pub fn print_conn_args(twoway: bool, out: &mut dyn Write) {
    let _ = writeln!(out, "              [Connection Args]");
    let _ = writeln!(out);
    if twoway {
        let _ = writeln!(
            out,
            "   -A authmode    requested modes: [A]uthenticated, [E]ncrypted, [M]ixed, [O]pen"
        );
        let _ = writeln!(
            out,
            "   -k passphrasefile     passphrasefile to use with Authenticated/Encrypted/Mixed modes"
        );
    } else {
        let _ = writeln!(
            out,
            "   -A authmode    requested modes: [A]uthenticated, [E]ncrypted, [O]pen"
        );
        let _ = writeln!(
            out,
            "   -k passphrasefile     passphrasefile to use with Authenticated/Encrypted modes"
        );
    }
    let _ = writeln!(
        out,
        "   -S srcaddr     specify the local address or interface for control connection and tests"
    );
    let _ = writeln!(
        out,
        "   -B interface   specify the interface to use for control connection and tests"
    );
    if twoway {
        let _ = writeln!(
            out,
            "   -Z             do not specify IP addresses for tests packets (NAT traversal)"
        );
        let _ = writeln!(
            out,
            "   -u username    username to use with Authenticated/Encrypted/Mixed modes"
        );
    } else {
        let _ = writeln!(
            out,
            "   -u username    username to use with Authenticated/Encrypted modes"
        );
    }
    let _ = writeln!(out, "   -4             connect using IPv4 addresses only");
    let _ = writeln!(out, "   -6             connect using IPv6 addresses only");
}

/// `print_test_args` from `owping.c`.
pub fn print_test_args(twoway: bool, out: &mut dyn Write) {
    let _ = writeln!(out, "              [Test Args]");
    let _ = writeln!(out);
    let _ = writeln!(out, "   -c count       number of test packets");
    let _ = writeln!(
        out,
        "   -D DSCP        RFC 2474 style DSCP value for TOS byte"
    );
    if twoway {
        let _ = writeln!(out, "   -F file        save results to file");
    } else {
        let _ = writeln!(
            out,
            "   -f | -F file   perform one-way test from testhost [and save results to file]"
        );
    }
    let _ = writeln!(
        out,
        "   -i wait        mean average time between packets (seconds)"
    );
    let _ = writeln!(
        out,
        "   -L timeout     maximum time to wait for a packet before declaring it lost (seconds)"
    );
    let _ = writeln!(out, "   -P portrange   port range to use during the test");
    let _ = writeln!(
        out,
        "   -s padding     size of the padding added to each packet (bytes)"
    );
    if !twoway {
        let _ = writeln!(
            out,
            "   -t | -T file   perform one-way test to testhost [and save results to file]"
        );
    }
    let _ = writeln!(
        out,
        "   -z delayStart  time to wait before executing test (seconds)"
    );
}

/// `print_output_args` from `owping.c`.
pub fn print_output_args(twoway: bool, out: &mut dyn Write) {
    let _ = writeln!(out, "              [Output Args]");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "   -a alpha       report an additional percentile level for the delays"
    );
    let _ = writeln!(out, "   -b bucketwidth bin size for histogram calculations");
    let _ = writeln!(
        out,
        "   -M             print machine (perl) readable summary"
    );
    let _ = writeln!(out, "   -n units       'n','u','m', or 's'");
    let _ = writeln!(
        out,
        "   -N count       number of test packets (to summarize per sub-session)"
    );
    let _ = writeln!(
        out,
        "   -Q             run the test and exit without reporting statistics"
    );
    if twoway {
        let _ = writeln!(
            out,
            "   -R             print RAW data: \"SSEQ STIME SS SERR SRTIME SRS SRERR STTL RSEQ RSTIME RSS RSERR RTIME RS RERR RTTL\\n\""
        );
    } else {
        let _ = writeln!(
            out,
            "   -R             print RAW data: \"SEQNO STIME SS SERR RTIME RS RERR TTL\\n\""
        );
    }
    let _ = writeln!(
        out,
        "   -v[N]          print out individual delays. You can supply an optional N here to limit the print to the first N packets"
    );
    let _ = writeln!(
        out,
        "   -U             Adds UNIX timestamps when printing individual delays"
    );
}

/// `usage` from `owping.c` for all embedded prog names.
pub fn usage_for_mode(mode: ProgMode, msg: Option<&str>) {
    let mut err = std::io::stderr();
    let progname = mode.name();
    if let Some(m) = msg {
        if !m.is_empty() {
            let _ = writeln!(err, "{progname}: {m}");
        }
    }
    match mode {
        ProgMode::Owping | ProgMode::Twping => {
            let twoway = mode.twoway();
            let _ = writeln!(
                err,
                "usage: {progname} [arguments] testaddr [servaddr]\n[arguments] are as follows: "
            );
            let _ = writeln!(err);
            let _ = writeln!(err, "   -h             print this message and exit");
            let _ = writeln!(err);
            print_test_args(twoway, &mut err);
            let _ = writeln!(err);
            print_conn_args(twoway, &mut err);
            let _ = writeln!(err);
            print_output_args(twoway, &mut err);
        },
        ProgMode::Owstats => {
            let _ = writeln!(
                err,
                "usage: {progname} [arguments] sessionfile [sessionfile]*\n[arguments] are as follows: "
            );
            let _ = writeln!(err);
            let _ = writeln!(err, "   -h             print this message and exit");
            let _ = writeln!(err);
            print_output_args(false, &mut err);
        },
        ProgMode::Owfetch => {
            let _ = writeln!(
                err,
                "usage: {progname} [arguments] servaddr [SID savefile]+\n[arguments] are as follows: "
            );
            let _ = writeln!(err);
            let _ = writeln!(err, "   -h             print this message and exit");
            let _ = writeln!(err);
            print_conn_args(false, &mut err);
            let _ = writeln!(err);
            print_output_args(false, &mut err);
        },
        ProgMode::Owup => {
            let _ = writeln!(
                err,
                "usage: {progname} [arguments] servaddr\n[arguments] are as follows: "
            );
            let _ = writeln!(err);
            let _ = writeln!(err, "   -h             print this message and exit");
            let _ = writeln!(err);
            print_conn_args(false, &mut err);
        },
    }
    let _ = writeln!(err);
    let _ = writeln!(err, "Version: {PACKAGE_VERSION}");
    let _ = writeln!(err);
}

/// `usage` from `owping.c` (owping/twping variants).
pub fn usage(progname: &str, msg: Option<&str>, twoway: bool) {
    let mode = if twoway {
        ProgMode::Twping
    } else if progname == "owstats" {
        ProgMode::Owstats
    } else if progname == "owfetch" {
        ProgMode::Owfetch
    } else if progname == "owup" {
        ProgMode::Owup
    } else {
        ProgMode::Owping
    };
    usage_for_mode(mode, msg);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_owping_mentions_from_to() {
        let mut buf = Vec::new();
        print_test_args(false, &mut buf);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("-f | -F"));
        assert!(s.contains("-t | -T"));
    }

    #[test]
    fn usage_twping_hides_from_to_flags() {
        let mut buf = Vec::new();
        print_test_args(true, &mut buf);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("-F file"));
        assert!(!s.contains("-t | -T"));
        assert!(!s.contains("-f | -F"));
    }

    #[test]
    fn raw_help_differs_ow_vs_tw() {
        let mut ow = Vec::new();
        let mut tw = Vec::new();
        print_output_args(false, &mut ow);
        print_output_args(true, &mut tw);
        let ow = String::from_utf8(ow).unwrap();
        let tw = String::from_utf8(tw).unwrap();
        assert!(ow.contains("SEQNO STIME"));
        assert!(tw.contains("SSEQ STIME"));
    }

    #[test]
    fn effective_defaults_both_directions() {
        let a = Args::parse_from(["owping", "host.example"]);
        assert!(a.effective_from(false));
        assert!(a.effective_to(false));
        assert!(a.effective_from(true));
        assert!(!a.effective_to(true));
        assert_eq!(a.test_host(), "host.example");
        assert_eq!(a.remote_serv(), "host.example");
    }

    #[test]
    fn progmode_from_basename() {
        assert_eq!(ProgMode::from_progname("owstats"), ProgMode::Owstats);
        assert_eq!(
            ProgMode::from_progname("/usr/bin/owfetch"),
            ProgMode::Owfetch
        );
        assert_eq!(ProgMode::from_progname("twping"), ProgMode::Twping);
        assert_eq!(ProgMode::from_progname("owping"), ProgMode::Owping);
    }

    #[test]
    fn servaddr_separate_positional() {
        let a = Args::parse_from(["owping", "test.host", "ctrl.host"]);
        assert_eq!(a.test_host(), "test.host");
        assert_eq!(a.remote_serv(), "ctrl.host");
    }

    #[test]
    fn usage_owstats_and_owfetch() {
        // Smoke: modes print distinct usage lines (no panic).
        usage_for_mode(ProgMode::Owstats, Some(""));
        usage_for_mode(ProgMode::Owfetch, None);
        usage_for_mode(ProgMode::Owup, None);
    }

    #[test]
    fn printfiles_and_percentile_flags_parse() {
        let a = Args::parse_from(["owping", "-p", "-a", "50,95", "-N", "10", "-d", "/tmp", "h"]);
        assert!(a.printfiles);
        assert_eq!(a.percentiles.as_deref(), Some("50,95"));
        assert_eq!(a.num_bucket_packets, 10);
        assert_eq!(a.savedir.as_deref(), Some("/tmp"));
    }
}
