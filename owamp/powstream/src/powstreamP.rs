//! Application context and constants — port of `powstreamP.h` + CLI defaults.

use owamp::api::PortRange;
use owamp::{OWP_MODE_AUTHENTICATED, OWP_MODE_ENCRYPTED, OWP_MODE_OPEN};

/// Bound of the RTT estimate used when scheduling the next session start (seconds).
pub const SETUP_ESTIMATE: u32 = 10;

pub const POWLOCK: &str = ".powlock";
#[allow(dead_code)]
pub const POWTMPFILEFMT: &str = "pow.XXXXXX";
pub const POW_INC_EXT: &str = ".i";
pub const POW_SUM_EXT: &str = ".sum";

pub const MAX_PADDING_SIZE: u32 = 0xffff;
pub const MAX_PASSPROMPT: usize = 256;

/// Command-line options (`powapp_trec.opt`).
#[derive(Debug, Clone)]
pub struct Options {
    pub v4only: bool,
    pub v6only: bool,
    pub srcaddr: Option<String>,
    pub interface: Option<String>,
    pub authmode: Option<String>,
    pub identity: Option<String>,
    pub pffile: Option<String>,

    pub num_packets: u32,
    pub loss_threshold: f64,
    pub mean_wait: f64,
    pub padding: u32,
    pub sender: bool,
    pub port_range: PortRange,

    pub savedir: Option<String>,
    pub printfiles: bool,
    pub display_unix_ts: bool,
    pub verbose: u32,
    pub bucket_width: f64,
    pub num_bucket_packets: u32,
    pub delay_start: u32,
    pub retry_delay: u32,

    pub set_end_delay: bool,
    pub end_delay: f64,

    /// Syslog facility (`-e`), default `LOG_USER`.
    pub syslog_facility: i32,
    /// Report level from `-g` (`OWPReportLevelByName`); `None` → INFO.
    pub syslog_report_level: Option<i32>,
    /// `-R`: only syslog, not STDERR (`LOG_PERROR` cleared).
    pub syslog_only: bool,
    /// `-w` / `OWPChildWait` — pause endpoint workers for debugger attach.
    pub childwait: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            v4only: false,
            v6only: false,
            srcaddr: None,
            interface: None,
            authmode: None,
            identity: None,
            pffile: None,
            num_packets: 300,
            loss_threshold: 10.0,
            mean_wait: 0.1,
            padding: 0,
            sender: false,
            port_range: PortRange {
                low: 8_760,
                high: 9_960,
            },
            savedir: None,
            printfiles: false,
            display_unix_ts: false,
            verbose: 0,
            bucket_width: 0.0001,
            num_bucket_packets: 0,
            delay_start: 0,
            retry_delay: 60,
            set_end_delay: false,
            end_delay: 0.0,
            syslog_facility: libc::LOG_USER,
            syslog_report_level: None,
            syslog_only: false,
            childwait: false,
        }
    }
}

/// Full application context (`powapp_trec`).
#[derive(Debug, Clone)]
pub struct AppCtx {
    pub opt: Options,
    pub remote_test: String,
    pub remote_serv: String,
    pub auth_mode: u32,
}

impl AppCtx {
    pub const fn new(opt: Options, remote_test: String, remote_serv: String) -> Self {
        Self {
            opt,
            remote_test,
            remote_serv,
            auth_mode: 0,
        }
    }
}

/// Decode `-A` authmode string into a mode mask (default: all modes).
pub fn decode_auth_mode(authmode: Option<&str>) -> Result<u32, String> {
    let Some(s) = authmode else {
        return Ok(OWP_MODE_OPEN | OWP_MODE_AUTHENTICATED | OWP_MODE_ENCRYPTED);
    };
    let mut mode = 0u32;
    for c in s.chars() {
        match c.to_ascii_uppercase() {
            'O' => mode |= OWP_MODE_OPEN,
            'A' => mode |= OWP_MODE_AUTHENTICATED,
            'E' => mode |= OWP_MODE_ENCRYPTED,
            other => return Err(format!("Invalid -A authmode character '{other}'")),
        }
    }
    Ok(mode)
}

/// Format an OWAMP Num64 timestamp as zero-padded decimal (`OWP_TSTAMPFMT`).
pub fn format_tstamp(n: owamp::OwampNum64) -> String {
    format!("{:020}", n.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use owamp::{OWP_MODE_AUTHENTICATED, OWP_MODE_ENCRYPTED, OWP_MODE_OPEN};

    #[test]
    fn decode_auth_mode_default_all() {
        let m = decode_auth_mode(None).unwrap();
        assert_eq!(
            m,
            OWP_MODE_OPEN | OWP_MODE_AUTHENTICATED | OWP_MODE_ENCRYPTED
        );
    }

    #[test]
    fn decode_auth_mode_subset() {
        assert_eq!(
            decode_auth_mode(Some("AE")).unwrap(),
            OWP_MODE_AUTHENTICATED | OWP_MODE_ENCRYPTED
        );
        assert!(decode_auth_mode(Some("X")).is_err());
    }

    #[test]
    fn format_tstamp_zero_padded() {
        assert_eq!(format_tstamp(owamp::OwampNum64(42)), "00000000000000000042");
    }
}
