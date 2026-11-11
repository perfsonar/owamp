//! Syslog helpers — port of `I2ErrLogSyslog` setup used by owampd/powstream.

use std::io;

use tracing_subscriber::fmt::MakeWriter;

/// Options for `openlog(3)` + tracing filter (C `-e` / `-g` / `-R`).
#[derive(Clone, Debug)]
pub struct SyslogOptions {
    pub ident: String,
    pub facility: i32,
    /// Mapped from `OWPReportLevelByName` (`None` → info).
    pub report_level: Option<i32>,
    /// `-R`: only syslog, not STDERR (`LOG_PERROR` cleared).
    pub syslog_only: bool,
    pub verbose: bool,
}

impl Default for SyslogOptions {
    fn default() -> Self {
        Self {
            ident: "owamp".into(),
            facility: libc::LOG_DAEMON,
            report_level: None,
            syslog_only: false,
            verbose: false,
        }
    }
}

/// `openlog` + install a tracing subscriber that mirrors C daemon logging.
pub fn init_logging(opt: &SyslogOptions) {
    let ident = std::ffi::CString::new(opt.ident.as_str()).unwrap_or_default();
    let mut logopt = libc::LOG_PID;
    if !opt.syslog_only {
        logopt |= libc::LOG_PERROR;
    }
    unsafe {
        libc::openlog(ident.as_ptr(), logopt, opt.facility);
    }

    let filter = if opt.verbose {
        "debug".to_string()
    } else if let Some(lvl) = opt.report_level {
        match lvl {
            0 => "off".into(),
            3 => "error".into(),
            4 => "warn".into(),
            7 | 8 => "debug".into(),
            _ => "info".into(),
        }
    } else {
        "info".into()
    };

    let env = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter));

    if opt.syslog_only {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(env)
            .with_writer(SyslogMakeWriter)
            .with_ansi(false)
            .with_target(false)
            .try_init();
    } else {
        // STDERR via LOG_PERROR from openlog; tracing also goes to stderr for structure.
        let _ = tracing_subscriber::fmt()
            .with_env_filter(env)
            .with_writer(io::stderr)
            .with_target(false)
            .try_init();
    }
}

/// Forwards tracing lines to `syslog(3)`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SyslogMakeWriter;

impl<'a> MakeWriter<'a> for SyslogMakeWriter {
    type Writer = SyslogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        SyslogWriter
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SyslogWriter;

impl io::Write for SyslogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
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

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
