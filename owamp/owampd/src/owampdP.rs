//! Private Daemon-Typen — Port von `owampdP.h` + Config-Laden aus `owampd.c`.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context as AnyhowContext, Result};
use owamp::context::PortRange;

/// Default-Conf-Dateiname (`OWAMPD_CONF_FILE`).
#[must_use]
pub const fn conf_file(twamp: bool) -> &'static str {
    if twamp {
        "twamp-server.conf"
    } else {
        "owamp-server.conf"
    }
}

#[must_use]
pub const fn file_prefix(twamp: bool) -> &'static str {
    if twamp {
        "twamp-server"
    } else {
        "owamp-server"
    }
}

#[must_use]
pub fn pid_file_name(twamp: bool) -> String {
    format!("{}.pid", file_prefix(twamp))
}

#[must_use]
pub fn info_file_name(twamp: bool) -> String {
    format!("{}.info", file_prefix(twamp))
}

#[must_use]
pub const fn default_control_timeout(twamp: bool) -> u32 {
    if twamp {
        900
    } else {
        1_800
    }
}

/// `owampd_opts` aus `owampdP.h`.
#[derive(Clone, Debug)]
pub struct OwampdOpts {
    pub verbose: bool,
    pub help: bool,
    pub cwd: PathBuf,
    pub confdir: Option<PathBuf>,
    pub vardir: Option<PathBuf>,
    pub passwd: Option<PathBuf>,
    pub datadir: Option<PathBuf>,
    pub authmode: Option<String>,
    pub auth_mode: u32,
    pub srcnode: Option<String>,
    pub portspec: Option<PortRange>,
    pub user: Option<String>,
    pub group: Option<String>,
    pub allowroot: bool,
    pub diskfudge: f64,
    pub dieby: u32,
    pub controltimeout: u32,
    pub testtimeout: Option<u32>,
    pub pbkdf2_count: Option<u32>,
    pub maxcontrolsessions: u32,
    pub daemon: bool,
    pub set_end_delay: bool,
    pub end_delay: f64,
    pub facility: Option<String>,
    pub loglevel: Option<String>,
    /// When true, tracing goes only via syslog (no stderr subscriber).
    pub syslog_only: bool,
    /// `-w` / `OWPChildWait`.
    pub childwait: bool,
}

impl OwampdOpts {
    #[must_use]
    pub fn defaults(twamp: bool) -> Self {
        Self {
            verbose: false,
            help: false,
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            confdir: None,
            vardir: None,
            passwd: Some(PathBuf::from("passwd.conf")),
            datadir: None,
            authmode: None,
            auth_mode: 0,
            srcnode: None,
            portspec: None,
            user: None,
            group: None,
            allowroot: false,
            diskfudge: 1.0,
            dieby: 5,
            controltimeout: default_control_timeout(twamp),
            testtimeout: None,
            pbkdf2_count: None,
            maxcontrolsessions: 0,
            daemon: true,
            set_end_delay: false,
            end_delay: 0.0,
            facility: None,
            loglevel: None,
            syslog_only: false,
            childwait: false,
        }
    }

    pub fn resolve_dirs(&mut self) {
        if self.vardir.is_none() {
            self.vardir = Some(self.cwd.clone());
        }
        if self.confdir.is_none() {
            self.confdir = Some(self.cwd.clone());
        }
        if self.datadir.is_none() {
            self.datadir = Some(self.cwd.clone());
        }
    }
}

impl Default for OwampdOpts {
    fn default() -> Self {
        Self::defaults(false)
    }
}

/// Port-Range wie `parse_ports` in `owampd.c`.
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn parse_ports(pspec: &str) -> Result<Option<PortRange>> {
    let mut range = PortRange::default();
    if !owamp::api::parse_port_range(pspec, &mut range) {
        bail!("Invalid port-range: \"{pspec}\"");
    }
    // Ephemeral 0-0 → nicht setzen
    if range.high == 0 && range.low == 0 {
        return Ok(None);
    }
    Ok(Some(range))
}

/// `LoadConfig` — liest `owamp-server.conf` / `twamp-server.conf`.
///
/// Fehlende Default-Conf (ohne explizites `-c`) ist ok; explizites confdir
/// ohne Datei ist ein Fehler.
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn load_config(opts: &mut OwampdOpts, twamp: bool) -> Result<()> {
    let name = conf_file(twamp);
    let conf_path = opts
        .confdir
        .as_ref()
        .map_or_else(|| PathBuf::from(name), |dir| dir.join(name));

    let file = match File::open(&conf_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if opts.confdir.is_some() {
                return Err(e).with_context(|| format!("Unable to open {}", conf_path.display()));
            }
            return Ok(());
        },
        Err(e) => {
            return Err(e).with_context(|| format!("Unable to open {}", conf_path.display()));
        },
    };

    let reader = BufReader::new(file);
    for (lineno, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("{}:{}", conf_path.display(), lineno + 1))?;
        let line = strip_conf_comment(&line);
        if line.is_empty() {
            continue;
        }
        let (key, val) = split_conf_kv(&line).ok_or_else(|| {
            anyhow::anyhow!(
                "{}:{} Problem parsing conffile",
                conf_path.display(),
                lineno + 1
            )
        })?;
        apply_conf_var(opts, twamp, key, val).with_context(|| {
            format!(
                "{}:{} Problem parsing conffile (key={key})",
                conf_path.display(),
                lineno + 1
            )
        })?;
    }
    Ok(())
}

fn strip_conf_comment(line: &str) -> String {
    let mut s = line;
    if let Some(i) = s.find('#') {
        s = &s[..i];
    }
    s.trim().to_string()
}

fn split_conf_kv(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    if let Some((k, v)) = line.split_once('=') {
        let k = k.trim();
        let v = v.trim().trim_matches('"');
        if k.is_empty() {
            return None;
        }
        return Some((k, v));
    }
    let mut parts = line.split_whitespace();
    let k = parts.next()?;
    let v = parts.next().unwrap_or("");
    Some((k, v))
}

fn apply_conf_var(opts: &mut OwampdOpts, twamp: bool, key: &str, val: &str) -> Result<()> {
    let k = key.to_ascii_lowercase();
    match k.as_str() {
        "facility" => opts.facility = Some(val.to_string()),
        "loglevel" => opts.loglevel = Some(val.to_string()),
        "loglocation" => { /* tracing spans — accepted for parity */ },
        "rootfolly" => opts.allowroot = true,
        "datadir" => opts.datadir = Some(PathBuf::from(val)),
        "user" => opts.user = Some(val.to_string()),
        "group" => opts.group = Some(val.to_string()),
        "verbose" => opts.verbose = true,
        "authmode" => opts.authmode = Some(val.to_string()),
        "srcnode" => opts.srcnode = Some(val.to_string()),
        "testports" => {
            opts.portspec = parse_ports(val)?;
        },
        "vardir" => opts.vardir = Some(PathBuf::from(val)),
        "diskfudge" if !twamp => {
            let tdbl: f64 = val.parse().context("diskfudge")?;
            if !(1.0..=10.0).contains(&tdbl) {
                bail!("Invalid diskfudge \"{tdbl}\": valid values 1.0<=diskfudge<=10.0");
            }
            opts.diskfudge = tdbl;
        },
        "dieby" => {
            opts.dieby = val.parse().context("dieby")?;
        },
        "controltimeout" => {
            opts.controltimeout = val.parse().context("controltimeout")?;
        },
        "pbkdf2_count" => {
            opts.pbkdf2_count = Some(val.parse().context("pbkdf2_count")?);
        },
        "enddelay" => {
            let tdbl: f64 = val.parse().context("enddelay")?;
            if tdbl < 0.0 {
                bail!("Invalid enddelay \"{tdbl}\": positive value expected");
            }
            opts.set_end_delay = true;
            opts.end_delay = tdbl;
        },
        "maxcontrolsessions" => {
            opts.maxcontrolsessions = val.parse().context("maxcontrolsessions")?;
        },
        "testtimeout" if twamp => {
            opts.testtimeout = Some(val.parse().context("testtimeout")?);
        },
        "diskfudge" if twamp => {
            // ignored for TWAMP like C `#ifndef TWAMP`
        },
        "testtimeout" if !twamp => {
            // ignored for OWAMP
        },
        _ => bail!("Unknown key={key}"),
    }
    Ok(())
}

/// Syslog + tracing setup (`I2ErrLogSyslog` / `-e` / conf `facility`+`loglevel`).
pub fn init_logging(opts: &OwampdOpts, twamp: bool) {
    let facility = opts
        .facility
        .as_deref()
        .and_then(owamp::syslog_facility_by_name)
        .unwrap_or(libc::LOG_DAEMON);
    let report_level = opts
        .loglevel
        .as_deref()
        .and_then(owamp::report_level_by_name);
    let ident = if twamp { "twampd" } else { "owampd" };
    owamp::syslog::init_logging(&owamp::syslog::SyslogOptions {
        ident: ident.into(),
        facility,
        report_level,
        syslog_only: opts.syslog_only,
        verbose: opts.verbose,
    });
}

/// Legacy helper kept for callers that only need a filter.
pub fn init_tracing(verbose: bool, loglevel: Option<&str>) {
    let mut opts = OwampdOpts::defaults(false);
    opts.verbose = verbose;
    opts.loglevel = loglevel.map(str::to_string);
    init_logging(&opts, false);
}

///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn ensure_dir(path: &Path) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(path).with_context(|| format!("mkdir {}", path.display()))
}
