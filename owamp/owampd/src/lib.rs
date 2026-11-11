//! Shared library surface for `owampd` / `twampd`.

pub mod fts;
pub mod owampd;
/// `owampdP.h` + LoadConfig
#[allow(non_snake_case)] // C-parity module name (`owampdP.h`)
pub mod owampdP;
pub mod policy;
pub mod signals;
/// `twampd.c` (`#define TWAMP` + include owampd)
pub mod twampd;

pub use owampd::{Daemon, DaemonConfig};
pub use owampdP::OwampdOpts;
pub use policy::Policy;

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Parser;
use tracing::{error, info, warn};

use owamp::context::{
    get_time_of_day, Context as OwpContext, OWP_CHILD_WAIT, OWP_END_DELAY,
    OWP_KEY_DERIVATION_COUNT, OWP_TEST_PORT_RANGE, TWP_TEST_TIMEOUT,
};

#[derive(Debug, Parser)]
#[command(version)]
pub struct Args {
    /// Auth modes: [E]ncrypted,[A]uthenticated,[O]pen ([M]ixed for TWAMP)
    #[arg(short = 'a', long = "authmode")]
    pub authmode: Option<String>,
    /// Configuration directory
    #[arg(short = 'c', long = "confdir")]
    pub confdir: Option<PathBuf>,
    /// Data directory
    #[arg(short = 'd', long = "datadir")]
    pub datadir: Option<PathBuf>,
    /// Syslog facility (`I2ErrLogSyslogFacility`)
    #[arg(short = 'e', long = "facility")]
    pub facility: Option<String>,
    /// Syslog report level: NONE, FATAL, WARN, INFO, DEBUG, ALL (also via conf `loglevel`)
    #[arg(long = "loglevel")]
    pub loglevel: Option<String>,
    /// Allow running as root
    #[arg(short = 'f', long = "allow-root")]
    pub allow_root: bool,
    /// Bind address (host or host:port)
    #[arg(short = 'S', long = "src")]
    pub srcnode: Option<String>,
    /// Verbose output
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
    /// Disk fudge factor
    #[arg(long = "diskfudge")]
    pub diskfudge: Option<f64>,
    /// Control idle timeout (seconds)
    #[arg(long = "control-timeout")]
    pub control_timeout: Option<u32>,
    /// Max concurrent control sessions (0 = unlimited)
    #[arg(long = "max-controls")]
    pub max_controls: Option<u32>,
    /// Var directory for pid/info
    #[arg(short = 'R', long = "vardir")]
    pub vardir: Option<PathBuf>,
    /// Test port range
    #[arg(short = 'P', long = "portrange")]
    pub portrange: Option<String>,
    /// Run as user
    #[arg(short = 'U', long = "user")]
    pub user: Option<String>,
    /// Run as group
    #[arg(short = 'G', long = "group")]
    pub group: Option<String>,
    /// Foreground (do not daemonize) — C `-Z`
    #[arg(short = 'Z', long = "foreground")]
    pub foreground: bool,
    /// DEBUG: pause endpoint workers for debugger attach (`OWPChildWait` / C `-w`)
    #[arg(short = 'w', long = "childwait")]
    pub childwait: bool,
}

///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn parse_bind(src: &str, default_port: u16) -> Result<SocketAddr> {
    if let Ok(sa) = src.parse::<SocketAddr>() {
        return Ok(sa);
    }
    format!("{src}:{default_port}")
        .parse()
        .with_context(|| format!("parse bind address {src:?}"))
}

/// Gemeinsamer Einstieg für `owampd` (`twamp=false`) und `twampd` (`twamp=true`).
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
///
/// # Panics
///
/// Panics if an internal invariant is violated.
pub fn run_server(twamp: bool) -> Result<()> {
    let args = Args::parse();
    let mut opts = OwampdOpts::defaults(twamp);

    // 1) confdir aus CLI vor LoadConfig (wie C: erster getopt-Pass)
    if let Some(c) = args.confdir.clone() {
        opts.confdir = Some(c);
    }

    owampdP::load_config(&mut opts, twamp)?;

    // 2) CLI überschreibt Conf
    if args.verbose {
        opts.verbose = true;
    }
    if args.allow_root {
        opts.allowroot = true;
    }
    if args.foreground {
        opts.daemon = false;
    }
    if let Some(d) = args.datadir {
        opts.datadir = Some(d);
    }
    if let Some(v) = args.vardir {
        opts.vardir = Some(v);
    }
    if let Some(u) = args.user {
        opts.user = Some(u);
    }
    if let Some(g) = args.group {
        opts.group = Some(g);
    }
    if let Some(s) = args.srcnode {
        opts.srcnode = Some(s);
    }
    if let Some(a) = args.authmode {
        opts.authmode = Some(a);
    }
    if let Some(f) = args.facility {
        opts.facility = Some(f);
    }
    if let Some(g) = args.loglevel {
        opts.loglevel = Some(g);
    }
    if args.childwait {
        opts.childwait = true;
    }
    if let Some(df) = args.diskfudge {
        if !(1.0..=10.0).contains(&df) {
            bail!("Invalid diskfudge \"{df}\": valid values 1.0<=diskfudge<=10.0");
        }
        opts.diskfudge = df;
    }
    if let Some(ct) = args.control_timeout {
        opts.controltimeout = ct;
    }
    if let Some(m) = args.max_controls {
        opts.maxcontrolsessions = m;
    }
    if let Some(ref pr) = args.portrange {
        opts.portspec = owampdP::parse_ports(pr)?;
    }

    opts.resolve_dirs();
    owampdP::init_logging(&opts, twamp);
    let file_prefix = owampdP::file_prefix(twamp);
    let confdir = opts.confdir.clone().unwrap();
    let datadir = opts.datadir.clone().unwrap();
    let vardir = opts.vardir.clone().unwrap();

    owampdP::ensure_dir(&datadir)?;
    owampdP::ensure_dir(&vardir)?;
    fts::ensure_datastore(&datadir)
        .with_context(|| format!("ensure datastore {}", datadir.display()))?;

    let pid_path = vardir.join(owampdP::pid_file_name(twamp));
    let pid_file = lock_pid_file(&pid_path)?;

    let ctx = OwpContext::create().context("OWPContext create")?;

    if let Some(pr) = opts.portspec {
        let boxed = Box::new(pr);
        if !ctx.config_set_v(OWP_TEST_PORT_RANGE, Box::into_raw(boxed) as usize) {
            bail!("Unable to set OWPTestPortRange");
        }
    }
    if let Some(n) = opts.pbkdf2_count {
        if !ctx.config_set_u32(OWP_KEY_DERIVATION_COUNT, n) {
            bail!("Can't set OWPKeyDerivationCount");
        }
    }
    if twamp {
        if let Some(n) = opts.testtimeout {
            if !ctx.config_set_u32(TWP_TEST_TIMEOUT, n) {
                bail!("Can't set TWPTestTimeout");
            }
        }
    }
    if opts.set_end_delay {
        let boxed = Box::new(opts.end_delay);
        if !ctx.config_set_v(OWP_END_DELAY, Box::into_raw(boxed) as usize) {
            bail!("Can't set OWPEndDelay");
        }
    }
    if opts.childwait && !ctx.config_set_v(OWP_CHILD_WAIT, 1) {
        bail!("OWPContextConfigSetV(): Unable to set OWPChildWait?!");
    }

    if let Some(ref am) = opts.authmode {
        opts.auth_mode = policy::parse_authmode(am, twamp)?;
    } else {
        opts.auth_mode = policy::default_offered_mode(twamp);
    }

    let policy = policy::policy_install(&ctx, &datadir, &confdir, opts.diskfudge, file_prefix)
        .with_context(|| "load policy")?;

    maybe_raise_nofile(opts.maxcontrolsessions);

    let (setuser, setgroup) = resolve_privdrop(&opts)?;
    if setgroup != 0 && unsafe { libc::setegid(setgroup) } != 0 {
        bail!(
            "Unable to setgid to {:?}: {}",
            opts.group,
            std::io::Error::last_os_error()
        );
    }
    if setuser != 0 && unsafe { libc::seteuid(setuser) } != 0 {
        bail!(
            "Unable to setuid to {:?}: {}",
            opts.user,
            std::io::Error::last_os_error()
        );
    }

    policy::policy_post_install(&policy)?;

    let uptime = get_time_of_day(&ctx)
        .map(|t| t.owptime)
        .ok_or_else(|| anyhow::anyhow!("OWPGetTimeOfDay failed"))?;

    let child_pid = if opts.daemon {
        daemonize()?
    } else {
        let mypid = unsafe { libc::getpid() };
        unsafe {
            if libc::getsid(0) != mypid && libc::setpgid(0, mypid) != 0 {
                bail!("setpgid(): {}", std::io::Error::last_os_error());
            }
        }
        0
    };

    // Root kurz zurück für Pid/Info (und anschließenden privilegierten Bind)
    if setuser != 0 {
        let _ = unsafe { libc::seteuid(libc::getuid()) };
    }
    if setgroup != 0 {
        let _ = unsafe { libc::setegid(libc::getgid()) };
    }

    let record_pid = if opts.daemon {
        child_pid
    } else {
        unsafe { libc::getpid() }
    };

    if record_pid > 0 {
        write_pid_info(&pid_file, &vardir, twamp, record_pid, uptime.0)?;
        if opts.daemon {
            std::process::exit(0);
        }
    }

    // Server-Socket noch mit Root-Rechten (C: NWPServerSockCreate vor setuid)
    // SO_REUSEADDR / dual-stack / listen(BACKLOG) via sapi::*_server_sock_create.
    let (listener, bind) = owampd::create_server_listener(&ctx, opts.srcnode.as_deref(), twamp)?;

    if setgroup != 0 && unsafe { libc::setgid(setgroup) } != 0 {
        bail!("setgid(): {}", std::io::Error::last_os_error());
    }
    if setuser != 0 && unsafe { libc::setuid(setuser) } != 0 {
        bail!("setuid(): {}", std::io::Error::last_os_error());
    }

    signals::install().context("sigaction")?;

    let cfg = DaemonConfig::from_opts(&opts, twamp, bind);

    info!(
        bind = %cfg.bind,
        twamp,
        conf = %confdir.display(),
        data = %datadir.display(),
        var = %vardir.display(),
        "starting {}",
        if twamp { "twampd" } else { "owampd" }
    );

    let daemon = Daemon::new(cfg, policy);
    daemon.run_with_listener(listener)?;
    Ok(())
}

fn lock_pid_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("open({})", path.display()))?;
    let fd = file.as_raw_fd();
    let mut flk: libc::flock = unsafe { std::mem::zeroed() };
    flk.l_type = libc::F_WRLCK as _;
    flk.l_whence = libc::SEEK_SET as _;
    flk.l_start = 0;
    flk.l_len = 0;
    let rc = unsafe { libc::fcntl(fd, libc::F_SETLK, &flk) };
    if rc < 0 {
        bail!(
            "Unable to lock file {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }
    Ok(file)
}

fn write_pid_info(
    pid_file: &File,
    vardir: &Path,
    twamp: bool,
    pid: libc::pid_t,
    uptime: u64,
) -> Result<()> {
    let fd = pid_file.as_raw_fd();
    if unsafe { libc::ftruncate(fd, 0) } != 0 {
        bail!("ftruncate: {}", std::io::Error::last_os_error());
    }
    let mut f = pid_file.try_clone().context("clone pid file")?;
    writeln!(f, "{pid}").context("write pid")?;
    f.flush().context("fflush pid")?;

    let info_path = vardir.join(owampdP::info_file_name(twamp));
    let mut info =
        File::create(&info_path).with_context(|| format!("fopen({})", info_path.display()))?;
    writeln!(info, "START={uptime}")?;
    writeln!(info, "PID={pid}")?;
    Ok(())
}

fn daemonize() -> Result<libc::pid_t> {
    if unsafe { libc::chdir(c"/".as_ptr()) } < 0 {
        bail!("Unable to chdir to /: {}", std::io::Error::last_os_error());
    }
    for rc in 0..3 {
        unsafe {
            let _ = libc::close(rc);
            if libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) != rc {
                bail!(
                    "Unable to reopen fd({rc}): {}",
                    std::io::Error::last_os_error()
                );
            }
        }
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        bail!("Unable to fork: {}", std::io::Error::last_os_error());
    }
    if pid == 0 {
        if unsafe { libc::setsid() } == -1 {
            eprintln!("setsid(): {}", std::io::Error::last_os_error());
            std::process::exit(1);
        }
        return Ok(0);
    }
    Ok(pid)
}

fn resolve_privdrop(opts: &OwampdOpts) -> Result<(libc::uid_t, libc::gid_t)> {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        return Ok((0, 0));
    }

    let mut setuser: libc::uid_t = 0;
    let mut setgroup: libc::gid_t = 0;

    if let Some(ref user) = opts.user {
        setuser = lookup_uid(user)?;
    }
    if setuser == 0 && !opts.allowroot {
        error!("Running as root is folly!");
        error!("Use the -U option! (or allow root with the -f option)");
        bail!("refusing to run as root without -f/--allow-root (or -U/--user)");
    }
    if let Some(ref group) = opts.group {
        setgroup = lookup_gid(group)?;
        if setgroup == 0 {
            bail!("Invalid user/-G option: {group}");
        }
    }
    Ok((setuser, setgroup))
}

fn lookup_uid(user: &str) -> Result<libc::uid_t> {
    if let Some(rest) = user.strip_prefix('-') {
        let uid: libc::uid_t = rest.parse().context("uid")?;
        let pw = unsafe { libc::getpwuid(uid) };
        if pw.is_null() {
            bail!("Invalid user/-U option: {user}");
        }
        return Ok(uid);
    }
    let c = std::ffi::CString::new(user).context("user")?;
    let pw = unsafe { libc::getpwnam(c.as_ptr()) };
    if pw.is_null() {
        bail!("Invalid user/-U option: {user}");
    }
    Ok(unsafe { (*pw).pw_uid })
}

fn lookup_gid(group: &str) -> Result<libc::gid_t> {
    if let Some(rest) = group.strip_prefix('-') {
        let gid: libc::gid_t = rest.parse().context("gid")?;
        let gr = unsafe { libc::getgrgid(gid) };
        if gr.is_null() {
            bail!("Invalid user/-G option: {group}");
        }
        return Ok(gid);
    }
    let c = std::ffi::CString::new(group).context("group")?;
    let gr = unsafe { libc::getgrnam(c.as_ptr()) };
    if gr.is_null() {
        bail!("Invalid user/-G option: {group}");
    }
    Ok(unsafe { (*gr).gr_gid })
}

fn maybe_raise_nofile(max_sessions: u32) {
    if max_sessions == 0 {
        return;
    }
    unsafe {
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) != 0 {
            warn!("getrlimit(): {}", std::io::Error::last_os_error());
            return;
        }
        let want = u64::from(max_sessions).saturating_mul(2);
        if rlim.rlim_cur < want && rlim.rlim_cur != rlim.rlim_max {
            rlim.rlim_cur = want.min(rlim.rlim_max);
            if libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) != 0 {
                warn!("setrlimit(): {}", std::io::Error::last_os_error());
            }
        }
    }
}
