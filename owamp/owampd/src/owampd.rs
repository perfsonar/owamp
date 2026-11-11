//! Core listen/accept/request loop — Port der Control-Pfad-Logik aus `owampd.c`.
//!
//! ## Fork approximation
//! C `NewConnection` uses `fork()` + `socketpair`. Safe Rust approximates the
//! child with a dedicated thread and keeps the same socketpair IPC so the
//! parent still brokers policy resources via `CheckFD` / `CleanPipes`.
//! Real `fork`/`setuid` per child is an intentional gap (daemon-wide privdrop
//! remains in `lib.rs`).
//!
//! ## TWAMP vs OWAMP
//! Same source with a runtime `twamp` flag (C uses `#define TWAMP` + include).
//! Listen uses `OWPServerSockCreate` / `TWPServerSockCreate`; the child request
//! loop gates `Test`/`TestTw`/`FetchSession` and the post-wait `StopSessions`
//! exchange exactly like the `#ifdef TWAMP` branches in C.

use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{bail, Context as AnyhowContext, Result};
use tracing::{error, info, warn};

use owamp::api::{
    read_request_type, stop_sessions, stop_sessions_wait as api_stop_sessions_wait, RequestType,
};
use owamp::context::{
    get_time_of_day, AcceptType, Addr, Context, Control, ErrSeverity, PortRange, OWP_END_DELAY,
    OWP_KEY_DERIVATION_COUNT, OWP_TEST_PORT_RANGE, TWP_TEST_TIMEOUT,
};
use owamp::owamp::OwampNum64;
use owamp::owampP::{OWP_CONTROL_SERVICE_NAME, OWP_MODE_OPEN, TWP_CONTROL_SERVICE_NAME};
use owamp::sapi::{
    control_accept, process_fetch_session, process_start_sessions, process_test_request,
    process_test_request_tw, server_sock_create, twp_control_accept, twp_server_sock_create,
    unexpected_request_type,
};

use crate::owampdP::OwampdOpts;
use crate::policy::{
    self, allow_open_mode, read_class, read_query, resource_demand, send_response, LimRec, Policy,
    PolicyNode, OWPD_MESG_DENIED, OWPD_MESG_OK,
};
use crate::signals;

#[derive(Clone, Debug)]
pub struct DaemonConfig {
    pub bind: SocketAddr,
    pub twamp: bool,
    pub auth_mode: u32,
    pub control_timeout: Duration,
    pub max_control_sessions: u32,
    pub verbose: bool,
    pub dieby: u32,
    pub portspec: Option<PortRange>,
    pub pbkdf2_count: Option<u32>,
    pub testtimeout: Option<u32>,
    pub end_delay: Option<f64>,
}

impl DaemonConfig {
    #[must_use]
    pub const fn service_port(twamp: bool) -> u16 {
        if twamp {
            862
        } else {
            861
        }
    }

    #[must_use]
    pub const fn service_name(twamp: bool) -> &'static str {
        if twamp {
            TWP_CONTROL_SERVICE_NAME
        } else {
            OWP_CONTROL_SERVICE_NAME
        }
    }

    #[must_use]
    pub fn from_opts(opts: &OwampdOpts, twamp: bool, bind: SocketAddr) -> Self {
        Self {
            bind,
            twamp,
            auth_mode: opts.auth_mode,
            control_timeout: Duration::from_secs(u64::from(opts.controltimeout)),
            max_control_sessions: opts.maxcontrolsessions,
            verbose: opts.verbose,
            dieby: opts.dieby,
            portspec: opts.portspec,
            pbkdf2_count: opts.pbkdf2_count,
            testtimeout: opts.testtimeout,
            end_delay: if opts.set_end_delay {
                Some(opts.end_delay)
            } else {
                None
            },
        }
    }
}

/// Split `srcnode` (`host`, `host:port`, or `SocketAddr`) like C `I2AddrByNode`.
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn split_srcnode(src: &str, default_port: u16) -> Result<(String, u16)> {
    if let Ok(sa) = src.parse::<SocketAddr>() {
        return Ok((sa.ip().to_string(), sa.port()));
    }
    // host:port (IPv4 / hostname) — avoid treating bare IPv6 as host:port
    if let Some((host, port_s)) = src.rsplit_once(':') {
        if !host.is_empty() && !host.contains(':') {
            if let Ok(port) = port_s.parse::<u16>() {
                return Ok((host.to_string(), port));
            }
        }
    }
    Ok((src.to_string(), default_port))
}

/// `NWPServerSockCreate` — `SO_REUSEADDR`, dual-stack prefer, `listen(BACKLOG)`.
///
/// Returns a owned `TcpListener` and the bound address for logging/config.
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn create_server_listener(
    ctx: &Context,
    srcnode: Option<&str>,
    twamp: bool,
) -> Result<(TcpListener, SocketAddr)> {
    let def_port = DaemonConfig::service_port(twamp);
    let def_serv = DaemonConfig::service_name(twamp);

    let addr = match srcnode {
        None => None,
        Some(src) => {
            let (host, port) = split_srcnode(src, def_port)?;
            let service = if port == def_port {
                def_serv.to_string()
            } else {
                port.to_string()
            };
            let mut a = Addr::by_node(&host, Some(&service));
            // Seed resolved sockaddrs when host is literal / already known.
            if a.addr_info(Some(def_serv)).is_none() {
                bail!("Invalid source address specified: {src}");
            }
            Some(a)
        },
    };

    let mut err = ErrSeverity::Ok;
    let mut listen_addr = if twamp {
        twp_server_sock_create(ctx, addr, &mut err)
    } else {
        server_sock_create(ctx, addr, &mut err)
    }
    .ok_or_else(|| anyhow::anyhow!("Unable to create server socket. Exiting... ({err:?})"))?;

    let fd = listen_addr
        .fd()
        .ok_or_else(|| anyhow::anyhow!("server socket missing fd"))?;
    // Transfer fd ownership to TcpListener (prevent Addr::Drop close).
    listen_addr.fd_close = false;
    listen_addr.fd = None;
    drop(listen_addr);

    // SAFETY: fd is a freshly listen()'d SOCK_STREAM from ServerSockCreate.
    let listener = unsafe { TcpListener::from_raw_fd(fd) };
    let bind = listener
        .local_addr()
        .context("local_addr after ServerSockCreate")?;
    Ok((listener, bind))
}

/// `ChldStateRec` — parent-side bookkeeping for one control child.
struct ChldState {
    policy: Arc<Policy>,
    /// Synthetic id standing in for C `pid_t` under the thread approximation.
    id: u64,
    /// Parent end of the socketpair; `None` after `ClosePipes`.
    fd: Option<UnixStream>,
    node: Option<Arc<PolicyNode>>,
    #[allow(dead_code)]
    used: [LimRec; 2],
    handle: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
}

impl ChldState {
    fn pipe_fd(&self) -> Option<RawFd> {
        self.fd.as_ref().map(std::os::fd::AsRawFd::as_raw_fd)
    }
}

/// Parent tables + poll set — mirrors C `pidtable` / `fdtable` / `pollfd[]`.
struct ChildTables {
    by_id: HashMap<u64, Arc<Mutex<ChldState>>>,
    by_fd: HashMap<i32, Arc<Mutex<ChldState>>>,
    /// pollfds[0] = listen; rest = child pipes (C layout).
    pollfds: Vec<libc::pollfd>,
    control_sessions: u32,
}

impl ChildTables {
    fn new(listen_fd: RawFd) -> Self {
        Self {
            by_id: HashMap::new(),
            by_fd: HashMap::new(),
            pollfds: vec![libc::pollfd {
                fd: listen_fd,
                events: libc::POLLIN,
                revents: 0,
            }],
            control_sessions: 0,
        }
    }
}

pub struct Daemon {
    pub cfg: DaemonConfig,
    pub policy: Arc<Policy>,
    pub stop: Arc<AtomicBool>,
    pub active: Arc<AtomicU32>,
    next_id: AtomicU64,
    tables: Mutex<ChildTables>,
}

impl Daemon {
    pub fn new(cfg: DaemonConfig, policy: Arc<Policy>) -> Self {
        Self {
            cfg,
            policy,
            stop: Arc::new(AtomicBool::new(false)),
            active: Arc::new(AtomicU32::new(0)),
            next_id: AtomicU64::new(1),
            // Placeholder listen fd; replaced in `run_with_listener`.
            tables: Mutex::new(ChildTables::new(-1)),
        }
    }

    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        signals::request_exit();
    }

    pub fn apply_ctx_config(&self, ctx: &Context) {
        apply_cfg_to_ctx(&self.cfg, ctx);
    }

    /// `listener` bereits gebunden (idealerweise vor setuid für Ports <1024).
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying operation fails.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant is violated.
    pub fn run_with_listener(&self, listener: TcpListener) -> Result<()> {
        let prog = if self.cfg.twamp { "twampd" } else { "owampd" };
        info!(
            addr = %self.cfg.bind,
            twamp = self.cfg.twamp,
            "listening for control connections"
        );

        let listen_fd = listener.as_raw_fd();
        {
            let mut t = self.tables.lock().unwrap();
            *t = ChildTables::new(listen_fd);
        }

        let boot_ctx = Context::create().context("OWPContext create (uptime)")?;
        self.apply_ctx_config(&boot_ctx);
        let uptime = get_time_of_day(&boot_ctx).map_or(OwampNum64(0), |t| t.owptime);

        // Main loop mirrors C `poll` + `NewConnection` / `CleanPipes` / `ReapChildren`.
        // SIGHUP/USR1/USR2/TERM set exit (C has no in-process config reload).
        while !self.stop.load(Ordering::Relaxed) && !signals::should_exit() {
            let nfound = {
                let mut t = self.tables.lock().unwrap();
                for p in &mut t.pollfds {
                    p.revents = 0;
                }
                let nfds = t.pollfds.len() as libc::nfds_t;
                let pfds = t.pollfds.as_mut_ptr();
                drop(t);
                unsafe { libc::poll(pfds, nfds, -1) }
            };

            if nfound < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    if signals::should_exit() {
                        break;
                    }
                    self.reap_children();
                    continue;
                }
                error!(error = %err, "select(): {err}");
                break;
            }
            if nfound == 0 {
                continue;
            }

            let listen_ready = {
                let t = self.tables.lock().unwrap();
                !t.pollfds.is_empty() && (t.pollfds[0].revents & libc::POLLIN) != 0
            };

            if listen_ready {
                // C: only NewConnection when listen POLLIN (child pipes deferred).
                self.new_connection(&listener, uptime);
                let mut t = self.tables.lock().unwrap();
                if !t.pollfds.is_empty() {
                    t.pollfds[0].revents = 0;
                }
            } else {
                self.clean_pipes(nfound);
            }

            if signals::should_exit() {
                break;
            }
            self.reap_children();
        }

        info!("{prog}: exiting...");
        // C: I2AddrFree(listenaddr); fds[0].fd = -1;
        {
            let mut t = self.tables.lock().unwrap();
            if !t.pollfds.is_empty() {
                t.pollfds[0].fd = -1;
            }
        }
        drop(listener);
        self.shutdown_children();
        info!("{prog}: exited.");
        Ok(())
    }

    ///
    /// # Errors
    ///
    /// Returns an error when the underlying operation fails.
    pub fn run(&self) -> Result<()> {
        let listener =
            TcpListener::bind(self.cfg.bind).with_context(|| format!("bind {}", self.cfg.bind))?;
        self.run_with_listener(listener)
    }

    /// `NewConnection` — accept, socketpair, spawn child thread, register pipe.
    fn new_connection(&self, listener: &TcpListener, uptime: OwampNum64) {
        let (stream, peer) = match listener.accept() {
            Ok(x) => x,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                if signals::should_exit() {
                    return;
                }
                self.reap_children();
                return;
            },
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionAborted => return,
            Err(e) => {
                error!(error = %e, "accept failed");
                return;
            },
        };

        {
            let t = self.tables.lock().unwrap();
            if self.cfg.max_control_sessions > 0
                && t.control_sessions.saturating_add(1) > self.cfg.max_control_sessions
            {
                drop(t);
                self.reap_children();
                let t = self.tables.lock().unwrap();
                if self.cfg.max_control_sessions > 0
                    && t.control_sessions.saturating_add(1) > self.cfg.max_control_sessions
                {
                    warn!(
                        %peer,
                        used = t.control_sessions,
                        limit = self.cfg.max_control_sessions,
                        "Resource usage exceeds limits maxcontrolsessions"
                    );
                    drop(stream);
                    return;
                }
            }
        }

        let (parent_pipe, child_pipe) = match UnixStream::pair() {
            Ok(p) => p,
            Err(e) => {
                error!(error = %e, "socketpair failed");
                drop(stream);
                return;
            },
        };

        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let child_stop = Arc::new(AtomicBool::new(false));
        let policy = Arc::clone(&self.policy);
        let stop = Arc::clone(&self.stop);
        let active = Arc::clone(&self.active);
        let cfg = self.cfg.clone();
        let twamp = self.cfg.twamp;
        let timeout = self.cfg.control_timeout;
        let mut mode = self.cfg.auth_mode;

        match allow_open_mode(&self.policy, peer) {
            Ok(false) => {
                info!(%peer, "open mode not allowed for peer class");
                mode &= !OWP_MODE_OPEN;
            },
            Err(_) => warn!(%peer, "policy lookup failed"),
            Ok(true) => {},
        }

        let child_stop_t = Arc::clone(&child_stop);
        let handle = match thread::Builder::new()
            .name(format!("owampd-ctrl-{id}"))
            .spawn(move || {
                // Child side of C NewConnection: keep pipe[1], run control loop.
                let child_fd = child_pipe.as_raw_fd();
                policy::policy_set_broker_fd(&policy, child_fd);
                let rc = (|| -> Result<()> {
                    let ctx = Context::create().context("child Context::create")?;
                    apply_cfg_to_ctx(&cfg, &ctx);
                    policy::attach_policy_hooks(&ctx, Arc::clone(&policy));
                    handle_control(
                        &ctx,
                        stream,
                        peer,
                        mode,
                        uptime,
                        twamp,
                        timeout,
                        &stop,
                        &child_stop_t,
                    )
                })();
                if let Err(e) = rc {
                    error!(%peer, error = %e, "control session failed");
                }
                policy::policy_clear_broker_fd();
                // Drop child_pipe → EOF on parent end (like process exit closing fds).
                drop(child_pipe);
                active.fetch_sub(1, Ordering::SeqCst);
            }) {
            Ok(h) => h,
            Err(e) => {
                error!(error = %e, "spawn control thread failed");
                return;
            },
        };

        self.active.fetch_add(1, Ordering::SeqCst);

        let cstate = Arc::new(Mutex::new(ChldState {
            policy: Arc::clone(&self.policy),
            id,
            fd: Some(parent_pipe),
            node: None,
            used: [LimRec { limit: 0, value: 0 }, LimRec { limit: 0, value: 0 }],
            handle: Some(handle),
            stop: child_stop,
        }));

        if let Err(e) = self.alloc_chld_state(Arc::clone(&cstate)) {
            error!(error = %e, "AllocChldState failed");
            cstate.lock().unwrap().stop.store(true, Ordering::SeqCst);
            let _ = cstate
                .lock()
                .unwrap()
                .handle
                .take()
                .map(std::thread::JoinHandle::join);
            self.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// `AllocChldState` — insert into id/fd maps and poll set.
    ///
    /// Lock order: take `cstate` briefly for (id, fd), then only `tables`.
    fn alloc_chld_state(&self, cstate: Arc<Mutex<ChldState>>) -> Result<()> {
        let (id, fd) = {
            let g = cstate.lock().unwrap();
            let fd = g
                .pipe_fd()
                .ok_or_else(|| anyhow::anyhow!("child pipe missing"))?;
            (g.id, fd)
        };
        let mut t = self.tables.lock().unwrap();
        if t.by_id.insert(id, Arc::clone(&cstate)).is_some() {
            anyhow::bail!("duplicate child id {id}");
        }
        if t.by_fd.insert(fd, Arc::clone(&cstate)).is_some() {
            t.by_id.remove(&id);
            anyhow::bail!("duplicate child fd {fd}");
        }
        t.pollfds.push(libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        });
        t.control_sessions = t.control_sessions.saturating_add(1);
        drop(t);
        Ok(())
    }

    /// `FreeChldState` — close pipe, drop from maps/poll, join thread.
    ///
    /// Lock order: `cstate` only to take fd/handle, then `tables` without holding
    /// `cstate` (avoids deadlock with `alloc_chld_state`).
    fn free_chld_state(&self, cstate: Arc<Mutex<ChldState>>) {
        let (id, sock, handle) = {
            let mut g = cstate.lock().unwrap();
            (g.id, g.fd.take(), g.handle.take())
        };

        if let Some(sock) = sock {
            let fd = sock.as_raw_fd();
            {
                let mut t = self.tables.lock().unwrap();
                if let Some(idx) = t.pollfds.iter().position(|p| p.fd == fd) {
                    // Never remove listen slot 0 by pipe fd coincidence in normal use.
                    if idx > 0 {
                        t.pollfds.remove(idx);
                    }
                } else {
                    warn!(fd, "fd not in poll fds");
                }
                if t.by_fd.remove(&fd).is_none() {
                    warn!(fd, "fd not in fdtable");
                }
            }
            drop(sock);
        }

        {
            let mut t = self.tables.lock().unwrap();
            if t.by_id.remove(&id).is_none() {
                warn!(id, "id not in pidtable");
            }
            t.control_sessions = t.control_sessions.saturating_sub(1);
        }

        if let Some(h) = handle {
            let _ = h.join();
        }
    }

    /// `ReapChildren` — join finished control threads (SIGCHLD analogue).
    fn reap_children(&self) {
        // With threads there is usually no SIGCHLD; still honour the flag like C.
        let _ = signals::got_chld();
        signals::clear_chld();

        let finished: Vec<Arc<Mutex<ChldState>>> = {
            let t = self.tables.lock().unwrap();
            t.by_id
                .values()
                .filter(|c| {
                    c.lock()
                        .unwrap()
                        .handle
                        .as_ref()
                        .is_some_and(std::thread::JoinHandle::is_finished)
                })
                .cloned()
                .collect()
        };
        for c in finished {
            self.free_chld_state(c);
        }
    }

    /// `CleanPipes` — iterate ready child fds through `CheckFD`.
    fn clean_pipes(&self, nready: i32) {
        let ready_fds: Vec<i32> = {
            let t = self.tables.lock().unwrap();
            t.pollfds
                .iter()
                .skip(1)
                .filter(|p| (p.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0)
                .map(|p| p.fd)
                .collect()
        };

        let mut remaining = nready;
        for fd in ready_fds {
            {
                let mut t = self.tables.lock().unwrap();
                if let Some(p) = t.pollfds.iter_mut().find(|p| p.fd == fd) {
                    p.revents = 0;
                }
            }
            remaining -= 1;
            let cstate = {
                let t = self.tables.lock().unwrap();
                t.by_fd.get(&fd).cloned()
            };
            let Some(cstate) = cstate else {
                continue;
            };
            if !Self::check_fd(&cstate) {
                // Invalid IPC → ask child to exit (C: kill(pid, SIGTERM)).
                cstate.lock().unwrap().stop.store(true, Ordering::SeqCst);
            }
            if remaining <= 0 {
                break;
            }
        }
    }

    /// `CheckFD` — first message = class; later = resource query/response.
    /// Returns `false` when the parent should terminate the child (err != 0).
    fn check_fd(cstate: &Arc<Mutex<ChldState>>) -> bool {
        let mut g = cstate.lock().unwrap();
        let Some(ref sock) = g.fd else {
            return true;
        };
        let fd = sock.as_raw_fd();
        let err = if g.node.is_none() {
            match read_class(&g.policy, fd) {
                Ok(node) => {
                    g.node = node;
                    0
                },
                Err(e) => e,
            }
        } else {
            match read_query(fd) {
                Ok((query, lim)) => {
                    let node = g.node.clone().expect("node set");
                    let ok = resource_demand(&g.policy, &node, query, lim);
                    let resp = if ok { OWPD_MESG_OK } else { OWPD_MESG_DENIED };
                    send_response(fd, resp)
                },
                Err(e) => e,
            }
        };

        let id = g.id;
        drop(g);
        if err != 0 {
            warn!(id, "Invalid message from child");
            return false;
        }
        true
    }

    /// `ClosePipes` — optionally `shutdown`, then close parent ends / clear fdtable.
    fn close_pipes(&self, do_shutdown: bool) {
        let children: Vec<Arc<Mutex<ChldState>>> = {
            let t = self.tables.lock().unwrap();
            t.by_id.values().cloned().collect()
        };
        for c in children {
            let sock = c.lock().unwrap().fd.take();
            if let Some(sock) = sock {
                let fd = sock.as_raw_fd();
                if do_shutdown {
                    let _ = unsafe { libc::shutdown(fd, libc::SHUT_RDWR) };
                }
                {
                    let mut t = self.tables.lock().unwrap();
                    t.by_fd.remove(&fd);
                    if let Some(idx) = t.pollfds.iter().position(|p| p.fd == fd) {
                        if idx > 0 {
                            t.pollfds.remove(idx);
                        }
                    }
                }
                drop(sock);
            }
        }
    }

    fn shutdown_children(&self) {
        self.stop.store(true, Ordering::SeqCst);
        signals::request_exit();

        // C: kill(-mypid, SIGTERM); here each child stop flag.
        {
            let t = self.tables.lock().unwrap();
            for c in t.by_id.values() {
                c.lock().unwrap().stop.store(true, Ordering::SeqCst);
            }
        }

        // C: owpd_alrm=0; alarm(opts.dieby); ClosePipes(shutdown=1).
        signals::clear_alarm();
        let dieby = self.cfg.dieby.max(1);
        unsafe {
            libc::alarm(dieby);
        }
        self.close_pipes(true);

        // C: sigsuspend until alarm or all children reaped.
        while !signals::got_alarm() {
            self.reap_children();
            if self.tables.lock().unwrap().by_id.is_empty() {
                unsafe {
                    libc::alarm(0);
                }
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        unsafe {
            libc::alarm(0);
        }

        let remaining = self.tables.lock().unwrap().by_id.len();
        if remaining > 0 {
            warn!(remaining, "Children still alive... Time for brute force.");
            // Detach remaining handles (C: kill(-mypid, SIGKILL)).
            let leftover: Vec<_> = {
                let mut t = self.tables.lock().unwrap();
                let v: Vec<_> = t.by_id.values().cloned().collect();
                t.by_id.clear();
                t.by_fd.clear();
                t.pollfds.truncate(1);
                t.control_sessions = 0;
                v
            };
            for c in leftover {
                let mut g = c.lock().unwrap();
                g.fd.take();
                let _ = g.handle.take(); // detach
            }
        }
    }
}

/// `intcmp` — C compares `dsize` keys; here integer inequality for tests/docs.
#[must_use]
pub const fn intcmp(a: usize, b: usize) -> bool {
    a != b
}

/// `inthash` — C returns `(uint32_t)key.dsize`.
#[must_use]
pub const fn inthash(key: usize) -> u32 {
    key as u32
}

fn apply_cfg_to_ctx(cfg: &DaemonConfig, ctx: &Context) {
    if let Some(pr) = cfg.portspec {
        let boxed = Box::new(pr);
        let _ = ctx.config_set_v(OWP_TEST_PORT_RANGE, Box::into_raw(boxed) as usize);
    }
    if let Some(n) = cfg.pbkdf2_count {
        let _ = ctx.config_set_u32(OWP_KEY_DERIVATION_COUNT, n);
    }
    if let Some(n) = cfg.testtimeout {
        let _ = ctx.config_set_u32(TWP_TEST_TIMEOUT, n);
    }
    if let Some(ed) = cfg.end_delay {
        let boxed = Box::new(ed);
        let _ = ctx.config_set_v(OWP_END_DELAY, Box::into_raw(boxed) as usize);
    }
}

/// Child half of C `NewConnection` — control accept + request server loop.
///
/// Mirrors the `#ifdef TWAMP` request switch and `StartSessions` wait/StopSessions
/// exchange. Socket I/O timeouts approximate C `setitimer(ITIMER_REAL)`.
fn handle_control(
    ctx: &Context,
    stream: TcpStream,
    peer: SocketAddr,
    mode: u32,
    uptime: OwampNum64,
    twamp: bool,
    control_timeout: Duration,
    stop: &AtomicBool,
    child_stop: &AtomicBool,
) -> Result<()> {
    // C: if(owpd_exit) exit(0); owpd_intr = 0;
    if stop.load(Ordering::Relaxed) || child_stop.load(Ordering::Relaxed) || signals::should_exit()
    {
        return Ok(());
    }
    signals::clear_intr();

    stream_refresh_timeout(stream.as_raw_fd(), control_timeout);
    info!(%peer, "accepted control");

    let fd = stream.into_raw_fd();
    let mut err = ErrSeverity::Ok;
    // NWPControlAccept — TWP vs OWP
    let cntrl = if twamp {
        twp_control_accept(ctx, fd, Some(peer), mode, uptime, &mut err)
    } else {
        control_accept(ctx, fd, Some(peer), mode, uptime, &mut err)
    };

    let Some(cntrl_rc) = cntrl else {
        // C: exit(out) — session not accepted
        bail!("control accept rejected ({err:?})");
    };

    let mut msgtype = RequestType::Invalid;
    let mut done = false;
    let mut abnormal = false;

    while !done {
        let mut rc = ErrSeverity::Ok;

        // C: owpd_intr = owpd_alrm = owpd_chld = 0; setitimer(controltimeout)
        signals::reset_request_flags();
        if child_exit_requested(stop, child_stop) {
            abnormal = true;
            break;
        }
        stream_refresh_timeout(fd, control_timeout);

        msgtype = {
            let mut cntrl = cntrl_rc.borrow_mut();
            read_request_type(&mut cntrl, Some(signals::intr_i32_ref()))
        };

        match msgtype {
            // #ifdef TWAMP → OWPReqTestTW only
            RequestType::TestTw if twamp => {
                let mut c = cntrl_rc.borrow_mut();
                rc = process_test_request_tw(&mut c);
            },
            // #ifndef TWAMP → OWPReqTest only
            RequestType::Test if !twamp => {
                let mut c = cntrl_rc.borrow_mut();
                rc = process_test_request(&mut c);
            },
            RequestType::StartSessions => {
                rc = {
                    let mut c = cntrl_rc.borrow_mut();
                    process_start_sessions(&mut c)
                };
                if (rc as i32) < (ErrSeverity::Ok as i32) {
                    // fall through to nextreq checks
                } else {
                    // C: unset timer, wait until sessions complete or exit.
                    stream_clear_timeout(fd);
                    let wait_outcome =
                        start_sessions_wait_loop(&cntrl_rc, stop, child_stop, &mut rc);
                    match wait_outcome {
                        StartWaitOutcome::NextRequest => {
                            // sessions completed inside Wait (StopSessions traded)
                            if (rc as i32) < (ErrSeverity::Warning as i32)
                                || child_exit_requested(stop, child_stop)
                                || signals::got_alarm()
                            {
                                abnormal = true;
                                done = true;
                            }
                            continue;
                        },
                        StartWaitOutcome::Done { abnormal: ab } => {
                            abnormal = ab;
                            done = true;
                            continue;
                        },
                        StartWaitOutcome::GracefulStop => {
                            // #ifndef TWAMP: trade StopSessions after interrupt
                            if !twamp {
                                stream_refresh_timeout(fd, control_timeout);
                                let mut aval = AcceptType::Accept;
                                let mut c = cntrl_rc.borrow_mut();
                                rc =
                                    stop_sessions(&mut c, Some(signals::intr_i32_ref()), &mut aval);
                            }
                            // then fall through to nextreq checks / break on exit
                        },
                    }
                }
            },
            // #ifndef TWAMP
            RequestType::FetchSession if !twamp => {
                let mut c = cntrl_rc.borrow_mut();
                rc = process_fetch_session(&mut c);
            },
            RequestType::SockIntr => {
                // C: case OWPReqSockIntr: break; (rc stays OK)
            },
            RequestType::SockClose => {
                // C: rc = OWPErrFATAL; then OWPControlClose + exit(0)
                let _ = Control::close_rc(cntrl_rc);
                return Ok(());
            },
            RequestType::StopSessions => {
                // unexpected here outside Wait — treat as end
                done = true;
                continue;
            },
            other => {
                // Wrong proto for mode (e.g. Test on TWAMP) lands here too.
                if !matches!(other, RequestType::Invalid) {
                    warn!(?other, "Unexpected message type");
                }
                let mut c = cntrl_rc.borrow_mut();
                rc = unexpected_request_type(&mut c);
            },
        }

        // nextreq:
        if (rc as i32) < (ErrSeverity::Warning as i32) {
            abnormal = true;
            break;
        }
        if child_exit_requested(stop, child_stop) || signals::got_alarm() {
            abnormal = true;
            break;
        }
    }

    let _ = Control::close_rc(cntrl_rc);

    // C: if(owpd_exit) exit(0);  — graceful parent exit is not abnormal
    if signals::should_exit() && !signals::got_int() {
        return Ok(());
    }
    if matches!(msgtype, RequestType::SockClose) {
        return Ok(());
    }
    if abnormal {
        warn!(%peer, "Control session terminated abnormally...");
    }
    Ok(())
}

fn child_exit_requested(stop: &AtomicBool, child_stop: &AtomicBool) -> bool {
    stop.load(Ordering::Relaxed) || child_stop.load(Ordering::Relaxed) || signals::should_exit()
}

enum StartWaitOutcome {
    /// `wstate <= 0` → `goto nextreq`
    NextRequest,
    /// SIGINT or non-graceful exit during wait → `goto done`
    Done { abnormal: bool },
    /// `owpd_exit && wstate == 2` → break wait, maybe `StopSessions`
    GracefulStop,
}

/// C `StartSessions` wait loop around `OWPStopSessionsWait`.
///
/// Uses a short `wake` so the thread-approx child can observe `child_stop`
/// without a real SIGTERM interrupting `poll` (C relies on EINTR).
fn start_sessions_wait_loop(
    cntrl_rc: &std::rc::Rc<std::cell::RefCell<Control>>,
    stop: &AtomicBool,
    child_stop: &AtomicBool,
    rc: &mut ErrSeverity,
) -> StartWaitOutcome {
    // ~250ms in OWPNum64 fixed-point (fraction = 1/4 of 2^32).
    const WAKE_SLICE: OwampNum64 = OwampNum64(1u64 << 30);

    loop {
        *rc = ErrSeverity::Ok;
        // C: owpd_intr = 0 before each Wait; signal handler may set it during poll.
        signals::clear_intr();
        if child_exit_requested(stop, child_stop) || signals::got_int() {
            signals::set_intr();
        }

        let mut aval = AcceptType::Accept;
        let wstate = {
            let mut c = cntrl_rc.borrow_mut();
            let wake = get_time_of_day(&c.ctx).map(|t| t.owptime + WAKE_SLICE);
            api_stop_sessions_wait(
                &mut c,
                wake.as_ref(),
                Some(signals::intr_i32_ref()),
                &mut aval,
                rc,
            )
        };

        if signals::got_int() {
            return StartWaitOutcome::Done { abnormal: true };
        }
        if child_exit_requested(stop, child_stop) {
            // C: if(wstate != 2) goto done; else break (graceful)
            if wstate != 2 {
                return StartWaitOutcome::Done { abnormal: true };
            }
            return StartWaitOutcome::GracefulStop;
        }
        if wstate <= 0 {
            return StartWaitOutcome::NextRequest;
        }
        // wstate == 1 (wake slice) or 2 without exit → keep waiting
    }
}

fn stream_refresh_timeout(fd: i32, timeout: Duration) {
    let secs = timeout.as_secs() as libc::time_t;
    let tv = libc::timeval {
        tv_sec: secs,
        tv_usec: 0,
    };
    unsafe {
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of_val(&tv) as libc::socklen_t,
        );
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of_val(&tv) as libc::socklen_t,
        );
    }
}

/// C: `setitimer` with `it_value.tv_sec = 0` during `StartSessions` wait.
fn stream_clear_timeout(fd: i32) {
    let tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    unsafe {
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of_val(&tv) as libc::socklen_t,
        );
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of_val(&tv) as libc::socklen_t,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owampdP::OwampdOpts;
    use crate::policy::{
        sample_policy_for_tests, send_class, OWPD_LIM_BANDWIDTH, OWPD_MESG_OK, OWPD_MESG_REQUEST,
    };

    #[test]
    fn intcmp_inthash_match_c() {
        assert!(!intcmp(7, 7));
        assert!(intcmp(7, 8));
        assert_eq!(inthash(42), 42);
        assert_eq!(inthash(usize::MAX), u32::MAX);
    }

    #[test]
    fn pipe_class_then_resource_roundtrip() {
        let policy = Arc::new(sample_policy_for_tests());
        let (parent, child) = UnixStream::pair().unwrap();
        let parent_fd = parent.as_raw_fd();
        let child_fd = child.as_raw_fd();

        let node = policy.node("root").unwrap();
        let child_policy = Arc::clone(&policy);
        let thr = thread::spawn(move || {
            policy::policy_set_broker_fd(&child_policy, child_fd);
            let r = send_class(&child_policy, &node);
            assert_eq!(r, OWPD_MESG_OK);
            let r = policy::query(
                &child_policy,
                &child_policy.node("root").unwrap(),
                OWPD_MESG_REQUEST,
                LimRec {
                    limit: OWPD_LIM_BANDWIDTH,
                    value: 100,
                },
            );
            assert_eq!(r, OWPD_MESG_OK);
            policy::policy_clear_broker_fd();
        });

        // Parent: CheckFD-equivalent first (class), then query.
        let got = read_class(&policy, parent_fd).unwrap();
        assert_eq!(got.as_ref().map(|n| n.nodename.as_str()), Some("root"));

        let (q, lim) = read_query(parent_fd).unwrap();
        assert_eq!(q, OWPD_MESG_REQUEST);
        assert_eq!(lim.limit, OWPD_LIM_BANDWIDTH);
        assert_eq!(lim.value, 100);
        let ok = resource_demand(&policy, &policy.node("root").unwrap(), q, lim);
        assert!(ok);
        assert_eq!(send_response(parent_fd, OWPD_MESG_OK), 0);

        thr.join().unwrap();
        drop(parent);
        drop(child);
    }

    #[test]
    fn alloc_free_chld_state_bookkeeping() {
        let policy = Arc::new(sample_policy_for_tests());
        let cfg = DaemonConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            twamp: false,
            auth_mode: 0,
            control_timeout: Duration::from_secs(1),
            max_control_sessions: 0,
            verbose: false,
            dieby: 1,
            portspec: None,
            pbkdf2_count: None,
            testtimeout: None,
            end_delay: None,
        };
        let daemon = Daemon::new(cfg, Arc::clone(&policy));
        {
            let mut t = daemon.tables.lock().unwrap();
            *t = ChildTables::new(3); // fake listen fd
        }

        let (parent_pipe, _child_pipe) = UnixStream::pair().unwrap();
        let cstate = Arc::new(Mutex::new(ChldState {
            policy,
            id: 99,
            fd: Some(parent_pipe),
            node: None,
            used: [LimRec { limit: 0, value: 0 }, LimRec { limit: 0, value: 0 }],
            handle: None,
            stop: Arc::new(AtomicBool::new(false)),
        }));
        daemon.alloc_chld_state(Arc::clone(&cstate)).unwrap();
        {
            let t = daemon.tables.lock().unwrap();
            assert_eq!(t.control_sessions, 1);
            assert_eq!(t.by_id.len(), 1);
            assert_eq!(t.by_fd.len(), 1);
            assert_eq!(t.pollfds.len(), 2);
        }
        daemon.free_chld_state(cstate);
        {
            let t = daemon.tables.lock().unwrap();
            assert_eq!(t.control_sessions, 0);
            assert!(t.by_id.is_empty());
            assert!(t.by_fd.is_empty());
            assert_eq!(t.pollfds.len(), 1);
        }
    }

    #[test]
    fn split_srcnode_host_port_and_socketaddr() {
        let (h, p) = split_srcnode("127.0.0.1:9861", 861).unwrap();
        assert_eq!((h.as_str(), p), ("127.0.0.1", 9_861));
        let (h, p) = split_srcnode("localhost", 861).unwrap();
        assert_eq!((h.as_str(), p), ("localhost", 861));
        let (h, p) = split_srcnode("127.0.0.1:861", 861).unwrap();
        assert_eq!((h.as_str(), p), ("127.0.0.1", 861));
        let sa: SocketAddr = "[::1]:862".parse().unwrap();
        let (h, p) = split_srcnode(&sa.to_string(), 862).unwrap();
        assert_eq!(p, 862);
        assert!(h.contains(':')); // IPv6 textual form
    }

    #[test]
    fn create_server_listener_ephemeral_owamp_and_twamp() {
        let ctx = Context::create().unwrap();
        for twamp in [false, true] {
            let (listener, bind) =
                create_server_listener(&ctx, Some("127.0.0.1:0"), twamp).unwrap();
            assert_eq!(bind.ip().to_string(), "127.0.0.1");
            assert_ne!(bind.port(), 0);
            assert_eq!(listener.local_addr().unwrap(), bind);
            drop(listener);
        }
    }

    #[test]
    fn max_control_sessions_limit_bookkeeping() {
        let policy = Arc::new(sample_policy_for_tests());
        let cfg = DaemonConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            twamp: false,
            auth_mode: 0,
            control_timeout: Duration::from_secs(1),
            max_control_sessions: 1,
            verbose: false,
            dieby: 1,
            portspec: None,
            pbkdf2_count: None,
            testtimeout: None,
            end_delay: None,
        };
        let daemon = Daemon::new(cfg, Arc::clone(&policy));
        {
            let mut t = daemon.tables.lock().unwrap();
            *t = ChildTables::new(3);
        }
        let (p1, _c1) = UnixStream::pair().unwrap();
        let c1 = Arc::new(Mutex::new(ChldState {
            policy: Arc::clone(&policy),
            id: 1,
            fd: Some(p1),
            node: None,
            used: [LimRec { limit: 0, value: 0 }, LimRec { limit: 0, value: 0 }],
            handle: None,
            stop: Arc::new(AtomicBool::new(false)),
        }));
        daemon.alloc_chld_state(c1).unwrap();
        let control_sessions = {
            let t = daemon.tables.lock().unwrap();
            t.control_sessions
        };
        assert_eq!(control_sessions, 1);
        assert!(
            daemon.cfg.max_control_sessions > 0
                && control_sessions.saturating_add(1) > daemon.cfg.max_control_sessions
        );
    }

    #[test]
    fn daemon_config_twamp_defaults() {
        assert_eq!(DaemonConfig::service_port(false), 861);
        assert_eq!(DaemonConfig::service_port(true), 862);
        assert_eq!(DaemonConfig::service_name(false), "861");
        assert_eq!(DaemonConfig::service_name(true), "862");
        let opts = OwampdOpts::defaults(true);
        assert_eq!(opts.controltimeout, 900);
        let opts = OwampdOpts::defaults(false);
        assert_eq!(opts.controltimeout, 1_800);
    }

    #[test]
    fn check_fd_invalid_kills_child_flag() {
        use std::io::Write;
        let policy = Arc::new(sample_policy_for_tests());
        let cfg = DaemonConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            twamp: true,
            auth_mode: 0,
            control_timeout: Duration::from_secs(1),
            max_control_sessions: 0,
            verbose: false,
            dieby: 1,
            portspec: None,
            pbkdf2_count: None,
            testtimeout: Some(30),
            end_delay: None,
        };
        let daemon = Daemon::new(cfg, Arc::clone(&policy));
        {
            let mut t = daemon.tables.lock().unwrap();
            *t = ChildTables::new(3);
        }
        let (parent, child) = UnixStream::pair().unwrap();
        // Write garbage so read_class fails.
        let mut child = child;
        child.write_all(&[0xff; 8]).unwrap();
        drop(child);

        let stop = Arc::new(AtomicBool::new(false));
        let cstate = Arc::new(Mutex::new(ChldState {
            policy,
            id: 7,
            fd: Some(parent),
            node: None,
            used: [LimRec { limit: 0, value: 0 }, LimRec { limit: 0, value: 0 }],
            handle: None,
            stop: Arc::clone(&stop),
        }));
        daemon.alloc_chld_state(Arc::clone(&cstate)).unwrap();
        // Simulate CleanPipes → CheckFD failure → stop child (C: kill SIGTERM).
        assert!(!Daemon::check_fd(&cstate));
        cstate.lock().unwrap().stop.store(true, Ordering::SeqCst);
        assert!(cstate.lock().unwrap().stop.load(Ordering::SeqCst));
        daemon.free_chld_state(cstate);
    }
}
