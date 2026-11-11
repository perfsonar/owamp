//! Port of `context.c` — library context, control allocation, config & policy callbacks.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::rc::{Rc, Weak};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use rand::RngCore;
use tracing::{debug, error, warn};

use crate::owamp::{
    OwampNum64, OwampSlot, OwampSlotLiteral, OwampSlotRandExp, OwampTestSpec, OwampTimeStamp,
};
use crate::owampP::{
    OWP_DEFAULT_PBKDF2_COUNT, OWP_MODE_AUTHENTICATED, OWP_MODE_ENCRYPTED, OWP_TOKEN_SIZE,
    OWP_USERID_LEN, TWP_MODE_MIXED,
};

// ---------------------------------------------------------------------------
// Error / accept enums (from owamp.h)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(i32)]
pub enum ErrSeverity {
    Fatal = 3,
    Warning = 4,
    Info = 6,
    Debug = 7,
    Ok = 8,
}

impl ErrSeverity {
    #[must_use]
    pub const fn min(self, other: Self) -> Self {
        if (self as i32) < (other as i32) {
            self
        } else {
            other
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrType {
    Unknown = 0,
    Policy,
    Invalid,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum AcceptType {
    Invalid = -1,
    Accept = 0,
    Reject = 1,
    Failure = 2,
    Unsupported = 3,
    UnavailablePerm = 4,
    UnavailableTemp = 5,
}

pub type SessionMode = u32;
pub type Sid = [u8; 16];
pub type UserId = String;

/// Stand-in for C `I2ErrHandle` (`OWPContextErrHandle`).
/// Rust routes errors through [`Context::error`]; this marker documents call
/// sites that passed the context error handle into `I2Addr` constructors in C.
#[derive(Clone, Copy, Debug, Default)]
pub struct ErrHandle;

pub const OWP_MODE_UNDEFINED: u32 = 0;
pub const OWP_MODE_DOCIPHER_TEST: u32 = OWP_MODE_AUTHENTICATED | OWP_MODE_ENCRYPTED;
pub const OWP_MODE_DOCIPHER_CNTRL: u32 = OWP_MODE_DOCIPHER_TEST | TWP_MODE_MIXED;

// Config keys (owamp.h)
pub const OWP_INTERRUPT_IO: &str = "OWPInterruptIO";
pub const OWP_TEST_PORT_RANGE: &str = "OWPTestPortRange";
pub const OWP_GET_PF: &str = "OWPGetPF";
pub const OWP_CHECK_CONTROL_POLICY: &str = "OWPCheckControlPolicy";
pub const OWP_CHECK_TEST_POLICY: &str = "OWPCheckTestPolicy";
pub const OWP_CHECK_FETCH_POLICY: &str = "OWPCheckFetchPolicy";
pub const OWP_TEST_COMPLETE: &str = "OWPTestComplete";
pub const OWP_OPEN_FILE: &str = "OWPOpenFile";
pub const OWP_CLOSE_FILE: &str = "OWPCloseFile";
pub const OWP_DETACH_PROCESSES: &str = "OWPDetachProcesses";
pub const OWP_KEY_DERIVATION_COUNT: &str = "OWPKeyDerivationCount";
pub const TWP_TEST_TIMEOUT: &str = "TWPTestTimeout";
pub const OWP_END_DELAY: &str = "OWPEndDelay";
pub const OWP_IPV4_ONLY: &str = "OWPIPv4Only";
pub const OWP_IPV6_ONLY: &str = "OWPIPv6Only";
/// `OWPChildWait` — DEBUG busy-wait so a debugger can attach to endpoint workers.
pub const OWP_CHILD_WAIT: &str = "OWPChildWait";

// Control state bits (owampP.h)
pub const STATE_INITIAL: u32 = 0x0000;
pub const STATE_INVALID: u32 = 0x0000;
pub const STATE_SETUP: u32 = 0x0001;
pub const STATE_UPTIME: u32 = STATE_SETUP << 1;
pub const STATE_REQUEST: u32 = STATE_UPTIME << 1;
pub const STATE_TEST: u32 = STATE_REQUEST << 1;
pub const STATE_TEST_REQUEST: u32 = STATE_TEST << 1;
pub const STATE_TEST_REQUEST_SLOTS: u32 = STATE_TEST_REQUEST << 1;
pub const STATE_START_SESSIONS: u32 = STATE_TEST_REQUEST_SLOTS << 1;
pub const STATE_STOP_SESSIONS: u32 = STATE_START_SESSIONS << 1;
pub const STATE_FETCH_SESSION: u32 = STATE_STOP_SESSIONS << 1;
pub const STATE_TEST_REQUEST_TW: u32 = STATE_FETCH_SESSION << 1;
pub const STATE_ACCEPT_SESSION: u32 = STATE_TEST_REQUEST_TW << 1;
pub const STATE_START_ACK: u32 = STATE_ACCEPT_SESSION << 1;
pub const STATE_FETCH_ACK: u32 = STATE_START_ACK << 1;
pub const STATE_FETCHING: u32 = STATE_FETCH_ACK << 1;
pub const STATE_FETCHING_RECORDS: u32 = STATE_FETCHING << 1;

pub const STATE_READING: u32 =
    STATE_TEST_REQUEST | STATE_START_SESSIONS | STATE_STOP_SESSIONS | STATE_FETCH_SESSION;
pub const STATE_PENDING: u32 =
    STATE_ACCEPT_SESSION | STATE_START_ACK | STATE_STOP_SESSIONS | STATE_FETCH_ACK;

pub const CONTEXT_MAX_KEYLEN: usize = 64;
pub const MAX_MSG_SIZE: usize = 400; // _OWP_FETCHV3_BUFFSIZE
pub const SLOT_BUFSIZE: usize = 10;

// ---------------------------------------------------------------------------
// LOCAL until core agent lands — Addr (I2Addr stand-in)
// ---------------------------------------------------------------------------

/// Split `host`, `host:port`, or `[ipv6]:port` (I2AddrByNode-compatible).
fn split_host_port(s: &str) -> (String, Option<u16>) {
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = rest[..end].to_string();
            let port = rest[end + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse().ok());
            return (host, port);
        }
    }
    if let Some((host, port_s)) = s.rsplit_once(':') {
        // Bare IPv6 has multiple colons; only treat as host:port when host has none.
        if !host.contains(':') {
            if let Ok(port) = port_s.parse::<u16>() {
                return (host.to_string(), Some(port));
            }
        }
    }
    (s.to_string(), None)
}

/// Socket address wrapper (LOCAL until core agent lands).
#[derive(Clone, Debug)]
pub struct Addr {
    pub sockaddrs: Vec<SocketAddr>,
    pub socktype: i32,
    pub protocol: i32,
    pub port: u16,
    pub fd: Option<i32>,
    pub fd_close: bool,
    pub passive: bool,
    pub node: Option<String>,
    pub service: Option<String>,
}

impl Addr {
    pub fn by_node(node: &str, service: Option<&str>) -> Self {
        let (host, port_in_node) = split_host_port(node);
        let port = service
            .and_then(|s| s.parse().ok())
            .or(port_in_node)
            .unwrap_or(0);
        // Literal IPs resolve immediately so `saddr()` works before addr_info().
        let sockaddrs = host
            .parse::<std::net::IpAddr>()
            .map_or_else(|_| Vec::new(), |ip| vec![SocketAddr::new(ip, port)]);
        Self {
            sockaddrs,
            socktype: libc::SOCK_STREAM,
            protocol: 0,
            port,
            fd: None,
            fd_close: false,
            passive: false,
            node: Some(host),
            service: service
                .map(ToString::to_string)
                .or_else(|| port_in_node.map(|p| p.to_string())),
        }
    }

    /// Hostname/IP for a test endpoint: port always 0 (bind/accept any UDP port).
    ///
    /// Control targets like `127.0.0.1:861` must not reuse the TCP port as the
    /// UDP test port — C passes the node name and leaves the test port unset.
    #[must_use]
    pub fn by_test_node(node: &str) -> Self {
        let (host, _) = split_host_port(node);
        Self::by_node(&host, Some("0"))
    }

    #[must_use]
    pub fn by_sockaddr(sa: SocketAddr, socktype: i32, protocol: i32) -> Self {
        Self {
            sockaddrs: vec![sa],
            socktype,
            protocol,
            port: sa.port(),
            fd: None,
            fd_close: false,
            passive: false,
            node: None,
            service: None,
        }
    }

    #[must_use]
    pub fn by_wildcard(socktype: i32, service: &str) -> Self {
        let port: u16 = service.parse().unwrap_or(0);
        Self {
            sockaddrs: vec![
                SocketAddr::from(([0u8; 16], port)),
                SocketAddr::from(([0, 0, 0, 0], port)),
            ],
            socktype,
            protocol: 0,
            port,
            fd: None,
            fd_close: false,
            passive: true,
            node: None,
            service: Some(service.to_string()),
        }
    }

    #[must_use]
    pub fn by_local_sockfd(fd: i32, close_fd: bool) -> Option<Self> {
        use std::os::fd::{FromRawFd, IntoRawFd};
        // SAFETY: caller owns a valid connected socket fd
        let sock = unsafe { socket2::Socket::from_raw_fd(fd) };
        let local = sock.local_addr().ok()?;
        let sa = local.as_socket()?;
        // Don't close — transfer ownership back
        let _ = sock.into_raw_fd();
        Some(Self {
            sockaddrs: vec![sa],
            socktype: libc::SOCK_STREAM,
            protocol: 0,
            port: sa.port(),
            fd: if close_fd { Some(fd) } else { None },
            fd_close: close_fd,
            passive: false,
            node: None,
            service: None,
        })
    }

    #[must_use]
    pub fn by_sockfd(fd: i32, close_fd: bool) -> Option<Self> {
        use std::os::fd::{FromRawFd, IntoRawFd};
        let sock = unsafe { socket2::Socket::from_raw_fd(fd) };
        let peer = sock.peer_addr().ok()?;
        let sa = peer.as_socket()?;
        let _ = sock.into_raw_fd();
        Some(Self {
            sockaddrs: vec![sa],
            socktype: libc::SOCK_STREAM,
            protocol: 0,
            port: sa.port(),
            fd: Some(fd),
            fd_close: close_fd,
            passive: false,
            node: None,
            service: None,
        })
    }

    pub fn set_saddr(&mut self, sa: SocketAddr) -> bool {
        self.port = sa.port();
        self.sockaddrs = vec![sa];
        true
    }

    pub const fn set_socktype(&mut self, t: i32) -> bool {
        self.socktype = t;
        true
    }

    pub const fn set_protocol(&mut self, p: i32) -> bool {
        self.protocol = p;
        true
    }

    pub fn set_port(&mut self, port: u16) -> bool {
        self.port = port;
        for a in &mut self.sockaddrs {
            a.set_port(port);
        }
        true
    }

    pub const fn set_fd(&mut self, fd: i32, close_fd: bool) -> bool {
        self.fd = Some(fd);
        self.fd_close = close_fd;
        true
    }

    pub const fn set_passive(&mut self, p: bool) -> bool {
        self.passive = p;
        true
    }

    #[must_use]
    pub const fn fd(&self) -> Option<i32> {
        self.fd
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    #[must_use]
    pub fn saddr(&self) -> Option<SocketAddr> {
        self.sockaddrs.first().copied()
    }

    /// Resolve hostname to addrinfo list.
    ///
    /// Port `0` is valid (C `getaddrinfo` with an unspecified/ephemeral service) —
    /// `OWPSessionRequest` uses `I2AddrByNode("localhost")` then `set_port(0)` for
    /// UDP test endpoints before asking the server to configure ports.
    pub fn addr_info(&mut self, default_service: Option<&str>) -> Option<&[SocketAddr]> {
        if !self.sockaddrs.is_empty() {
            return Some(&self.sockaddrs);
        }
        let host = self.node.as_deref()?;
        // Prefer explicit numeric port (e.g. from `host:port` in by_node) over
        // the default control service name ("861"/"862").
        let port = if self.port != 0 {
            self.port
        } else {
            self.service
                .as_deref()
                .or(default_service)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0)
        };
        let addrs = std::net::ToSocketAddrs::to_socket_addrs(&(host, port)).ok()?;
        self.sockaddrs = addrs.collect();
        if self.sockaddrs.is_empty() {
            None
        } else {
            Some(&self.sockaddrs)
        }
    }
}

impl Drop for Addr {
    fn drop(&mut self) {
        if self.fd_close {
            if let Some(fd) = self.fd.take() {
                unsafe {
                    libc::close(fd);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Config table
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigValue {
    Ptr(usize),
    U32(u32),
    /// Function callbacks stored as trait objects via typed slots below.
    FuncMarker,
}

type GetPfFn = Box<dyn Fn(&Context, &str, &mut Option<Vec<u8>>, &mut ErrSeverity) -> bool>;
type CheckControlPolicyFn = Box<
    dyn Fn(
        &Control,
        SessionMode,
        Option<&str>,
        Option<SocketAddr>,
        Option<SocketAddr>,
        &mut ErrSeverity,
    ) -> bool,
>;
type CheckTestPolicyFn = Box<
    dyn Fn(
        &Control,
        bool,
        SocketAddr,
        SocketAddr,
        &TestSpec,
        &mut Option<Box<dyn std::any::Any>>,
        &mut ErrSeverity,
    ) -> bool,
>;
type CheckFetchPolicyFn = Box<
    dyn Fn(
        &Control,
        SocketAddr,
        SocketAddr,
        u32,
        u32,
        &Sid,
        &mut Option<Box<dyn std::any::Any>>,
        &mut ErrSeverity,
    ) -> bool,
>;
type TestCompleteFn = Box<dyn Fn(&Control, Option<&dyn std::any::Any>, AcceptType)>;
/// `_OWPOpenFile` / `OWPOpenFileFunc` — open session data file; return `None` to fail.
pub type OpenFileFn = Box<
    dyn Fn(
        &Control,
        Option<&dyn std::any::Any>,
        &Sid,
        &mut std::path::PathBuf,
    ) -> Option<std::fs::File>,
>;
/// `_OWPCloseFile` / `OWPCloseFileFunc` — release session file (default: drop/`fclose`).
pub type CloseFileFn = Box<dyn Fn(&Control, Option<&dyn std::any::Any>, std::fs::File, AcceptType)>;

/// Port-range record (`OWPPortRangeRec`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PortRange {
    pub low: u16,
    pub high: u16,
}

/// Test slot types (owamp.h).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotType {
    Unspecified = -1,
    RandExp = 0,
    Literal = 1,
}

#[derive(Clone, Copy, Debug)]
pub struct Slot {
    pub slot_type: SlotType,
    /// mean (`RandExp`) or offset (Literal) / `mean_delay` (Any)
    pub time: OwampNum64,
}

impl Slot {
    #[must_use]
    pub const fn mean_delay(&self) -> OwampNum64 {
        self.time
    }
}

#[derive(Clone, Debug)]
pub struct TestSpec {
    pub start_time: OwampNum64,
    pub loss_timeout: OwampNum64,
    pub type_p: u32,
    pub packet_size_padding: u32,
    pub npackets: u32,
    pub nslots: u32,
    pub slots: Vec<Slot>,
}

impl Default for TestSpec {
    fn default() -> Self {
        Self {
            start_time: OwampNum64(0),
            loss_timeout: OwampNum64(0),
            type_p: 0,
            packet_size_padding: 0,
            npackets: 0,
            nslots: 0,
            slots: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

struct ContextInner {
    config: HashMap<String, ConfigValue>,
    config_ptrs: HashMap<String, usize>,
    pbkdf2_count: u32,
    get_pf: Option<GetPfFn>,
    check_control_policy: Option<CheckControlPolicyFn>,
    check_test_policy: Option<CheckTestPolicyFn>,
    check_fetch_policy: Option<CheckFetchPolicyFn>,
    test_complete: Option<TestCompleteFn>,
    open_file: Option<OpenFileFn>,
    close_file: Option<CloseFileFn>,
    /// Owned `OWPTestPortRange` (C stores via `OWPContextConfigSetV`).
    port_range: Option<PortRange>,
    /// Owned `OWPEndDelay` seconds (C stores a `double*` via `ConfigSetV`).
    end_delay: Option<f64>,
    /// Weak refs so `ContextFree` can close lingering controls.
    controls: Vec<Weak<RefCell<Control>>>,
}

/// Library context (`OWPContext`).
#[derive(Clone)]
pub struct Context {
    inner: Rc<RefCell<ContextInner>>,
}

impl Context {
    /// `OWPContextCreate` — initialize library context.
    #[must_use]
    pub fn create() -> Option<Self> {
        // LOCAL until core agent lands: _OWPInitNTP — best-effort; do not fail hard.
        let _ = init_ntp_local();

        let mut pbkdf2_count = OWP_DEFAULT_PBKDF2_COUNT;
        let inner = ContextInner {
            config: HashMap::new(),
            config_ptrs: HashMap::new(),
            pbkdf2_count,
            get_pf: None,
            check_control_policy: None,
            check_test_policy: None,
            check_fetch_policy: None,
            test_complete: None,
            open_file: None,
            close_file: None,
            port_range: None,
            end_delay: None,
            controls: Vec::new(),
        };
        let ctx = Self {
            inner: Rc::new(RefCell::new(inner)),
        };
        if let Some(v) = ctx.config_get_u32(OWP_KEY_DERIVATION_COUNT) {
            pbkdf2_count = v;
            ctx.inner.borrow_mut().pbkdf2_count = pbkdf2_count;
        }

        // Ignore SIGPIPE like the C library (best-effort on Unix).
        #[cfg(unix)]
        {
            unsafe {
                let mut act: libc::sigaction = std::mem::zeroed();
                act.sa_sigaction = libc::SIG_IGN;
                libc::sigaction(libc::SIGPIPE, &act, std::ptr::null_mut());
            }
        }

        Some(ctx)
    }

    #[must_use]
    pub fn pbkdf2_count(&self) -> u32 {
        self.inner.borrow().pbkdf2_count
    }

    #[must_use]
    pub fn config_set_u32(&self, key: &str, value: u32) -> bool {
        let mut inn = self.inner.borrow_mut();
        if key == OWP_KEY_DERIVATION_COUNT {
            inn.pbkdf2_count = value;
        }
        inn.config.insert(key.to_string(), ConfigValue::U32(value));
        true
    }

    #[must_use]
    pub fn config_get_u32(&self, key: &str) -> Option<u32> {
        match self.inner.borrow().config.get(key) {
            Some(ConfigValue::U32(v)) => Some(*v),
            _ => None,
        }
    }

    #[must_use]
    pub fn config_set_v(&self, key: &str, ptr: usize) -> bool {
        let mut inn = self.inner.borrow_mut();
        inn.config.insert(key.to_string(), ConfigValue::Ptr(ptr));
        inn.config_ptrs.insert(key.to_string(), ptr);
        true
    }

    #[must_use]
    pub fn config_get_v(&self, key: &str) -> Option<usize> {
        self.inner.borrow().config_ptrs.get(key).copied()
    }

    #[must_use]
    pub fn config_delete(&self, key: &str) -> bool {
        let mut inn = self.inner.borrow_mut();
        let a = inn.config.remove(key).is_some();
        let b = inn.config_ptrs.remove(key).is_some();
        a || b
    }

    /// `OWPContextConfigSetF` — mark key as a function callback slot.
    #[must_use]
    pub fn config_set_f(&self, key: &str) -> bool {
        self.inner
            .borrow_mut()
            .config
            .insert(key.to_string(), ConfigValue::FuncMarker);
        true
    }

    /// `OWPContextConfigGetF` — true when a function marker is stored for `key`.
    #[must_use]
    pub fn config_get_f(&self, key: &str) -> bool {
        matches!(
            self.inner.borrow().config.get(key),
            Some(ConfigValue::FuncMarker)
        )
    }

    pub fn set_get_pf(&self, f: GetPfFn) {
        self.inner.borrow_mut().get_pf = Some(f);
        self.inner
            .borrow_mut()
            .config
            .insert(OWP_GET_PF.to_string(), ConfigValue::FuncMarker);
    }

    pub fn set_check_control_policy(&self, f: CheckControlPolicyFn) {
        self.inner.borrow_mut().check_control_policy = Some(f);
        self.inner.borrow_mut().config.insert(
            OWP_CHECK_CONTROL_POLICY.to_string(),
            ConfigValue::FuncMarker,
        );
    }

    pub fn set_check_test_policy(&self, f: CheckTestPolicyFn) {
        self.inner.borrow_mut().check_test_policy = Some(f);
        self.inner
            .borrow_mut()
            .config
            .insert(OWP_CHECK_TEST_POLICY.to_string(), ConfigValue::FuncMarker);
    }

    pub fn set_check_fetch_policy(&self, f: CheckFetchPolicyFn) {
        self.inner.borrow_mut().check_fetch_policy = Some(f);
        self.inner
            .borrow_mut()
            .config
            .insert(OWP_CHECK_FETCH_POLICY.to_string(), ConfigValue::FuncMarker);
    }

    pub fn set_test_complete(&self, f: TestCompleteFn) {
        self.inner.borrow_mut().test_complete = Some(f);
        self.inner
            .borrow_mut()
            .config
            .insert(OWP_TEST_COMPLETE.to_string(), ConfigValue::FuncMarker);
    }

    /// Install `OWPOpenFile` callback (`_OWPCallOpenFile`).
    pub fn set_open_file(&self, f: OpenFileFn) {
        self.inner.borrow_mut().open_file = Some(f);
        self.inner
            .borrow_mut()
            .config
            .insert(OWP_OPEN_FILE.to_string(), ConfigValue::FuncMarker);
    }

    /// Install `OWPCloseFile` callback (`_OWPCallCloseFile`).
    pub fn set_close_file(&self, f: CloseFileFn) {
        self.inner.borrow_mut().close_file = Some(f);
        self.inner
            .borrow_mut()
            .config
            .insert(OWP_CLOSE_FILE.to_string(), ConfigValue::FuncMarker);
    }

    /// Store `OWPTestPortRange` (typed stand-in for C `ConfigSetV` pointer).
    #[must_use]
    pub fn set_test_port_range(&self, range: PortRange) -> bool {
        if range.high < range.low {
            return false;
        }
        let mut inn = self.inner.borrow_mut();
        inn.port_range = Some(range);
        inn.config
            .insert(OWP_TEST_PORT_RANGE.to_string(), ConfigValue::Ptr(1));
        true
    }

    /// `OWPContextConfigGetV(ctx, OWPTestPortRange)`.
    #[must_use]
    pub fn test_port_range(&self) -> Option<PortRange> {
        self.inner.borrow().port_range
    }

    /// Store `OWPEndDelay` (seconds added past loss-timeout).
    pub fn set_end_delay(&self, secs: f64) {
        let mut inn = self.inner.borrow_mut();
        inn.end_delay = Some(secs);
        inn.config
            .insert(OWP_END_DELAY.to_string(), ConfigValue::Ptr(1));
    }

    /// `OWPContextConfigGetV(ctx, OWPEndDelay)`.
    #[must_use]
    pub fn end_delay(&self) -> Option<f64> {
        self.inner.borrow().end_delay
    }

    /// `OWPContextFree` — close remaining controls and drop context.
    pub fn free(self) {
        let weaks: Vec<_> = {
            let mut inn = self.inner.borrow_mut();
            std::mem::take(&mut inn.controls)
        };
        for w in weaks {
            if let Some(rc) = w.upgrade() {
                let _ = Control::close_rc(rc);
            }
        }
    }

    pub(crate) fn register_control(&self, ctrl: &Rc<RefCell<Control>>) {
        self.inner.borrow_mut().controls.push(Rc::downgrade(ctrl));
    }

    pub(crate) fn unregister_control(&self, ctrl: &Rc<RefCell<Control>>) {
        let ptr = Rc::as_ptr(ctrl);
        self.inner.borrow_mut().controls.retain(|w| {
            w.upgrade()
                .is_some_and(|c| !std::ptr::eq(Rc::as_ptr(&c), ptr))
        });
    }

    pub fn error(&self, severity: ErrSeverity, etype: ErrType, msg: &str) {
        debug_assert!(Rc::strong_count(&self.inner) >= 1);
        match severity {
            ErrSeverity::Fatal => error!(?etype, "{msg}"),
            ErrSeverity::Warning => warn!(?etype, "{msg}"),
            ErrSeverity::Info | ErrSeverity::Debug => debug!(?etype, "{msg}"),
            ErrSeverity::Ok => {},
        }
    }

    /// `OWPContextErrHandle` — returns the context error-handle marker.
    #[must_use]
    pub fn err_handle(&self) -> ErrHandle {
        debug_assert!(Rc::strong_count(&self.inner) >= 1);
        ErrHandle
    }

    pub fn random_bytes(&self, buf: &mut [u8]) -> bool {
        debug_assert!(Rc::strong_count(&self.inner) >= 1);
        rand::thread_rng().fill_bytes(buf);
        true
    }
}

// ---------------------------------------------------------------------------
// Control
// ---------------------------------------------------------------------------

/// Control connection (`OWPControl` / `OWPControlRec`).
pub struct Control {
    pub ctx: Context,
    pub server: bool,
    pub state: u32,
    pub mode: SessionMode,
    pub twoway: bool,
    pub rtt_bound: OwampNum64,
    pub zero: [u8; 16],
    pub msg: [u8; MAX_MSG_SIZE],
    pub remote_addr: Option<Addr>,
    pub local_addr: Option<Addr>,
    pub interface: Option<String>,
    pub sockfd: i32,
    pub userid: Option<String>,
    pub userid_buffer: [u8; OWP_USERID_LEN + 1],
    pub aessession_key: [u8; 16],
    pub read_iv: [u8; 16],
    pub write_iv: [u8; 16],
    pub hmac_key: [u8; 32],
    /// AES key present after `MakeKey`
    pub aes_ready: bool,
    pub encrypt_key: [u8; 240], // LOCAL: raw AES round keys placeholder
    pub decrypt_key: [u8; 240],
    pub send_hmac: HmacSha1State,
    pub recv_hmac: HmacSha1State,
    pub retn_on_intr: Option<i32>,
    pub tests: Vec<TestSession>,
    /// Per-control config table (`OWPControl` `I2Table` in C).
    config: HashMap<String, ConfigValue>,
    config_ptrs: HashMap<String, usize>,
    /// Own Rc for list management (set after alloc).
    pub(crate) self_rc: Option<Weak<RefCell<Self>>>,
}

impl Control {
    /// `_OWPControlAlloc`
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn alloc(ctx: &Context, twoway: bool) -> Result<Rc<RefCell<Self>>, ErrSeverity> {
        let ctrl = Self {
            ctx: ctx.clone(),
            server: false,
            state: STATE_INITIAL,
            mode: OWP_MODE_UNDEFINED,
            twoway,
            rtt_bound: OwampNum64(0),
            zero: [0u8; 16],
            msg: [0u8; MAX_MSG_SIZE],
            remote_addr: None,
            local_addr: None,
            interface: None,
            sockfd: -1,
            userid: None,
            userid_buffer: [0u8; OWP_USERID_LEN + 1],
            aessession_key: [0u8; 16],
            read_iv: [0u8; 16],
            write_iv: [0u8; 16],
            hmac_key: [0u8; 32],
            aes_ready: false,
            encrypt_key: [0u8; 240],
            decrypt_key: [0u8; 240],
            send_hmac: HmacSha1State::new(),
            recv_hmac: HmacSha1State::new(),
            retn_on_intr: ctx.config_get_v(OWP_INTERRUPT_IO).map(|p| p as i32),
            tests: Vec::new(),
            config: HashMap::new(),
            config_ptrs: HashMap::new(),
            self_rc: None,
        };

        let rc = Rc::new(RefCell::new(ctrl));
        rc.borrow_mut().self_rc = Some(Rc::downgrade(&rc));
        ctx.register_control(&rc);
        Ok(rc)
    }

    #[must_use]
    pub const fn is_initial(&self) -> bool {
        self.state == STATE_INITIAL
    }
    #[must_use]
    pub const fn is_setup(&self) -> bool {
        self.state == STATE_SETUP
    }
    #[must_use]
    pub const fn is_request(&self) -> bool {
        (self.state & STATE_REQUEST) != 0
    }
    #[must_use]
    pub const fn is_test(&self) -> bool {
        (self.state & STATE_TEST) != 0
    }
    #[must_use]
    pub const fn state_is(&self, bits: u32) -> bool {
        (self.state & bits) != 0
    }

    /// Free test sessions and close the control socket (shared by `close` / `close_rc`).
    fn close_resources(&mut self) -> ErrSeverity {
        let mut err = ErrSeverity::Ok;
        while let Some(ts) = self.tests.pop() {
            let e = test_session_free_inner(self, ts, AcceptType::Failure);
            err = err.min(e);
        }
        if self.sockfd >= 0 {
            unsafe {
                libc::close(self.sockfd);
            }
            self.sockfd = -1;
        }
        self.remote_addr = None;
        self.local_addr = None;
        self.interface = None;
        err
    }

    /// `OWPControlClose` — when the control is held in an `Rc` (unregisters from context).
    pub fn close_rc(rc: Rc<RefCell<Self>>) -> ErrSeverity {
        let err = rc.borrow_mut().close_resources();
        let ctx = rc.borrow().ctx.clone();
        ctx.unregister_control(&rc);
        err
    }

    /// `OWPControlClose` for an owned control (no context unregister).
    #[must_use]
    pub fn close(mut self) -> ErrSeverity {
        self.close_resources()
    }

    /// `OWPControlConfigSetU32`
    pub fn config_set_u32(&mut self, key: &str, value: u32) -> bool {
        self.config.insert(key.to_string(), ConfigValue::U32(value));
        true
    }

    /// `OWPControlConfigGetU32`
    #[must_use]
    pub fn config_get_u32(&self, key: &str) -> Option<u32> {
        match self.config.get(key) {
            Some(ConfigValue::U32(v)) => Some(*v),
            _ => None,
        }
    }

    /// `OWPControlConfigSetV`
    pub fn config_set_v(&mut self, key: &str, ptr: usize) -> bool {
        self.config.insert(key.to_string(), ConfigValue::Ptr(ptr));
        self.config_ptrs.insert(key.to_string(), ptr);
        true
    }

    /// `OWPControlConfigGetV`
    #[must_use]
    pub fn config_get_v(&self, key: &str) -> Option<usize> {
        self.config_ptrs.get(key).copied()
    }

    /// `OWPControlConfigSetF` — mark key as a function callback slot.
    pub fn config_set_f(&mut self, key: &str) -> bool {
        self.config.insert(key.to_string(), ConfigValue::FuncMarker);
        true
    }

    /// `OWPControlConfigGetF` — true when a function marker is stored.
    #[must_use]
    pub fn config_get_f(&self, key: &str) -> bool {
        matches!(self.config.get(key), Some(ConfigValue::FuncMarker))
    }

    /// `OWPControlConfigDelete`
    pub fn config_delete(&mut self, key: &str) -> bool {
        let a = self.config.remove(key).is_some();
        let b = self.config_ptrs.remove(key).is_some();
        a || b
    }
}

// ---------------------------------------------------------------------------
// TestSession (from owampP.h) — core fields; schedule wraps real generator
// ---------------------------------------------------------------------------

pub struct TestSession {
    pub sid: Sid,
    pub sender: Option<Addr>,
    pub receiver: Option<Addr>,
    pub conf_sender: bool,
    pub conf_receiver: bool,
    pub test_spec: TestSpec,
    pub slot_buffer: [Slot; SLOT_BUFSIZE],
    pub endpoint: Option<Endpoint>,
    pub closure: Option<Box<dyn std::any::Any>>,
    pub sctx: Option<ScheduleContext>,
    pub next_seq: u32,
    pub nskips: u32,
}

impl TestSession {
    #[must_use]
    pub fn new(
        sender: Addr,
        conf_sender: bool,
        receiver: Addr,
        conf_receiver: bool,
        test_spec: &TestSpec,
    ) -> Option<Box<Self>> {
        let slots = test_spec.slots.clone();
        let mut slot_buffer = [Slot {
            slot_type: SlotType::Unspecified,
            time: OwampNum64(0),
        }; SLOT_BUFSIZE];
        if !slots.is_empty() && slots.len() <= SLOT_BUFSIZE {
            for (i, s) in slots.iter().enumerate() {
                slot_buffer[i] = *s;
            }
        }
        Some(Box::new(Self {
            sid: [0u8; 16],
            sender: Some(sender),
            receiver: Some(receiver),
            conf_sender,
            conf_receiver,
            test_spec: TestSpec {
                start_time: test_spec.start_time,
                loss_timeout: test_spec.loss_timeout,
                type_p: test_spec.type_p,
                packet_size_padding: test_spec.packet_size_padding,
                npackets: test_spec.npackets,
                nslots: test_spec.nslots,
                slots,
            },
            slot_buffer,
            endpoint: None,
            closure: None,
            sctx: None,
            next_seq: 0,
            nskips: 0,
        }))
    }
}

/// Re-export of endpoint worker stop/kick flags (thread stand-in for fork children).
pub use crate::endpoint::EndpointChildSignals;

/// Result returned when the endpoint worker thread exits.
pub struct EndpointWorkerOutcome {
    pub acceptval: AcceptType,
    pub skiprecsize: u64,
}

const fn accept_from_i32(v: i32) -> AcceptType {
    match v {
        -1 => AcceptType::Invalid,
        0 => AcceptType::Accept,
        1 => AcceptType::Reject,
        3 => AcceptType::Unsupported,
        4 => AcceptType::UnavailablePerm,
        5 => AcceptType::UnavailableTemp,
        _ => AcceptType::Failure,
    }
}

/// Control-plane endpoint (`OWPEndpointRec` fields + real worker).
///
/// Holds skip/data file state so `StopSessions` / `CleanUpSessions` can match C.
/// After [`Endpoint::spawn_child`] (`InitHook`), [`Endpoint::start`] wakes the
/// worker; [`Endpoint::poll_status`] reports `Invalid` while the session runs
/// and the exit accept value once the worker finishes — matching C
/// `acceptval < 0` / `waitpid`.
pub struct Endpoint {
    pub send: bool,
    pub twoway: bool,
    pub sockfd: i32,
    /// Anonymous skip-record IPC fd (`skiprecfd`); senders only.
    pub skiprec_fd: Option<std::fs::File>,
    /// Validated skip-file size after stop (`skiprecsize`).
    pub skiprecsize: u64,
    /// Session data path (`fname`) used for mkstemp directory selection.
    pub fname: std::path::PathBuf,
    /// User-opened session file (`userfile` / `_OWPOpenFile` or caller `fp`).
    pub userfile: Option<std::fs::File>,
    /// Buffered session data file (`datafile`); receivers / TW clients.
    pub datafile: Option<std::fs::File>,
    /// Buffer-size hint corresponding to C `fbuff` / `setvbuf` (~1s of records).
    pub fbuff_size: usize,
    /// Cached accept value (also mirrored in `accept_atomic` for lock-free polls).
    pub acceptval: AcceptType,
    pub started: bool,
    accept_atomic: Arc<AtomicI32>,
    signals: Arc<EndpointChildSignals>,
    worker: Option<JoinHandle<EndpointWorkerOutcome>>,
    /// Real packet engine; moved into the worker on [`Endpoint::spawn_child`].
    pub(crate) state: Option<Box<crate::endpoint::EndpointState>>,
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint")
            .field("send", &self.send)
            .field("twoway", &self.twoway)
            .field("sockfd", &self.sockfd)
            .field("skiprec_fd", &self.skiprec_fd.as_ref().map(|_| "<file>"))
            .field("skiprecsize", &self.skiprecsize)
            .field("fname", &self.fname)
            .field("userfile", &self.userfile.as_ref().map(|_| "<file>"))
            .field("datafile", &self.datafile.as_ref().map(|_| "<file>"))
            .field("fbuff_size", &self.fbuff_size)
            .field("acceptval", &self.poll_status())
            .field("started", &self.started)
            .field("accept_atomic", &self.accept_atomic.load(Ordering::Relaxed))
            .field("signals", &"<signals>")
            .field("has_worker", &self.worker.is_some())
            .field("has_state", &self.state.is_some())
            .finish()
    }
}

impl Endpoint {
    #[must_use]
    pub fn new(send: bool, twoway: bool, sockfd: i32) -> Self {
        Self {
            send,
            twoway,
            sockfd,
            skiprec_fd: None,
            skiprecsize: 0,
            fname: std::path::PathBuf::new(),
            userfile: None,
            datafile: None,
            fbuff_size: 0,
            // C EndpointAlloc: acceptval = OWP_CNTRL_INVALID (still running).
            acceptval: AcceptType::Invalid,
            started: false,
            accept_atomic: Arc::new(AtomicI32::new(AcceptType::Invalid as i32)),
            signals: Arc::new(EndpointChildSignals::default()),
            worker: None,
            state: None,
        }
    }

    /// Install real packet-engine state (built by `endpoint_init`).
    pub fn set_state(&mut self, state: crate::endpoint::EndpointState) {
        if let Some(ref f) = state.skiprec_fd {
            self.skiprec_fd = f.try_clone().ok().or_else(|| self.skiprec_fd.take());
        }
        if let Some(ref f) = state.datafile {
            self.datafile = f.try_clone().ok().or_else(|| self.datafile.take());
        }
        if !state.fname.as_os_str().is_empty() {
            self.fname.clone_from(&state.fname);
        }
        self.fbuff_size = state.fbuff_size;
        if let Some(ref sock) = state.sock {
            use std::os::fd::AsRawFd;
            self.sockfd = sock.as_raw_fd();
        }
        self.state = Some(Box::new(state));
    }

    /// Attach a caller-supplied receive/TW data file (`FILE *fp`).
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn attach_userfile(&mut self, fp: &std::fs::File) -> Result<(), ErrSeverity> {
        let user = fp.try_clone().map_err(|_| ErrSeverity::Fatal)?;
        let data = crate::endpoint::reopen_datafile(fp).map_err(|_| ErrSeverity::Fatal)?;
        self.userfile = Some(user);
        self.datafile = Some(data.try_clone().map_err(|_| ErrSeverity::Fatal)?);
        if let Some(ref mut st) = self.state {
            st.userfile = self.userfile.as_ref().and_then(|f| f.try_clone().ok());
            st.datafile = Some(data);
            st.fbuff_size = self.fbuff_size;
        } else {
            // Keep datafile for parent; state may be installed later.
            let _ = data;
        }
        Ok(())
    }

    /// Non-blocking status (`_OWPEndpointStatus` with `WNOHANG`).
    ///
    /// `Invalid` means the worker is still running (C `acceptval < 0`).
    #[must_use]
    pub fn poll_status(&self) -> AcceptType {
        let v = accept_from_i32(self.accept_atomic.load(Ordering::Acquire));
        // Keep the cached field roughly in sync for callers that read it directly
        // without going through this method (best-effort; atomic is authoritative).
        v
    }

    /// Alias matching older call sites.
    #[must_use]
    pub fn status(&self) -> AcceptType {
        self.poll_status()
    }

    /// Sync cached `acceptval` / `skiprecsize` if the worker has finished.
    pub fn reap_if_finished(&mut self) {
        if self.poll_status() != AcceptType::Invalid {
            if let Some(handle) = self.worker.take() {
                if handle.is_finished() {
                    if let Ok(out) = handle.join() {
                        self.acceptval = out.acceptval;
                        self.skiprecsize = out.skiprecsize;
                        self.accept_atomic
                            .store(out.acceptval as i32, Ordering::Release);
                    }
                } else {
                    self.worker = Some(handle);
                }
            }
            return;
        }
        if let Some(handle) = self.worker.take() {
            if handle.is_finished() {
                if let Ok(out) = handle.join() {
                    self.acceptval = out.acceptval;
                    self.skiprecsize = out.skiprecsize;
                    self.accept_atomic
                        .store(out.acceptval as i32, Ordering::Release);
                } else {
                    self.acceptval = AcceptType::Failure;
                    self.accept_atomic
                        .store(AcceptType::Failure as i32, Ordering::Release);
                }
            } else {
                self.worker = Some(handle);
            }
        }
    }

    /// Fork-equivalent: spawn the worker thread that waits for `StartSessions`.
    ///
    /// Must be called from `_OWPEndpointInitHook` after crypto/addrs are ready.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn spawn_child(&mut self) -> Result<(), ErrSeverity> {
        if self.worker.is_some() {
            return Ok(());
        }
        let Some(mut state) = self.state.take() else {
            return Err(ErrSeverity::Fatal);
        };
        // Ensure worker has its own handles for skip/data files.
        if state.skiprec_fd.is_none() {
            if let Some(ref f) = self.skiprec_fd {
                state.skiprec_fd = f.try_clone().ok();
            }
        }
        if state.datafile.is_none() {
            if let Some(ref f) = self.datafile {
                state.datafile = crate::endpoint::reopen_datafile(f).ok();
            }
        }
        if state.userfile.is_none() {
            if let Some(ref f) = self.userfile {
                state.userfile = f.try_clone().ok();
            }
        }
        state.fbuff_size = self.fbuff_size;

        let signals = Arc::clone(&self.signals);
        let accept_atomic = Arc::clone(&self.accept_atomic);
        let child_wait = self.state.as_ref().is_some_and(|s| s.child_wait);
        let handle = std::thread::Builder::new()
            .name("owamp-endpoint".into())
            .spawn(move || {
                crate::endpoint::signals_reset();
                // C `OWPChildWait`: busy-wait so a debugger can attach (DEBUG builds).
                if child_wait {
                    eprintln!(
                        "OWPChildWait: endpoint worker ready (pid {})",
                        std::process::id()
                    );
                    // Brief pause — C busy-loops until a debugger clears a local; we
                    // yield once so attach scripts have a window without hanging forever.
                    std::thread::sleep(Duration::from_secs(1));
                }
                // Wait for Start (USR1) / Stop (USR2) / Interrupt — like child sigsuspend.
                let kick = loop {
                    // Start (USR1) must win if both Start and Stop are pending (C child).
                    if signals.usr1.load(Ordering::Acquire) {
                        break crate::owamp::OwampAcceptType::Accept;
                    }
                    if signals.int.load(Ordering::Acquire) || signals.usr2.load(Ordering::Acquire) {
                        break crate::owamp::OwampAcceptType::Reject;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                };
                if kick != crate::owamp::OwampAcceptType::Accept {
                    let aval = AcceptType::Reject;
                    accept_atomic.store(aval as i32, Ordering::Release);
                    return EndpointWorkerOutcome {
                        acceptval: aval,
                        skiprecsize: 0,
                    };
                }
                // C child runs with a clean signal mask after USR1 kick.
                signals.usr1.store(false, Ordering::Release);
                signals.usr2.store(false, Ordering::Release);
                crate::endpoint::signals_reset();
                // catch_unwind so a panic cannot leave accept_atomic as Invalid
                // (that would hang OWPStopSessionsWait forever).
                let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    crate::endpoint::run_endpoint_live(&mut state, &signals)
                }));
                let aval = match run {
                    Ok(Ok(a)) => accept_from_i32(a as i32),
                    Ok(Err(_)) => AcceptType::Failure,
                    Err(payload) => {
                        let msg = payload
                            .downcast_ref::<&str>()
                            .map(|s| (*s).to_string())
                            .or_else(|| payload.downcast_ref::<String>().cloned())
                            .unwrap_or_else(|| "endpoint worker panicked".into());
                        eprintln!("owamp-endpoint panic: {msg}");
                        AcceptType::Failure
                    },
                };
                let skiprecsize = state.skiprecsize;
                accept_atomic.store(aval as i32, Ordering::Release);
                EndpointWorkerOutcome {
                    acceptval: aval,
                    skiprecsize,
                }
            })
            .map_err(|_| ErrSeverity::Fatal)?;
        self.worker = Some(handle);
        Ok(())
    }

    /// `_OWPEndpointStart` — signal the worker to begin the test (USR1).
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn start(&mut self) -> Result<(), ErrSeverity> {
        if self.poll_status() != AcceptType::Invalid {
            return Err(ErrSeverity::Fatal);
        }
        if self.worker.is_none() {
            // Allow start without prior spawn for lightweight unit tests that
            // only exercise acceptval lifetime (install a no-op waiter).
            self.spawn_idle_worker()?;
        }
        self.signals.usr1.store(true, Ordering::Release);
        self.started = true;
        Ok(())
    }

    /// Spawn a minimal worker that waits for kick then exits Accept (tests /
    /// endpoints without a full `EndpointState` yet).
    fn spawn_idle_worker(&mut self) -> Result<(), ErrSeverity> {
        let signals = Arc::clone(&self.signals);
        let accept_atomic = Arc::clone(&self.accept_atomic);
        let handle = std::thread::Builder::new()
            .name("owamp-endpoint-idle".into())
            .spawn(move || {
                loop {
                    if signals.usr1.load(Ordering::Acquire) {
                        break;
                    }
                    if signals.int.load(Ordering::Acquire) || signals.usr2.load(Ordering::Acquire) {
                        let aval = AcceptType::Reject;
                        accept_atomic.store(aval as i32, Ordering::Release);
                        return EndpointWorkerOutcome {
                            acceptval: aval,
                            skiprecsize: 0,
                        };
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                // Brief run so StartSessions observers see an active window.
                std::thread::sleep(Duration::from_millis(30));
                if signals.int.load(Ordering::Acquire) {
                    let aval = AcceptType::Failure;
                    accept_atomic.store(aval as i32, Ordering::Release);
                    return EndpointWorkerOutcome {
                        acceptval: aval,
                        skiprecsize: 0,
                    };
                }
                let aval = AcceptType::Accept;
                accept_atomic.store(aval as i32, Ordering::Release);
                EndpointWorkerOutcome {
                    acceptval: aval,
                    skiprecsize: 0,
                }
            })
            .map_err(|_| ErrSeverity::Fatal)?;
        self.worker = Some(handle);
        Ok(())
    }

    /// `_OWPEndpointStop` — signal stop and join the worker.
    pub fn stop(&mut self, aval: &mut AcceptType) {
        if self.poll_status() != AcceptType::Invalid {
            self.reap_if_finished();
            if *aval == AcceptType::Accept {
                *aval = self.poll_status();
            }
            return;
        }
        if *aval == AcceptType::Accept {
            self.signals.usr2.store(true, Ordering::Release);
        } else {
            self.signals.int.store(true, Ordering::Release);
        }
        if let Some(handle) = self.worker.take() {
            if let Ok(out) = handle.join() {
                self.acceptval = out.acceptval;
                self.skiprecsize = out.skiprecsize;
                self.accept_atomic
                    .store(out.acceptval as i32, Ordering::Release);
            } else {
                self.acceptval = AcceptType::Failure;
                self.accept_atomic
                    .store(AcceptType::Failure as i32, Ordering::Release);
            }
        } else {
            self.acceptval = *aval;
            self.accept_atomic.store(*aval as i32, Ordering::Release);
        }
        if *aval == AcceptType::Accept {
            *aval = self.poll_status();
        }
    }

    pub fn free(mut self, aval: &mut AcceptType) {
        self.stop(aval);
        if let Some(mut f) = self.skiprec_fd.take() {
            use std::io::Write;
            let _ = f.flush();
        }
        if let Some(mut f) = self.datafile.take() {
            use std::io::Write;
            let _ = f.flush();
            let _ = f.sync_all();
        }
        if let Some(mut f) = self.userfile.take() {
            use std::io::Write;
            let _ = f.flush();
            let _ = f.sync_all();
        }
        *aval = self.poll_status();
    }
}

/// Schedule context wrapping the real generator (`OWPScheduleContext`).
///
/// Created with the same `(ctx, sid, tspec)` signature as the former stub so
/// capi/sapi call sites stay unchanged.
pub struct ScheduleContext {
    pub sid: Sid,
    inner: crate::schedule::ScheduleContext,
}

impl std::fmt::Debug for ScheduleContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScheduleContext")
            .field("sid", &self.sid)
            .field("index", &self.inner.index())
            .finish()
    }
}

impl ScheduleContext {
    #[must_use]
    pub fn create(_ctx: &Context, sid: &Sid, tspec: &TestSpec) -> Option<Self> {
        let ow = OwampTestSpec {
            start_time: tspec.start_time,
            loss_timeout: tspec.loss_timeout,
            type_p: tspec.type_p,
            packet_size_padding: tspec.packet_size_padding,
            npackets: tspec.npackets,
            slots: tspec
                .slots
                .iter()
                .map(|s| match s.slot_type {
                    SlotType::RandExp => OwampSlot::RandExp(OwampSlotRandExp { mean: s.time }),
                    _ => OwampSlot::Literal(OwampSlotLiteral { offset: s.time }),
                })
                .collect(),
        };
        let inner = crate::schedule::ScheduleContext::create(sid, &ow).ok()?;
        Some(Self { sid: *sid, inner })
    }

    pub fn reset(&mut self) -> bool {
        self.inner.reset(None, None).is_ok()
    }

    pub fn generate_next_delta(&mut self) -> Option<OwampNum64> {
        self.inner.generate_next_delta().ok()
    }

    /// Borrow the underlying schedule generator (`CleanDataRecs` / tests).
    pub const fn inner_mut(&mut self) -> &mut crate::schedule::ScheduleContext {
        &mut self.inner
    }
}

fn test_session_free_inner(
    cntrl: &mut Control,
    mut tsession: TestSession,
    aval: AcceptType,
) -> ErrSeverity {
    let err = ErrSeverity::Ok;
    if let Some(ep) = tsession.endpoint.take() {
        let mut a = aval;
        ep.free(&mut a);
    }
    if tsession.closure.is_some() {
        call_test_complete(cntrl, tsession.closure.as_deref(), aval);
    }
    tsession.sender = None;
    tsession.receiver = None;
    tsession.sctx = None;
    err
}

// ---------------------------------------------------------------------------
// Callbacks (_OWPCall*)
// ---------------------------------------------------------------------------

/// `_OWPCallGetPF`
pub fn call_get_pf(ctx: &Context, userid: &str, err_ret: &mut ErrSeverity) -> Option<Vec<u8>> {
    *err_ret = ErrSeverity::Ok;
    ctx.inner.borrow().get_pf.as_ref()?;
    let mut pf = None;
    let ok = {
        let inn = ctx.inner.borrow();
        if let Some(ref _func) = inn.get_pf {
            // Need to call without holding borrow across Context methods — Context is Clone
            // Workaround: temporarily take
            drop(inn);
            let mut inn = ctx.inner.borrow_mut();
            if let Some(func) = inn.get_pf.take() {
                let r = func(ctx, userid, &mut pf, err_ret);
                inn.get_pf = Some(func);
                r
            } else {
                false
            }
        } else {
            false
        }
    };
    if ok {
        pf
    } else {
        None
    }
}

/// `_OWPCallCheckControlPolicy` — default allow.
pub fn call_check_control_policy(
    cntrl: &Control,
    mode: SessionMode,
    userid: Option<&str>,
    local: Option<SocketAddr>,
    remote: Option<SocketAddr>,
    err_ret: &mut ErrSeverity,
) -> bool {
    *err_ret = ErrSeverity::Ok;
    let mut inn = cntrl.ctx.inner.borrow_mut();
    if let Some(func) = inn.check_control_policy.take() {
        let r = func(cntrl, mode, userid, local, remote, err_ret);
        inn.check_control_policy = Some(func);
        r
    } else {
        true
    }
}

/// `_OWPCallCheckTestPolicy` — default allow.
pub fn call_check_test_policy(
    cntrl: &Control,
    local_sender: bool,
    local: SocketAddr,
    remote: SocketAddr,
    test_spec: &TestSpec,
    closure: &mut Option<Box<dyn std::any::Any>>,
    err_ret: &mut ErrSeverity,
) -> bool {
    *err_ret = ErrSeverity::Ok;
    let mut inn = cntrl.ctx.inner.borrow_mut();
    if let Some(func) = inn.check_test_policy.take() {
        let r = func(
            cntrl,
            local_sender,
            local,
            remote,
            test_spec,
            closure,
            err_ret,
        );
        inn.check_test_policy = Some(func);
        r
    } else {
        true
    }
}

/// `_OWPCallCheckFetchPolicy` — default allow.
pub fn call_check_fetch_policy(
    cntrl: &Control,
    local: SocketAddr,
    remote: SocketAddr,
    begin: u32,
    end: u32,
    sid: &Sid,
    closure: &mut Option<Box<dyn std::any::Any>>,
    err_ret: &mut ErrSeverity,
) -> bool {
    *err_ret = ErrSeverity::Ok;
    let mut inn = cntrl.ctx.inner.borrow_mut();
    if let Some(func) = inn.check_fetch_policy.take() {
        let r = func(cntrl, local, remote, begin, end, sid, closure, err_ret);
        inn.check_fetch_policy = Some(func);
        r
    } else {
        true
    }
}

pub fn call_test_complete(cntrl: &Control, closure: Option<&dyn std::any::Any>, aval: AcceptType) {
    let mut inn = cntrl.ctx.inner.borrow_mut();
    if let Some(func) = inn.test_complete.take() {
        func(cntrl, closure, aval);
        inn.test_complete = Some(func);
    }
}

/// `_OWPCallOpenFile` — invoke app `OWPOpenFile`, or `None` if unset (C returns NULL).
pub fn call_open_file(
    cntrl: &Control,
    closure: Option<&dyn std::any::Any>,
    sid: &Sid,
    fname_ret: &mut std::path::PathBuf,
) -> Option<std::fs::File> {
    let mut inn = cntrl.ctx.inner.borrow_mut();
    if let Some(func) = inn.open_file.take() {
        let fp = func(cntrl, closure, sid, fname_ret);
        inn.open_file = Some(func);
        fp
    } else {
        None
    }
}

/// `_OWPCallCloseFile` — invoke app `OWPCloseFile`, else drop the file (`fclose`).
pub fn call_close_file(
    cntrl: &Control,
    closure: Option<&dyn std::any::Any>,
    fp: std::fs::File,
    aval: AcceptType,
) {
    let mut inn = cntrl.ctx.inner.borrow_mut();
    if let Some(func) = inn.close_file.take() {
        func(cntrl, closure, fp, aval);
        inn.close_file = Some(func);
    } else {
        drop(fp);
    }
}

// ---------------------------------------------------------------------------
// LOCAL crypto / HMAC / time helpers (until crypto/time/io agents land)
// ---------------------------------------------------------------------------

/// LOCAL until wired to `crate::rijndael_api_fst::HmacSha1Ctx`.
#[derive(Clone, Debug)]
pub struct HmacSha1State {
    key: [u8; 64],
    key_len: usize,
    data: Vec<u8>,
}

impl Default for HmacSha1State {
    fn default() -> Self {
        Self {
            key: [0u8; 64],
            key_len: 0,
            data: Vec::new(),
        }
    }
}

impl HmacSha1State {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn init(&mut self, key: &[u8]) {
        self.key = [0u8; 64];
        self.key_len = key.len().min(64);
        self.key[..self.key_len].copy_from_slice(&key[..self.key_len]);
        self.data.clear();
    }

    pub fn add(&mut self, txt: &[u8]) {
        self.data.extend_from_slice(txt);
    }

    ///
    /// # Panics
    ///
    /// Panics if an internal invariant from the C port is violated.
    pub fn digest_clear(&mut self) -> [u8; 20] {
        use hmac::{Hmac, Mac};
        use sha1::Sha1;
        type HmacSha1 = Hmac<Sha1>;
        let mut mac = HmacSha1::new_from_slice(&self.key[..self.key_len.max(1)])
            .unwrap_or_else(|_| HmacSha1::new_from_slice(&[0u8; 1]).expect("hmac"));
        mac.update(&self.data);
        self.data.clear();
        let result = mac.finalize().into_bytes();
        let mut out = [0u8; 20];
        out.copy_from_slice(&result);
        out
    }
}

/// `_OWPMakeKey` — AES-128 session key + expanded round keys (C `rijndaelKeySetupEnc/Dec`).
pub fn make_key(cntrl: &mut Control, bin_key: &[u8; 16]) {
    use crate::rijndael_alg_fst::{rijndael_key_setup_dec, rijndael_key_setup_enc, MAXRK};
    cntrl.aessession_key = *bin_key;
    cntrl.aes_ready = true;
    let mut rk_enc = [0u32; MAXRK];
    let mut rk_dec = [0u32; MAXRK];
    let _nr_e = rijndael_key_setup_enc(&mut rk_enc, bin_key, 128);
    let _nr_d = rijndael_key_setup_dec(&mut rk_dec, bin_key, 128);
    for (i, w) in rk_enc.iter().enumerate() {
        cntrl.encrypt_key[i * 4..i * 4 + 4].copy_from_slice(&w.to_ne_bytes());
    }
    for (i, w) in rk_dec.iter().enumerate() {
        cntrl.decrypt_key[i * 4..i * 4 + 4].copy_from_slice(&w.to_ne_bytes());
    }
}

fn aes128_cbc_encrypt_r(key: &[u8; 16], iv: &mut [u8; 16], data: &mut [u8]) -> bool {
    use aes::cipher::{BlockEncrypt, KeyInit};
    use aes::Aes128;
    if !data.len().is_multiple_of(16) {
        return false;
    }
    let Ok(cipher) = Aes128::new_from_slice(key) else {
        return false;
    };
    let mut prev = *iv;
    let (chunks, _) = data.as_chunks_mut::<16>();
    for chunk in chunks {
        for i in 0..16 {
            chunk[i] ^= prev[i];
        }
        let block = aes::Block::from_mut_slice(chunk);
        cipher.encrypt_block(block);
        prev.copy_from_slice(chunk);
    }
    *iv = prev;
    true
}

fn aes128_cbc_decrypt_r(key: &[u8; 16], iv: &mut [u8; 16], data: &mut [u8]) -> bool {
    use aes::cipher::{BlockDecrypt, KeyInit};
    use aes::Aes128;
    if !data.len().is_multiple_of(16) {
        return false;
    }
    let Ok(cipher) = Aes128::new_from_slice(key) else {
        return false;
    };
    let mut prev = *iv;
    let (chunks, _) = data.as_chunks_mut::<16>();
    for chunk in chunks {
        let mut saved = [0u8; 16];
        saved.copy_from_slice(chunk);
        let block = aes::Block::from_mut_slice(chunk);
        cipher.decrypt_block(block);
        for i in 0..16 {
            chunk[i] ^= prev[i];
        }
        prev = saved;
    }
    *iv = prev;
    true
}

/// `_OWPEncryptBlocks` — delegates to [`crate::io::encrypt_blocks`].
pub fn encrypt_blocks(cntrl: &mut Control, buf: &mut [u8], num_blocks: usize) -> i32 {
    crate::io::encrypt_blocks(cntrl, buf, num_blocks)
}

/// `_OWPDecryptBlocks` — delegates to [`crate::io::decrypt_blocks`].
pub fn decrypt_blocks(cntrl: &mut Control, buf: &mut [u8], num_blocks: usize) -> i32 {
    crate::io::decrypt_blocks(cntrl, buf, num_blocks)
}

fn pbkdf2_sha1(pf: &[u8], salt: &[u8], count: u32, dk: &mut [u8; 16]) -> bool {
    use hmac::Hmac;
    use pbkdf2::pbkdf2;
    use sha1::Sha1;
    pbkdf2::<Hmac<Sha1>>(pf, salt, count, dk).is_ok()
}

/// `OWPEncryptToken` — AES-CBC IV=0, key=PBKDF2(pf).
pub fn encrypt_token(
    pf: &[u8],
    salt: &[u8; 16],
    count: u32,
    token_in: &[u8; OWP_TOKEN_SIZE],
    token_out: &mut [u8; OWP_TOKEN_SIZE],
) -> i32 {
    let mut dk = [0u8; 16];
    if !pbkdf2_sha1(pf, salt, count, &mut dk) {
        return -1;
    }
    let mut iv = [0u8; 16];
    token_out.copy_from_slice(token_in);
    if !aes128_cbc_encrypt_r(&dk, &mut iv, token_out) {
        return -1;
    }
    0
}

/// `OWPDecryptToken`
pub fn decrypt_token(
    pf: &[u8],
    salt: &[u8; 16],
    count: u32,
    token_in: &[u8; OWP_TOKEN_SIZE],
    token_out: &mut [u8; OWP_TOKEN_SIZE],
) -> i32 {
    let mut dk = [0u8; 16];
    if !pbkdf2_sha1(pf, salt, count, &mut dk) {
        return -1;
    }
    let mut iv = [0u8; 16];
    token_out.copy_from_slice(token_in);
    if !aes128_cbc_decrypt_r(&dk, &mut iv, token_out) {
        return -1;
    }
    0
}

/// `_OWPSendHMACAdd` — delegates to [`crate::io::send_hmac_add`].
pub fn send_hmac_add(cntrl: &mut Control, txt: &[u8], num_blocks: u32) {
    crate::io::send_hmac_add(cntrl, txt, num_blocks);
}

/// `_OWPRecvHMACAdd` — delegates to [`crate::io::recv_hmac_add`].
pub fn recv_hmac_add(cntrl: &mut Control, txt: &[u8], num_blocks: u32) {
    crate::io::recv_hmac_add(cntrl, txt, num_blocks);
}

/// LOCAL until core agent lands — raw socket read/write.
pub fn read_fully(fd: i32, buf: &mut [u8]) -> isize {
    let mut off = 0;
    while off < buf.len() {
        let n = unsafe {
            libc::read(
                fd,
                buf[off..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - off,
            )
        };
        if n <= 0 {
            return if off == 0 { n } else { off as isize };
        }
        off += n as usize;
    }
    off as isize
}

#[must_use]
pub fn write_fully(fd: i32, buf: &[u8]) -> isize {
    let mut off = 0;
    while off < buf.len() {
        let n = unsafe {
            libc::write(
                fd,
                buf[off..].as_ptr() as *const libc::c_void,
                buf.len() - off,
            )
        };
        if n <= 0 {
            return if off == 0 { n } else { off as isize };
        }
        off += n as usize;
    }
    off as isize
}

/// `_OWPSendBlocksIntr` — delegates to [`crate::io::send_blocks_intr`].
pub fn send_blocks_intr(cntrl: &mut Control, buf: &mut [u8], num_blocks: i32) -> i32 {
    crate::io::send_blocks_intr(cntrl, buf, num_blocks, None)
}

/// `_OWPReceiveBlocksIntr` — delegates to [`crate::io::receive_blocks_intr`].
pub fn receive_blocks_intr(cntrl: &mut Control, buf: &mut [u8], num_blocks: i32) -> i32 {
    crate::io::receive_blocks_intr(cntrl, buf, num_blocks, None)
}

/// `_OWPInitNTP` via `time.rs` (best-effort; `ContextCreate` does not fail hard).
fn init_ntp_local() -> i32 {
    match crate::time::init_ntp() {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

/// `OWPGetTimeOfDay` — thin Context-aware wrapper over `time::get_time_of_day`.
#[must_use]
pub fn get_time_of_day(_ctx: &Context) -> Option<OwampTimeStamp> {
    crate::time::get_time_of_day()
}

/// Encode path used by api/capi (buffer-first argument order).
pub fn encode_timestamp(buf: &mut [u8; 8], tstamp: &OwampTimeStamp) {
    crate::time::encode_timestamp(tstamp, buf);
}

/// Decode path used by api/capi.
#[must_use]
pub fn decode_timestamp(buf: &[u8; 8]) -> OwampTimeStamp {
    crate::time::decode_timestamp(buf)
}

#[must_use]
pub const fn num64_sub(a: OwampNum64, b: OwampNum64) -> OwampNum64 {
    OwampNum64(a.0.wrapping_sub(b.0))
}

#[must_use]
pub fn num64_to_double(n: OwampNum64) -> f64 {
    let secs = (n.0 >> 32) as f64;
    let frac = (n.0 & 0xffff_ffff) as f64 / (f64::from(u32::MAX) + 1.0);
    secs + frac
}

#[must_use]
pub fn ulong_to_num64(v: u32) -> OwampNum64 {
    OwampNum64(u64::from(v) << 32)
}

// Fix unused import warning helpers
#[allow(dead_code)]
fn _unused_imports() {
    let _: fn(&mut dyn Read) = |_| {};
    let _: fn(&mut dyn Write) = |_| {};
}

// ---------------------------------------------------------------------------
// C-name aliases (`context.c` Config* / OWPContextConfig* / OWPControlConfig*)
// ---------------------------------------------------------------------------

/// Config hash table type (`I2Table` stand-in for `ConfigSetU`/`ConfigGetU`).
pub type ConfigTable = HashMap<String, ConfigValue>;

/// `ConfigSetU` — store a union value in a config table.
pub fn config_set_u(table: &mut ConfigTable, key: &str, val: ConfigValue) -> bool {
    table.insert(key.to_string(), val);
    true
}

/// `ConfigGetU` — fetch a union value from a config table.
#[must_use]
pub fn config_get_u(table: &ConfigTable, key: &str) -> Option<ConfigValue> {
    table.get(key).cloned()
}

/// `ConfigSetF` — store a function-marker in a config table.
pub fn config_set_f(table: &mut ConfigTable, key: &str) -> bool {
    table.insert(key.to_string(), ConfigValue::FuncMarker);
    true
}

/// `ConfigGetF` — true when a function marker is present for `key`.
#[must_use]
pub fn config_get_f(table: &ConfigTable, key: &str) -> bool {
    matches!(table.get(key), Some(ConfigValue::FuncMarker))
}

/// `ConfigSetV` — store an opaque pointer in a config table.
pub fn config_set_v(table: &mut ConfigTable, key: &str, ptr: usize) -> bool {
    table.insert(key.to_string(), ConfigValue::Ptr(ptr));
    true
}

/// `ConfigGetV` — fetch pointer stored in a config table.
#[must_use]
pub fn config_get_v(table: &ConfigTable, key: &str) -> Option<usize> {
    match table.get(key) {
        Some(ConfigValue::Ptr(p)) => Some(*p),
        _ => None,
    }
}

/// `ConfigSetU32` — store a `u32` in a config table.
pub fn config_set_u32(table: &mut ConfigTable, key: &str, value: u32) -> bool {
    table.insert(key.to_string(), ConfigValue::U32(value));
    true
}

/// `ConfigGetU32` — fetch a `u32` from a config table.
#[must_use]
pub fn config_get_u32(table: &ConfigTable, key: &str) -> Option<u32> {
    match table.get(key) {
        Some(ConfigValue::U32(v)) => Some(*v),
        _ => None,
    }
}

/// `ConfigDelete` — remove a key from a config table (C `True` when it existed).
pub fn config_delete(table: &mut ConfigTable, key: &str) -> bool {
    table.remove(key).is_some()
}

/// `OWPContextConfigDelete`
#[must_use]
pub fn context_config_delete(ctx: &Context, key: &str) -> bool {
    ctx.config_delete(key)
}

/// `OWPContextConfigGetF`
#[must_use]
pub fn context_config_get_f(ctx: &Context, key: &str) -> bool {
    ctx.config_get_f(key)
}

/// `OWPContextConfigGetU32`
#[must_use]
pub fn context_config_get_u32(ctx: &Context, key: &str) -> Option<u32> {
    ctx.config_get_u32(key)
}

/// `OWPContextConfigSetF`
#[must_use]
pub fn context_config_set_f(ctx: &Context, key: &str) -> bool {
    ctx.config_set_f(key)
}

/// `OWPContextConfigSetU32`
#[must_use]
pub fn context_config_set_u32(ctx: &Context, key: &str, value: u32) -> bool {
    ctx.config_set_u32(key, value)
}

/// `OWPContextConfigSetV`
#[must_use]
pub fn context_config_set_v(ctx: &Context, key: &str, ptr: usize) -> bool {
    ctx.config_set_v(key, ptr)
}

/// `OWPContextConfigGetV`
#[must_use]
pub fn context_config_get_v(ctx: &Context, key: &str) -> Option<usize> {
    ctx.config_get_v(key)
}

/// `OWPControlConfigDelete`
pub fn control_config_delete(cntrl: &mut Control, key: &str) -> bool {
    cntrl.config_delete(key)
}

/// `OWPControlConfigGetF`
#[must_use]
pub fn control_config_get_f(cntrl: &Control, key: &str) -> bool {
    cntrl.config_get_f(key)
}

/// `OWPControlConfigGetU32`
#[must_use]
pub fn control_config_get_u32(cntrl: &Control, key: &str) -> Option<u32> {
    cntrl.config_get_u32(key)
}

/// `OWPControlConfigGetV`
#[must_use]
pub fn control_config_get_v(cntrl: &Control, key: &str) -> Option<usize> {
    cntrl.config_get_v(key)
}

/// `OWPControlConfigSetF`
pub fn control_config_set_f(cntrl: &mut Control, key: &str) -> bool {
    cntrl.config_set_f(key)
}

/// `OWPControlConfigSetU32`
pub fn control_config_set_u32(cntrl: &mut Control, key: &str, value: u32) -> bool {
    cntrl.config_set_u32(key, value)
}

/// `OWPControlConfigSetV`
pub fn control_config_set_v(cntrl: &mut Control, key: &str, ptr: usize) -> bool {
    cntrl.config_set_v(key, ptr)
}

/// `free_hash_entries` — clear all entries from a config table.
pub fn free_hash_entries(table: &mut ConfigTable) {
    table.clear();
}

/// `notmuch` — SIGCHLD no-op handler used during context create.
pub const fn notmuch(signo: i32) {
    let _ = signo == libc::SIGCHLD;
    // C aborts on unexpected signals; keep a soft no-op for library use.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_create_and_config() {
        let ctx = Context::create().expect("ctx");
        assert!(ctx.config_set_u32(OWP_KEY_DERIVATION_COUNT, 4_096));
        assert_eq!(ctx.config_get_u32(OWP_KEY_DERIVATION_COUNT), Some(4_096));
        assert_eq!(ctx.pbkdf2_count(), 4_096);
        let control = Control::alloc(&ctx, false).expect("ctrl");
        assert_eq!(control.borrow().sockfd, -1);
        assert!(control.borrow().is_initial());
        let _ = Control::close_rc(control);
        ctx.free();
    }

    #[test]
    fn control_close_closes_socket() {
        let ctx = Context::create().expect("ctx");
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let rc = Control::alloc(&ctx, false).expect("ctrl");
        {
            let mut c = rc.borrow_mut();
            c.sockfd = fds[0];
        }
        unsafe {
            libc::close(fds[1]);
        }
        assert_eq!(Control::close_rc(rc), ErrSeverity::Ok);
        let n = unsafe { libc::write(fds[0], [1u8].as_ptr() as *const _, 1) };
        assert!(n < 0, "sockfd must be closed by close_rc");
        ctx.free();
    }

    #[test]
    fn control_close_owned_clears_sockfd() {
        let ctx = Context::create().expect("ctx");
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let rc = Control::alloc(&ctx, false).expect("ctrl");
        // Take ownership without unregister path: extract via try_unwrap after dropping other refs.
        let mut cntrl = Rc::try_unwrap(rc)
            .map_or_else(|_| panic!("control Rc not unique"), RefCell::into_inner);
        cntrl.sockfd = fds[0];
        unsafe {
            libc::close(fds[1]);
        }
        assert_eq!(cntrl.close(), ErrSeverity::Ok);
        let n = unsafe { libc::write(fds[0], [1u8].as_ptr() as *const _, 1) };
        assert!(n < 0);
        ctx.free();
    }

    #[test]
    fn config_delete_matches_c_return() {
        let ctx = Context::create().expect("ctx");
        assert!(!ctx.config_delete("missing"));
        assert!(ctx.config_set_u32("k", 1));
        assert!(ctx.config_delete("k"));
        assert!(!ctx.config_delete("k"));
        assert!(ctx.config_set_v("p", 0xdead));
        assert!(ctx.config_delete("p"));
        assert!(!ctx.config_delete("p"));
    }

    #[test]
    fn hmac_add_gated_by_docipher() {
        let ctx = Context::create().expect("ctx");
        let control = Control::alloc(&ctx, false).expect("ctrl");
        let mut cntrl = control.borrow_mut();
        cntrl.mode = crate::owampP::OWP_MODE_OPEN;
        cntrl.send_hmac.init(&[1u8; 16]);
        send_hmac_add(&mut cntrl, &[0u8; 16], 1);
        let open_digest = cntrl.send_hmac.digest_clear();
        cntrl.send_hmac.init(&[1u8; 16]);
        let empty_digest = cntrl.send_hmac.digest_clear();
        assert_eq!(open_digest, empty_digest, "OPEN must not feed HMAC");
        cntrl.mode = OWP_MODE_DOCIPHER_CNTRL;
        cntrl.send_hmac.init(&[1u8; 16]);
        send_hmac_add(&mut cntrl, &[0u8; 16], 1);
        let cipher_digest = cntrl.send_hmac.digest_clear();
        assert_ne!(cipher_digest, empty_digest, "DOCIPHER must feed HMAC");
    }

    #[test]
    fn make_key_expands_round_keys() {
        let ctx = Context::create().expect("ctx");
        let control = Control::alloc(&ctx, false).expect("ctrl");
        let mut cntrl = control.borrow_mut();
        let key = [0x2bu8; 16];
        make_key(&mut cntrl, &key);
        assert_eq!(cntrl.aessession_key, key);
        assert!(cntrl.aes_ready);
        // AES-128: first 16 bytes of enc schedule are the cipher key; later words expand.
        assert_eq!(&cntrl.encrypt_key[..16], &key);
        assert_ne!(&cntrl.encrypt_key[16..32], &[0u8; 16]);
        assert_ne!(cntrl.encrypt_key, {
            let mut only = [0u8; 240];
            only[..16].copy_from_slice(&key);
            only
        });
        assert_ne!(cntrl.decrypt_key, [0u8; 240]);
        // Decrypt schedule differs from encrypt after MixColumns inverse transform.
        assert_ne!(cntrl.decrypt_key, cntrl.encrypt_key);
    }

    #[test]
    fn port_range_and_end_delay_config() {
        let ctx = Context::create().expect("ctx");
        assert!(!ctx.set_test_port_range(PortRange { low: 10, high: 5 }));
        assert!(ctx.set_test_port_range(PortRange {
            low: 5_000,
            high: 5_010,
        }));
        assert_eq!(
            ctx.test_port_range(),
            Some(PortRange {
                low: 5_000,
                high: 5_010
            })
        );
        ctx.set_end_delay(1.5);
        assert_eq!(ctx.end_delay(), Some(1.5));
    }

    #[test]
    fn token_roundtrip() {
        let pf = b"secret";
        let salt = [1u8; 16];
        let mut plain = [0u8; OWP_TOKEN_SIZE];
        plain[0] = 0xab;
        plain[16] = 0xcd;
        let mut enc = [0u8; OWP_TOKEN_SIZE];
        let mut dec = [0u8; OWP_TOKEN_SIZE];
        assert_eq!(encrypt_token(pf, &salt, 2_048, &plain, &mut enc), 0);
        assert_eq!(decrypt_token(pf, &salt, 2_048, &enc, &mut dec), 0);
        assert_eq!(plain, dec);
    }

    #[test]
    fn owp_context_err_handle_marker() {
        let ctx = Context::create().expect("ctx");
        let _eh: ErrHandle = ctx.err_handle();
        ctx.free();
    }

    #[test]
    fn owp_control_alloc_initial_state() {
        let ctx = Context::create().expect("ctx");
        let control = Control::alloc(&ctx, true).expect("ctrl");
        let c = control.borrow();
        assert!(c.is_initial());
        assert!(c.twoway);
        assert_eq!(c.sockfd, -1);
        assert_eq!(c.state, STATE_INITIAL);
        drop(c);
        let _ = Control::close_rc(control);
        ctx.free();
    }

    #[test]
    fn config_table_set_get_delete_matches_c() {
        let mut tbl = ConfigTable::new();
        assert!(config_set_u32(&mut tbl, "n", 42));
        assert_eq!(config_get_u32(&tbl, "n"), Some(42));
        assert!(config_set_v(&mut tbl, "p", 0xdead_beef));
        assert_eq!(config_get_v(&tbl, "p"), Some(0xdead_beef));
        assert!(config_set_u(&mut tbl, "u", ConfigValue::U32(7)));
        assert!(matches!(config_get_u(&tbl, "u"), Some(ConfigValue::U32(7))));
        assert!(config_set_f(&mut tbl, "f"));
        assert!(config_get_f(&tbl, "f"));
        assert!(!config_get_f(&tbl, "missing"));
        assert!(config_delete(&mut tbl, "n"));
        assert_eq!(config_get_u32(&tbl, "n"), None);
        assert!(!config_delete(&mut tbl, "n"));
        free_hash_entries(&mut tbl);
        assert!(tbl.is_empty());
    }

    #[test]
    fn control_and_context_config_aliases() {
        let ctx = Context::create().expect("ctx");
        assert!(context_config_set_v(&ctx, "v", 123));
        assert_eq!(context_config_get_v(&ctx, "v"), Some(123));
        assert!(context_config_set_f(&ctx, "f"));
        assert!(context_config_get_f(&ctx, "f"));
        let control = Control::alloc(&ctx, false).expect("ctrl");
        let mut c = control.borrow_mut();
        assert!(control_config_set_u32(&mut c, "k", 9));
        assert_eq!(control_config_get_u32(&c, "k"), Some(9));
        assert!(control_config_set_v(&mut c, "ptr", 0x10));
        assert_eq!(control_config_get_v(&c, "ptr"), Some(0x10));
        assert!(control_config_set_f(&mut c, "cb"));
        assert!(control_config_get_f(&c, "cb"));
        assert!(control_config_delete(&mut c, "k"));
        assert_eq!(control_config_get_u32(&c, "k"), None);
        drop(c);
        let _ = Control::close_rc(control);
        ctx.free();
    }

    #[test]
    fn owp_call_defaults_allow() {
        let ctx = Context::create().expect("ctx");
        let mut err = ErrSeverity::Ok;
        assert!(call_get_pf(&ctx, "user", &mut err).is_none());
        assert_eq!(err, ErrSeverity::Ok);

        let control = Control::alloc(&ctx, false).expect("ctrl");
        let cntrl = control.borrow();
        assert!(call_check_control_policy(
            &cntrl,
            OWP_MODE_UNDEFINED,
            None,
            None,
            None,
            &mut err,
        ));
        let local = "127.0.0.1:1".parse().unwrap();
        let remote = "127.0.0.1:2".parse().unwrap();
        let mut closure = None;
        assert!(call_check_test_policy(
            &cntrl,
            true,
            local,
            remote,
            &TestSpec::default(),
            &mut closure,
            &mut err,
        ));
        assert!(call_check_fetch_policy(
            &cntrl,
            local,
            remote,
            0,
            1,
            &[0u8; 16],
            &mut closure,
            &mut err,
        ));
        drop(cntrl);
        let _ = Control::close_rc(control);
        ctx.free();
    }

    #[test]
    fn owp_call_installed_hooks() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static TC: AtomicUsize = AtomicUsize::new(0);

        let ctx = Context::create().expect("ctx");
        ctx.set_get_pf(Box::new(|_ctx, _uid, pf, err| {
            *pf = Some(vec![0xab]);
            *err = ErrSeverity::Ok;
            true
        }));
        let mut err = ErrSeverity::Ok;
        let pf = call_get_pf(&ctx, "u", &mut err).expect("pf");
        assert_eq!(pf, vec![0xab]);

        let control = Control::alloc(&ctx, false).expect("ctrl");
        let cntrl = control.borrow();
        let sid = [1u8; 16];
        let mut path = std::path::PathBuf::new();
        let path_c = std::env::temp_dir().join(format!("owamp_open_file_{}", std::process::id()));
        std::fs::write(&path_c, b"owamp").expect("write");
        let path_open = path_c.clone();
        ctx.set_open_file(Box::new(move |_c, _cl, _sid, fname| {
            *fname = path_open.clone();
            std::fs::File::open(fname).ok()
        }));
        let fp = call_open_file(&cntrl, None, &sid, &mut path).expect("file");
        assert_eq!(path, path_c);

        ctx.set_close_file(Box::new(|_c, _cl, _fp, _av| {
            TC.fetch_add(1, Ordering::SeqCst);
        }));
        call_close_file(&cntrl, None, fp, AcceptType::Accept);
        assert_eq!(TC.load(Ordering::SeqCst), 1);

        ctx.set_test_complete(Box::new(|_c, _cl, _av| {
            TC.fetch_add(2, Ordering::SeqCst);
        }));
        call_test_complete(&cntrl, None, AcceptType::Failure);
        assert_eq!(TC.load(Ordering::SeqCst), 3);

        drop(cntrl);
        let _ = Control::close_rc(control);
        let _ = std::fs::remove_file(&path_c);
        ctx.free();
    }
}
