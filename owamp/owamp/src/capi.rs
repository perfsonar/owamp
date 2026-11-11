//! Port of `capi.c` — client control open, session request, start/fetch.

use std::cell::RefCell;
use std::net::{SocketAddr, ToSocketAddrs};
use std::rc::Rc;

use crate::api::{
    self, endpoint_init, endpoint_init_hook, endpoint_start, fail_control_session,
    read_accept_session, read_fetch_ack, read_server_greeting, read_server_start, read_start_ack,
    read_test_request_fetch, test_session_alloc, test_session_free_unlinked, write_data_header,
    write_fetch_session, write_setup_response, write_start_sessions, write_test_request,
    SessionFinishedType, SessionHeader,
};
use crate::context::{
    call_check_control_policy, call_check_test_policy, call_get_pf, encrypt_token, get_time_of_day,
    make_key, num64_sub, num64_to_double, AcceptType, Addr, Context, Control, ErrHandle,
    ErrSeverity, ErrType, PortRange, ScheduleContext, Sid, TestSpec, OWP_IPV4_ONLY, OWP_IPV6_ONLY,
    OWP_MODE_DOCIPHER_CNTRL,
};
use crate::io::{recv_hmac_add as io_recv_hmac_add, recv_hmac_check_clear};
use crate::owamp::{OwampNum64, OwampTimeStamp};
use crate::owampP::{
    OWP_CONTROL_SERVICE_NAME, OWP_DATAREC_SIZE, OWP_FETCH_AES_BLOCKS, OWP_FETCH_BUFFSIZE,
    OWP_FETCH_DATAREC_BLOCKS, OWP_MODE_AUTHENTICATED, OWP_MODE_ENCRYPTED, OWP_MODE_OPEN,
    OWP_RIJNDAEL_BLOCK_SIZE, OWP_SKIPREC_SIZE, OWP_TOKEN_SIZE, OWP_USERID_LEN,
    TWP_CONTROL_SERVICE_NAME, TWP_MODE_MIXED,
};
use crate::rijndael_api_fst as rijndael;
use std::ffi::CStr;
use std::io::Write;
use std::ptr;

/// `_OWPIsInterface` — true if `name` matches a local interface via `getifaddrs`.
#[must_use]
pub fn is_interface(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    unsafe {
        let mut ifaddr: *mut libc::ifaddrs = ptr::null_mut();
        if libc::getifaddrs(&mut ifaddr) == -1 {
            return false;
        }
        let mut found = false;
        let mut cur = ifaddr;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_name.is_null() {
                if let Ok(n) = CStr::from_ptr(ifa.ifa_name).to_str() {
                    if n == name {
                        found = true;
                        break;
                    }
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifaddr);
        found
    }
}

/// Bind `fd` to an address belonging to interface `iface` matching `remote_family`.
fn bind_to_interface_addr(fd: i32, iface: &str, remote_family: i32) -> bool {
    unsafe {
        let mut ifaddr: *mut libc::ifaddrs = ptr::null_mut();
        if libc::getifaddrs(&mut ifaddr) == -1 {
            return false;
        }
        let mut ok = false;
        let mut cur = ifaddr;
        while !cur.is_null() {
            let ifa = &*cur;
            let name_ok = !ifa.ifa_name.is_null()
                && CStr::from_ptr(ifa.ifa_name)
                    .to_str()
                    .is_ok_and(|n| n == iface);
            if name_ok && !ifa.ifa_addr.is_null() {
                let family = i32::from((*ifa.ifa_addr).sa_family);
                if family == remote_family {
                    // Prefer remote_addrinfo->ai_addrlen style sizing (C `_OWPClientBind`).
                    let addrlen = match family {
                        libc::AF_INET => {
                            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
                        },
                        libc::AF_INET6 => {
                            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
                        },
                        _ => 0,
                    };
                    if addrlen > 0 && libc::bind(fd, ifa.ifa_addr, addrlen) == 0 {
                        ok = true;
                        break;
                    }
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifaddr);
        ok
    }
}

/// Numeric host for policy/deny messages (`getnameinfo(…, NI_NUMERICHOST)`).
fn addr_numeric_host(sa: Option<SocketAddr>) -> String {
    match sa {
        Some(SocketAddr::V4(a)) => a.ip().to_string(),
        Some(SocketAddr::V6(a)) => a.ip().to_string(),
        None => "unknown".to_string(),
    }
}

/// C `OWPControlOpenCommon` failure paths: `error` forces FATAL; `denied` leaves
/// `*err_ret` untouched (often still Ok after a Warning log).
#[derive(Clone, Copy)]
enum OpenFail {
    Error,
    Denied,
}

/// Default `retn_on_intr` (=1) matching C stack locals when `cntrl.retn_on_intr`
/// is unset; otherwise the control's configured interrupt flag.
fn control_intr_flag(cntrl: &Control) -> i32 {
    cntrl.retn_on_intr.unwrap_or(1)
}

fn client_bind(
    cntrl: &Control,
    fd: i32,
    local_addr: &str,
    remote_family: i32,
) -> Result<(), ErrSeverity> {
    // C: if local_addr names an interface, bind to that iface's address (family match).
    if is_interface(local_addr) {
        if bind_to_interface_addr(fd, local_addr, remote_family) {
            return Ok(());
        }
        return Err(ErrSeverity::Warning);
    }

    let Ok(addrs) = (local_addr, 0u16).to_socket_addrs() else {
        cntrl.ctx.error(
            ErrSeverity::Fatal,
            ErrType::Unknown,
            &format!("getaddrinfo(): {local_addr}"),
        );
        return Err(ErrSeverity::Fatal);
    };
    let addrs: Vec<_> = addrs.collect();

    for sa in addrs {
        let family_ok = match sa {
            SocketAddr::V4(_) => remote_family == libc::AF_INET,
            SocketAddr::V6(_) => remote_family == libc::AF_INET6,
        };
        if !family_ok {
            continue;
        }
        let sock_addr: socket2::SockAddr = sa.into();
        let rc = unsafe {
            libc::bind(
                fd,
                sock_addr.as_ptr() as *const libc::sockaddr,
                sock_addr.len(),
            )
        };
        if rc == 0 {
            return Ok(());
        }
        // C reports selected bind() errno as Fatal (EADDRINUSE, EACCES, …).
        let err = std::io::Error::last_os_error();
        if let Some(
            libc::EAGAIN
            | libc::EBADF
            | libc::ENOTSOCK
            | libc::EADDRNOTAVAIL
            | libc::EADDRINUSE
            | libc::EACCES
            | libc::EFAULT,
        ) = err.raw_os_error()
        {
            cntrl.ctx.error(
                ErrSeverity::Fatal,
                ErrType::Unknown,
                &format!("bind(): {err}"),
            );
            return Err(ErrSeverity::Fatal);
        }
    }
    Err(ErrSeverity::Warning)
}

/// Returns: `0` success, `1` try next addr, `-1` fatal (abort connect).
fn try_addr(
    cntrl: &mut Control,
    ai: SocketAddr,
    local_addr: Option<&str>,
    interface: Option<&str>,
    mut server_addr: Addr,
) -> i32 {
    use std::os::fd::{AsRawFd, IntoRawFd};
    let domain = match ai {
        SocketAddr::V4(_) => socket2::Domain::IPV4,
        SocketAddr::V6(_) => socket2::Domain::IPV6,
    };
    let Ok(sock) =
        socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))
    else {
        return 1;
    };
    let fd = sock.as_raw_fd();

    let family = match ai {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };

    if let Some(iface) = interface {
        if !api::socket_interface_bind(cntrl, fd, iface) {
            drop(sock);
            return 1;
        }
        // Platforms without SO_BINDTODEVICE (e.g. macOS): when no explicit
        // local_addr will bind next, pin the socket to an address on `iface`
        // so outbound traffic still leaves via that interface.
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        if local_addr.is_none() && !bind_to_interface_addr(fd, iface, family) {
            drop(sock);
            return 1;
        }
        cntrl.interface = Some(iface.to_string());
    }

    if let Some(local) = local_addr {
        match client_bind(cntrl, fd, local, family) {
            Ok(()) => {},
            Err(ErrSeverity::Fatal) => {
                drop(sock);
                return -1;
            },
            Err(_) => {
                drop(sock);
                return 1;
            },
        }
    }

    if sock.connect(&ai.into()).is_ok() {
        let fd = sock.into_raw_fd();
        server_addr.set_saddr(ai);
        server_addr.set_socktype(libc::SOCK_STREAM);
        server_addr.set_protocol(libc::IPPROTO_TCP);
        server_addr.set_fd(fd, true);
        cntrl.remote_addr = Some(server_addr);
        // C: I2AddrByLocalSockFD(OWPContextErrHandle(cntrl->ctx), fd, False)
        let _eh: ErrHandle = cntrl.ctx.err_handle();
        if let Some(local) = Addr::by_local_sockfd(fd, false) {
            cntrl.local_addr = Some(local);
        } else {
            cntrl.ctx.error(
                ErrSeverity::Fatal,
                ErrType::Unknown,
                "I2AddrByLocalSockFD() failed",
            );
            let _ = unsafe { libc::close(fd) };
            return 1;
        }
        cntrl.sockfd = fd;
        return 0;
    }
    // sock dropped → closes fd
    1
}

fn client_connect(
    cntrl: &mut Control,
    local_addr: Option<&str>,
    interface: Option<&str>,
    mut server_addr: Addr,
) -> Result<(), ErrSeverity> {
    if let Some(fd) = server_addr.fd() {
        if fd >= 0 {
            cntrl.sockfd = fd;
            cntrl.remote_addr = Some(server_addr);
            return Ok(());
        }
    }

    let serv = if cntrl.twoway {
        TWP_CONTROL_SERVICE_NAME
    } else {
        OWP_CONTROL_SERVICE_NAME
    };

    // Resolve once; then retry each addrinfo entry (IPv6 preferred, then IPv4),
    // matching `_OWPClientConnect` / `TryAddr` loops.
    let addrs: Vec<SocketAddr> = server_addr
        .addr_info(Some(serv))
        .map(<[SocketAddr]>::to_vec)
        .unwrap_or_default();
    if addrs.is_empty() {
        return Err(ErrSeverity::Fatal);
    }

    let ipv4_only = cntrl.ctx.config_get_v(OWP_IPV4_ONLY).is_some();
    let ipv6_only = cntrl.ctx.config_get_v(OWP_IPV6_ONLY).is_some();

    if !ipv4_only {
        for ai in addrs.iter().copied().filter(SocketAddr::is_ipv6) {
            let rc = try_addr(cntrl, ai, local_addr, interface, server_addr.clone());
            if rc == 0 {
                return Ok(());
            }
            if rc < 0 {
                return Err(ErrSeverity::Fatal);
            }
        }
    }
    if !ipv6_only {
        for ai in addrs.iter().copied().filter(SocketAddr::is_ipv4) {
            let rc = try_addr(cntrl, ai, local_addr, interface, server_addr.clone());
            if rc == 0 {
                return Ok(());
            }
            if rc < 0 {
                return Err(ErrSeverity::Fatal);
            }
        }
    }
    // C suppresses the "Unable to connect" log here (retries would spam);
    // callers of ControlOpen report the failure via NULL + FATAL.
    Err(ErrSeverity::Fatal)
}

/// Core of `OWPControlOpen` / `TWPControlOpen` (+ Interface variants).
///
/// # Panics
///
/// Panics if an internal invariant from the C port is violated.
#[allow(clippy::too_many_lines)] // C-parity body
pub fn control_open_common(
    ctx: &Context,
    local_addr: Option<&str>,
    interface: Option<&str>,
    server_addr: Addr,
    mode_req_mask: u32,
    userid: Option<&str>,
    uptime_ret: Option<&mut OwampNum64>,
    err_ret: &mut ErrSeverity,
    twoway: bool,
) -> Option<Rc<RefCell<Control>>> {
    *err_ret = ErrSeverity::Ok;

    let cntrl_rc = match Control::alloc(ctx, twoway) {
        Ok(c) => c,
        Err(e) => {
            *err_ret = e;
            return None;
        },
    };

    let result = (|| -> Result<(), OpenFail> {
        {
            let mut cntrl = cntrl_rc.borrow_mut();
            if client_connect(&mut cntrl, local_addr, interface, server_addr.clone()).is_err() {
                return Err(OpenFail::Error);
            }
            if cntrl.local_addr.is_none() {
                // C: I2AddrByLocalSockFD failure → error (FATAL).
                match Addr::by_local_sockfd(cntrl.sockfd, false) {
                    Some(local) => cntrl.local_addr = Some(local),
                    None => return Err(OpenFail::Error),
                }
            }

            let intr = control_intr_flag(&cntrl);
            let mut mode_avail = 0u32;
            let mut challenge = [0u8; 16];
            let mut salt = [0u8; 16];
            let mut count = 0u32;
            let rc = read_server_greeting(
                &mut cntrl,
                Some(&intr),
                &mut mode_avail,
                &mut challenge,
                &mut salt,
                &mut count,
            );
            if rc < ErrSeverity::Ok {
                *err_ret = rc;
                return Err(OpenFail::Error);
            }

            mode_avail &= mode_req_mask; // mask out unwanted modes

            let mut pf: Option<Vec<u8>> = None;
            if let Some(uid) = userid {
                if (mode_avail & OWP_MODE_DOCIPHER_CNTRL) != 0 {
                    let bytes = uid.as_bytes();
                    let n = bytes.len().min(OWP_USERID_LEN);
                    cntrl.userid_buffer[..n].copy_from_slice(&bytes[..n]);
                    cntrl.userid_buffer[n..].fill(0);
                    let mut e = ErrSeverity::Ok;
                    if let Some(pass) = call_get_pf(&cntrl.ctx, uid, &mut e) {
                        cntrl.userid = Some(uid.to_string());
                        pf = Some(pass);
                    } else if e != ErrSeverity::Ok {
                        *err_ret = e;
                        return Err(OpenFail::Error);
                    }
                }
            }
            // If no passphrase, drop auth/crypt modes.
            if pf.is_none() {
                mode_avail &= !OWP_MODE_DOCIPHER_CNTRL;
            }

            let local_sa = cntrl.local_addr.as_ref().and_then(Addr::saddr);
            let remote_sa = cntrl.remote_addr.as_ref().and_then(Addr::saddr);
            let uid_opt = cntrl.userid.clone();

            let pick = |mode: u32, err: &mut ErrSeverity, c: &Control| -> bool {
                (mode_avail & mode) != 0
                    && call_check_control_policy(
                        c,
                        mode,
                        uid_opt.as_deref(),
                        local_sa,
                        remote_sa,
                        err,
                    )
            };

            // Pick highest remaining mode (Encrypted → Auth → Mixed/TW → Open).
            if pick(OWP_MODE_ENCRYPTED, err_ret, &cntrl) {
                cntrl.mode = OWP_MODE_ENCRYPTED;
            } else if *err_ret == ErrSeverity::Ok && pick(OWP_MODE_AUTHENTICATED, err_ret, &cntrl) {
                cntrl.mode = OWP_MODE_AUTHENTICATED;
            } else if *err_ret == ErrSeverity::Ok && twoway && pick(TWP_MODE_MIXED, err_ret, &cntrl)
            {
                cntrl.mode = TWP_MODE_MIXED;
            } else if *err_ret == ErrSeverity::Ok && pick(OWP_MODE_OPEN, err_ret, &cntrl) {
                cntrl.mode = OWP_MODE_OPEN;
            } else if *err_ret != ErrSeverity::Ok {
                return Err(OpenFail::Error);
            } else {
                cntrl.ctx.error(
                    ErrSeverity::Warning,
                    ErrType::Policy,
                    "OWPControlOpen: No Common Modes",
                );
                return Err(OpenFail::Denied);
            }

            let mut token = [0u8; OWP_TOKEN_SIZE];
            if (cntrl.mode & OWP_MODE_DOCIPHER_CNTRL) != 0 {
                let pf_bytes = pf.as_ref().expect("pf required for cipher modes");
                let mut aes_key = [0u8; 16];
                let mut hmac_key = [0u8; 32];
                // C order: AES key → MakeKey → HMAC key → HMAC init → encrypt token → writeIV.
                if !cntrl.ctx.random_bytes(&mut aes_key) {
                    return Err(OpenFail::Error);
                }
                cntrl.aessession_key = aes_key;
                make_key(&mut cntrl, &aes_key);

                if !cntrl.ctx.random_bytes(&mut hmac_key) {
                    return Err(OpenFail::Error);
                }
                cntrl.hmac_key = hmac_key;
                cntrl.send_hmac.init(&hmac_key);
                cntrl.recv_hmac.init(&hmac_key);

                let plain = rijndael::build_token_plaintext(&challenge, &aes_key, &hmac_key);
                if encrypt_token(pf_bytes, &salt, count, &plain, &mut token) != 0 {
                    return Err(OpenFail::Error);
                }

                let mut write_iv = [0u8; 16];
                if !cntrl.ctx.random_bytes(&mut write_iv) {
                    return Err(OpenFail::Error);
                }
                cntrl.write_iv = write_iv;
            }
            // Zero passphrase material (C memset + free).
            if let Some(ref mut p) = pf {
                p.fill(0);
            }
            drop(pf);

            let Some(timestart) = get_time_of_day(&cntrl.ctx) else {
                return Err(OpenFail::Error);
            };

            let rc = write_setup_response(&mut cntrl, Some(&intr), &token);
            if rc < ErrSeverity::Ok {
                *err_ret = rc;
                return Err(OpenFail::Error);
            }
            let mut acceptval = AcceptType::Invalid;
            let mut uptime = OwampNum64(0);
            let rc = read_server_start(&mut cntrl, Some(&intr), &mut acceptval, &mut uptime);
            if rc < ErrSeverity::Ok {
                *err_ret = rc;
                return Err(OpenFail::Error);
            }
            if acceptval != AcceptType::Accept {
                let host = addr_numeric_host(server_addr.saddr().or(remote_sa));
                cntrl.ctx.error(
                    ErrSeverity::Warning,
                    ErrType::Policy,
                    &format!("Server denied access: {host}"),
                );
                return Err(OpenFail::Denied);
            }

            let Some(timeend) = get_time_of_day(&cntrl.ctx) else {
                return Err(OpenFail::Error);
            };
            cntrl.rtt_bound = num64_sub(timeend.owptime, timestart.owptime);
            if let Some(u) = uptime_ret {
                *u = uptime;
            }
        }
        Ok(())
    })();

    match result {
        Ok(()) => Some(cntrl_rc),
        Err(OpenFail::Denied) => {
            let _ = Control::close_rc(cntrl_rc);
            None
        },
        Err(OpenFail::Error) => {
            // C `error:` always forces FATAL before cleanup.
            *err_ret = ErrSeverity::Fatal;
            let _ = Control::close_rc(cntrl_rc);
            None
        },
    }
}

pub fn control_open(
    ctx: &Context,
    local_addr: Option<&str>,
    server_addr: Addr,
    mode_req_mask: u32,
    userid: Option<&str>,
    uptime_ret: Option<&mut OwampNum64>,
    err_ret: &mut ErrSeverity,
) -> Option<Rc<RefCell<Control>>> {
    control_open_common(
        ctx,
        local_addr,
        None,
        server_addr,
        mode_req_mask,
        userid,
        uptime_ret,
        err_ret,
        false,
    )
}

pub fn control_open_interface(
    ctx: &Context,
    local_addr: Option<&str>,
    interface: Option<&str>,
    server_addr: Addr,
    mode_req_mask: u32,
    userid: Option<&str>,
    uptime_ret: Option<&mut OwampNum64>,
    err_ret: &mut ErrSeverity,
) -> Option<Rc<RefCell<Control>>> {
    control_open_common(
        ctx,
        local_addr,
        interface,
        server_addr,
        mode_req_mask,
        userid,
        uptime_ret,
        err_ret,
        false,
    )
}

pub fn twp_control_open(
    ctx: &Context,
    local_addr: Option<&str>,
    server_addr: Addr,
    mode_req_mask: u32,
    userid: Option<&str>,
    uptime_ret: Option<&mut OwampNum64>,
    err_ret: &mut ErrSeverity,
) -> Option<Rc<RefCell<Control>>> {
    control_open_common(
        ctx,
        local_addr,
        None,
        server_addr,
        mode_req_mask,
        userid,
        uptime_ret,
        err_ret,
        true,
    )
}

pub fn twp_control_open_interface(
    ctx: &Context,
    local_addr: Option<&str>,
    interface: Option<&str>,
    server_addr: Addr,
    mode_req_mask: u32,
    userid: Option<&str>,
    uptime_ret: Option<&mut OwampNum64>,
    err_ret: &mut ErrSeverity,
) -> Option<Rc<RefCell<Control>>> {
    control_open_common(
        ctx,
        local_addr,
        interface,
        server_addr,
        mode_req_mask,
        userid,
        uptime_ret,
        err_ret,
        true,
    )
}

/// After `AcceptSession`, copy negotiated UDP ports into the session/endpoint.
fn apply_accepted_ports_to_session(
    tsession: &mut crate::context::TestSession,
    sender: &Addr,
    receiver: &Addr,
) {
    tsession.sender = Some(sender.clone());
    tsession.receiver = Some(receiver.clone());
    if let Some(ep) = tsession.endpoint.as_mut() {
        if let Some(st) = ep.state.as_mut() {
            if st.role == crate::endpoint::EndpointRole::Sender {
                if let Some(sa) = receiver.saddr() {
                    st.remote = Some(sa);
                }
                if let Some(sa) = sender.saddr() {
                    // Keep local bind; only refresh if still port 0.
                    if st.local.map(|l| l.port()) == Some(0) {
                        st.local = Some(sa);
                    }
                }
            } else if let Some(sa) = sender.saddr() {
                st.remote = Some(sa);
            }
        }
    }
}

/// C `EndpointInit` mutates the same `I2Addr` later encoded into `TestRequest`.
/// Publish bound ports from `tsession` back onto the caller's Addr handles.
fn sync_bound_ports_to_addrs(
    tsession: &crate::context::TestSession,
    sender: &mut Addr,
    receiver: &mut Addr,
) {
    if let Some(p) = tsession.sender.as_ref().map(Addr::port) {
        if p != 0 {
            let _ = sender.set_port(p);
        }
    }
    if let Some(p) = tsession.receiver.as_ref().map(Addr::port) {
        if p != 0 {
            let _ = receiver.set_port(p);
        }
    }
}

fn client_request_test_read_response(
    cntrl: &mut Control,
    sender: &mut Addr,
    server_conf_sender: bool,
    receiver: &mut Addr,
    server_conf_receiver: bool,
    zero_addr: bool,
    test_spec: &TestSpec,
    sid: &mut Sid,
    err_ret: &mut ErrSeverity,
) -> i32 {
    // TW: if receiver port unset, ask server to use the local sender port.
    if cntrl.twoway && receiver.port() == 0 && !receiver.set_port(sender.port()) {
        return 1;
    }

    let intr = control_intr_flag(cntrl);
    let rc = write_test_request(
        cntrl,
        Some(&intr),
        sender.saddr(),
        receiver.saddr(),
        server_conf_sender,
        server_conf_receiver,
        zero_addr,
        if cntrl.twoway { None } else { Some(sid) },
        test_spec,
    );
    if rc < ErrSeverity::Ok {
        *err_ret = rc;
        return 1;
    }

    let mut acceptval = AcceptType::Invalid;
    let mut port_ret = 0u16;
    let sid_opt = if cntrl.twoway || server_conf_receiver {
        Some(sid)
    } else {
        None
    };
    let rc = read_accept_session(cntrl, Some(&intr), &mut acceptval, &mut port_ret, sid_opt);
    if rc < ErrSeverity::Ok {
        *err_ret = rc;
        return 1;
    }

    // Apply returned Port to the side the server configured.
    if server_conf_sender && !server_conf_receiver {
        if !sender.set_port(port_ret) {
            return 1;
        }
    } else if (cntrl.twoway || (!server_conf_sender && server_conf_receiver))
        && !receiver.set_port(port_ret)
    {
        return 1;
    }

    if acceptval == AcceptType::Accept {
        return 0;
    }
    let host = addr_numeric_host(cntrl.remote_addr.as_ref().and_then(Addr::saddr));
    cntrl.ctx.error(
        ErrSeverity::Warning,
        ErrType::Policy,
        &format!("Server denied test: {host}"),
    );
    *err_ret = ErrSeverity::Ok;
    1
}

/// `OWPSessionRequest` — no local session data file.
pub fn session_request(
    cntrl: &mut Control,
    sender: Option<Addr>,
    server_conf_sender: bool,
    receiver: Option<Addr>,
    server_conf_receiver: bool,
    zero_addr: bool,
    test_spec: &TestSpec,
    sid_ret: &mut Sid,
    err_ret: &mut ErrSeverity,
) -> bool {
    session_request_ex(
        cntrl,
        sender,
        server_conf_sender,
        receiver,
        server_conf_receiver,
        zero_addr,
        test_spec,
        None,
        sid_ret,
        err_ret,
    )
}

/// `OWPSessionRequest` with optional local receive/TW data file (`FILE *fp`).
///
/// # Panics
///
/// Panics if an internal invariant from the C port is violated.
#[allow(clippy::too_many_lines)] // C-parity body
pub fn session_request_ex(
    cntrl: &mut Control,
    mut sender: Option<Addr>,
    server_conf_sender: bool,
    mut receiver: Option<Addr>,
    server_conf_receiver: bool,
    zero_addr: bool,
    test_spec: &TestSpec,
    fp: Option<&std::fs::File>,
    sid_ret: &mut Sid,
    err_ret: &mut ErrSeverity,
) -> bool {
    *err_ret = ErrSeverity::Ok;
    let mut aval = AcceptType::Accept;
    let mut tsession_opt: Option<Box<crate::context::TestSession>> = None;

    let done = (|| {
        if !cntrl.is_request() {
            *err_ret = ErrSeverity::Fatal;
            cntrl.ctx.error(
                *err_ret,
                ErrType::Invalid,
                "OWPSessionRequest: called with invalid cntrl record",
            );
            return false;
        }

        // Fill missing receiver/sender with local control address.
        if receiver.is_none() {
            if server_conf_receiver {
                cntrl.ctx.error(
                    *err_ret,
                    ErrType::Invalid,
                    "OWPSessionRequest: called with invalid receiver address",
                );
                return false;
            }
            let Some(local) = cntrl.local_addr.as_ref().and_then(Addr::saddr) else {
                return false;
            };
            receiver = Some(Addr::by_sockaddr(
                local,
                libc::SOCK_DGRAM,
                libc::IPPROTO_UDP,
            ));
        }
        if let Some(ref mut r) = receiver {
            if !r.set_socktype(libc::SOCK_DGRAM)
                || !r.set_protocol(libc::IPPROTO_UDP)
                || !r.set_port(0)
            {
                return false;
            }
        }

        if sender.is_none() {
            if server_conf_sender {
                cntrl.ctx.error(
                    *err_ret,
                    ErrType::Invalid,
                    "OWPSessionRequest: called with invalid sender address",
                );
                return false;
            }
            let Some(local) = cntrl.local_addr.as_ref().and_then(Addr::saddr) else {
                return false;
            };
            sender = Some(Addr::by_sockaddr(
                local,
                libc::SOCK_DGRAM,
                libc::IPPROTO_UDP,
            ));
        }
        if let Some(ref mut s) = sender {
            if !s.set_socktype(libc::SOCK_DGRAM)
                || !s.set_protocol(libc::IPPROTO_UDP)
                || !s.set_port(0)
            {
                return false;
            }
        }

        let mut receiver = receiver.take().expect("receiver");
        let mut sender = sender.take().expect("sender");

        let ipv4_only = cntrl.ctx.config_get_v(OWP_IPV4_ONLY).is_some();
        let ipv6_only = cntrl.ctx.config_get_v(OWP_IPV6_ONLY).is_some();

        // Resolve both sides; fail if either cannot produce addrinfo (C).
        let Some(recv_list) = receiver.addr_info(None).map(<[SocketAddr]>::to_vec) else {
            return false;
        };
        let Some(send_list) = sender.addr_info(None).map(<[SocketAddr]>::to_vec) else {
            return false;
        };

        // Prefer IPv6, then IPv4; require matching family (AF_INET / AF_INET6 only).
        let mut found: Option<(SocketAddr, SocketAddr)> = None;
        if !ipv4_only {
            if let Some(r) = recv_list.iter().find(|a| a.is_ipv6()) {
                if let Some(s) = send_list.iter().find(|a| a.is_ipv6()) {
                    found = Some((*r, *s));
                }
            }
        }
        if found.is_none() && !ipv6_only {
            if let Some(r) = recv_list.iter().find(|a| a.is_ipv4()) {
                if let Some(s) = send_list.iter().find(|a| a.is_ipv4()) {
                    found = Some((*r, *s));
                }
            }
        }
        let Some((rai, sai)) = found else {
            *err_ret = ErrSeverity::Warning;
            cntrl.ctx.error(
                *err_ret,
                ErrType::Invalid,
                "OWPSessionRequest called with incompatible addresses",
            );
            return false;
        };
        if !receiver.set_saddr(rai) || !sender.set_saddr(sai) {
            cntrl.ctx.error(
                *err_ret,
                ErrType::Invalid,
                "OWPSessionRequest: Unable to set socket information",
            );
            return false;
        }

        let Some(mut tsession) = test_session_alloc(
            cntrl,
            sender.clone(),
            server_conf_sender,
            receiver.clone(),
            server_conf_receiver,
            test_spec,
        ) else {
            return false;
        };

        if cntrl.twoway || server_conf_receiver {
            // C: EndpointInit(sender, twoway ? fp : NULL) when send is local.
            if !server_conf_sender {
                let sender_fp = if cntrl.twoway { fp } else { None };
                if !endpoint_init(cntrl, &mut tsession, &sender, sender_fp, &mut aval, true) {
                    tsession_opt = Some(tsession);
                    return false;
                }
                // Bound UDP port must appear in TestRequest (C mutates I2Addr in place).
                sync_bound_ports_to_addrs(&tsession, &mut sender, &mut receiver);
            }

            if client_request_test_read_response(
                cntrl,
                &mut sender,
                !cntrl.twoway && server_conf_sender,
                &mut receiver,
                !cntrl.twoway && server_conf_receiver,
                zero_addr,
                test_spec,
                &mut tsession.sid,
                err_ret,
            ) != 0
            {
                tsession_opt = Some(tsession);
                return false;
            }

            // AcceptSession returns the server-bound UDP port — push it into the
            // local endpoint engine before spawn (C updates I2Addr in place).
            apply_accepted_ports_to_session(&mut tsession, &sender, &receiver);

            tsession.sctx = ScheduleContext::create(&cntrl.ctx, &tsession.sid, &tsession.test_spec);
            if tsession.sctx.is_none() {
                cntrl.ctx.error(
                    ErrSeverity::Fatal,
                    ErrType::Unknown,
                    "Unable to init schedule generator",
                );
                tsession_opt = Some(tsession);
                return false;
            }

            if !server_conf_sender {
                if !call_check_test_policy(
                    cntrl,
                    true,
                    sai,
                    rai,
                    test_spec,
                    &mut tsession.closure,
                    err_ret,
                ) {
                    cntrl
                        .ctx
                        .error(*err_ret, ErrType::Policy, "Test not allowed");
                    tsession_opt = Some(tsession);
                    return false;
                }
                if !endpoint_init_hook(cntrl, &mut tsession, &mut aval) {
                    tsession_opt = Some(tsession);
                    return false;
                }
            }
        } else {
            // Local receiver: create SID, schedule, policy, then request sender.
            if api::create_sid(cntrl, &mut tsession) != 0 {
                tsession_opt = Some(tsession);
                return false;
            }
            tsession.sctx = ScheduleContext::create(&cntrl.ctx, &tsession.sid, &tsession.test_spec);
            if tsession.sctx.is_none() {
                cntrl.ctx.error(
                    ErrSeverity::Fatal,
                    ErrType::Unknown,
                    "Unable to init schedule generator",
                );
                tsession_opt = Some(tsession);
                return false;
            }
            if !call_check_test_policy(
                cntrl,
                false,
                rai,
                sai,
                test_spec,
                &mut tsession.closure,
                err_ret,
            ) {
                cntrl
                    .ctx
                    .error(*err_ret, ErrType::Policy, "Test not allowed");
                tsession_opt = Some(tsession);
                return false;
            }
            if !endpoint_init(cntrl, &mut tsession, &receiver, fp, &mut aval, false) {
                tsession_opt = Some(tsession);
                return false;
            }
            // Server sender needs the client's bound UDP port from TestRequest.
            sync_bound_ports_to_addrs(&tsession, &mut sender, &mut receiver);
            if !server_conf_sender {
                // Client configuring both ends without a server request — denied.
                cntrl
                    .ctx
                    .error(*err_ret, ErrType::Policy, "Test not allowed");
                tsession_opt = Some(tsession);
                return false;
            }
            if client_request_test_read_response(
                cntrl,
                &mut sender,
                server_conf_sender,
                &mut receiver,
                server_conf_receiver,
                zero_addr,
                test_spec,
                &mut tsession.sid,
                err_ret,
            ) != 0
            {
                tsession_opt = Some(tsession);
                return false;
            }
            apply_accepted_ports_to_session(&mut tsession, &sender, &receiver);
            if !endpoint_init_hook(cntrl, &mut tsession, &mut aval) {
                tsession_opt = Some(tsession);
                return false;
            }
        }

        *sid_ret = tsession.sid;
        cntrl.tests.push(*tsession);
        true
    })();

    if done {
        return true;
    }

    // C error: report aval-specific reason, then free tsession (or addrs).
    match aval {
        AcceptType::Accept => {},
        AcceptType::Reject => {
            cntrl
                .ctx
                .error(*err_ret, ErrType::Policy, "Test not allowed");
        },
        AcceptType::Unsupported => {
            cntrl
                .ctx
                .error(*err_ret, ErrType::Unknown, "Test type unsupported");
        },
        AcceptType::UnavailablePerm => {
            cntrl.ctx.error(
                *err_ret,
                ErrType::Policy,
                "Test denied: resources unavailable",
            );
        },
        AcceptType::UnavailableTemp => {
            cntrl.ctx.error(
                *err_ret,
                ErrType::Policy,
                "Test denied: resource temporarily unavailable",
            );
        },
        AcceptType::Failure | AcceptType::Invalid => {
            cntrl.ctx.error(*err_ret, ErrType::Unknown, "Test failed");
        },
    }

    if let Some(ts) = tsession_opt {
        let _ = test_session_free_unlinked(cntrl, ts, AcceptType::Failure);
    }
    false
}

/// `OWPStartSessions`
pub fn start_sessions(cntrl: &mut Control) -> ErrSeverity {
    let mut err2 = ErrSeverity::Ok;
    let intr = control_intr_flag(cntrl);

    // Send StartSessions, then start local receivers while waiting for StartAck
    // (do not start senders until the server accepts).
    if write_start_sessions(cntrl, Some(&intr)) < ErrSeverity::Ok {
        return fail_control_session(cntrl, ErrSeverity::Fatal);
    }

    for t in &mut cntrl.tests {
        if let Some(ref mut ep) = t.endpoint {
            if !ep.send {
                match endpoint_start(ep) {
                    Ok(()) => err2 = err2.min(ErrSeverity::Ok),
                    Err(e) => return fail_control_session(cntrl, e),
                }
            }
        }
    }

    let mut acceptval = AcceptType::Invalid;
    if read_start_ack(cntrl, Some(&intr), &mut acceptval) < ErrSeverity::Ok
        || acceptval != AcceptType::Accept
    {
        return fail_control_session(cntrl, ErrSeverity::Fatal);
    }

    for t in &mut cntrl.tests {
        if let Some(ref mut ep) = t.endpoint {
            if ep.send {
                match endpoint_start(ep) {
                    Ok(()) => err2 = err2.min(ErrSeverity::Ok),
                    Err(e) => return fail_control_session(cntrl, e),
                }
            }
        }
    }
    err2
}

/// `OWPDelay` — signed timestamp difference in seconds.
#[must_use]
pub fn delay(send_time: &OwampTimeStamp, recv_time: &OwampTimeStamp) -> f64 {
    num64_to_double(recv_time.owptime) - num64_to_double(send_time.owptime)
}

/// `OWPParsePortRange` — parse `"N"` or `"low-high"` into a [`PortRange`].
///
/// Matches C: single value must be non-zero; `0` / `0-0` means ephemeral (ok);
/// `high < low` fails. Leading/trailing whitespace around numbers is accepted.
pub fn parse_port_range(pspec: &str, portspec: &mut PortRange) -> bool {
    let s = pspec.trim();
    if s.is_empty() {
        return false;
    }

    let parse_u16 = |t: &str| -> Option<u16> {
        let t = t.trim();
        if t.is_empty() {
            return None;
        }
        // Reject negatives / junk like C strtol bounds (0..=0xffff).
        if t.starts_with('-') {
            return None;
        }
        t.parse::<u16>().ok()
    };

    if let Some((lo, hi)) = s.split_once('-') {
        let Some(low) = parse_u16(lo) else {
            return false;
        };
        let Some(high) = parse_u16(hi) else {
            return false;
        };
        if high < low {
            return false;
        }
        portspec.low = low;
        portspec.high = high;
        // Ephemeral shortcut: both zero.
        return true;
    }

    let Some(low) = parse_u16(s) else {
        return false;
    };
    // C: only allow a single value if it is non-zero.
    if low == 0 {
        return false;
    }
    portspec.low = low;
    portspec.high = low;
    true
}

/// `OWPFetchSession` — request session data and write an `.owp` file body.
#[allow(clippy::too_many_lines)] // C-parity body
pub fn fetch_session(
    cntrl: &mut Control,
    fp: &mut dyn Write,
    begin: u32,
    end: u32,
    sid: &Sid,
    err_ret: &mut ErrSeverity,
) -> u32 {
    *err_ret = ErrSeverity::Ok;
    let intr = control_intr_flag(cntrl);

    if cntrl.twoway {
        cntrl.ctx.error(
            ErrSeverity::Fatal,
            ErrType::Invalid,
            "OWPFetchSession: not allowed on two-way connection",
        );
        *err_ret = ErrSeverity::Fatal;
        return 0;
    }

    // C: `< OWPErrWARNING` → fail control; Warning itself continues.
    if write_fetch_session(cntrl, Some(&intr), begin, end, sid) < ErrSeverity::Warning {
        *err_ret = fail_control_session(cntrl, ErrSeverity::Fatal);
        return 0;
    }

    let mut acceptval = AcceptType::Invalid;
    let mut finished = 0u8;
    let mut next_seqno = 0u32;
    let mut num_skiprecs = 0u32;
    let mut num_datarecs = 0u32;
    if read_fetch_ack(
        cntrl,
        Some(&intr),
        &mut acceptval,
        &mut finished,
        &mut next_seqno,
        &mut num_skiprecs,
        &mut num_datarecs,
    ) < ErrSeverity::Warning
    {
        *err_ret = fail_control_session(cntrl, ErrSeverity::Fatal);
        return 0;
    }

    // Server denial completes the fetch exchange without tearing down control.
    if acceptval != AcceptType::Accept {
        return 0;
    }

    let tsession = match read_test_request_fetch(cntrl, Some(&intr)) {
        Ok(t) => t,
        Err(e) => {
            *err_ret = fail_control_session(cntrl, e);
            return 0;
        },
    };

    // Sender/receiver must resolve for a valid file header (C memcpy asserts).
    let Some(sender_sa) = tsession.sender.as_ref().and_then(Addr::saddr) else {
        *err_ret = fail_control_session(cntrl, ErrSeverity::Fatal);
        let _ = api::test_session_free_unlinked(cntrl, tsession, AcceptType::Invalid);
        return 0;
    };
    let Some(receiver_sa) = tsession.receiver.as_ref().and_then(Addr::saddr) else {
        *err_ret = fail_control_session(cntrl, ErrSeverity::Fatal);
        let _ = api::test_session_free_unlinked(cntrl, tsession, AcceptType::Invalid);
        return 0;
    };

    // C stores the raw 8-bit `finished` into the header; map to typed enum for write.
    let finished_ty = match finished {
        0 => SessionFinishedType::Error,
        1 => SessionFinishedType::Normal,
        _ => SessionFinishedType::Incomplete,
    };

    let hdr = SessionHeader {
        header: true,
        version: 3,
        rec_size: OWP_DATAREC_SIZE as u32,
        twoway: false,
        finished: finished_ty,
        next_seqno,
        num_skiprecs,
        num_datarecs,
        oset_skiprecs: 0,
        oset_datarecs: 0,
        conf_sender: tsession.conf_sender,
        conf_receiver: tsession.conf_receiver,
        sid: tsession.sid,
        sender: Some(sender_sa),
        receiver: Some(receiver_sa),
        test_spec: tsession.test_spec.clone(),
    };

    let mut dowrite = if write_data_header(fp, &hdr) {
        true
    } else {
        cntrl.ctx.error(
            ErrSeverity::Fatal,
            ErrType::Unknown,
            "OWPFetchSession: OWPWriteDataHeader() failed",
        );
        *err_ret = ErrSeverity::Warning;
        false
    };
    // Free tsession (slots may be shared with hdr.test_spec — drop hdr usage after).
    let _ = api::test_session_free_unlinked(cntrl, tsession, AcceptType::Invalid);

    // Skip records (AES-block framed) then HMAC.
    let mut toff = u64::from(num_skiprecs) * OWP_SKIPREC_SIZE as u64;
    let mut buf = vec![0u8; OWP_FETCH_BUFFSIZE];
    while toff > OWP_RIJNDAEL_BLOCK_SIZE as u64 {
        if crate::io::receive_blocks_intr(cntrl, &mut buf, 1, None) != 1 {
            *err_ret = fail_control_session(cntrl, ErrSeverity::Fatal);
            return 0;
        }
        io_recv_hmac_add(cntrl, &buf[..OWP_RIJNDAEL_BLOCK_SIZE], 1);
        if dowrite && fp.write_all(&buf[..OWP_RIJNDAEL_BLOCK_SIZE]).is_err() {
            cntrl.ctx.error(
                ErrSeverity::Fatal,
                ErrType::Unknown,
                "OWPFetchSession: fwrite() failed",
            );
            dowrite = false;
            *err_ret = ErrSeverity::Warning;
        }
        toff -= OWP_RIJNDAEL_BLOCK_SIZE as u64;
    }
    if toff > 0 {
        if crate::io::receive_blocks_intr(cntrl, &mut buf, 1, None) != 1 {
            *err_ret = fail_control_session(cntrl, ErrSeverity::Fatal);
            return 0;
        }
        io_recv_hmac_add(cntrl, &buf[..OWP_RIJNDAEL_BLOCK_SIZE], 1);
        if dowrite && fp.write_all(&buf[..toff as usize]).is_err() {
            cntrl.ctx.error(
                ErrSeverity::Fatal,
                ErrType::Unknown,
                "OWPFetchSession: fwrite() failed",
            );
            dowrite = false;
            *err_ret = ErrSeverity::Warning;
        }
    }
    let mut digest = [0u8; OWP_RIJNDAEL_BLOCK_SIZE];
    if crate::io::receive_blocks_intr(cntrl, &mut digest, 1, None) != 1 {
        *err_ret = fail_control_session(cntrl, ErrSeverity::Fatal);
        return 0;
    }
    if !recv_hmac_check_clear(cntrl, &digest) {
        cntrl.ctx.error(
            ErrSeverity::Fatal,
            ErrType::Unknown,
            "OWPFetchSession: Invalid HMAC",
        );
        *err_ret = fail_control_session(cntrl, ErrSeverity::Fatal);
        return 0;
    }

    // Data records.
    let mut n = num_datarecs;
    while n >= OWP_FETCH_DATAREC_BLOCKS as u32 {
        let blks = OWP_FETCH_AES_BLOCKS as i32;
        if crate::io::receive_blocks_intr(cntrl, &mut buf, blks, None) != blks {
            *err_ret = fail_control_session(cntrl, ErrSeverity::Fatal);
            return 0;
        }
        io_recv_hmac_add(
            cntrl,
            &buf[..blks as usize * OWP_RIJNDAEL_BLOCK_SIZE],
            blks as u32,
        );
        if dowrite
            && fp
                .write_all(&buf[..OWP_FETCH_DATAREC_BLOCKS * OWP_DATAREC_SIZE])
                .is_err()
        {
            cntrl.ctx.error(
                ErrSeverity::Fatal,
                ErrType::Unknown,
                "OWPFetchSession: fwrite() failed",
            );
            dowrite = false;
            *err_ret = ErrSeverity::Warning;
        }
        n -= OWP_FETCH_DATAREC_BLOCKS as u32;
    }
    if n > 0 {
        let blks = (n as usize * OWP_DATAREC_SIZE) / OWP_RIJNDAEL_BLOCK_SIZE + 1;
        if crate::io::receive_blocks_intr(cntrl, &mut buf, blks as i32, None) != blks as i32 {
            *err_ret = fail_control_session(cntrl, ErrSeverity::Fatal);
            return 0;
        }
        io_recv_hmac_add(cntrl, &buf[..blks * OWP_RIJNDAEL_BLOCK_SIZE], blks as u32);
        if dowrite && fp.write_all(&buf[..n as usize * OWP_DATAREC_SIZE]).is_err() {
            cntrl.ctx.error(
                ErrSeverity::Fatal,
                ErrType::Unknown,
                "OWPFetchSession: fwrite() failed",
            );
            dowrite = false;
            *err_ret = ErrSeverity::Warning;
        }
    }

    let _ = fp.flush(); // C fflush(fp) before final HMAC

    if crate::io::receive_blocks_intr(cntrl, &mut digest, 1, None) != 1 {
        *err_ret = fail_control_session(cntrl, ErrSeverity::Fatal);
        return 0;
    }
    if !recv_hmac_check_clear(cntrl, &digest) {
        cntrl.ctx.error(
            ErrSeverity::Fatal,
            ErrType::Unknown,
            "OWPFetchSession: Invalid HMAC",
        );
        *err_ret = fail_control_session(cntrl, ErrSeverity::Fatal);
        return 0;
    }

    cntrl.state &= !crate::context::STATE_FETCHING;
    cntrl.state |= crate::context::STATE_REQUEST;

    if !dowrite {
        *err_ret = ErrSeverity::Warning;
        return 0;
    }
    num_datarecs
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn interface_lookup_loopback_or_absent() {
        // Loopback interface name differs by platform; either lo or lo0 is common.
        let lo = is_interface("lo") || is_interface("lo0");
        assert!(lo, "expected loopback interface lo/lo0");
        assert!(!is_interface("127.0.0.1"));
        assert!(!is_interface("::1"));
        assert!(!is_interface("definitely-not-an-iface-zzzz"));
        assert!(!is_interface(""));
    }

    #[test]
    fn parse_port_range_matches_c() {
        let mut pr = PortRange::default();
        assert!(parse_port_range("5000-5010", &mut pr));
        assert_eq!((pr.low, pr.high), (5_000, 5_010));
        assert!(parse_port_range(" 861 ", &mut pr));
        assert_eq!((pr.low, pr.high), (861, 861));
        assert!(parse_port_range("0-0", &mut pr));
        assert_eq!((pr.low, pr.high), (0, 0));
        assert!(!parse_port_range("0", &mut pr));
        assert!(!parse_port_range("10-9", &mut pr));
        assert!(!parse_port_range("", &mut pr));
        assert!(!parse_port_range("abc", &mut pr));
        assert!(!parse_port_range("-1", &mut pr));
        assert!(parse_port_range(" 100 - 200 ", &mut pr));
        assert_eq!((pr.low, pr.high), (100, 200));
    }

    #[test]
    fn delay_and_err_handle_wiring() {
        let send = OwampTimeStamp {
            owptime: OwampNum64(0),
            sync: true,
            multiplier: 1,
            scale: 0,
        };
        let recv = OwampTimeStamp {
            owptime: OwampNum64(1u64 << 32), // +1.0 second in OWPNum64
            sync: true,
            multiplier: 1,
            scale: 0,
        };
        let d = delay(&send, &recv);
        assert!((d - 1.0).abs() < 1e-9);

        let ctx = Context::create().expect("ctx");
        let _eh: ErrHandle = ctx.err_handle();
    }

    #[test]
    fn addr_numeric_host_formats() {
        assert_eq!(addr_numeric_host(None), "unknown");
        let v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 861));
        assert_eq!(addr_numeric_host(Some(v4)), "192.0.2.1");
        let v6 = SocketAddr::from((
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            861,
        ));
        assert_eq!(addr_numeric_host(Some(v6)), "2001:db8::1");
    }

    #[test]
    fn control_open_fails_fast_without_server_addrs() {
        // Addr with neither fd nor sockaddrs/node → client_connect fails immediately.
        let ctx = Context::create().expect("ctx");
        let server = Addr {
            sockaddrs: Vec::new(),
            socktype: libc::SOCK_STREAM,
            protocol: libc::IPPROTO_TCP,
            port: 861,
            fd: None,
            fd_close: false,
            passive: false,
            node: None,
            service: Some("861".into()),
        };
        let mut err = ErrSeverity::Ok;
        let cntrl = control_open(
            &ctx,
            None,
            server,
            crate::owampP::OWP_MODE_OPEN,
            None,
            None,
            &mut err,
        );
        assert!(cntrl.is_none());
        // Connect failure takes the C `error` path → FATAL.
        assert_eq!(err, ErrSeverity::Fatal);
    }

    #[test]
    fn control_open_interface_unreachable_iface_fails() {
        let ctx = Context::create().expect("ctx");
        // Pre-resolved IPv4 so TryAddr runs; bogus interface → bind fails → try next → FATAL.
        let server = Addr {
            sockaddrs: vec![SocketAddr::from(([127, 0, 0, 1], 1))], // port 1: unlikely listener
            socktype: libc::SOCK_STREAM,
            protocol: libc::IPPROTO_TCP,
            port: 1,
            fd: None,
            fd_close: false,
            passive: false,
            node: Some("127.0.0.1".into()),
            service: Some("1".into()),
        };
        let mut err = ErrSeverity::Ok;
        let cntrl = control_open_interface(
            &ctx,
            None,
            Some("definitely-not-an-iface-zzzz"),
            server,
            crate::owampP::OWP_MODE_OPEN,
            None,
            None,
            &mut err,
        );
        assert!(cntrl.is_none());
        assert_eq!(err, ErrSeverity::Fatal);
    }

    #[test]
    fn client_bind_rejects_non_matching_family_as_warning() {
        use std::os::fd::AsRawFd;
        // Bind to a V4-only literal while asking for AF_INET6 → Warning (try next).
        let ctx = Context::create().expect("ctx");
        let cntrl_rc = Control::alloc(&ctx, false).expect("cntrl");
        let cntrl = cntrl_rc.borrow();
        let sock = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .expect("socket");
        let rc = client_bind(&cntrl, sock.as_raw_fd(), "127.0.0.1", libc::AF_INET6);
        assert!(matches!(rc, Err(ErrSeverity::Warning)));
    }

    #[test]
    fn session_request_rejects_non_request_state() {
        let ctx = Context::create().expect("ctx");
        let cntrl_rc = Control::alloc(&ctx, false).expect("cntrl");
        let mut cntrl = cntrl_rc.borrow_mut();
        // Fresh control is SETUP, not REQUEST.
        cntrl.state = crate::context::STATE_SETUP;
        let mut sid = [0u8; 16];
        let mut err = ErrSeverity::Ok;
        let spec = TestSpec::default();
        assert!(!session_request(
            &mut cntrl, None, false, None, true, false, &spec, &mut sid, &mut err,
        ));
        assert_eq!(err, ErrSeverity::Fatal);
    }

    #[test]
    fn fetch_session_rejects_twoway() {
        let ctx = Context::create().expect("ctx");
        let cntrl_rc = Control::alloc(&ctx, true).expect("cntrl");
        let mut cntrl = cntrl_rc.borrow_mut();
        let mut buf = Vec::new();
        let mut err = ErrSeverity::Ok;
        let sid = [0u8; 16];
        assert_eq!(fetch_session(&mut cntrl, &mut buf, 0, 1, &sid, &mut err), 0);
        assert_eq!(err, ErrSeverity::Fatal);
        assert_eq!(buf, []);
    }

    #[test]
    fn try_addr_unreachable_peer_returns_one() {
        let ctx = Context::create().expect("ctx");
        let cntrl_rc = Control::alloc(&ctx, false).expect("cntrl");
        let mut cntrl = cntrl_rc.borrow_mut();
        let ai = SocketAddr::from(([127, 0, 0, 1], 1));
        let server = Addr::by_sockaddr(ai, libc::SOCK_STREAM, libc::IPPROTO_TCP);
        let rc = try_addr(&mut cntrl, ai, None, None, server);
        assert_eq!(rc, 1);
        assert_eq!(cntrl.sockfd, -1);
    }

    #[test]
    fn try_addr_bogus_interface_returns_one() {
        let ctx = Context::create().expect("ctx");
        let cntrl_rc = Control::alloc(&ctx, false).expect("cntrl");
        let mut cntrl = cntrl_rc.borrow_mut();
        let ai = SocketAddr::from(([127, 0, 0, 1], 1));
        let server = Addr::by_sockaddr(ai, libc::SOCK_STREAM, libc::IPPROTO_TCP);
        let rc = try_addr(
            &mut cntrl,
            ai,
            None,
            Some("owamp-definitely-not-an-iface"),
            server,
        );
        assert_eq!(rc, 1);
        assert_eq!(cntrl.sockfd, -1);
    }

    #[test]
    fn bind_to_loopback_iface_addr() {
        use std::os::fd::AsRawFd;
        let iface = if is_interface("lo0") {
            "lo0"
        } else if is_interface("lo") {
            "lo"
        } else {
            return; // skip if no loopback name
        };
        let sock = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .expect("socket");
        assert!(bind_to_interface_addr(
            sock.as_raw_fd(),
            iface,
            libc::AF_INET
        ));
    }
}
