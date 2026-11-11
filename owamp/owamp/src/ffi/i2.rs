//! Minimal `I2Addr` / `I2Err` symbols for drop-in C callers.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;
use std::sync::{Mutex, OnceLock};

use libc::{
    in_addr, sa_family_t, sockaddr, sockaddr_in, sockaddr_in6, sockaddr_storage, socklen_t,
};

use crate::context::{Addr, ErrHandle};
use crate::error;

use super::handles::{addr_from_ptr, addr_into_ptr, free_addr, I2Addr, I2ErrHandle};

struct CachedSa {
    storage: sockaddr_storage,
    len: socklen_t,
}

fn sa_cache() -> &'static Mutex<HashMap<usize, Box<CachedSa>>> {
    static CACHE: OnceLock<Mutex<HashMap<usize, Box<CachedSa>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_cache() -> std::sync::MutexGuard<'static, HashMap<usize, Box<CachedSa>>> {
    sa_cache().lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) fn forget_cached_sa(p: I2Addr) {
    if p.is_null() {
        return;
    }
    lock_cache().remove(&(p as usize));
}

fn i2b(v: bool) -> c_int {
    c_int::from(v)
}

fn cstr<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        None
    } else {
        unsafe { std::ffi::CStr::from_ptr(p) }.to_str().ok()
    }
}

fn has_socklen() -> bool {
    cfg!(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    ))
}

/// Copy a C `sockaddr` into [`SocketAddr`].
pub(crate) fn sockaddr_to_std(sa: *const sockaddr, len: socklen_t) -> Option<SocketAddr> {
    if sa.is_null() || len == 0 {
        return None;
    }
    let family = unsafe { (*sa).sa_family } as i32;
    if family == libc::AF_INET && (len as usize) >= std::mem::size_of::<sockaddr_in>() {
        let sin = unsafe { &*(sa.cast::<sockaddr_in>()) };
        let ip = Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
        let port = u16::from_be(sin.sin_port);
        Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
    } else if family == libc::AF_INET6 && (len as usize) >= std::mem::size_of::<sockaddr_in6>() {
        let sin6 = unsafe { &*(sa.cast::<sockaddr_in6>()) };
        let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
        let port = u16::from_be(sin6.sin6_port);
        Some(SocketAddr::V6(SocketAddrV6::new(
            ip,
            port,
            sin6.sin6_flowinfo,
            sin6.sin6_scope_id,
        )))
    } else {
        None
    }
}

pub(crate) fn storage_to_std(ss: &sockaddr_storage, len: socklen_t) -> Option<SocketAddr> {
    let l = if len == 0 {
        std::mem::size_of::<sockaddr_storage>() as socklen_t
    } else {
        len
    };
    sockaddr_to_std(ptr::from_ref(ss).cast::<sockaddr>(), l)
}

pub(crate) fn std_to_storage(sa: SocketAddr) -> (sockaddr_storage, socklen_t) {
    let mut storage: sockaddr_storage = unsafe { std::mem::zeroed() };
    match sa {
        SocketAddr::V4(v4) => {
            let mut sin: sockaddr_in = unsafe { std::mem::zeroed() };
            if has_socklen() {
                #[cfg(any(
                    target_os = "macos",
                    target_os = "ios",
                    target_os = "tvos",
                    target_os = "watchos",
                    target_os = "freebsd",
                    target_os = "netbsd",
                    target_os = "openbsd",
                    target_os = "dragonfly",
                ))]
                {
                    sin.sin_len = std::mem::size_of::<sockaddr_in>() as u8;
                }
            }
            sin.sin_family = libc::AF_INET as sa_family_t;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr = in_addr {
                s_addr: u32::from_ne_bytes(v4.ip().octets()),
            };
            unsafe {
                ptr::copy_nonoverlapping(
                    ptr::from_ref(&sin).cast::<u8>(),
                    ptr::from_mut(&mut storage).cast::<u8>(),
                    std::mem::size_of::<sockaddr_in>(),
                );
            }
            (storage, std::mem::size_of::<sockaddr_in>() as socklen_t)
        },
        SocketAddr::V6(v6) => {
            let mut sin6: sockaddr_in6 = unsafe { std::mem::zeroed() };
            if has_socklen() {
                #[cfg(any(
                    target_os = "macos",
                    target_os = "ios",
                    target_os = "tvos",
                    target_os = "watchos",
                    target_os = "freebsd",
                    target_os = "netbsd",
                    target_os = "openbsd",
                    target_os = "dragonfly",
                ))]
                {
                    sin6.sin6_len = std::mem::size_of::<sockaddr_in6>() as u8;
                }
            }
            sin6.sin6_family = libc::AF_INET6 as sa_family_t;
            sin6.sin6_port = v6.port().to_be();
            sin6.sin6_flowinfo = v6.flowinfo();
            sin6.sin6_addr.s6_addr = v6.ip().octets();
            sin6.sin6_scope_id = v6.scope_id();
            unsafe {
                ptr::copy_nonoverlapping(
                    ptr::from_ref(&sin6).cast::<u8>(),
                    ptr::from_mut(&mut storage).cast::<u8>(),
                    std::mem::size_of::<sockaddr_in6>(),
                );
            }
            (storage, std::mem::size_of::<sockaddr_in6>() as socklen_t)
        },
    }
}

fn remember_sa(p: I2Addr, sa: SocketAddr) -> *mut sockaddr {
    let (storage, len) = std_to_storage(sa);
    let mut map = lock_cache();
    let entry = map.entry(p as usize).or_insert_with(|| {
        Box::new(CachedSa {
            storage: unsafe { std::mem::zeroed() },
            len: 0,
        })
    });
    entry.storage = storage;
    entry.len = len;
    ptr::from_mut(&mut entry.storage).cast::<sockaddr>()
}

/// # Safety
/// `p` is a non-null pointer from [`addr_into_ptr`].
unsafe fn addr_mut<'a>(p: I2Addr) -> Option<&'a mut Addr> {
    if p.is_null() {
        None
    } else {
        Some(unsafe { &mut *p })
    }
}

fn refresh_sa(p: I2Addr) -> Option<(*mut sockaddr, socklen_t)> {
    let addr = unsafe { &mut *p };
    if addr.saddr().is_none() {
        let _ = addr.addr_info(None);
    }
    let sa = addr.saddr()?;
    let ptr = remember_sa(p, sa);
    let len = lock_cache().get(&(p as usize)).map(|c| c.len)?;
    Some((ptr, len))
}

/// Take ownership of an `I2Addr` (C frees it on hand-off).
///
/// # Safety
/// `p` is null or a pointer from [`addr_into_ptr`].
pub(crate) unsafe fn take_addr(p: I2Addr) -> Option<Addr> {
    if p.is_null() {
        return None;
    }
    forget_cached_sa(p);
    Some(*unsafe { Box::from_raw(p) })
}

/// Give `f` ownership of `p`. On `Some`, the same allocation is reused.
///
/// # Safety
/// `p` is null or a pointer from [`addr_into_ptr`].
pub(crate) unsafe fn exchange_addr(
    p: I2Addr,
    f: impl FnOnce(Option<Addr>) -> Option<Addr>,
) -> I2Addr {
    if p.is_null() {
        return match f(None) {
            Some(a) => addr_into_ptr(a),
            None => ptr::null_mut(),
        };
    }
    forget_cached_sa(p);
    let val = unsafe { ptr::read(p) };
    match f(Some(val)) {
        Some(a) => {
            unsafe { ptr::write(p, a) };
            p
        },
        None => {
            unsafe {
                std::alloc::dealloc(p.cast(), std::alloc::Layout::new::<Addr>());
            }
            ptr::null_mut()
        },
    }
}

fn global_eh() -> I2ErrHandle {
    static EH: OnceLock<ErrHandle> = OnceLock::new();
    let r = EH.get_or_init(ErrHandle::default);
    ptr::from_ref(r).cast_mut()
}

/// `I2AddrByNode(eh, node)`.
#[no_mangle]
pub unsafe extern "C" fn I2AddrByNode(_eh: I2ErrHandle, node: *const c_char) -> I2Addr {
    let Some(node) = cstr(node) else {
        return ptr::null_mut();
    };
    addr_into_ptr(Addr::by_node(node, None))
}

/// `I2AddrFree`.
#[no_mangle]
pub unsafe extern "C" fn I2AddrFree(addr: I2Addr) {
    forget_cached_sa(addr);
    unsafe { free_addr(addr) };
}

/// `I2AddrSAddr` — pointer stays valid until the next mutating call on `addr`.
#[no_mangle]
pub unsafe extern "C" fn I2AddrSAddr(addr: I2Addr, sa_len: *mut socklen_t) -> *mut sockaddr {
    if addr.is_null() {
        return ptr::null_mut();
    }
    let Some((ptr_sa, len)) = refresh_sa(addr) else {
        return ptr::null_mut();
    };
    if !sa_len.is_null() {
        unsafe { *sa_len = len };
    }
    ptr_sa
}

/// `I2AddrSetPort`.
#[no_mangle]
pub unsafe extern "C" fn I2AddrSetPort(addr: I2Addr, port: u16) -> c_int {
    let Some(a) = (unsafe { addr_mut(addr) }) else {
        return 0;
    };
    i2b(a.set_port(port))
}

/// `I2AddrPort`.
#[no_mangle]
pub unsafe extern "C" fn I2AddrPort(addr: I2Addr) -> u16 {
    unsafe { addr_from_ptr(addr) }.map(Addr::port).unwrap_or(0)
}

/// `I2AddrFD` — `-1` when unset.
#[no_mangle]
pub unsafe extern "C" fn I2AddrFD(addr: I2Addr) -> c_int {
    unsafe { addr_from_ptr(addr) }
        .and_then(Addr::fd)
        .unwrap_or(-1)
}

/// `I2AddrSetFD`.
#[no_mangle]
pub unsafe extern "C" fn I2AddrSetFD(addr: I2Addr, fd: c_int, close_fd: c_int) -> c_int {
    let Some(a) = (unsafe { addr_mut(addr) }) else {
        return 0;
    };
    i2b(a.set_fd(fd, close_fd != 0))
}

/// `I2AddrBySAddr(eh, saddr, len, socktype, protocol)`.
#[no_mangle]
pub unsafe extern "C" fn I2AddrBySAddr(
    _eh: I2ErrHandle,
    saddr: *const sockaddr,
    saddrlen: socklen_t,
    socktype: c_int,
    protocol: c_int,
) -> I2Addr {
    let Some(sa) = sockaddr_to_std(saddr, saddrlen) else {
        return ptr::null_mut();
    };
    addr_into_ptr(Addr::by_sockaddr(sa, socktype, protocol))
}

/// `I2AddrByLocalSockFD(eh, fd, close)`.
#[no_mangle]
pub unsafe extern "C" fn I2AddrByLocalSockFD(
    eh: I2ErrHandle,
    fd: c_int,
    close_fd: c_int,
) -> I2Addr {
    let _ = eh;
    match Addr::by_local_sockfd(fd, close_fd != 0) {
        Some(a) => addr_into_ptr(a),
        None => ptr::null_mut(),
    }
}

/// `I2AddrSetSocktype`.
#[no_mangle]
pub unsafe extern "C" fn I2AddrSetSocktype(addr: I2Addr, socktype: c_int) -> c_int {
    let Some(a) = (unsafe { addr_mut(addr) }) else {
        return 0;
    };
    i2b(a.set_socktype(socktype))
}

/// `I2AddrSetProtocol`.
#[no_mangle]
pub unsafe extern "C" fn I2AddrSetProtocol(addr: I2Addr, protocol: c_int) -> c_int {
    let Some(a) = (unsafe { addr_mut(addr) }) else {
        return 0;
    };
    i2b(a.set_protocol(protocol))
}

/// `I2AddrSetSAddr`.
#[no_mangle]
pub unsafe extern "C" fn I2AddrSetSAddr(
    addr: I2Addr,
    saddr: *const sockaddr,
    saddrlen: socklen_t,
) -> c_int {
    let Some(sa) = sockaddr_to_std(saddr, saddrlen) else {
        return 0;
    };
    let Some(a) = (unsafe { addr_mut(addr) }) else {
        return 0;
    };
    let ok = a.set_saddr(sa);
    if ok {
        let _ = remember_sa(addr, sa);
    }
    i2b(ok)
}

/// `I2ErrOpen` — returns a process-lifetime handle. Extra variadic args are ignored.
#[no_mangle]
pub unsafe extern "C" fn I2ErrOpen(
    _progname: *const c_char,
    _log_func: *mut c_void,
    _log_arg: *mut c_void,
) -> I2ErrHandle {
    global_eh()
}

/// `I2ErrLogSyslogFacility` — syslog `LOG_*`, or `-1` when unknown.
#[no_mangle]
pub unsafe extern "C" fn I2ErrLogSyslogFacility(name: *const c_char) -> c_int {
    let Some(name) = cstr(name) else {
        return -1;
    };
    error::syslog_facility_by_name(name).unwrap_or(-1)
}
