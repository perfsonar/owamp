//! `#[no_mangle]` exports for every `OWP*` / `TWP*` symbol in `owamp.h`.

#![allow(non_snake_case)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::CStr;
use std::io::{Seek, SeekFrom};
use std::os::fd::FromRawFd;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr::{self, null_mut};
use std::rc::Rc;
use std::sync::{Mutex, OnceLock};

use crate::api::{self, SessionFinishedType};
use crate::arithm64::{self, TimeSpec, TimeVal};
use crate::capi::{self, session_request_ex};
use crate::context::{self, AcceptType, Context, Control, ErrSeverity, ErrType, Slot, SlotType};
use crate::owamp::{
    self, OwampNum64, OwampSlot, OwampSlotLiteral, OwampSlotRandExp, OwampTestSpec, OwampTimeStamp,
};
use crate::sapi;
use crate::schedule::{self, ScheduleContext};
use crate::stats::{self, Stats};
use crate::time;

use super::cfile::CFile;
use super::handles::{
    control_from_ptr, control_into_ptr, ctx_from_ptr, ctx_into_ptr, exp_from_ptr, exp_into_ptr,
    free_control, free_ctx, sched_from_ptr, sched_into_ptr, stats_from_ptr, stats_into_ptr,
    OWPContext, OWPControl, OWPExpContext, OWPScheduleContext, OWPStats,
};
use super::i2;
use super::types::{self, owp_bool, owp_false, owp_true, OWPBoolean, OWPNum64};

fn ctrl_map() -> std::sync::MutexGuard<'static, HashMap<usize, usize>> {
    static M: OnceLock<Mutex<HashMap<usize, usize>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn stats_map() -> std::sync::MutexGuard<'static, HashMap<usize, usize>> {
    static M: OnceLock<Mutex<HashMap<usize, usize>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn c_str<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(p) }.to_str().ok()
    }
}

fn c_owned(p: *const c_char) -> Option<String> {
    let s = c_str(p)?;
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn set_err(p: *mut c_int, s: ErrSeverity) {
    if !p.is_null() {
        unsafe { *p = s as c_int };
    }
}

fn etype_from(v: c_int) -> ErrType {
    match v {
        1 => ErrType::Policy,
        2 => ErrType::Invalid,
        3 => ErrType::Unsupported,
        _ => ErrType::Unknown,
    }
}

fn accept_from(v: c_int) -> AcceptType {
    match v {
        -1 => AcceptType::Invalid,
        0 => AcceptType::Accept,
        1 => AcceptType::Reject,
        2 => AcceptType::Failure,
        3 => AcceptType::Unsupported,
        4 => AcceptType::UnavailablePerm,
        5 => AcceptType::UnavailableTemp,
        _ => AcceptType::Invalid,
    }
}

fn load_accept(p: *mut c_int) -> AcceptType {
    if p.is_null() {
        AcceptType::Accept
    } else {
        accept_from(unsafe { *p })
    }
}

fn store_accept(p: *mut c_int, a: AcceptType) {
    if !p.is_null() {
        unsafe { *p = a as c_int };
    }
}

fn load_sid(p: *const u8) -> Option<[u8; 16]> {
    if p.is_null() {
        None
    } else {
        let mut sid = [0u8; 16];
        unsafe { ptr::copy_nonoverlapping(p, sid.as_mut_ptr(), 16) };
        Some(sid)
    }
}

fn store_sid(p: *mut u8, sid: &[u8; 16]) {
    if !p.is_null() {
        unsafe { ptr::copy_nonoverlapping(sid.as_ptr(), p, 16) };
    }
}

fn intr_ref<'a>(p: *mut c_int) -> Option<&'a c_int> {
    if p.is_null() {
        None
    } else {
        Some(unsafe { &*p })
    }
}

fn ctrl_ref<R>(p: OWPControl, f: impl FnOnce(&Control) -> R) -> Option<R> {
    let rc = unsafe { control_from_ptr(p) }?;
    Some(f(&rc.borrow()))
}

fn ctrl_mut<R>(p: OWPControl, f: impl FnOnce(&mut Control) -> R) -> Option<R> {
    let rc = unsafe { control_from_ptr(p) }?;
    Some(f(&mut rc.borrow_mut()))
}

fn ctx_ref<R>(p: OWPContext, f: impl FnOnce(&Context) -> R) -> Option<R> {
    let c = unsafe { ctx_from_ptr(p) }?;
    Some(f(c))
}

fn bind_control(ctx: OWPContext, rc: Rc<RefCell<Control>>) -> OWPControl {
    let p = control_into_ptr(rc);
    ctrl_map().insert(p as usize, ctx as usize);
    p
}

fn ts_from_c(t: &types::OWPTimeStamp) -> OwampTimeStamp {
    OwampTimeStamp {
        owptime: OwampNum64(t.owptime),
        sync: t.sync != 0,
        multiplier: t.multiplier,
        scale: t.scale,
    }
}

fn ts_to_c(t: &OwampTimeStamp) -> types::OWPTimeStamp {
    types::OWPTimeStamp {
        owptime: t.owptime.0,
        sync: u8::from(t.sync),
        multiplier: t.multiplier,
        scale: t.scale,
    }
}

fn data_from_c(r: &types::OWPDataRec) -> api::DataRec {
    api::DataRec {
        seq_no: r.seq_no,
        send: ts_from_c(&r.send),
        recv: ts_from_c(&r.recv),
        ttl: r.ttl,
    }
}

fn data_to_c(r: &api::DataRec) -> types::OWPDataRec {
    types::OWPDataRec {
        seq_no: r.seq_no,
        send: ts_to_c(&r.send),
        recv: ts_to_c(&r.recv),
        ttl: r.ttl,
    }
}

fn tw_from_c(r: &types::OWPTWDataRec) -> api::TwDataRec {
    api::TwDataRec {
        sent: data_from_c(&r.sent),
        reflected: data_from_c(&r.reflected),
    }
}

fn tw_to_c(r: &api::TwDataRec) -> types::OWPTWDataRec {
    types::OWPTWDataRec {
        sent: data_to_c(&r.sent),
        reflected: data_to_c(&r.reflected),
    }
}

fn slot_from_c(s: &types::OWPSlot) -> Slot {
    let ty = unsafe { s.slot_type };
    let time = if ty == 0 {
        unsafe { s.rand_exp.mean }
    } else {
        unsafe { s.literal.offset }
    };
    Slot {
        slot_type: match ty {
            0 => SlotType::RandExp,
            1 => SlotType::Literal,
            _ => SlotType::Unspecified,
        },
        time: OwampNum64(time),
    }
}

fn slot_to_c(s: &Slot) -> types::OWPSlot {
    match s.slot_type {
        SlotType::RandExp => types::OWPSlot {
            rand_exp: types::OWPSlotRandExp {
                slot_type: 0,
                mean: s.time.0,
            },
        },
        SlotType::Literal => types::OWPSlot {
            literal: types::OWPSlotLiteral {
                slot_type: 1,
                offset: s.time.0,
            },
        },
        SlotType::Unspecified => types::OWPSlot { slot_type: -1 },
    }
}

fn slot_to_owamp(s: &Slot) -> OwampSlot {
    match s.slot_type {
        SlotType::RandExp => OwampSlot::RandExp(OwampSlotRandExp { mean: s.time }),
        SlotType::Literal | SlotType::Unspecified => {
            OwampSlot::Literal(OwampSlotLiteral { offset: s.time })
        },
    }
}

fn c_slots(t: &types::OWPTestSpec) -> Vec<Slot> {
    if t.slots.is_null() || t.nslots == 0 {
        return Vec::new();
    }
    let slice = unsafe { std::slice::from_raw_parts(t.slots, t.nslots as usize) };
    slice.iter().map(slot_from_c).collect()
}

fn ctx_tspec_from_c(t: &types::OWPTestSpec) -> context::TestSpec {
    context::TestSpec {
        start_time: OwampNum64(t.start_time),
        loss_timeout: OwampNum64(t.loss_timeout),
        type_p: t.typeP,
        packet_size_padding: t.packet_size_padding,
        npackets: t.npackets,
        nslots: t.nslots,
        slots: c_slots(t),
    }
}

fn owamp_tspec_from_c(t: &types::OWPTestSpec) -> OwampTestSpec {
    let spec = ctx_tspec_from_c(t);
    OwampTestSpec {
        start_time: spec.start_time,
        loss_timeout: spec.loss_timeout,
        type_p: spec.type_p,
        packet_size_padding: spec.packet_size_padding,
        npackets: spec.npackets,
        slots: spec.slots.iter().map(slot_to_owamp).collect(),
    }
}

fn finished_from(v: c_int) -> SessionFinishedType {
    match v {
        1 => SessionFinishedType::Normal,
        2 => SessionFinishedType::Incomplete,
        _ => SessionFinishedType::Error,
    }
}

fn finished_to(v: SessionFinishedType) -> c_int {
    match v {
        SessionFinishedType::Error => 0,
        SessionFinishedType::Normal => 1,
        SessionFinishedType::Incomplete => 2,
    }
}

fn session_header_from_c(h: &types::OWPSessionHeaderRec) -> api::SessionHeader {
    api::SessionHeader {
        header: h.header != 0,
        version: h.version,
        rec_size: h.rec_size,
        twoway: h.twoway != 0,
        finished: finished_from(h.finished),
        next_seqno: h.next_seqno,
        num_skiprecs: h.num_skiprecs,
        num_datarecs: h.num_datarecs,
        oset_skiprecs: h.oset_skiprecs as u64,
        oset_datarecs: h.oset_datarecs as u64,
        conf_sender: h.conf_sender != 0,
        conf_receiver: h.conf_receiver != 0,
        sid: h.sid,
        sender: i2::storage_to_std(&h.addr_sender, h.addr_len),
        receiver: i2::storage_to_std(&h.addr_receiver, h.addr_len),
        test_spec: ctx_tspec_from_c(&h.test_spec),
    }
}

fn session_header_into_c(
    h: &api::SessionHeader,
    out: &mut types::OWPSessionHeaderRec,
    fp: *mut libc::FILE,
) {
    out.header = owp_bool(h.header);
    out.version = h.version;
    out.rec_size = h.rec_size;
    out.twoway = owp_bool(h.twoway);
    out.finished = finished_to(h.finished);
    out.next_seqno = h.next_seqno;
    out.num_skiprecs = h.num_skiprecs;
    out.num_datarecs = h.num_datarecs;
    out.oset_skiprecs = h.oset_skiprecs as libc::off_t;
    out.oset_datarecs = h.oset_datarecs as libc::off_t;
    out.conf_sender = owp_bool(h.conf_sender);
    out.conf_receiver = owp_bool(h.conf_receiver);
    out.sid = h.sid;
    out.ipvn = 0;
    out.addr_len = 0;
    out.addr_sender = unsafe { std::mem::zeroed() };
    out.addr_receiver = unsafe { std::mem::zeroed() };
    if let Some(sa) = h.sender {
        let (st, len) = i2::std_to_storage(sa);
        out.addr_sender = st;
        out.addr_len = len;
        out.ipvn = if sa.is_ipv4() { 4 } else { 6 };
    }
    if let Some(sa) = h.receiver {
        let (st, len) = i2::std_to_storage(sa);
        out.addr_receiver = st;
        if out.addr_len == 0 {
            out.addr_len = len;
        }
        if out.ipvn == 0 {
            out.ipvn = if sa.is_ipv4() { 4 } else { 6 };
        }
    }
    out.test_spec.start_time = h.test_spec.start_time.0;
    out.test_spec.loss_timeout = h.test_spec.loss_timeout.0;
    out.test_spec.typeP = h.test_spec.type_p;
    out.test_spec.packet_size_padding = h.test_spec.packet_size_padding;
    out.test_spec.npackets = h.test_spec.npackets;
    out.test_spec.nslots = h.test_spec.nslots;
    out.test_spec.slots = null_mut();
    out.sbuf = unsafe { std::mem::zeroed() };
    if !fp.is_null() {
        let fd = unsafe { libc::fileno(fp) };
        if fd >= 0 {
            let rc = unsafe { libc::fstat(fd, &mut out.sbuf) };
            let _ = rc;
        }
    }
}

fn timeval_from_libc(tv: &libc::timeval) -> TimeVal {
    TimeVal {
        tv_sec: tv.tv_sec as i64,
        tv_usec: tv.tv_usec as i64,
    }
}

fn timeval_to_libc(tv: TimeVal) -> libc::timeval {
    let mut out: libc::timeval = unsafe { std::mem::zeroed() };
    out.tv_sec = tv.tv_sec as _;
    out.tv_usec = tv.tv_usec as _;
    out
}

fn timespec_from_libc(tv: &libc::timespec) -> TimeSpec {
    TimeSpec {
        tv_sec: tv.tv_sec as i64,
        tv_nsec: tv.tv_nsec as i64,
    }
}

fn timespec_to_libc(tv: TimeSpec) -> libc::timespec {
    let mut out: libc::timespec = unsafe { std::mem::zeroed() };
    out.tv_sec = tv.tv_sec as _;
    out.tv_nsec = tv.tv_nsec as _;
    out
}

fn dup_cfile(fp: *mut libc::FILE) -> Option<std::fs::File> {
    if fp.is_null() {
        return None;
    }
    let fd = unsafe { libc::fileno(fp) };
    if fd < 0 {
        return None;
    }
    let duped = unsafe { libc::dup(fd) };
    if duped < 0 {
        return None;
    }
    Some(unsafe { std::fs::File::from_raw_fd(duped) })
}

unsafe extern "C" {
    fn vsnprintf(
        s: *mut c_char,
        n: usize,
        format: *const c_char,
        ap: std::ffi::VaList<'_>,
    ) -> c_int;
}

fn format_c_message(fmt: *const c_char, args: std::ffi::VaList<'_>) -> String {
    if fmt.is_null() {
        return String::new();
    }
    let mut buf = [0u8; 1024];
    let n = unsafe { vsnprintf(buf.as_mut_ptr().cast(), buf.len(), fmt, args) };
    if n < 0 {
        return unsafe { CStr::from_ptr(fmt) }
            .to_string_lossy()
            .into_owned();
    }
    let n = (n as usize).min(buf.len().saturating_sub(1));
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

fn apply_ctx_value(ctx: &Context, key: &str, value: *mut c_void) {
    if value.is_null() {
        return;
    }
    if key == context::OWP_TEST_PORT_RANGE {
        let pr = unsafe { &*value.cast::<types::OWPPortRangeRec>() };
        let _ = ctx.set_test_port_range(context::PortRange {
            low: pr.low,
            high: pr.high,
        });
    } else if key == context::OWP_END_DELAY {
        let d = unsafe { *value.cast::<f64>() };
        ctx.set_end_delay(d);
    }
}

enum OpenHow {
    Client,
    Interface(*const c_char),
}

fn control_open_ffi(
    ctx: OWPContext,
    local_addr: *const c_char,
    how: OpenHow,
    server_addr: super::handles::I2Addr,
    mode_mask: u32,
    userid: *const c_char,
    uptime_ret: *mut OWPNum64,
    err_ret: *mut c_int,
    twoway: bool,
) -> OWPControl {
    let Some(ctx_ref) = (unsafe { ctx_from_ptr(ctx) }) else {
        set_err(err_ret, ErrSeverity::Fatal);
        return null_mut();
    };
    let Some(server) = (unsafe { i2::take_addr(server_addr) }) else {
        set_err(err_ret, ErrSeverity::Fatal);
        return null_mut();
    };
    let local = c_owned(local_addr);
    let user = c_owned(userid);
    let with_if = matches!(how, OpenHow::Interface(_));
    let iface = if let OpenHow::Interface(p) = how {
        c_owned(p)
    } else {
        None
    };
    let mut uptime = OwampNum64(0);
    let mut err = ErrSeverity::Ok;
    let up_arg = if uptime_ret.is_null() {
        None
    } else {
        Some(&mut uptime)
    };
    let rc = match (twoway, with_if) {
        (false, false) => capi::control_open(
            ctx_ref,
            local.as_deref(),
            server,
            mode_mask,
            user.as_deref(),
            up_arg,
            &mut err,
        ),
        (false, true) => capi::control_open_interface(
            ctx_ref,
            local.as_deref(),
            iface.as_deref(),
            server,
            mode_mask,
            user.as_deref(),
            up_arg,
            &mut err,
        ),
        (true, false) => capi::twp_control_open(
            ctx_ref,
            local.as_deref(),
            server,
            mode_mask,
            user.as_deref(),
            up_arg,
            &mut err,
        ),
        (true, true) => capi::twp_control_open_interface(
            ctx_ref,
            local.as_deref(),
            iface.as_deref(),
            server,
            mode_mask,
            user.as_deref(),
            up_arg,
            &mut err,
        ),
    };
    set_err(err_ret, err);
    if let Some(rc) = rc {
        if !uptime_ret.is_null() {
            unsafe { *uptime_ret = uptime.0 };
        }
        bind_control(ctx, rc)
    } else {
        null_mut()
    }
}

fn server_sock_ffi(
    ctx: OWPContext,
    addr: super::handles::I2Addr,
    err_ret: *mut c_int,
    twoway: bool,
) -> super::handles::I2Addr {
    let Some(ctx_ref) = (unsafe { ctx_from_ptr(ctx) }) else {
        if !addr.is_null() {
            drop(unsafe { i2::take_addr(addr) });
        }
        set_err(err_ret, ErrSeverity::Fatal);
        return null_mut();
    };
    let mut err = ErrSeverity::Ok;
    let out = unsafe {
        i2::exchange_addr(addr, |a| {
            if twoway {
                sapi::twp_server_sock_create(ctx_ref, a, &mut err)
            } else {
                sapi::server_sock_create(ctx_ref, a, &mut err)
            }
        })
    };
    set_err(err_ret, err);
    out
}

fn accept_ffi(
    ctx: OWPContext,
    connfd: c_int,
    connsaddr: *const libc::sockaddr,
    connsaddrlen: libc::socklen_t,
    mode_offered: u32,
    uptime: OWPNum64,
    retn_on_intr: *mut c_int,
    err_ret: *mut c_int,
    twoway: bool,
) -> OWPControl {
    let Some(ctx_ref) = (unsafe { ctx_from_ptr(ctx) }) else {
        set_err(err_ret, ErrSeverity::Fatal);
        return null_mut();
    };
    let sa = if connsaddr.is_null() {
        None
    } else {
        i2::sockaddr_to_std(connsaddr, connsaddrlen)
    };
    let mut err = ErrSeverity::Ok;
    let rc = if twoway {
        sapi::twp_control_accept(
            ctx_ref,
            connfd,
            sa,
            mode_offered,
            OwampNum64(uptime),
            &mut err,
        )
    } else {
        sapi::control_accept(
            ctx_ref,
            connfd,
            sa,
            mode_offered,
            OwampNum64(uptime),
            &mut err,
        )
    };
    set_err(err_ret, err);
    if let Some(rc) = rc {
        if !retn_on_intr.is_null() {
            rc.borrow_mut().retn_on_intr = Some(unsafe { *retn_on_intr });
        }
        bind_control(ctx, rc)
    } else {
        null_mut()
    }
}

// ---------------------------------------------------------------------------
// arithm64
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn OWPNum64Mult(x: OWPNum64, y: OWPNum64) -> OWPNum64 {
    arithm64::num64_mult(OwampNum64(x), OwampNum64(y)).0
}

#[no_mangle]
pub unsafe extern "C" fn OWPULongToNum64(from: u32) -> OWPNum64 {
    arithm64::ulong_to_num64(from).0
}

#[no_mangle]
pub unsafe extern "C" fn OWPNum64ToTimeval(to: *mut libc::timeval, from: OWPNum64) {
    if to.is_null() {
        return;
    }
    unsafe { *to = timeval_to_libc(arithm64::num64_to_timeval(OwampNum64(from))) };
}

#[no_mangle]
pub unsafe extern "C" fn OWPTimevalToNum64(to: *mut OWPNum64, from: *const libc::timeval) {
    if to.is_null() || from.is_null() {
        return;
    }
    unsafe { *to = arithm64::timeval_to_num64(&timeval_from_libc(&*from)).0 };
}

#[no_mangle]
pub unsafe extern "C" fn OWPNum64ToTimespec(to: *mut libc::timespec, from: OWPNum64) {
    if to.is_null() {
        return;
    }
    unsafe { *to = timespec_to_libc(arithm64::num64_to_timespec(OwampNum64(from))) };
}

#[no_mangle]
pub unsafe extern "C" fn OWPTimespecToNum64(to: *mut OWPNum64, from: *const libc::timespec) {
    if to.is_null() || from.is_null() {
        return;
    }
    unsafe { *to = arithm64::timespec_to_num64(&timespec_from_libc(&*from)).0 };
}

#[no_mangle]
pub unsafe extern "C" fn OWPNum64ToDouble(from: OWPNum64) -> f64 {
    arithm64::num64_to_double(OwampNum64(from))
}

#[no_mangle]
pub unsafe extern "C" fn OWPDoubleToNum64(from: f64) -> OWPNum64 {
    arithm64::double_to_num64(from).0
}

#[no_mangle]
pub unsafe extern "C" fn OWPUsecToNum64(usec: u32) -> OWPNum64 {
    arithm64::usec_to_num64(usec).0
}

// ---------------------------------------------------------------------------
// time
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn OWPGetTimeOfDay(
    ctx: OWPContext,
    tstamp: *mut types::OWPTimeStamp,
) -> *mut types::OWPTimeStamp {
    if ctx.is_null() || tstamp.is_null() {
        return null_mut();
    }
    match time::get_time_of_day() {
        Some(ts) => {
            unsafe { *tstamp = ts_to_c(&ts) };
            tstamp
        },
        None => null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn OWPGetTimeStampError(tstamp: *const types::OWPTimeStamp) -> f64 {
    if tstamp.is_null() {
        return 0.0;
    }
    time::get_timestamp_error(&ts_from_c(unsafe { &*tstamp }))
}

#[no_mangle]
pub unsafe extern "C" fn OWPTimevalToTimestamp(
    tstamp: *mut types::OWPTimeStamp,
    tval: *const libc::timeval,
) -> *mut types::OWPTimeStamp {
    if tstamp.is_null() || tval.is_null() {
        return null_mut();
    }
    let tv = timeval_from_libc(unsafe { &*tval });
    match time::timeval_to_timestamp(&tv) {
        Some(ts) => {
            unsafe { *tstamp = ts_to_c(&ts) };
            tstamp
        },
        None => null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn OWPTimestampToTimeval(
    tval: *mut libc::timeval,
    tstamp: *const types::OWPTimeStamp,
) -> *mut libc::timeval {
    if tval.is_null() || tstamp.is_null() {
        return null_mut();
    }
    let ts = ts_from_c(unsafe { &*tstamp });
    match time::timestamp_to_timeval(&ts) {
        Some(tv) => {
            unsafe { *tval = timeval_to_libc(tv) };
            tval
        },
        None => null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn OWPTimespecToTimestamp(
    tstamp: *mut types::OWPTimeStamp,
    tspec: *const libc::timespec,
    errest: *const u32,
    last_errest: *const u32,
) -> *mut types::OWPTimeStamp {
    if tstamp.is_null() || tspec.is_null() {
        return null_mut();
    }
    let mut ts = ts_from_c(unsafe { &*tstamp });
    let spec = timespec_from_libc(unsafe { &*tspec });
    let err = if errest.is_null() {
        None
    } else {
        Some(unsafe { *errest })
    };
    let last = if last_errest.is_null() {
        None
    } else {
        Some(unsafe { *last_errest })
    };
    match time::timespec_to_timestamp(&mut ts, &spec, err, last) {
        Some(out) => {
            unsafe { *tstamp = ts_to_c(&out) };
            tstamp
        },
        None => null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn OWPTimestampToTimespec(
    tspec: *mut libc::timespec,
    tstamp: *const types::OWPTimeStamp,
) -> *mut libc::timespec {
    if tspec.is_null() || tstamp.is_null() {
        return null_mut();
    }
    let ts = ts_from_c(unsafe { &*tstamp });
    match time::timestamp_to_timespec(&ts) {
        Some(spec) => {
            unsafe { *tspec = timespec_to_libc(spec) };
            tspec
        },
        None => null_mut(),
    }
}

// ---------------------------------------------------------------------------
// context / error
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn OWPContextCreate(_eh: super::handles::I2ErrHandle) -> OWPContext {
    match Context::create() {
        Some(ctx) => ctx_into_ptr(ctx),
        None => null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn OWPContextFree(ctx: OWPContext) {
    unsafe { free_ctx(ctx) };
}

#[no_mangle]
pub unsafe extern "C" fn OWPContextErrHandle(ctx: OWPContext) -> super::handles::I2ErrHandle {
    if ctx.is_null() {
        null_mut()
    } else {
        unsafe { i2::I2ErrOpen(ptr::null(), null_mut(), null_mut()) }
    }
}

#[no_mangle]
pub unsafe extern "C" fn OWPError_(
    ctx: OWPContext,
    severity: c_int,
    etype: c_int,
    fmt: *const c_char,
    args: ...
) {
    let msg = format_c_message(fmt, args);
    if let Some(c) = unsafe { ctx_from_ptr(ctx) } {
        c.error(types::sev_from_i32(severity), etype_from(etype), &msg);
    } else {
        eprintln!("{msg}");
    }
}

#[no_mangle]
pub unsafe extern "C" fn OWPReportLevelByName(name: *const c_char) -> c_int {
    c_str(name)
        .and_then(crate::error::report_level_by_name)
        .unwrap_or(-1)
}

#[no_mangle]
pub unsafe extern "C" fn OWPErrorFD(ctx: OWPContext) -> c_int {
    let _ = ctx;
    -1
}

#[no_mangle]
pub unsafe extern "C" fn OWPContextConfigSetF(
    ctx: OWPContext,
    key: *const c_char,
    func: *mut c_void,
) -> OWPBoolean {
    let Some(key) = c_str(key) else {
        return owp_false();
    };
    let Some(ok) = ctx_ref(ctx, |c| {
        let _ = c.config_set_v(key, func as usize);
        c.config_set_f(key)
    }) else {
        return owp_false();
    };
    owp_bool(ok)
}

#[no_mangle]
pub unsafe extern "C" fn OWPContextConfigSetV(
    ctx: OWPContext,
    key: *const c_char,
    value: *mut c_void,
) -> OWPBoolean {
    let Some(key) = c_str(key) else {
        return owp_false();
    };
    let Some(ok) = ctx_ref(ctx, |c| {
        apply_ctx_value(c, key, value);
        c.config_set_v(key, value as usize)
    }) else {
        return owp_false();
    };
    owp_bool(ok)
}

#[no_mangle]
pub unsafe extern "C" fn OWPContextConfigSetU32(
    ctx: OWPContext,
    key: *const c_char,
    value: u32,
) -> OWPBoolean {
    let Some(key) = c_str(key) else {
        return owp_false();
    };
    ctx_ref(ctx, |c| owp_bool(c.config_set_u32(key, value))).unwrap_or_else(owp_false)
}

#[no_mangle]
pub unsafe extern "C" fn OWPContextConfigGetF(ctx: OWPContext, key: *const c_char) -> *mut c_void {
    let Some(key) = c_str(key) else {
        return null_mut();
    };
    ctx_ref(ctx, |c| {
        c.config_get_v(key)
            .map(|p| p as *mut c_void)
            .unwrap_or(null_mut())
    })
    .unwrap_or(null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn OWPContextConfigGetV(ctx: OWPContext, key: *const c_char) -> *mut c_void {
    let Some(key) = c_str(key) else {
        return null_mut();
    };
    ctx_ref(ctx, |c| {
        c.config_get_v(key)
            .map(|p| p as *mut c_void)
            .unwrap_or(null_mut())
    })
    .unwrap_or(null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn OWPContextConfigGetU32(
    ctx: OWPContext,
    key: *const c_char,
    val: *mut u32,
) -> OWPBoolean {
    let Some(key) = c_str(key) else {
        return owp_false();
    };
    let Some(got) = ctx_ref(ctx, |c| c.config_get_u32(key)) else {
        return owp_false();
    };
    if let Some(v) = got {
        if !val.is_null() {
            unsafe { *val = v };
        }
        owp_true()
    } else {
        owp_false()
    }
}

#[no_mangle]
pub unsafe extern "C" fn OWPContextConfigDelete(ctx: OWPContext, key: *const c_char) -> OWPBoolean {
    let Some(key) = c_str(key) else {
        return owp_false();
    };
    ctx_ref(ctx, |c| owp_bool(c.config_delete(key))).unwrap_or_else(owp_false)
}

#[no_mangle]
pub unsafe extern "C" fn OWPControlConfigSetF(
    cntrl: OWPControl,
    key: *const c_char,
    func: *mut c_void,
) -> OWPBoolean {
    let Some(key) = c_str(key) else {
        return owp_false();
    };
    let Some(ok) = ctrl_mut(cntrl, |c| {
        let _ = c.config_set_v(key, func as usize);
        c.config_set_f(key)
    }) else {
        return owp_false();
    };
    owp_bool(ok)
}

#[no_mangle]
pub unsafe extern "C" fn OWPControlConfigSetV(
    cntrl: OWPControl,
    key: *const c_char,
    value: *mut c_void,
) -> OWPBoolean {
    let Some(key) = c_str(key) else {
        return owp_false();
    };
    ctrl_mut(cntrl, |c| owp_bool(c.config_set_v(key, value as usize))).unwrap_or_else(owp_false)
}

#[no_mangle]
pub unsafe extern "C" fn OWPControlConfigGetF(
    cntrl: OWPControl,
    key: *const c_char,
) -> *mut c_void {
    let Some(key) = c_str(key) else {
        return null_mut();
    };
    ctrl_ref(cntrl, |c| {
        c.config_get_v(key)
            .map(|p| p as *mut c_void)
            .unwrap_or(null_mut())
    })
    .unwrap_or(null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn OWPControlConfigGetV(
    cntrl: OWPControl,
    key: *const c_char,
) -> *mut c_void {
    let Some(key) = c_str(key) else {
        return null_mut();
    };
    ctrl_ref(cntrl, |c| {
        c.config_get_v(key)
            .map(|p| p as *mut c_void)
            .unwrap_or(null_mut())
    })
    .unwrap_or(null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn OWPControlConfigDelete(
    cntrl: OWPControl,
    key: *const c_char,
) -> OWPBoolean {
    let Some(key) = c_str(key) else {
        return owp_false();
    };
    ctrl_mut(cntrl, |c| owp_bool(c.config_delete(key))).unwrap_or_else(owp_false)
}

// ---------------------------------------------------------------------------
// control open / accept / close
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn OWPControlOpen(
    ctx: OWPContext,
    local_addr: *const c_char,
    server_addr: super::handles::I2Addr,
    mode_mask: u32,
    userid: *const c_char,
    uptime_ret: *mut OWPNum64,
    err_ret: *mut c_int,
) -> OWPControl {
    control_open_ffi(
        ctx,
        local_addr,
        OpenHow::Client,
        server_addr,
        mode_mask,
        userid,
        uptime_ret,
        err_ret,
        false,
    )
}

#[no_mangle]
pub unsafe extern "C" fn OWPControlOpenInterface(
    ctx: OWPContext,
    local_addr: *const c_char,
    interface: *const c_char,
    server_addr: super::handles::I2Addr,
    mode_mask: u32,
    userid: *const c_char,
    uptime_ret: *mut OWPNum64,
    err_ret: *mut c_int,
) -> OWPControl {
    control_open_ffi(
        ctx,
        local_addr,
        OpenHow::Interface(interface),
        server_addr,
        mode_mask,
        userid,
        uptime_ret,
        err_ret,
        false,
    )
}

#[no_mangle]
pub unsafe extern "C" fn TWPControlOpen(
    ctx: OWPContext,
    local_addr: *const c_char,
    server_addr: super::handles::I2Addr,
    mode_mask: u32,
    userid: *const c_char,
    uptime_ret: *mut OWPNum64,
    err_ret: *mut c_int,
) -> OWPControl {
    control_open_ffi(
        ctx,
        local_addr,
        OpenHow::Client,
        server_addr,
        mode_mask,
        userid,
        uptime_ret,
        err_ret,
        true,
    )
}

#[no_mangle]
pub unsafe extern "C" fn TWPControlOpenInterface(
    ctx: OWPContext,
    local_addr: *const c_char,
    interface: *const c_char,
    server_addr: super::handles::I2Addr,
    mode_mask: u32,
    userid: *const c_char,
    uptime_ret: *mut OWPNum64,
    err_ret: *mut c_int,
) -> OWPControl {
    control_open_ffi(
        ctx,
        local_addr,
        OpenHow::Interface(interface),
        server_addr,
        mode_mask,
        userid,
        uptime_ret,
        err_ret,
        true,
    )
}

#[no_mangle]
pub unsafe extern "C" fn OWPControlClose(cntrl: OWPControl) -> c_int {
    let rc = {
        let Some(rc_ref) = (unsafe { control_from_ptr(cntrl) }) else {
            return ErrSeverity::Fatal as c_int;
        };
        Rc::clone(rc_ref)
    };
    let sev = Control::close_rc(rc);
    ctrl_map().remove(&(cntrl as usize));
    unsafe { free_control(cntrl) };
    sev as c_int
}

#[no_mangle]
pub unsafe extern "C" fn OWPControlFD(cntrl: OWPControl) -> c_int {
    ctrl_ref(cntrl, api::control_fd).unwrap_or(-1)
}

#[no_mangle]
pub unsafe extern "C" fn OWPControlIsTwoWay(cntrl: OWPControl) -> OWPBoolean {
    ctrl_ref(cntrl, |c| owp_bool(api::control_is_two_way(c))).unwrap_or_else(owp_false)
}

#[no_mangle]
pub unsafe extern "C" fn OWPGetContext(cntrl: OWPControl) -> OWPContext {
    if cntrl.is_null() {
        return null_mut();
    }
    ctrl_map().get(&(cntrl as usize)).copied().unwrap_or(0) as OWPContext
}

#[no_mangle]
pub unsafe extern "C" fn OWPGetMode(cntrl: OWPControl) -> u32 {
    ctrl_ref(cntrl, api::get_mode).unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn OWPGetRTTBound(cntrl: OWPControl) -> OWPNum64 {
    ctrl_ref(cntrl, |c| api::get_rtt_bound(c).0).unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn OWPServerSockCreate(
    ctx: OWPContext,
    addr: super::handles::I2Addr,
    err_ret: *mut c_int,
) -> super::handles::I2Addr {
    server_sock_ffi(ctx, addr, err_ret, false)
}

#[no_mangle]
pub unsafe extern "C" fn TWPServerSockCreate(
    ctx: OWPContext,
    addr: super::handles::I2Addr,
    err_ret: *mut c_int,
) -> super::handles::I2Addr {
    server_sock_ffi(ctx, addr, err_ret, true)
}

#[no_mangle]
pub unsafe extern "C" fn OWPControlAccept(
    ctx: OWPContext,
    connfd: c_int,
    connsaddr: *mut libc::sockaddr,
    connsaddrlen: libc::socklen_t,
    mode_offered: u32,
    uptime: OWPNum64,
    retn_on_intr: *mut c_int,
    err_ret: *mut c_int,
) -> OWPControl {
    accept_ffi(
        ctx,
        connfd,
        connsaddr,
        connsaddrlen,
        mode_offered,
        uptime,
        retn_on_intr,
        err_ret,
        false,
    )
}

#[no_mangle]
pub unsafe extern "C" fn TWPControlAccept(
    ctx: OWPContext,
    connfd: c_int,
    connsaddr: *mut libc::sockaddr,
    connsaddrlen: libc::socklen_t,
    mode_offered: u32,
    uptime: OWPNum64,
    retn_on_intr: *mut c_int,
    err_ret: *mut c_int,
) -> OWPControl {
    accept_ffi(
        ctx,
        connfd,
        connsaddr,
        connsaddrlen,
        mode_offered,
        uptime,
        retn_on_intr,
        err_ret,
        true,
    )
}

// ---------------------------------------------------------------------------
// sessions
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn OWPSessionRequest(
    cntrl: OWPControl,
    sender: super::handles::I2Addr,
    server_conf_sender: OWPBoolean,
    receiver: super::handles::I2Addr,
    server_conf_receiver: OWPBoolean,
    zero_addr: OWPBoolean,
    test_spec: *const types::OWPTestSpec,
    fp: *mut libc::FILE,
    sid_ret: *mut u8,
    err_ret: *mut c_int,
) -> OWPBoolean {
    let sender = unsafe { i2::take_addr(sender) };
    let receiver = unsafe { i2::take_addr(receiver) };
    if test_spec.is_null() || sid_ret.is_null() {
        set_err(err_ret, ErrSeverity::Fatal);
        return owp_false();
    }
    let spec = ctx_tspec_from_c(unsafe { &*test_spec });
    let file = if fp.is_null() {
        None
    } else {
        match dup_cfile(fp) {
            Some(f) => Some(f),
            None => {
                set_err(err_ret, ErrSeverity::Fatal);
                return owp_false();
            },
        }
    };
    let mut sid = [0u8; 16];
    let mut err = ErrSeverity::Ok;
    let Some(ok) = ctrl_mut(cntrl, |c| {
        session_request_ex(
            c,
            sender,
            server_conf_sender != 0,
            receiver,
            server_conf_receiver != 0,
            zero_addr != 0,
            &spec,
            file.as_ref(),
            &mut sid,
            &mut err,
        )
    }) else {
        set_err(err_ret, ErrSeverity::Fatal);
        return owp_false();
    };
    set_err(err_ret, err);
    if ok {
        store_sid(sid_ret, &sid);
    }
    owp_bool(ok)
}

#[no_mangle]
pub unsafe extern "C" fn OWPStartSessions(cntrl: OWPControl) -> c_int {
    ctrl_mut(cntrl, capi::start_sessions)
        .map(|s| s as c_int)
        .unwrap_or(ErrSeverity::Fatal as c_int)
}

#[no_mangle]
pub unsafe extern "C" fn OWPStopSessions(
    cntrl: OWPControl,
    retn_on_intr: *mut c_int,
    acceptval: *mut c_int,
) -> c_int {
    let mut aval = load_accept(acceptval);
    let Some(sev) = ctrl_mut(cntrl, |c| {
        api::stop_sessions(c, intr_ref(retn_on_intr), &mut aval)
    }) else {
        return ErrSeverity::Fatal as c_int;
    };
    store_accept(acceptval, aval);
    sev as c_int
}

#[no_mangle]
pub unsafe extern "C" fn OWPStopSessionsWait(
    cntrl: OWPControl,
    wake_time: *const OWPNum64,
    retn_on_intr: *mut c_int,
    acceptval: *mut c_int,
    err_ret: *mut c_int,
) -> c_int {
    let wake = if wake_time.is_null() {
        None
    } else {
        Some(OwampNum64(unsafe { *wake_time }))
    };
    let mut aval = load_accept(acceptval);
    let mut err = ErrSeverity::Ok;
    let Some(rc) = ctrl_mut(cntrl, |c| {
        api::stop_sessions_wait(
            c,
            wake.as_ref(),
            intr_ref(retn_on_intr),
            &mut aval,
            &mut err,
        )
    }) else {
        set_err(err_ret, ErrSeverity::Fatal);
        return -1;
    };
    store_accept(acceptval, aval);
    set_err(err_ret, err);
    rc
}

#[no_mangle]
pub unsafe extern "C" fn OWPSessionStatus(
    cntrl: OWPControl,
    sid: *const u8,
    aval: *mut c_int,
) -> OWPBoolean {
    let Some(sid) = load_sid(sid) else {
        return owp_false();
    };
    match ctrl_ref(cntrl, |c| api::session_status(c, &sid)) {
        Some(Some(a)) => {
            store_accept(aval, a);
            owp_true()
        },
        _ => owp_false(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn OWPSessionsActive(cntrl: OWPControl, acceptval: *mut c_int) -> c_int {
    match ctrl_ref(cntrl, api::sessions_active) {
        Some((n, aval)) => {
            store_accept(acceptval, aval);
            n
        },
        None => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn OWPReadRequestType(cntrl: OWPControl, retn_on_intr: *mut c_int) -> c_int {
    ctrl_mut(cntrl, |c| {
        api::read_request_type(c, intr_ref(retn_on_intr)) as c_int
    })
    .unwrap_or(-1)
}

#[no_mangle]
pub unsafe extern "C" fn OWPProcessTestRequest(
    cntrl: OWPControl,
    retn_on_intr: *mut c_int,
) -> c_int {
    ctrl_mut(cntrl, |c| {
        if !retn_on_intr.is_null() {
            c.retn_on_intr = Some(unsafe { *retn_on_intr });
        }
        sapi::process_test_request(c) as c_int
    })
    .unwrap_or(ErrSeverity::Fatal as c_int)
}

#[no_mangle]
pub unsafe extern "C" fn OWPProcessTestRequestTW(
    cntrl: OWPControl,
    retn_on_intr: *mut c_int,
) -> c_int {
    ctrl_mut(cntrl, |c| {
        if !retn_on_intr.is_null() {
            c.retn_on_intr = Some(unsafe { *retn_on_intr });
        }
        sapi::process_test_request_tw(c) as c_int
    })
    .unwrap_or(ErrSeverity::Fatal as c_int)
}

#[no_mangle]
pub unsafe extern "C" fn OWPProcessStartSessions(
    cntrl: OWPControl,
    retn_on_intr: *mut c_int,
) -> c_int {
    ctrl_mut(cntrl, |c| {
        if !retn_on_intr.is_null() {
            c.retn_on_intr = Some(unsafe { *retn_on_intr });
        }
        sapi::process_start_sessions(c) as c_int
    })
    .unwrap_or(ErrSeverity::Fatal as c_int)
}

#[no_mangle]
pub unsafe extern "C" fn OWPProcessStopSessions(cntrl: OWPControl) -> c_int {
    ctrl_mut(cntrl, |c| {
        let mut accept = AcceptType::Accept;
        api::stop_sessions(c, None, &mut accept) as c_int
    })
    .unwrap_or(ErrSeverity::Fatal as c_int)
}

#[no_mangle]
pub unsafe extern "C" fn OWPProcessFetchSession(
    cntrl: OWPControl,
    retn_on_intr: *mut c_int,
) -> c_int {
    ctrl_mut(cntrl, |c| {
        if !retn_on_intr.is_null() {
            c.retn_on_intr = Some(unsafe { *retn_on_intr });
        }
        sapi::process_fetch_session(c) as c_int
    })
    .unwrap_or(ErrSeverity::Fatal as c_int)
}

#[no_mangle]
pub unsafe extern "C" fn OWPUnexpectedRequestType(cntrl: OWPControl) -> c_int {
    ctrl_mut(cntrl, |c| sapi::unexpected_request_type(c) as c_int)
        .unwrap_or(ErrSeverity::Fatal as c_int)
}

#[no_mangle]
pub unsafe extern "C" fn OWPFetchSession(
    cntrl: OWPControl,
    fp: *mut libc::FILE,
    begin: u32,
    end: u32,
    sid: *const u8,
    err_ret: *mut c_int,
) -> u32 {
    let Some(sid) = load_sid(sid) else {
        set_err(err_ret, ErrSeverity::Fatal);
        return 0;
    };
    if fp.is_null() {
        set_err(err_ret, ErrSeverity::Fatal);
        return 0;
    }
    let mut file = CFile::new(fp);
    let mut err = ErrSeverity::Ok;
    let Some(n) = ctrl_mut(cntrl, |c| {
        capi::fetch_session(c, &mut file, begin, end, &sid, &mut err)
    }) else {
        set_err(err_ret, ErrSeverity::Fatal);
        return 0;
    };
    set_err(err_ret, err);
    n
}

// ---------------------------------------------------------------------------
// packet sizing / delay
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn OWPTestPayloadSize(mode: u32, padding: u32) -> u32 {
    api::test_payload_size(mode, padding)
}

#[no_mangle]
pub unsafe extern "C" fn OWPTestTWPayloadSize(mode: u32, padding: u32) -> u32 {
    api::test_tw_payload_size(mode, padding)
}

#[no_mangle]
pub unsafe extern "C" fn OWPTestPacketSize(af: c_int, mode: u32, padding: u32) -> u32 {
    api::test_packet_size(af, mode, padding)
}

#[no_mangle]
pub unsafe extern "C" fn OWPTestTWPacketSize(af: c_int, mode: u32, padding: u32) -> u32 {
    api::test_tw_packet_size(af, mode, padding)
}

#[no_mangle]
pub unsafe extern "C" fn OWPTestPacketRate(
    ctx: OWPContext,
    tspec: *const types::OWPTestSpec,
) -> f64 {
    if tspec.is_null() {
        return 0.0;
    }
    let spec = ctx_tspec_from_c(unsafe { &*tspec });
    ctx_ref(ctx, |c| api::test_packet_rate(c, &spec)).unwrap_or(0.0)
}

#[no_mangle]
pub unsafe extern "C" fn OWPTestPacketBandwidth(
    ctx: OWPContext,
    af: c_int,
    mode: u32,
    tspec: *const types::OWPTestSpec,
) -> f64 {
    if tspec.is_null() {
        return 0.0;
    }
    let spec = ctx_tspec_from_c(unsafe { &*tspec });
    ctx_ref(ctx, |c| api::test_packet_bandwidth(c, af, mode, &spec)).unwrap_or(0.0)
}

#[no_mangle]
pub unsafe extern "C" fn OWPDelay(
    send_time: *const types::OWPTimeStamp,
    recv_time: *const types::OWPTimeStamp,
) -> f64 {
    if send_time.is_null() || recv_time.is_null() {
        return 0.0;
    }
    let send = ts_from_c(unsafe { &*send_time });
    let recv = ts_from_c(unsafe { &*recv_time });
    capi::delay(&send, &recv)
}

#[no_mangle]
pub unsafe extern "C" fn OWPIsLostRecord(rec: *const types::OWPDataRec) -> OWPBoolean {
    if rec.is_null() {
        return owp_false();
    }
    owp_bool(api::is_lost_record(&data_from_c(unsafe { &*rec })))
}

#[no_mangle]
pub unsafe extern "C" fn OWPParsePortRange(
    pspec: *const c_char,
    portspec: *mut types::OWPPortRangeRec,
) -> c_int {
    let Some(spec) = c_str(pspec) else {
        return 0;
    };
    if portspec.is_null() {
        return 0;
    }
    let mut pr = context::PortRange::default();
    let ok = capi::parse_port_range(spec, &mut pr);
    if ok {
        unsafe {
            (*portspec).low = pr.low;
            (*portspec).high = pr.high;
        }
    }
    c_int::from(ok)
}

#[no_mangle]
pub unsafe extern "C" fn OWPTestDiskspace(tspec: *const types::OWPTestSpec) -> u64 {
    if tspec.is_null() {
        return 0;
    }
    api::test_diskspace(&ctx_tspec_from_c(unsafe { &*tspec }))
}

// ---------------------------------------------------------------------------
// schedule / exp
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn OWPScheduleContextCreate(
    ctx: OWPContext,
    sid: *const u8,
    tspec: *const types::OWPTestSpec,
) -> OWPScheduleContext {
    if ctx.is_null() || tspec.is_null() {
        return null_mut();
    }
    let Some(sid) = load_sid(sid) else {
        return null_mut();
    };
    let spec = owamp_tspec_from_c(unsafe { &*tspec });
    match ScheduleContext::create(&sid, &spec) {
        Ok(s) => sched_into_ptr(s),
        Err(_) => null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn OWPScheduleContextFree(sctx: OWPScheduleContext) {
    if sctx.is_null() {
        return;
    }
    let s = unsafe { Box::from_raw(sctx) };
    schedule::schedule_context_free(*s);
}

#[no_mangle]
pub unsafe extern "C" fn OWPScheduleContextReset(
    sctx: OWPScheduleContext,
    sid: *const u8,
    tspec: *const types::OWPTestSpec,
) -> c_int {
    let Some(s) = (unsafe { sched_from_ptr(sctx) }) else {
        return ErrSeverity::Fatal as c_int;
    };
    let sid = load_sid(sid);
    let spec = if tspec.is_null() {
        None
    } else {
        Some(owamp_tspec_from_c(unsafe { &*tspec }))
    };
    match s.reset(sid.as_ref(), spec.as_ref()) {
        Ok(()) => ErrSeverity::Ok as c_int,
        Err(_) => ErrSeverity::Fatal as c_int,
    }
}

#[no_mangle]
pub unsafe extern "C" fn OWPScheduleContextGenerateNextDelta(sctx: OWPScheduleContext) -> OWPNum64 {
    let Some(s) = (unsafe { sched_from_ptr(sctx) }) else {
        return 0;
    };
    s.generate_next_delta().map(|n| n.0).unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn OWPExpContextCreate(ctx: OWPContext, seed: *const u8) -> OWPExpContext {
    if ctx.is_null() {
        return null_mut();
    }
    let Some(seed) = load_sid(seed) else {
        return null_mut();
    };
    exp_into_ptr(schedule::exp_context_create(&seed))
}

#[no_mangle]
pub unsafe extern "C" fn OWPExpContextNext(exp: OWPExpContext) -> OWPNum64 {
    let Some(e) = (unsafe { exp_from_ptr(exp) }) else {
        return 0;
    };
    schedule::exp_context_next(e).0
}

#[no_mangle]
pub unsafe extern "C" fn OWPExpContextFree(exp: OWPExpContext) {
    if exp.is_null() {
        return;
    }
    let e = unsafe { Box::from_raw(exp) };
    schedule::exp_context_free(*e);
}

// ---------------------------------------------------------------------------
// session files
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn OWPWriteDataHeader(
    _ctx: OWPContext,
    fp: *mut libc::FILE,
    hdr: *const types::OWPSessionHeaderRec,
) -> OWPBoolean {
    if fp.is_null() || hdr.is_null() {
        return owp_false();
    }
    let session = session_header_from_c(unsafe { &*hdr });
    let mut file = CFile::new(fp);
    owp_bool(api::write_data_header(&mut file, &session))
}

#[no_mangle]
pub unsafe extern "C" fn OWPWriteDataHeaderNumSkipRecs(
    _ctx: OWPContext,
    fp: *mut libc::FILE,
    num_skiprecs: u32,
) -> OWPBoolean {
    if fp.is_null() {
        return owp_false();
    }
    let mut file = CFile::new(fp);
    owp_bool(api::write_data_header_num_skip_recs(
        &mut file,
        num_skiprecs,
    ))
}

#[no_mangle]
pub unsafe extern "C" fn OWPWriteDataHeaderNumDataRecs(
    _ctx: OWPContext,
    fp: *mut libc::FILE,
    num_datarecs: u32,
) -> OWPBoolean {
    if fp.is_null() {
        return owp_false();
    }
    let mut file = CFile::new(fp);
    owp_bool(api::write_data_header_num_data_recs(
        &mut file,
        num_datarecs,
    ))
}

#[no_mangle]
pub unsafe extern "C" fn OWPReadDataHeader(
    _ctx: OWPContext,
    fp: *mut libc::FILE,
    hdr_ret: *mut types::OWPSessionHeaderRec,
) -> u32 {
    if fp.is_null() || hdr_ret.is_null() {
        return 0;
    }
    let mut file = CFile::new(fp);
    let mut session = api::SessionHeader::default();
    let n = api::read_data_header(&mut file, &mut session);
    session_header_into_c(&session, unsafe { &mut *hdr_ret }, fp);
    n
}

#[no_mangle]
pub unsafe extern "C" fn OWPReadDataHeaderSlots(
    _ctx: OWPContext,
    fp: *mut libc::FILE,
    nslots: u32,
    slots: *mut types::OWPSlot,
) -> OWPBoolean {
    if fp.is_null() || (nslots > 0 && slots.is_null()) {
        return owp_false();
    }
    let mut file = CFile::new(fp);
    let mut got = Vec::new();
    if !api::read_data_header_slots(&mut file, nslots, &mut got) || got.len() != nslots as usize {
        return owp_false();
    }
    for (i, slot) in got.iter().enumerate() {
        unsafe { *slots.add(i) = slot_to_c(slot) };
    }
    owp_true()
}

#[no_mangle]
pub unsafe extern "C" fn OWPWriteDataRecord(
    _ctx: OWPContext,
    fp: *mut libc::FILE,
    rec: *const types::OWPDataRec,
) -> OWPBoolean {
    if fp.is_null() || rec.is_null() {
        return owp_false();
    }
    let rec = data_from_c(unsafe { &*rec });
    let mut file = CFile::new(fp);
    owp_bool(api::write_data_record(&mut file, &rec))
}

#[no_mangle]
pub unsafe extern "C" fn OWPWriteTWDataRecord(
    _ctx: OWPContext,
    fp: *mut libc::FILE,
    rec: *const types::OWPTWDataRec,
) -> OWPBoolean {
    if fp.is_null() || rec.is_null() {
        return owp_false();
    }
    let rec = tw_from_c(unsafe { &*rec });
    let mut file = CFile::new(fp);
    owp_bool(api::write_tw_data_record(&mut file, &rec))
}

type DoData = Option<unsafe extern "C" fn(*mut types::OWPDataRec, *mut c_void) -> c_int>;
type DoTw = Option<unsafe extern "C" fn(*mut types::OWPTWDataRec, *mut c_void) -> c_int>;

#[no_mangle]
pub unsafe extern "C" fn OWPParseRecords(
    _ctx: OWPContext,
    fp: *mut libc::FILE,
    num_rec: u32,
    file_version: u32,
    proc_rec: DoData,
    udata: *mut c_void,
) -> c_int {
    if fp.is_null() || proc_rec.is_none() {
        return ErrSeverity::Fatal as c_int;
    }
    let mut file = CFile::new(fp);
    let mut fatal = false;
    let sev = api::parse_records(&mut file, num_rec, file_version, |rec| {
        let Some(cb) = proc_rec else {
            fatal = true;
            return false;
        };
        let mut c = data_to_c(rec);
        let rc = unsafe { cb(&mut c, udata) };
        if rc < 0 {
            fatal = true;
            false
        } else {
            rc == 0
        }
    });
    if fatal {
        ErrSeverity::Fatal as c_int
    } else {
        sev as c_int
    }
}

#[no_mangle]
pub unsafe extern "C" fn OWPParseTWRecords(
    _ctx: OWPContext,
    fp: *mut libc::FILE,
    num_rec: u32,
    file_version: u32,
    proc_rec: DoTw,
    app_data: *mut c_void,
) -> c_int {
    if fp.is_null() || proc_rec.is_none() {
        return ErrSeverity::Fatal as c_int;
    }
    let mut file = CFile::new(fp);
    let mut fatal = false;
    let sev = api::parse_tw_records(&mut file, num_rec, file_version, |rec| {
        let Some(cb) = proc_rec else {
            fatal = true;
            return false;
        };
        let mut c = tw_to_c(rec);
        let rc = unsafe { cb(&mut c, app_data) };
        if rc < 0 {
            fatal = true;
            false
        } else {
            rc == 0
        }
    });
    if fatal {
        ErrSeverity::Fatal as c_int
    } else {
        sev as c_int
    }
}

#[no_mangle]
pub unsafe extern "C" fn OWPReadDataSkips(
    _ctx: OWPContext,
    fp: *mut libc::FILE,
    nskips: u32,
    skips: *mut types::OWPSkipRec,
) -> OWPBoolean {
    if fp.is_null() || (nskips > 0 && skips.is_null()) {
        return owp_false();
    }
    let mut file = CFile::new(fp);
    let mut got = Vec::new();
    let sev = api::read_data_skips(&mut file, nskips, &mut got);
    if sev < ErrSeverity::Warning || got.len() != nskips as usize {
        return owp_false();
    }
    for (i, skip) in got.iter().enumerate() {
        unsafe {
            (*skips.add(i)).begin = skip.begin;
            (*skips.add(i)).end = skip.end;
        }
    }
    owp_true()
}

// ---------------------------------------------------------------------------
// stats
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn OWPStatsScaleFactor(
    scale: c_char,
    abrv: *mut c_char,
    abrv_len: *mut usize,
) -> f32 {
    let (factor, name) = stats::scale_factor(scale as u8 as char);
    if factor == 0.0 {
        if !abrv_len.is_null() {
            unsafe { *abrv_len = 0 };
        }
        return 0.0;
    }
    if !abrv.is_null() && !abrv_len.is_null() && unsafe { *abrv_len } >= name.len() + 1 {
        let bytes = name.as_bytes();
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), abrv.cast(), bytes.len());
            *abrv.add(bytes.len()) = 0;
            *abrv_len = bytes.len();
        }
    }
    factor
}

#[no_mangle]
pub unsafe extern "C" fn OWPStatsCreate(
    ctx: OWPContext,
    fp: *mut libc::FILE,
    hdr: *const types::OWPSessionHeaderRec,
    fromhost: *const c_char,
    tohost: *const c_char,
    scale: c_char,
    bucket_width: f64,
) -> OWPStats {
    if ctx.is_null() || fp.is_null() || hdr.is_null() {
        return null_mut();
    }
    let mut session = session_header_from_c(unsafe { &*hdr });
    let mut file = CFile::new(fp);
    if session.test_spec.slots.is_empty() && session.test_spec.nslots > 0 {
        let nslots = session.test_spec.nslots;
        let mut slots = Vec::new();
        if !api::read_data_header_slots(&mut file, nslots, &mut slots) {
            return null_mut();
        }
        session.test_spec.slots = slots;
    }
    let mut skips_api = Vec::new();
    if session.num_skiprecs > 0 {
        if file.seek(SeekFrom::Start(session.oset_skiprecs)).is_err() {
            return null_mut();
        }
        let rc = api::read_data_skips(&mut file, session.num_skiprecs, &mut skips_api);
        if rc < ErrSeverity::Warning {
            return null_mut();
        }
    }
    let skips = skips_api
        .into_iter()
        .map(|s| owamp::OwampSkipRec {
            begin: s.begin,
            end: s.end,
        })
        .collect();
    let from = c_owned(fromhost);
    let to = c_owned(tohost);
    match Stats::create_from_header(
        &session,
        from.as_deref(),
        to.as_deref(),
        scale as u8 as char,
        bucket_width,
        skips,
    ) {
        Ok(stats) => {
            let p = stats_into_ptr(stats);
            stats_map().insert(p as usize, fp as usize);
            p
        },
        Err(_) => null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn OWPStatsFree(stats: OWPStats) {
    if stats.is_null() {
        return;
    }
    if let Some(s) = unsafe { stats_from_ptr(stats) } {
        s.free();
    }
    stats_map().remove(&(stats as usize));
    unsafe { super::handles::free_stats(stats) };
}

#[no_mangle]
pub unsafe extern "C" fn OWPStatsParse(
    stats: OWPStats,
    output: *mut libc::FILE,
    begin_oset: libc::off_t,
    first: u32,
    last: u32,
) -> OWPBoolean {
    let fp = {
        let map = stats_map();
        match map.get(&(stats as usize)).copied() {
            Some(p) => p as *mut libc::FILE,
            None => return owp_false(),
        }
    };
    if let Some(s) = unsafe { stats_from_ptr(stats) } {
        if !output.is_null() {
            s.emit_packet_lines = true;
        }
    }
    let Some(s) = (unsafe { stats_from_ptr(stats) }) else {
        return owp_false();
    };
    let mut file = CFile::new(fp);
    let begin = if begin_oset < 0 { 0 } else { begin_oset as u64 };
    match stats::stats_parse_file(s, &mut file, begin, first, last) {
        Ok(()) => owp_true(),
        Err(_) => owp_false(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn OWPStatsPrintSummary(
    stats: OWPStats,
    output: *mut libc::FILE,
    percentiles: *const f32,
    npercentiles: u32,
) -> OWPBoolean {
    if output.is_null() {
        return owp_false();
    }
    let percs: Vec<f32> = if percentiles.is_null() || npercentiles == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(percentiles, npercentiles as usize) }.to_vec()
    };
    let Some(s) = (unsafe { stats_from_ptr(stats) }) else {
        return owp_false();
    };
    let mut out = CFile::new(output);
    owp_bool(s.print_summary_to(&mut out, &percs, true).is_ok())
}

#[no_mangle]
pub unsafe extern "C" fn OWPStatsPrintMachine(
    stats: OWPStats,
    output: *mut libc::FILE,
) -> OWPBoolean {
    if output.is_null() {
        return owp_false();
    }
    let Some(s) = (unsafe { stats_from_ptr(stats) }) else {
        return owp_false();
    };
    let mut out = CFile::new(output);
    owp_bool(s.print_machine_to(&mut out).is_ok())
}
