//! Port of `api.c` — session helpers, packet sizing, status, shared protocol handshake.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::arithm64::{num64_mult, num64_to_timespec, ulong_to_num64};
use crate::context::{
    self, call_test_complete, decode_timestamp, encode_timestamp, get_time_of_day, num64_sub,
    num64_to_double, read_fully, receive_blocks_intr, send_blocks_intr, write_fully, AcceptType,
    Addr, Context, Control, Endpoint, ErrSeverity, ErrType, SessionMode, Sid, SlotType,
    TestSession, TestSpec, OWP_MODE_DOCIPHER_CNTRL, STATE_INVALID, STATE_REQUEST, STATE_SETUP,
    STATE_TEST,
};
use crate::io::{
    encrypt_blocks, recv_hmac_add, recv_hmac_check_clear, send_hmac_add, send_hmac_digest_clear,
};
use crate::owamp::{
    OwampNum64, OwampSlot, OwampSlotLiteral, OwampSlotRandExp, OwampTestSpec, OwampTimeStamp,
};
use crate::owampP::{
    OWP_DATARECV2_SIZE, OWP_DATARECV3_SIZE, OWP_DATAREC_SIZE, OWP_DATAREC_TWV3_SIZE,
    OWP_MAXDATAREC_SIZE, OWP_MODE_AUTHENTICATED, OWP_MODE_ENCRYPTED, OWP_MODE_OPEN,
    OWP_RIJNDAEL_BLOCK_SIZE, OWP_SKIPREC_SIZE, OWP_TEST_REQUEST_PREAMBLE_SIZE, OWP_VERSION_TWOWAY,
    TWP_DEFAULT_TEST_TIMEOUT, TWP_MODE_MIXED, TWP_TEST_TIMEOUT,
};
use crate::protocol::{
    after_read_accept_session, after_read_fetch_ack, after_read_start_ack,
    after_read_start_sessions, after_read_stop_sessions, after_write_accept_session,
    after_write_fetch_session, after_write_start_ack, after_write_start_sessions,
    after_write_test_request, apply_ipv6_ll_scope, decode_skip_record, decode_slot, encode_slot,
    set_saddr_if_unspecified, validate_skip_record, AcceptSession as ProtoAcceptSession,
    FetchAck as ProtoFetchAck, FetchSession as ProtoFetchSession, SkipRec as ProtoSkipRec,
    Slot as ProtoSlot, StartAck as ProtoStartAck, StartSessions as ProtoStartSessions,
    StopSessionsHeader, TestRequestPreamble, TestSpec as ProtoTestSpec, ACCEPT_SESSION_SIZE,
    FETCH_ACK_SIZE, FETCH_SESSION_SIZE, SLOT_SIZE, START_ACK_SIZE, START_SESSIONS_SIZE,
    STOP_SESSIONS_HEADER_SIZE,
};

pub use crate::context::{
    AcceptType as OwpAcceptType, Context as OwpContext, Control as OwpControl,
    ErrSeverity as OwpErrSeverity, PortRange, Slot, TestSpec as OwpTestSpec,
};

// ---------------------------------------------------------------------------
// Data / session record types (owamp.h)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Default)]
pub struct DataRec {
    pub seq_no: u32,
    pub send: OwampTimeStamp,
    pub recv: OwampTimeStamp,
    pub ttl: u8,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TwDataRec {
    pub sent: DataRec,
    pub reflected: DataRec,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SkipRec {
    pub begin: u32,
    pub end: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SessionFinishedType {
    #[default]
    Error = 0,
    Normal = 1,
    Incomplete = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestType {
    Invalid = -1,
    Test = 1,
    StartSessions = 2,
    StopSessions = 3,
    FetchSession = 4,
    TestTw = 5,
    SockClose = 10,
    SockIntr = 11,
}

pub type PacketSizeT = u32;

const IP4_HDR_SIZE: u32 = 20;
const IP6_HDR_SIZE: u32 = 40;
const UDP_HDR_SIZE: u32 = 8;

// ---------------------------------------------------------------------------
// Accessors (api.c)
// ---------------------------------------------------------------------------

#[must_use]
pub fn get_context(cntrl: &Control) -> Context {
    cntrl.ctx.clone()
}

#[must_use]
pub const fn get_mode(cntrl: &Control) -> SessionMode {
    cntrl.mode
}

#[must_use]
pub const fn control_fd(cntrl: &Control) -> i32 {
    cntrl.sockfd
}

#[must_use]
pub const fn get_rtt_bound(cntrl: &Control) -> OwampNum64 {
    cntrl.rtt_bound
}

#[must_use]
pub const fn control_is_two_way(cntrl: &Control) -> bool {
    cntrl.twoway
}

/// `_OWPFailControlSession`
pub const fn fail_control_session(cntrl: &mut Control, level: ErrSeverity) -> ErrSeverity {
    cntrl.state = STATE_INVALID;
    level
}

/// `_OWPTestSessionAlloc`
#[must_use]
pub fn test_session_alloc(
    _cntrl: &Control,
    sender: Addr,
    conf_sender: bool,
    receiver: Addr,
    conf_receiver: bool,
    test_spec: &TestSpec,
) -> Option<Box<TestSession>> {
    TestSession::new(sender, conf_sender, receiver, conf_receiver, test_spec)
}

/// `_OWPTestSessionFree` — remove from control list and free resources.
pub fn test_session_free(cntrl: &mut Control, sid: &Sid, aval: AcceptType) -> ErrSeverity {
    let idx = cntrl.tests.iter().position(|t| t.sid == *sid);
    let Some(i) = idx else {
        return ErrSeverity::Ok;
    };
    let mut tsession = cntrl.tests.remove(i);
    let err = ErrSeverity::Ok;
    if let Some(mut ep) = tsession.endpoint.take() {
        let mut a = aval;
        if let Some(f) = ep.userfile.take() {
            context::call_close_file(cntrl, tsession.closure.as_deref(), f, a);
        }
        ep.free(&mut a);
    }
    if tsession.closure.is_some() {
        call_test_complete(cntrl, tsession.closure.as_deref(), aval);
    }
    tsession.sender = None;
    tsession.receiver = None;
    tsession.sctx = None;
    let _ = err;
    ErrSeverity::Ok
}

/// Free a session that is not yet linked into `cntrl.tests`.
#[must_use]
pub fn test_session_free_unlinked(
    cntrl: &Control,
    mut tsession: Box<TestSession>,
    aval: AcceptType,
) -> ErrSeverity {
    if let Some(mut ep) = tsession.endpoint.take() {
        let mut a = aval;
        if let Some(f) = ep.userfile.take() {
            context::call_close_file(cntrl, tsession.closure.as_deref(), f, a);
        }
        ep.free(&mut a);
    }
    if tsession.closure.is_some() {
        call_test_complete(cntrl, tsession.closure.as_deref(), aval);
    }
    ErrSeverity::Ok
}

/// `_OWPCreateSID` — addr(4) + time(8) + random(4).
pub fn create_sid(cntrl: &Control, tsession: &mut TestSession) -> i32 {
    let Some(recv) = tsession.receiver.as_ref().and_then(Addr::saddr) else {
        cntrl.ctx.error(
            ErrSeverity::Fatal,
            ErrType::Unsupported,
            "_OWPCreateSID: Invalid socket address",
        );
        return 1;
    };
    match recv {
        SocketAddr::V4(v4) => {
            tsession.sid[0..4].copy_from_slice(&v4.ip().octets());
        },
        SocketAddr::V6(v6) => {
            let o = v6.ip().octets();
            tsession.sid[0..4].copy_from_slice(&o[12..16]);
        },
    }
    if let Some(ts) = get_time_of_day(&cntrl.ctx) {
        let mut tb = [0u8; 8];
        encode_timestamp(&mut tb, &ts);
        tsession.sid[4..12].copy_from_slice(&tb);
    }
    let mut rnd = [0u8; 4];
    if !cntrl.ctx.random_bytes(&mut rnd) {
        return 1;
    }
    tsession.sid[12..16].copy_from_slice(&rnd);
    0
}

#[must_use]
pub const fn test_payload_size(mode: SessionMode, padding: u32) -> PacketSizeT {
    let msg_size = match mode {
        OWP_MODE_OPEN | TWP_MODE_MIXED => 14,
        OWP_MODE_AUTHENTICATED | OWP_MODE_ENCRYPTED => 48,
        _ => 0,
    };
    msg_size + padding
}

#[must_use]
pub const fn test_tw_payload_size(mode: SessionMode, padding: u32) -> PacketSizeT {
    let msg_size = match mode {
        OWP_MODE_OPEN | TWP_MODE_MIXED => 41,
        OWP_MODE_AUTHENTICATED | OWP_MODE_ENCRYPTED => 112,
        _ => 0,
    };
    msg_size + padding
}

#[must_use]
pub fn test_packet_rate(ctx: &Context, tspec: &TestSpec) -> f64 {
    if tspec.nslots == 0 || tspec.slots.is_empty() {
        ctx.error(
            ErrSeverity::Fatal,
            ErrType::Invalid,
            "OWPTestPacketRate: Invalid empty test specification",
        );
        return 0.0;
    }
    let mut duration = OwampNum64(0);
    for s in &tspec.slots {
        duration = OwampNum64(duration.0.wrapping_add(s.mean_delay().0));
    }
    if duration.0 == 0 {
        return 0.0;
    }
    f64::from(tspec.nslots) / num64_to_double(duration)
}

#[must_use]
pub const fn test_packet_size(af: i32, mode: SessionMode, padding: u32) -> PacketSizeT {
    let header = match af {
        libc::AF_INET => IP4_HDR_SIZE + UDP_HDR_SIZE,
        libc::AF_INET6 => IP6_HDR_SIZE + UDP_HDR_SIZE,
        _ => return 0,
    };
    let payload = test_payload_size(mode, padding);
    if payload == 0 {
        return 0;
    }
    payload + header
}

#[must_use]
pub const fn test_tw_packet_size(af: i32, mode: SessionMode, padding: u32) -> PacketSizeT {
    let header = match af {
        libc::AF_INET => IP4_HDR_SIZE + UDP_HDR_SIZE,
        libc::AF_INET6 => IP6_HDR_SIZE + UDP_HDR_SIZE,
        _ => return 0,
    };
    let payload = test_tw_payload_size(mode, padding);
    if payload == 0 {
        return 0;
    }
    payload + header
}

#[must_use]
pub fn test_packet_bandwidth(ctx: &Context, af: i32, mode: SessionMode, tspec: &TestSpec) -> f64 {
    test_packet_rate(ctx, tspec)
        * f64::from(test_packet_size(af, mode, tspec.packet_size_padding))
        * 8.0
}

pub fn session_status(cntrl: &Control, sid: &Sid) -> Option<AcceptType> {
    for t in &cntrl.tests {
        if &t.sid == sid {
            return t.endpoint.as_ref().map(Endpoint::poll_status);
        }
    }
    None
}

/// `_OWPSessionsActive` — count endpoints still running (`acceptval < 0` in C).
///
/// Reads the shared atomic accept value updated by the worker thread, so a
/// shared `&Control` borrow is enough (C mutates via `waitpid`/`WNOHANG`).
#[must_use]
pub fn sessions_active(cntrl: &Control) -> (i32, AcceptType) {
    let mut n = 0;
    let mut raval = AcceptType::Accept;
    for t in &cntrl.tests {
        if let Some(ep) = &t.endpoint {
            let aval = ep.poll_status();
            if matches!(aval, AcceptType::Invalid) {
                n += 1;
            } else if (aval as i32) > (raval as i32) {
                raval = aval;
            }
        }
    }
    (n, raval)
}

#[must_use]
pub const fn is_lost_record(rec: &DataRec) -> bool {
    rec.recv.owptime.0 == 0
}

#[must_use]
pub fn delay(send_time: &OwampTimeStamp, recv_time: &OwampTimeStamp) -> f64 {
    num64_to_double(recv_time.owptime) - num64_to_double(send_time.owptime)
}

#[must_use]
pub fn test_diskspace(tspec: &TestSpec) -> u64 {
    // 56 == 40 initial + 16 IZP; preamble 7*16; slots
    let hdr_len = 56u64 + 7 * 16 + 16 * (u64::from(tspec.nslots) + 1);
    hdr_len + u64::from(tspec.npackets) * 25 // _OWP_DATARECV3_SIZE
}

/// `OWPSocketInterfaceBind` — `SO_BINDTODEVICE` where available.
#[must_use]
pub fn socket_interface_bind(cntrl: &Control, fd: i32, interface: &str) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let _ = add_effective_capability(&cntrl.ctx, "cap_net_raw");
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                interface.as_ptr() as *const libc::c_void,
                interface.len() as libc::socklen_t,
            )
        };
        let _ = remove_effective_capability(&cntrl.ctx, "cap_net_raw");
        if rc != 0 {
            cntrl.ctx.error(
                ErrSeverity::Fatal,
                ErrType::Unknown,
                &format!("SO_BINDTODEVICE {interface} failed"),
            );
            return false;
        }
        true
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = (fd, interface);
        // macOS has no SO_BINDTODEVICE — treat as success (bind via local addr instead).
        cntrl.ctx.error(
            ErrSeverity::Warning,
            ErrType::Unsupported,
            "SO_BINDTODEVICE not available on this platform",
        );
        true
    }
}

/// `OWPParsePortRange`
pub fn parse_port_range(pspec: &str, portspec: &mut crate::context::PortRange) -> bool {
    let parts: Vec<&str> = pspec.split('-').collect();
    match parts.len() {
        1 => {
            let Ok(p) = parts[0].trim().parse::<u16>() else {
                return false;
            };
            portspec.low = p;
            portspec.high = p;
            true
        },
        2 => {
            let Ok(lo) = parts[0].trim().parse::<u16>() else {
                return false;
            };
            let Ok(hi) = parts[1].trim().parse::<u16>() else {
                return false;
            };
            if lo > hi {
                return false;
            }
            portspec.low = lo;
            portspec.high = hi;
            true
        },
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// LOCAL protocol handshake (until protocol agent lands) — greeting/setup/start
// ---------------------------------------------------------------------------

const fn get_accept_type(val: u8) -> AcceptType {
    match val {
        0 => AcceptType::Accept,
        1 => AcceptType::Reject,
        2 => AcceptType::Failure,
        3 => AcceptType::Unsupported,
        4 => AcceptType::UnavailablePerm,
        5 => AcceptType::UnavailableTemp,
        _ => AcceptType::Invalid,
    }
}

/// `_OWPWriteServerGreeting`
pub fn write_server_greeting(
    cntrl: &mut Control,
    _retn_on_intr: Option<&i32>,
    avail_modes: u32,
    challenge: &[u8; 16],
    salt: &[u8; 16],
    count: u32,
) -> ErrSeverity {
    if !cntrl.is_initial() {
        cntrl.ctx.error(
            ErrSeverity::Fatal,
            ErrType::Invalid,
            "_OWPWriteServerGreeting: called in wrong state.",
        );
        return ErrSeverity::Fatal;
    }
    let buf = &mut cntrl.msg[..64];
    buf.fill(0);
    buf[12..16].copy_from_slice(&avail_modes.to_be_bytes());
    buf[16..32].copy_from_slice(challenge);
    buf[32..48].copy_from_slice(salt);
    buf[48..52].copy_from_slice(&count.to_be_bytes());
    if write_fully(cntrl.sockfd, buf) != 64 {
        return ErrSeverity::Fatal;
    }
    cntrl.state = STATE_SETUP;
    ErrSeverity::Ok
}

/// `_OWPReadServerGreeting`
pub fn read_server_greeting(
    cntrl: &mut Control,
    _retn_on_intr: Option<&i32>,
    mode: &mut u32,
    challenge: &mut [u8; 16],
    salt: &mut [u8; 16],
    count: &mut u32,
) -> ErrSeverity {
    if !cntrl.is_initial() {
        return ErrSeverity::Fatal;
    }
    let mut buf = [0u8; 64];
    if read_fully(cntrl.sockfd, &mut buf) != 64 {
        return ErrSeverity::Fatal;
    }
    cntrl.msg[..64].copy_from_slice(&buf);
    let mut mb = [0u8; 4];
    mb.copy_from_slice(&buf[12..16]);
    *mode = u32::from_be_bytes(mb);
    challenge.copy_from_slice(&buf[16..32]);
    salt.copy_from_slice(&buf[32..48]);
    mb.copy_from_slice(&buf[48..52]);
    *count = u32::from_be_bytes(mb);
    cntrl.state = STATE_SETUP;
    ErrSeverity::Ok
}

/// `_OWPWriteSetupResponse`
pub fn write_setup_response(
    cntrl: &mut Control,
    _retn_on_intr: Option<&i32>,
    token: &[u8; 64],
) -> ErrSeverity {
    if !cntrl.is_setup() {
        return ErrSeverity::Fatal;
    }
    let mut buf = [0u8; 164];
    buf[0..4].copy_from_slice(&cntrl.mode.to_be_bytes());
    if (cntrl.mode & OWP_MODE_DOCIPHER_CNTRL) != 0 {
        let uid = cntrl.userid.as_deref().unwrap_or("");
        let bytes = uid.as_bytes();
        let n = bytes.len().min(80);
        buf[4..4 + n].copy_from_slice(&bytes[..n]);
        buf[84..148].copy_from_slice(token);
        buf[148..164].copy_from_slice(&cntrl.write_iv);
    }
    if write_fully(cntrl.sockfd, &buf) != 164 {
        return ErrSeverity::Fatal;
    }
    ErrSeverity::Ok
}

/// `_OWPReadSetupResponse`
pub fn read_setup_response(
    cntrl: &mut Control,
    _retn_on_intr: Option<&i32>,
    mode: &mut u32,
    token: &mut [u8; 64],
    client_iv: &mut [u8; 16],
) -> ErrSeverity {
    if !cntrl.is_setup() {
        return ErrSeverity::Fatal;
    }
    let mut buf = [0u8; 164];
    let len = read_fully(cntrl.sockfd, &mut buf);
    if len != 164 {
        return ErrSeverity::Fatal;
    }
    let mut mb = [0u8; 4];
    mb.copy_from_slice(&buf[0..4]);
    *mode = u32::from_be_bytes(mb);
    cntrl.userid_buffer[..80].copy_from_slice(&buf[4..84]);
    // NUL-terminate userid string view
    let uid_end = cntrl.userid_buffer[..80]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(80);
    if uid_end > 0 {
        if let Ok(s) = std::str::from_utf8(&cntrl.userid_buffer[..uid_end]) {
            // stored later by caller if auth succeeds
            let _ = s;
        }
    }
    token.copy_from_slice(&buf[84..148]);
    client_iv.copy_from_slice(&buf[148..164]);
    ErrSeverity::Ok
}

/// `_OWPWriteServerStart`
pub fn write_server_start(
    cntrl: &mut Control,
    _retn_on_intr: Option<&i32>,
    code: AcceptType,
    uptime: OwampNum64,
) -> ErrSeverity {
    if !cntrl.is_setup() {
        return ErrSeverity::Fatal;
    }
    let mut buf = [0u8; 48];
    buf[15] = (code as i32) as u8;
    buf[16..32].copy_from_slice(&cntrl.write_iv);
    if code == AcceptType::Accept {
        let tstamp = OwampTimeStamp {
            owptime: uptime,
            sync: false,
            multiplier: 0,
            scale: 0,
        };
        let mut tb = [0u8; 8];
        encode_timestamp(&mut tb, &tstamp);
        buf[32..40].copy_from_slice(&tb);
        cntrl.state = STATE_REQUEST;
    } else {
        cntrl.mode = OWP_MODE_OPEN;
        cntrl.state = STATE_INVALID;
    }
    send_hmac_add(cntrl, &buf[32..48], 1);
    if (cntrl.mode & OWP_MODE_DOCIPHER_CNTRL) != 0 {
        let mut block = [0u8; 16];
        block.copy_from_slice(&buf[32..48]);
        if encrypt_blocks(cntrl, &mut block, 1) != 0 {
            return ErrSeverity::Fatal;
        }
        buf[32..48].copy_from_slice(&block);
    }
    if write_fully(cntrl.sockfd, &buf) != 48 {
        return ErrSeverity::Fatal;
    }
    ErrSeverity::Ok
}

/// `_OWPReadServerStart`
///
/// # Panics
///
/// Panics if an internal invariant from the C port is violated.
pub fn read_server_start(
    cntrl: &mut Control,
    _retn_on_intr: Option<&i32>,
    acceptval: &mut AcceptType,
    uptime: &mut OwampNum64,
) -> ErrSeverity {
    if !cntrl.is_setup() {
        return ErrSeverity::Fatal;
    }
    let mut buf = [0u8; 32];
    if read_fully(cntrl.sockfd, &mut buf) != 32 {
        cntrl.state = STATE_INVALID;
        return ErrSeverity::Fatal;
    }
    *acceptval = get_accept_type(buf[15]);
    if *acceptval == AcceptType::Invalid {
        cntrl.state = STATE_INVALID;
        return ErrSeverity::Fatal;
    }
    cntrl.read_iv.copy_from_slice(&buf[16..32]);
    if *acceptval != AcceptType::Accept {
        cntrl.mode = OWP_MODE_OPEN;
    }
    let mut enc = [0u8; 16];
    if receive_blocks_intr(cntrl, &mut enc, 1) != 1 {
        cntrl.state = STATE_INVALID;
        return ErrSeverity::Fatal;
    }
    recv_hmac_add(cntrl, &enc, 1);
    let tstamp = decode_timestamp(&enc[..8].try_into().unwrap());
    *uptime = tstamp.owptime;
    cntrl.state = STATE_REQUEST;
    ErrSeverity::Ok
}

/// `OWPReadRequestType` — peek first control message type.
pub fn read_request_type(cntrl: &mut Control, _retn_on_intr: Option<&i32>) -> RequestType {
    if !cntrl.is_request() || cntrl.state_is(context::STATE_READING) {
        return RequestType::Invalid;
    }
    let mut block = [0u8; OWP_RIJNDAEL_BLOCK_SIZE];
    let n = receive_blocks_intr(cntrl, &mut block, 1);
    if n != 1 {
        cntrl.state = STATE_INVALID;
        if n < 0 {
            return RequestType::SockIntr;
        }
        return RequestType::SockClose;
    }
    cntrl.msg[..16].copy_from_slice(&block);
    let msgtype = block[0];
    if (cntrl.is_test() && msgtype != 3) || (!cntrl.is_test() && msgtype == 3) {
        cntrl.state = STATE_INVALID;
        return RequestType::Invalid;
    }
    match msgtype {
        1 => {
            cntrl.state |= context::STATE_TEST_REQUEST;
            RequestType::Test
        },
        2 => {
            cntrl.state |= context::STATE_START_SESSIONS;
            RequestType::StartSessions
        },
        3 => {
            cntrl.state |= context::STATE_STOP_SESSIONS;
            RequestType::StopSessions
        },
        4 => {
            cntrl.state |= context::STATE_FETCH_SESSION;
            RequestType::FetchSession
        },
        5 => {
            cntrl.state |= context::STATE_TEST_REQUEST_TW;
            RequestType::TestTw
        },
        _ => {
            cntrl.state = STATE_INVALID;
            RequestType::Invalid
        },
    }
}

const fn slot_to_proto(s: &Slot) -> ProtoSlot {
    match s.slot_type {
        SlotType::RandExp => ProtoSlot::RandExp { mean: s.time },
        SlotType::Literal | SlotType::Unspecified => ProtoSlot::Literal { offset: s.time },
    }
}

const fn slot_from_proto(s: ProtoSlot) -> Slot {
    match s {
        ProtoSlot::RandExp { mean } => Slot {
            slot_type: SlotType::RandExp,
            time: mean,
        },
        ProtoSlot::Literal { offset } => Slot {
            slot_type: SlotType::Literal,
            time: offset,
        },
    }
}

fn to_proto_accept(a: AcceptType) -> crate::protocol::AcceptType {
    crate::protocol::AcceptType::from_u8(if a == AcceptType::Invalid {
        0xff
    } else {
        a as u8
    })
}

const fn from_proto_accept(a: crate::protocol::AcceptType) -> AcceptType {
    match a {
        crate::protocol::AcceptType::Accept => AcceptType::Accept,
        crate::protocol::AcceptType::Reject => AcceptType::Reject,
        crate::protocol::AcceptType::Failure => AcceptType::Failure,
        crate::protocol::AcceptType::Unsupported => AcceptType::Unsupported,
        crate::protocol::AcceptType::UnavailablePerm => AcceptType::UnavailablePerm,
        crate::protocol::AcceptType::UnavailableTemp => AcceptType::UnavailableTemp,
        crate::protocol::AcceptType::Invalid => AcceptType::Invalid,
    }
}

fn context_tspec_to_proto(tspec: &TestSpec) -> ProtoTestSpec {
    ProtoTestSpec {
        start_time: tspec.start_time,
        loss_timeout: tspec.loss_timeout,
        type_p: tspec.type_p,
        packet_size_padding: tspec.packet_size_padding,
        npackets: tspec.npackets,
        nslots: tspec.nslots,
        slots: tspec.slots.iter().map(slot_to_proto).collect(),
    }
}

/// `_OWPWriteStartSessions`
pub fn write_start_sessions(cntrl: &mut Control, _retn_on_intr: Option<&i32>) -> ErrSeverity {
    let mut msg = ProtoStartSessions { hmac: [0u8; 16] };
    let mut buf = [0u8; START_SESSIONS_SIZE];
    if msg.encode(&mut buf).is_err() {
        return fail_control_session(cntrl, ErrSeverity::Fatal);
    }
    crate::io::send_hmac_add(cntrl, &buf[..16], 1);
    send_hmac_digest_clear(cntrl, &mut msg.hmac);
    buf[16..32].copy_from_slice(&msg.hmac);
    if send_blocks_intr(cntrl, &mut buf, 2) != 2 {
        return fail_control_session(cntrl, ErrSeverity::Fatal);
    }
    after_write_start_sessions(&mut cntrl.state);
    ErrSeverity::Ok
}

/// `_OWPReadStartSessions`
pub fn read_start_sessions(cntrl: &mut Control, _retn_on_intr: Option<&i32>) -> ErrSeverity {
    // First block already in msg from ReadRequestType — read remaining HMAC block.
    let mut buf = [0u8; START_SESSIONS_SIZE];
    buf[..16].copy_from_slice(&cntrl.msg[..16]);
    if receive_blocks_intr(cntrl, &mut buf[16..], 1) != 1 {
        cntrl.state = STATE_INVALID;
        return ErrSeverity::Fatal;
    }
    crate::io::recv_hmac_add(cntrl, &buf[..16], 1);
    let mut digest = [0u8; 16];
    digest.copy_from_slice(&buf[16..32]);
    if !recv_hmac_check_clear(cntrl, &digest) {
        cntrl.state = STATE_INVALID;
        return ErrSeverity::Fatal;
    }
    if ProtoStartSessions::decode(&buf).is_err() {
        cntrl.state = STATE_INVALID;
        return ErrSeverity::Fatal;
    }
    after_read_start_sessions(&mut cntrl.state);
    ErrSeverity::Ok
}

/// `_OWPWriteStartAck`
pub fn write_start_ack(
    cntrl: &mut Control,
    _retn_on_intr: Option<&i32>,
    acceptval: AcceptType,
) -> ErrSeverity {
    let mut msg = ProtoStartAck {
        accept: to_proto_accept(acceptval),
        hmac: [0u8; 16],
    };
    let mut buf = [0u8; START_ACK_SIZE];
    if msg.encode(&mut buf).is_err() {
        return ErrSeverity::Fatal;
    }
    crate::io::send_hmac_add(cntrl, &buf[..16], 1);
    send_hmac_digest_clear(cntrl, &mut msg.hmac);
    buf[16..32].copy_from_slice(&msg.hmac);
    if send_blocks_intr(cntrl, &mut buf, 2) != 2 {
        cntrl.state = STATE_INVALID;
        return ErrSeverity::Fatal;
    }
    after_write_start_ack(&mut cntrl.state, to_proto_accept(acceptval));
    ErrSeverity::Ok
}

/// `_OWPReadStartAck`
pub fn read_start_ack(
    cntrl: &mut Control,
    _retn_on_intr: Option<&i32>,
    acceptval: &mut AcceptType,
) -> ErrSeverity {
    let mut buf = [0u8; START_ACK_SIZE];
    if receive_blocks_intr(cntrl, &mut buf, 2) != 2 {
        cntrl.state = STATE_INVALID;
        return ErrSeverity::Fatal;
    }
    crate::io::recv_hmac_add(cntrl, &buf[..16], 1);
    let mut digest = [0u8; 16];
    digest.copy_from_slice(&buf[16..32]);
    if !recv_hmac_check_clear(cntrl, &digest) {
        cntrl.state = STATE_INVALID;
        return ErrSeverity::Fatal;
    }
    let Ok(msg) = ProtoStartAck::decode(&buf) else {
        cntrl.state = STATE_INVALID;
        return ErrSeverity::Fatal;
    };
    *acceptval = from_proto_accept(msg.accept);
    after_read_start_ack(&mut cntrl.state, msg.accept);
    ErrSeverity::Ok
}

/// `_OWPWriteAcceptSession` — 48 octets / 3 blocks.
pub fn write_accept_session(
    cntrl: &mut Control,
    _retn_on_intr: Option<&i32>,
    acceptval: AcceptType,
    port: u16,
    sid: Option<&Sid>,
) -> ErrSeverity {
    let mut sid_buf = [0u8; 16];
    if let Some(s) = sid {
        sid_buf.copy_from_slice(s);
    }
    let mut msg = ProtoAcceptSession {
        accept: to_proto_accept(acceptval),
        port,
        sid: sid_buf,
        hmac: [0u8; 16],
    };
    let mut buf = [0u8; ACCEPT_SESSION_SIZE];
    if msg.encode(&mut buf).is_err() {
        return ErrSeverity::Fatal;
    }
    crate::io::send_hmac_add(cntrl, &buf[..32], 2);
    send_hmac_digest_clear(cntrl, &mut msg.hmac);
    buf[32..48].copy_from_slice(&msg.hmac);
    if send_blocks_intr(cntrl, &mut buf, 3) != 3 {
        cntrl.state = STATE_INVALID;
        return ErrSeverity::Fatal;
    }
    after_write_accept_session(&mut cntrl.state);
    ErrSeverity::Ok
}

/// `_OWPReadAcceptSession`
pub fn read_accept_session(
    cntrl: &mut Control,
    _retn_on_intr: Option<&i32>,
    acceptval: &mut AcceptType,
    port: &mut u16,
    sid: Option<&mut Sid>,
) -> ErrSeverity {
    let mut buf = [0u8; ACCEPT_SESSION_SIZE];
    if receive_blocks_intr(cntrl, &mut buf, 3) != 3 {
        cntrl.state = STATE_INVALID;
        return ErrSeverity::Fatal;
    }
    crate::io::recv_hmac_add(cntrl, &buf[..32], 2);
    let mut digest = [0u8; 16];
    digest.copy_from_slice(&buf[32..48]);
    if !recv_hmac_check_clear(cntrl, &digest) {
        cntrl.state = STATE_INVALID;
        return ErrSeverity::Fatal;
    }
    let Ok(msg) = ProtoAcceptSession::decode(&buf) else {
        cntrl.state = STATE_INVALID;
        return ErrSeverity::Fatal;
    };
    *acceptval = from_proto_accept(msg.accept);
    *port = msg.port;
    if let Some(s) = sid {
        *s = msg.sid;
    }
    after_read_accept_session(&mut cntrl.state);
    ErrSeverity::Ok
}

/// `_OWPWriteTestRequest`
pub fn write_test_request(
    cntrl: &mut Control,
    _retn_on_intr: Option<&i32>,
    sender: Option<SocketAddr>,
    receiver: Option<SocketAddr>,
    server_conf_sender: bool,
    server_conf_receiver: bool,
    zero_addr: bool,
    sid: Option<&Sid>,
    test_spec: &TestSpec,
) -> ErrSeverity {
    if !cntrl.is_request() || cntrl.state_is(context::STATE_PENDING) {
        cntrl.ctx.error(
            ErrSeverity::Fatal,
            ErrType::Invalid,
            "_OWPWriteTestRequest: called in wrong state.",
        );
        return ErrSeverity::Fatal;
    }
    let (Some(sender), Some(receiver)) = (sender, receiver) else {
        return ErrSeverity::Fatal;
    };
    let proto_tspec = context_tspec_to_proto(test_spec);
    let Ok(mut preamble) = TestRequestPreamble::from_test_spec(
        cntrl.twoway,
        server_conf_sender,
        server_conf_receiver,
        zero_addr,
        sid,
        sender,
        receiver,
        &proto_tspec,
    ) else {
        return ErrSeverity::Fatal;
    };

    let mut buf = [0u8; OWP_TEST_REQUEST_PREAMBLE_SIZE];
    if preamble.encode(&mut buf).is_err() {
        return ErrSeverity::Fatal;
    }
    crate::io::send_hmac_add(cntrl, &buf[..96], 6);
    send_hmac_digest_clear(cntrl, &mut preamble.hmac);
    buf[96..112].copy_from_slice(&preamble.hmac);
    cntrl.msg[..112].copy_from_slice(&buf);
    if send_blocks_intr(cntrl, &mut buf, 7) != 7 {
        cntrl.state = STATE_INVALID;
        return ErrSeverity::Fatal;
    }

    if !cntrl.twoway {
        for slot in &test_spec.slots {
            let mut sbuf = [0u8; SLOT_SIZE];
            if encode_slot(&mut sbuf, &slot_to_proto(slot)).is_err() {
                cntrl.state = STATE_INVALID;
                return ErrSeverity::Fatal;
            }
            crate::io::send_hmac_add(cntrl, &sbuf, 1);
            if send_blocks_intr(cntrl, &mut sbuf, 1) != 1 {
                cntrl.state = STATE_INVALID;
                return ErrSeverity::Fatal;
            }
        }
        let mut digest = [0u8; 16];
        send_hmac_digest_clear(cntrl, &mut digest);
        if send_blocks_intr(cntrl, &mut digest, 1) != 1 {
            cntrl.state = STATE_INVALID;
            return ErrSeverity::Fatal;
        }
    }

    after_write_test_request(&mut cntrl.state);
    ErrSeverity::Ok
}

fn read_test_request_slots(cntrl: &mut Control, nslots: u32, slots: &mut Vec<Slot>) -> ErrSeverity {
    if !cntrl.state_is(context::STATE_TEST_REQUEST_SLOTS) {
        return ErrSeverity::Fatal;
    }
    slots.clear();
    slots.reserve(nslots as usize);
    for _ in 0..nslots {
        let mut sbuf = [0u8; SLOT_SIZE];
        if receive_blocks_intr(cntrl, &mut sbuf, 1) != 1 {
            cntrl.state = STATE_INVALID;
            return ErrSeverity::Fatal;
        }
        crate::io::recv_hmac_add(cntrl, &sbuf, 1);
        let Ok(ps) = decode_slot(&sbuf) else {
            cntrl.state = STATE_INVALID;
            return ErrSeverity::Fatal;
        };
        slots.push(slot_from_proto(ps));
    }
    let mut digest = [0u8; 16];
    if receive_blocks_intr(cntrl, &mut digest, 1) != 1 {
        cntrl.state = STATE_INVALID;
        return ErrSeverity::Fatal;
    }
    if !recv_hmac_check_clear(cntrl, &digest) {
        cntrl.state = STATE_INVALID;
        return ErrSeverity::Fatal;
    }
    cntrl.state &= !context::STATE_TEST_REQUEST_SLOTS;
    ErrSeverity::Ok
}

/// Core `TestRequest` reader. When `as_server` is true the first AES block is
/// already in `cntrl.msg` (from `read_request_type`).
fn read_test_request_inner(
    cntrl: &mut Control,
    as_server: bool,
    accept_ret: &mut AcceptType,
) -> Result<Box<TestSession>, ErrSeverity> {
    *accept_ret = AcceptType::Accept;
    let expect_tw = cntrl.twoway;
    let need_state = if expect_tw {
        context::STATE_TEST_REQUEST_TW
    } else {
        context::STATE_TEST_REQUEST
    };
    if !cntrl.state_is(need_state) && as_server {
        return Err(ErrSeverity::Fatal);
    }

    let mut buf = [0u8; OWP_TEST_REQUEST_PREAMBLE_SIZE];
    if as_server {
        buf[..16].copy_from_slice(&cntrl.msg[..16]);
        if receive_blocks_intr(cntrl, &mut buf[16..], 6) != 6 {
            cntrl.state = STATE_INVALID;
            *accept_ret = AcceptType::Invalid;
            return Err(ErrSeverity::Fatal);
        }
    } else if receive_blocks_intr(cntrl, &mut buf, 7) != 7 {
        cntrl.state = STATE_INVALID;
        *accept_ret = AcceptType::Invalid;
        return Err(ErrSeverity::Fatal);
    }

    crate::io::recv_hmac_add(cntrl, &buf[..96], 6);
    let mut digest = [0u8; 16];
    digest.copy_from_slice(&buf[96..112]);
    if !recv_hmac_check_clear(cntrl, &digest) {
        cntrl.state = STATE_INVALID;
        *accept_ret = AcceptType::Invalid;
        return Err(ErrSeverity::Fatal);
    }

    let Ok(preamble) = TestRequestPreamble::decode(&buf, as_server, expect_tw) else {
        if as_server {
            *accept_ret = AcceptType::Unsupported;
            return Err(ErrSeverity::Fatal);
        }
        cntrl.state = STATE_INVALID;
        *accept_ret = AcceptType::Invalid;
        return Err(ErrSeverity::Fatal);
    };

    let mut sender = preamble.sender;
    let mut receiver = preamble.receiver;
    let remote = cntrl.remote_addr.as_ref().and_then(Addr::saddr);
    if !apply_ipv6_ll_scope(remote, &mut sender) || !apply_ipv6_ll_scope(remote, &mut receiver) {
        *accept_ret = AcceptType::Unsupported;
        return Err(ErrSeverity::Fatal);
    }
    if cntrl.twoway {
        if let Some(r) = remote {
            set_saddr_if_unspecified(r, &mut sender);
        }
        if let Some(l) = cntrl.local_addr.as_ref().and_then(Addr::saddr) {
            set_saddr_if_unspecified(l, &mut receiver);
        }
    }

    cntrl.state &= !(context::STATE_TEST_REQUEST | context::STATE_TEST_REQUEST_TW);
    cntrl.state |= context::STATE_TEST_REQUEST_SLOTS;

    let send_addr = Addr::by_sockaddr(sender, libc::SOCK_DGRAM, libc::IPPROTO_UDP);
    let recv_addr = Addr::by_sockaddr(receiver, libc::SOCK_DGRAM, libc::IPPROTO_UDP);

    let mut tspec = TestSpec {
        start_time: preamble.start_time,
        loss_timeout: preamble.loss_timeout,
        type_p: preamble.type_p,
        packet_size_padding: preamble.packet_size_padding,
        npackets: preamble.npackets,
        nslots: preamble.nslots,
        slots: Vec::new(),
    };

    let Some(mut tsession) = test_session_alloc(
        cntrl,
        send_addr,
        preamble.conf_sender,
        recv_addr,
        preamble.conf_receiver,
        &tspec,
    ) else {
        *accept_ret = AcceptType::Failure;
        return Err(ErrSeverity::Warning);
    };

    if cntrl.twoway {
        cntrl.state &= !context::STATE_TEST_REQUEST_SLOTS;
    } else {
        tsession.sid = preamble.sid;
        let mut slots = Vec::new();
        if read_test_request_slots(cntrl, preamble.nslots, &mut slots) < ErrSeverity::Ok {
            *accept_ret = AcceptType::Invalid;
            let _ = test_session_free_unlinked(cntrl, tsession, AcceptType::Invalid);
            return Err(ErrSeverity::Fatal);
        }
        tspec.slots = slots;
        tspec.nslots = preamble.nslots;
        tsession.test_spec = tspec;
    }

    if as_server {
        cntrl.state |= context::STATE_ACCEPT_SESSION;
    } else {
        cntrl.state |= context::STATE_FETCHING;
    }
    Ok(tsession)
}

/// `_OWPReadTestRequest` — server context (first block already peeked).
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn read_test_request(
    cntrl: &mut Control,
    _retn_on_intr: Option<&i32>,
    accept_ret: &mut AcceptType,
) -> Result<Box<TestSession>, ErrSeverity> {
    read_test_request_inner(cntrl, true, accept_ret)
}

/// Client-side `TestRequest` read used by `FetchSession` (reads all 7 blocks).
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn read_test_request_fetch(
    cntrl: &mut Control,
    _retn_on_intr: Option<&i32>,
) -> Result<Box<TestSession>, ErrSeverity> {
    let mut accept = AcceptType::Accept;
    // Ensure expected state for fetch path.
    cntrl.state |= if cntrl.twoway {
        context::STATE_TEST_REQUEST_TW
    } else {
        context::STATE_TEST_REQUEST
    };
    read_test_request_inner(cntrl, false, &mut accept)
}

/// `_OWPWriteFetchSession`
pub fn write_fetch_session(
    cntrl: &mut Control,
    _retn_on_intr: Option<&i32>,
    begin: u32,
    end: u32,
    sid: &Sid,
) -> ErrSeverity {
    let mut msg = ProtoFetchSession {
        begin,
        end,
        sid: *sid,
        hmac: [0u8; 16],
    };
    let mut buf = [0u8; FETCH_SESSION_SIZE];
    if msg.encode(&mut buf).is_err() {
        return ErrSeverity::Fatal;
    }
    crate::io::send_hmac_add(cntrl, &buf[..32], 2);
    send_hmac_digest_clear(cntrl, &mut msg.hmac);
    buf[32..48].copy_from_slice(&msg.hmac);
    if send_blocks_intr(cntrl, &mut buf, 3) != 3 {
        cntrl.state = STATE_INVALID;
        return ErrSeverity::Fatal;
    }
    after_write_fetch_session(&mut cntrl.state);
    ErrSeverity::Ok
}

/// `_OWPReadFetchAck`
pub fn read_fetch_ack(
    cntrl: &mut Control,
    _retn_on_intr: Option<&i32>,
    acceptval: &mut AcceptType,
    finished: &mut u8,
    next_seqno: &mut u32,
    num_skiprecs: &mut u32,
    num_datarecs: &mut u32,
) -> ErrSeverity {
    let mut buf = [0u8; FETCH_ACK_SIZE];
    if receive_blocks_intr(cntrl, &mut buf, 2) != 2 {
        cntrl.state = STATE_INVALID;
        return ErrSeverity::Fatal;
    }
    crate::io::recv_hmac_add(cntrl, &buf[..16], 1);
    let mut digest = [0u8; 16];
    digest.copy_from_slice(&buf[16..32]);
    if !recv_hmac_check_clear(cntrl, &digest) {
        cntrl.state = STATE_INVALID;
        return ErrSeverity::Fatal;
    }
    let Ok(msg) = ProtoFetchAck::decode(&buf) else {
        cntrl.state = STATE_INVALID;
        return ErrSeverity::Fatal;
    };
    *acceptval = from_proto_accept(msg.accept);
    *finished = msg.finished;
    *next_seqno = msg.next_seqno;
    *num_skiprecs = msg.num_skiprecs;
    *num_datarecs = msg.num_datarecs;
    after_read_fetch_ack(&mut cntrl.state, msg.accept, cntrl.twoway);
    ErrSeverity::Ok
}

fn test_spec_to_owamp(ts: &TestSpec) -> crate::owamp::OwampTestSpec {
    use crate::owamp::{OwampSlot, OwampSlotLiteral, OwampSlotRandExp, OwampTestSpec};
    OwampTestSpec {
        start_time: ts.start_time,
        loss_timeout: ts.loss_timeout,
        type_p: ts.type_p,
        packet_size_padding: ts.packet_size_padding,
        npackets: ts.npackets,
        slots: ts
            .slots
            .iter()
            .map(|s| match s.slot_type {
                crate::context::SlotType::RandExp => {
                    OwampSlot::RandExp(OwampSlotRandExp { mean: s.time })
                },
                _ => OwampSlot::Literal(OwampSlotLiteral { offset: s.time }),
            })
            .collect(),
    }
}

/// Endpoint init — bind local UDP socket, build real [`endpoint::EndpointState`],
/// and record role / files on the control-plane [`Endpoint`].
///
/// Optional `fp` is the session data file (`FILE *` in C `_OWPEndpointInit`);
/// when `None` for a receiver / TW client, the Context `OWPOpenFile` callback is
/// invoked (`_OWPCallOpenFile`). Missing file ⇒ failure like C.
#[allow(clippy::too_many_lines)] // C-parity body
pub fn endpoint_init(
    cntrl: &Control,
    tsession: &mut TestSession,
    local: &Addr,
    fp: Option<&std::fs::File>,
    aval: &mut AcceptType,
    send: bool,
) -> bool {
    use std::os::fd::AsRawFd;
    let Some(local_sa) = local.saddr() else {
        *aval = AcceptType::Failure;
        return false;
    };
    let remote_sa = if send {
        tsession.receiver.as_ref().and_then(Addr::saddr)
    } else {
        tsession.sender.as_ref().and_then(Addr::saddr)
    };
    let Some(remote_sa) = remote_sa else {
        *aval = AcceptType::UnavailableTemp;
        return false;
    };

    let role = if send {
        crate::endpoint::EndpointRole::Sender
    } else {
        crate::endpoint::EndpointRole::Receiver
    };
    let ow_spec = test_spec_to_owamp(&tsession.test_spec);
    let Ok(mut state) = crate::endpoint::EndpointState::alloc(
        role,
        cntrl.mode,
        tsession.sid,
        ow_spec,
        cntrl.twoway,
    ) else {
        *aval = AcceptType::Failure;
        return false;
    };

    // Context knobs used by `_OWPEndpointInit` / reflector REFWAIT.
    if let Some(secs) = cntrl.ctx.end_delay() {
        state.apply_end_delay(secs);
    }
    if let Some(t) = cntrl.ctx.config_get_u32(TWP_TEST_TIMEOUT) {
        state.test_timeout_secs = t;
    }
    state.child_wait = cntrl
        .ctx
        .config_get_v(crate::context::OWP_CHILD_WAIT)
        .is_some_and(|v| v != 0);

    let portrange = cntrl
        .ctx
        .test_port_range()
        .map(|pr| crate::owamp::OwampPortRange {
            low: pr.low,
            high: pr.high,
        });
    let is_server_reflector = cntrl.server && cntrl.twoway;
    state.conf_sender = tsession.conf_sender;
    state.conf_receiver = tsession.conf_receiver;

    if state
        .init_socket(local_sa, remote_sa, portrange, is_server_reflector)
        .is_err()
    {
        *aval = AcceptType::Failure;
        return false;
    }

    // Publish the bound port back onto the session address (C via I2AddrSetSAddr).
    if let Some(bound) = state.local {
        if let Some(ref mut a) = if send {
            tsession.sender.as_mut()
        } else {
            tsession.receiver.as_mut()
        } {
            a.set_port(bound.port());
        }
    }

    // TW client or one-way receiver: require a session data file.
    let is_recv_or_tw_client = (cntrl.twoway && !cntrl.server) || (!cntrl.twoway && !send);
    let mut opened_via_callback: Option<std::fs::File> = None;
    if is_recv_or_tw_client {
        let file_ref: Option<&std::fs::File> = if let Some(f) = fp {
            Some(f)
        } else {
            let mut fname = std::path::PathBuf::new();
            opened_via_callback = context::call_open_file(
                cntrl,
                tsession.closure.as_deref(),
                &tsession.sid,
                &mut fname,
            );
            if opened_via_callback.is_some() {
                state.set_fname(fname);
            }
            opened_via_callback.as_ref()
        };
        let Some(f) = file_ref else {
            *aval = AcceptType::Failure;
            return false;
        };
        if state.attach_datafile(f).is_err() {
            *aval = AcceptType::Failure;
            return false;
        }
    }

    let sockfd = state.sock.as_ref().map_or(-1, AsRawFd::as_raw_fd);
    let mut ep = Endpoint::new(send, cntrl.twoway, sockfd);
    if let Some(f) = fp {
        if let Ok(u) = f.try_clone() {
            ep.userfile = Some(u);
        }
    } else if let Some(ref f) = opened_via_callback {
        if let Ok(u) = f.try_clone() {
            ep.userfile = Some(u);
        }
    }
    ep.fbuff_size = state.fbuff_size;
    if !state.fname.as_os_str().is_empty() {
        ep.fname.clone_from(&state.fname);
    }
    ep.set_state(state);
    tsession.endpoint = Some(ep);
    *aval = AcceptType::Accept;
    true
}

/// `_OWPEndpointInitHook` — refresh peer addr/crypto and spawn the worker thread
/// that waits for `StartSessions` (thread stand-in for `fork`).
pub fn endpoint_init_hook(
    cntrl: &Control,
    tsession: &mut TestSession,
    aval: &mut AcceptType,
) -> bool {
    let Some(ep) = tsession.endpoint.as_mut() else {
        *aval = AcceptType::Failure;
        return false;
    };

    if let Some(ref mut st) = ep.state {
        let remote = if ep.send {
            tsession.receiver.as_ref().and_then(Addr::saddr)
        } else {
            tsession.sender.as_ref().and_then(Addr::saddr)
        };
        if let Some(r) = remote {
            st.remote = Some(r);
        }
        st.sid = tsession.sid;
        if (cntrl.mode & crate::context::OWP_MODE_DOCIPHER_TEST) != 0 {
            let aes = cntrl.aessession_key;
            let hmac = cntrl.hmac_key;
            let _ = st.setup_crypto(&aes, &hmac);
        }
    }

    if ep.spawn_child().is_err() {
        *aval = AcceptType::Failure;
        return false;
    }
    *aval = AcceptType::Accept;
    true
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn endpoint_start(ep: &mut Endpoint) -> Result<(), ErrSeverity> {
    ep.start()
}

/// C magic is the 3-char string `"OwA"` including the trailing NUL → 4 octets.
const OWP_MAGIC_BYTES: [u8; 4] = [b'O', b'w', b'A', 0];

// ---------------------------------------------------------------------------
// StopSessions helpers / orchestration (api.c)
// ---------------------------------------------------------------------------

fn stop_send_sessions(cntrl: &mut Control, acceptval: &mut AcceptType) -> (ErrSeverity, u32) {
    let mut err2 = ErrSeverity::Ok;
    let mut num_senders = 0u32;
    let twoway = cntrl.twoway;

    for t in &mut cntrl.tests {
        let Some(ep) = t.endpoint.as_mut() else {
            cntrl.ctx.error(
                ErrSeverity::Warning,
                ErrType::Invalid,
                "_OWPStopSendSessions: no endpoint state!",
            );
            *acceptval = AcceptType::Failure;
            break;
        };
        // Two-way and receive sessions are not done here.
        if !twoway && !ep.send {
            continue;
        }
        ep.stop(acceptval);
        num_senders += 1;

        if !twoway {
            // Validate skip records: filesize == (nskip+1)*8, then rewind for WriteStopSessions.
            let Some(ref mut skipfd) = ep.skiprec_fd else {
                cntrl.ctx.error(
                    ErrSeverity::Warning,
                    ErrType::Invalid,
                    "_OWPStopSendSessions: missing skiprecfd",
                );
                *acceptval = AcceptType::Failure;
                err2 = err2.min(ErrSeverity::Warning);
                continue;
            };
            let Ok(meta) = skipfd.metadata() else {
                cntrl
                    .ctx
                    .error(ErrSeverity::Warning, ErrType::Unknown, "fstat(skiprecfd)");
                *acceptval = AcceptType::Failure;
                err2 = err2.min(ErrSeverity::Warning);
                continue;
            };
            if skipfd.seek(SeekFrom::Start(0)).is_err() {
                cntrl
                    .ctx
                    .error(ErrSeverity::Warning, ErrType::Unknown, "lseek(skiprecfd,0)");
                *acceptval = AcceptType::Failure;
                err2 = err2.min(ErrSeverity::Warning);
                continue;
            }
            let mut sdr = [0u8; 8];
            if skipfd.read_exact(&mut sdr).is_err() {
                cntrl
                    .ctx
                    .error(ErrSeverity::Warning, ErrType::Unknown, "I2Readn(skiprecfd)");
                *acceptval = AcceptType::Failure;
                err2 = err2.min(ErrSeverity::Warning);
                continue;
            }
            if skipfd.seek(SeekFrom::Start(0)).is_err() {
                cntrl
                    .ctx
                    .error(ErrSeverity::Warning, ErrType::Unknown, "lseek(skiprecfd,0)");
                *acceptval = AcceptType::Failure;
                err2 = err2.min(ErrSeverity::Warning);
                continue;
            }
            let next_seq = u32::from_be_bytes([sdr[0], sdr[1], sdr[2], sdr[3]]);
            let nskip = u32::from_be_bytes([sdr[4], sdr[5], sdr[6], sdr[7]]);
            let expect = u64::from(nskip.saturating_add(1)) * 8;
            if expect != meta.len() {
                cntrl.ctx.error(
                    ErrSeverity::Warning,
                    ErrType::Invalid,
                    "_OWPStopSendSessions: Invalid skiprecfd data",
                );
                *acceptval = AcceptType::Failure;
                err2 = err2.min(ErrSeverity::Warning);
                continue;
            }
            ep.skiprecsize = meta.len();
            t.next_seq = next_seq;
            t.nskips = nskip;
        }
    }
    (err2, num_senders)
}

fn stop_recv_sessions(
    cntrl: &mut Control,
    stoptime: &OwampTimeStamp,
    nowait: bool,
    acceptval: &mut AcceptType,
) -> ErrSeverity {
    let mut err2 = ErrSeverity::Ok;
    let twoway = cntrl.twoway;
    let server = cntrl.server;

    for t in &mut cntrl.tests {
        let Some(ep) = t.endpoint.as_mut() else {
            cntrl.ctx.error(
                ErrSeverity::Warning,
                ErrType::Invalid,
                "_OWPStopRecvSessions: no endpoint state!",
            );
            *acceptval = AcceptType::Failure;
            break;
        };
        if !twoway && ep.send {
            continue;
        }

        if twoway && server && !nowait {
            if let Some(curr) = get_time_of_day(&cntrl.ctx) {
                let mut testtimeout = cntrl
                    .ctx
                    .config_get_u32(TWP_TEST_TIMEOUT)
                    .unwrap_or(TWP_DEFAULT_TEST_TIMEOUT);
                // Bound by loss_timeout (C stores Num64; take seconds as upper bound).
                let loss_secs = t.test_spec.loss_timeout.seconds();
                if loss_secs > 0 {
                    testtimeout = testtimeout.min(loss_secs);
                }
                let stop_abs = stoptime.owptime;
                let loss = ulong_to_num64(testtimeout);
                let deadline = OwampNum64(stop_abs.0.wrapping_add(loss.0));
                if deadline.cmp_num(curr.owptime) > 0 {
                    let rel = num64_sub(deadline, curr.owptime);
                    let ts = num64_to_timespec(rel);
                    let req = libc::timespec {
                        tv_sec: ts.tv_sec,
                        tv_nsec: ts.tv_nsec,
                    };
                    unsafe {
                        libc::nanosleep(&req, std::ptr::null_mut());
                    }
                }
            }
        }

        ep.stop(acceptval);
        err2 = err2.min(ErrSeverity::Ok);
    }
    err2
}

/// `_OWPWriteStopSessions` — wire `StopSessions` (+ session desc for one-way senders).
pub fn write_stop_sessions(
    cntrl: &mut Control,
    _retn_on_intr: Option<&i32>,
    acceptval: AcceptType,
    num_sessions: u32,
) -> ErrSeverity {
    if !(cntrl.is_request() && cntrl.is_test()) {
        cntrl.ctx.error(
            ErrSeverity::Fatal,
            ErrType::Invalid,
            "_OWPWriteStopSessions: called in wrong state.",
        );
        return ErrSeverity::Fatal;
    }

    let hdr = StopSessionsHeader {
        accept: match acceptval {
            AcceptType::Accept => crate::protocol::AcceptType::Accept,
            AcceptType::Reject => crate::protocol::AcceptType::Reject,
            AcceptType::Failure => crate::protocol::AcceptType::Failure,
            AcceptType::Unsupported => crate::protocol::AcceptType::Unsupported,
            AcceptType::UnavailablePerm => crate::protocol::AcceptType::UnavailablePerm,
            AcceptType::UnavailableTemp => crate::protocol::AcceptType::UnavailableTemp,
            AcceptType::Invalid => crate::protocol::AcceptType::Invalid,
        },
        num_sessions,
    };
    let mut buf = [0u8; 32];
    if hdr.encode(&mut buf[..STOP_SESSIONS_HEADER_SIZE]).is_err() {
        return fail_control_session(cntrl, ErrSeverity::Fatal);
    }
    send_hmac_add(cntrl, &buf[..16], 1);

    if cntrl.twoway {
        let mut digest = [0u8; 16];
        send_hmac_digest_clear(cntrl, &mut digest);
        buf[16..32].copy_from_slice(&digest);
        if send_blocks_intr(cntrl, &mut buf, 2) != 2 {
            return fail_control_session(cntrl, ErrSeverity::Fatal);
        }
        return ErrSeverity::Ok;
    }

    // One-way: send header, then per-sender SID + skiprecfd stream.
    if send_blocks_intr(cntrl, &mut buf[..16], 1) != 1 {
        return fail_control_session(cntrl, ErrSeverity::Fatal);
    }

    // Read skip IPC into memory first so HMAC/send can borrow cntrl mutably.
    let mut payloads: Vec<(Sid, Vec<u8>)> = Vec::new();
    for t in &mut cntrl.tests {
        let Some(ep) = t.endpoint.as_mut() else {
            cntrl.ctx.error(
                ErrSeverity::Fatal,
                ErrType::Invalid,
                "_OWPWriteStopSessions: invalid session information.",
            );
            continue;
        };
        if !ep.send {
            continue;
        }
        let mut body = Vec::new();
        let sd_size = ep.skiprecsize as usize;
        if let Some(ref mut skipfd) = ep.skiprec_fd {
            body.resize(sd_size, 0);
            if skipfd.read_exact(&mut body).is_err() {
                return fail_control_session(cntrl, ErrSeverity::Fatal);
            }
        } else if sd_size != 0 {
            return fail_control_session(cntrl, ErrSeverity::Fatal);
        }
        // Pad trailing 8-octet remnant to a 16-octet block (C WriteStopSessions).
        if body.len() % 16 == 8 {
            body.extend_from_slice(&[0u8; 8]);
        } else if body.len() % 16 != 0 {
            return fail_control_session(cntrl, ErrSeverity::Fatal);
        }
        payloads.push((t.sid, body));
    }

    for (sid, body) in payloads {
        let mut sid_buf = [0u8; 16];
        sid_buf.copy_from_slice(&sid);
        send_hmac_add(cntrl, &sid_buf, 1);
        if send_blocks_intr(cntrl, &mut sid_buf, 1) != 1 {
            return fail_control_session(cntrl, ErrSeverity::Fatal);
        }
        let mut off = 0;
        while off < body.len() {
            let mut block = [0u8; 16];
            block.copy_from_slice(&body[off..off + 16]);
            send_hmac_add(cntrl, &block, 1);
            if send_blocks_intr(cntrl, &mut block, 1) != 1 {
                return fail_control_session(cntrl, ErrSeverity::Fatal);
            }
            off += 16;
        }
    }

    let mut digest = [0u8; 16];
    send_hmac_digest_clear(cntrl, &mut digest);
    if send_blocks_intr(cntrl, &mut digest, 1) != 1 {
        return fail_control_session(cntrl, ErrSeverity::Fatal);
    }
    ErrSeverity::Ok
}

/// `_OWPReadStopSessions` — consume `StopSessions` body; update recv session files.
///
/// # Panics
///
/// Panics if an internal invariant from the C port is violated.
#[allow(clippy::too_many_lines)] // C-parity body
pub fn read_stop_sessions(
    cntrl: &mut Control,
    _retn_on_intr: Option<&i32>,
    acceptval: &mut AcceptType,
    stoptime: &OwampTimeStamp,
) -> ErrSeverity {
    if !cntrl.state_is(context::STATE_STOP_SESSIONS) {
        cntrl.ctx.error(
            ErrSeverity::Fatal,
            ErrType::Invalid,
            "_OWPReadStopSessions: Failed - called in wrong state.",
        );
        return ErrSeverity::Fatal;
    }

    // First AES block already peeked by read_request_type into cntrl.msg.
    let mut hdr_buf = [0u8; 16];
    hdr_buf.copy_from_slice(&cntrl.msg[..16]);
    let Ok(hdr) = StopSessionsHeader::decode(&hdr_buf) else {
        *acceptval = AcceptType::Failure;
        return fail_control_session(cntrl, ErrSeverity::Fatal);
    };
    *acceptval = from_proto_accept(hdr.accept);
    crate::io::recv_hmac_add(cntrl, &hdr_buf, 1);

    if cntrl.twoway {
        let mut digest = [0u8; 16];
        if receive_blocks_intr(cntrl, &mut digest, 1) != 1 {
            return fail_control_session(cntrl, ErrSeverity::Fatal);
        }
        if !recv_hmac_check_clear(cntrl, &digest) {
            return fail_control_session(cntrl, ErrSeverity::Fatal);
        }
        after_read_stop_sessions(&mut cntrl.state);
        return ErrSeverity::Ok;
    }

    let num_sessions = hdr.num_sessions;
    for _ in 0..num_sessions {
        let mut sid_buf = [0u8; 16];
        if receive_blocks_intr(cntrl, &mut sid_buf, 1) != 1 {
            return fail_control_session(cntrl, ErrSeverity::Fatal);
        }
        crate::io::recv_hmac_add(cntrl, &sid_buf, 1);

        // next_seqno + num_skiprecs share first block with first skip / padding.
        let mut meta = [0u8; 16];
        if receive_blocks_intr(cntrl, &mut meta, 1) != 1 {
            return fail_control_session(cntrl, ErrSeverity::Fatal);
        }
        crate::io::recv_hmac_add(cntrl, &meta, 1);
        let next_seqno = u32::from_be_bytes([meta[0], meta[1], meta[2], meta[3]]);
        let num_skips = u32::from_be_bytes([meta[4], meta[5], meta[6], meta[7]]);

        // Collect skip records (validate order) while draining wire bytes.
        let mut skips: Vec<SkipRec> = Vec::with_capacity(num_skips as usize);
        let mut prev: Option<ProtoSkipRec> = None;
        for j in 0..num_skips {
            let bufi = (((j + 1) % 2) * 8) as usize;
            if bufi == 0 {
                if receive_blocks_intr(cntrl, &mut meta, 1) != 1 {
                    return fail_control_session(cntrl, ErrSeverity::Fatal);
                }
                crate::io::recv_hmac_add(cntrl, &meta, 1);
            }
            let Ok(curr) = decode_skip_record(&meta[bufi..bufi + 8]) else {
                return fail_control_session(cntrl, ErrSeverity::Fatal);
            };
            if !validate_skip_record(prev.as_ref(), &curr) {
                cntrl.ctx.error(
                    ErrSeverity::Fatal,
                    ErrType::Invalid,
                    if curr.end < curr.begin {
                        "_OWPReadStopSessions: Failed - Invalid skip record: end < begin"
                    } else {
                        "_OWPReadStopSessions: Failed - Invalid skip record: skips out of order"
                    },
                );
                return fail_control_session(cntrl, ErrSeverity::Fatal);
            }
            prev = Some(curr);
            skips.push(SkipRec {
                begin: curr.begin,
                end: curr.end,
            });
        }
        // Even num_skips ⇒ trailing 8 zero pad in last block (meta[8..16]).
        if num_skips % 2 == 0 && meta[8..16] != [0u8; 8] {
            cntrl.ctx.error(
                ErrSeverity::Fatal,
                ErrType::Invalid,
                "_OWPReadStopSessions: Failed - Invalid zero padding",
            );
            return fail_control_session(cntrl, ErrSeverity::Fatal);
        }

        let Some(tidx) = cntrl.tests.iter().position(|t| t.sid == sid_buf) else {
            cntrl.ctx.error(
                ErrSeverity::Fatal,
                ErrType::Invalid,
                "_OWPReadStopSessions: Failed - sid from StopSessions not valid.",
            );
            *acceptval = AcceptType::Failure;
            return fail_control_session(cntrl, ErrSeverity::Fatal);
        };
        cntrl.tests[tidx].next_seq = next_seqno;
        cntrl.tests[tidx].nskips = num_skips;

        // Update recv datafile when present (C locks → CleanDataRecs → skips → finished).
        let has_datafile = cntrl.tests[tidx]
            .endpoint
            .as_ref()
            .and_then(|e| e.datafile.as_ref())
            .is_some();
        if has_datafile {
            let ctx = cntrl.ctx.clone();
            let stop = *stoptime;
            let ok = {
                let t = &mut cntrl.tests[tidx];
                let mut fp = t.endpoint.as_mut().unwrap().datafile.take().unwrap();
                let result = if crate::endpoint::flock_write_lock(&fp).is_err() {
                    ctx.error(
                        ErrSeverity::Fatal,
                        ErrType::Unknown,
                        "_OWPReadStopSessions: Unable to lock file",
                    );
                    false
                } else if clean_data_recs(&ctx, t, &mut fp, next_seqno, &stop).is_none() {
                    ctx.error(
                        ErrSeverity::Fatal,
                        ErrType::Unknown,
                        "_OWPReadStopSessions: Unable to clean data",
                    );
                    let _ = crate::endpoint::flock_unlock(&fp);
                    false
                } else {
                    let wrote = write_stop_skips_and_finish(&mut fp, &ctx, &skips, next_seqno);
                    let _ = crate::endpoint::flock_unlock(&fp);
                    wrote
                };
                t.endpoint.as_mut().unwrap().datafile = Some(fp);
                result
            };
            if !ok {
                return fail_control_session(cntrl, ErrSeverity::Fatal);
            }
        }
    }

    let mut digest = [0u8; 16];
    if receive_blocks_intr(cntrl, &mut digest, 1) != 1 {
        return fail_control_session(cntrl, ErrSeverity::Fatal);
    }
    if !recv_hmac_check_clear(cntrl, &digest) {
        return fail_control_session(cntrl, ErrSeverity::Fatal);
    }
    after_read_stop_sessions(&mut cntrl.state);
    ErrSeverity::Ok
}

/// Append skip records + `num_skips` + finished after `CleanDataRecs` (`ReadStopSessions`).
fn write_stop_skips_and_finish(
    fp: &mut File,
    _ctx: &Context,
    skips: &[SkipRec],
    next_seqno: u32,
) -> bool {
    let Some(fhdr) = read_data_header_initial(fp) else {
        return false;
    };
    if !skips.is_empty() {
        let toff = fhdr.oset_datarecs + u64::from(fhdr.num_datarecs) * u64::from(fhdr.rec_size);
        if fp.seek(SeekFrom::Start(toff)).is_err() {
            return false;
        }
        for s in skips {
            let mut buf = [0u8; OWP_SKIPREC_SIZE];
            buf[0..4].copy_from_slice(&s.begin.to_be_bytes());
            buf[4..8].copy_from_slice(&s.end.to_be_bytes());
            if fp.write_all(&buf).is_err() {
                return false;
            }
        }
    }
    if !write_data_header_num_skip_recs(fp, skips.len() as u32) {
        return false;
    }
    write_data_header_finished(fp, SessionFinishedType::Normal, next_seqno)
}

/// `OWPStopSessions`
pub fn stop_sessions(
    cntrl: &mut Control,
    retn_on_intr: Option<&i32>,
    acceptval: &mut AcceptType,
) -> ErrSeverity {
    let mut err2 = ErrSeverity::Ok;
    let mut readstop = true;

    let (err, num_sessions) = stop_send_sessions(cntrl, acceptval);
    err2 = err2.min(err);
    let mut do_clean = (err2 as i32) >= (ErrSeverity::Warning as i32);
    if do_clean {
        let err = write_stop_sessions(cntrl, retn_on_intr, *acceptval, num_sessions);
        err2 = err2.min(err);
        if (err2 as i32) < (ErrSeverity::Warning as i32) || (cntrl.twoway && !cntrl.server) {
            readstop = false;
        } else {
            match read_request_type(cntrl, retn_on_intr) {
                RequestType::StopSessions => {},
                RequestType::SockClose | RequestType::SockIntr => {
                    readstop = false;
                },
                _ => {
                    cntrl.ctx.error(
                        ErrSeverity::Fatal,
                        ErrType::Invalid,
                        "OWPStopSessions: Invalid protocol message received.",
                    );
                    err2 = ErrSeverity::Fatal;
                    do_clean = false; // C: goto done — skip clean_sessions
                },
            }
        }
    } else {
        do_clean = false;
    }

    if do_clean {
        let stoptime = get_time_of_day(&cntrl.ctx).unwrap_or_default();
        let err = stop_recv_sessions(cntrl, &stoptime, !readstop, acceptval);
        err2 = err2.min(err);
        if (err2 as i32) >= (ErrSeverity::Warning as i32) {
            if readstop {
                let err = read_stop_sessions(cntrl, retn_on_intr, acceptval, &stoptime);
                err2 = err2.min(err);
            } else if !clean_up_sessions(cntrl, acceptval, &stoptime) {
                err2 = ErrSeverity::Fatal;
            }
        }
    }

    while let Some(t) = cntrl.tests.pop() {
        let e = test_session_free_unlinked(cntrl, Box::new(t), *acceptval);
        err2 = err2.min(e);
    }

    if (err2 as i32) < (ErrSeverity::Warning as i32) {
        if *acceptval == AcceptType::Accept {
            *acceptval = AcceptType::Failure;
        }
        return fail_control_session(cntrl, err2);
    } else if !readstop {
        return fail_control_session(cntrl, ErrSeverity::Fatal);
    }

    cntrl.state &= !STATE_TEST;
    err2
}

/// `OWPStopSessionsWait` — poll control fd / complete sessions.
///
/// Returns: `0` success/complete, `1` wake timeout, `2` interrupted, `-1` fatal.
#[allow(clippy::too_many_lines)] // C-parity body
pub fn stop_sessions_wait(
    cntrl: &mut Control,
    wake: Option<&OwampNum64>,
    retn_on_intr: Option<&i32>,
    acceptval: &mut AcceptType,
    err_ret: &mut ErrSeverity,
) -> i32 {
    *err_ret = ErrSeverity::Ok;
    *acceptval = AcceptType::Accept;
    let mut readstop = !cntrl.twoway || cntrl.server;
    let intr = retn_on_intr.copied().unwrap_or(0);

    if cntrl.sockfd < 0 {
        *err_ret = ErrSeverity::Fatal;
        return -1;
    }

    let (active, aval) = sessions_active(cntrl);
    *acceptval = aval;

    if cntrl.twoway && cntrl.server {
        if active == 0 && *acceptval != AcceptType::Accept {
            cntrl.state &= !STATE_TEST;
            return 0;
        }
    } else if active == 0 || *acceptval != AcceptType::Accept {
        *err_ret = stop_sessions(cntrl, retn_on_intr, acceptval);
        return 0;
    }

    if intr != 0 {
        return 2;
    }

    // C relies on SIGCHLD → EINTR to re-check sessions_active when a child
    // exits. Thread workers produce no SIGCHLD, so with wake=NULL we poll in
    // short slices and re-check local completion (stand-in for SIGCHLD).
    let child_poll_ms: i32 = 50;
    let mut wake_remaining_ms: Option<i32> = if let Some(wake_t) = wake {
        if let Some(curr) = get_time_of_day(&cntrl.ctx) {
            if curr.owptime.cmp_num(*wake_t) < 0 {
                let rel = num64_sub(*wake_t, curr.owptime);
                let ts = num64_to_timespec(rel);
                Some((ts.tv_sec * 1_000 + ts.tv_nsec / 1_000_000) as i32)
            } else {
                Some(0)
            }
        } else {
            *err_ret = ErrSeverity::Fatal;
            return -1;
        }
    } else {
        None
    };

    loop {
        let timeout_ms =
            wake_remaining_ms.map_or(child_poll_ms, |rem| rem.min(child_poll_ms).max(0));
        let mut pfd = libc::pollfd {
            fd: cntrl.sockfd,
            events: libc::POLLIN | libc::POLLERR | libc::POLLHUP,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                cntrl.ctx.error(
                    ErrSeverity::Fatal,
                    ErrType::Unknown,
                    &format!("poll(): {err}"),
                );
                *err_ret = ErrSeverity::Fatal;
                return -1;
            }
            if wake.is_some() || retn_on_intr.is_some_and(|v| *v != 0) {
                return 2;
            }
            let (active, aval) = sessions_active(cntrl);
            *acceptval = aval;
            if active != 0 && *acceptval == AcceptType::Accept {
                continue;
            }
            if cntrl.twoway && cntrl.server {
                if active == 0 && *acceptval != AcceptType::Accept {
                    cntrl.state &= !STATE_TEST;
                    return 0;
                }
                continue;
            }
            *err_ret = stop_sessions(cntrl, retn_on_intr, acceptval);
            return 0;
        }
        if rc == 0 {
            // Slice timeout: re-check worker completion (thread SIGCHLD stand-in).
            if let Some(ref mut rem) = wake_remaining_ms {
                *rem = (*rem - timeout_ms).max(0);
                if *rem == 0 {
                    return 1;
                }
            }
            let (active, aval) = sessions_active(cntrl);
            *acceptval = aval;
            if active != 0 && *acceptval == AcceptType::Accept {
                continue;
            }
            if cntrl.twoway && cntrl.server {
                if active == 0 && *acceptval != AcceptType::Accept {
                    cntrl.state &= !STATE_TEST;
                    return 0;
                }
                continue;
            }
            *err_ret = stop_sessions(cntrl, retn_on_intr, acceptval);
            return 0;
        }
        if pfd.revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) == 0 {
            *err_ret = fail_control_session(cntrl, ErrSeverity::Fatal);
            break;
        }

        match read_request_type(cntrl, retn_on_intr) {
            RequestType::StopSessions => {
                if cntrl.twoway && !cntrl.server {
                    cntrl.ctx.error(
                        ErrSeverity::Fatal,
                        ErrType::Invalid,
                        "OWPStopSessionsWait: StopSessions message should not be received by TWAMP client",
                    );
                    *err_ret = ErrSeverity::Fatal;
                    break;
                }
            },
            RequestType::SockClose | RequestType::SockIntr => {
                readstop = false;
            },
            _ => {
                cntrl.ctx.error(
                    ErrSeverity::Fatal,
                    ErrType::Invalid,
                    "OWPStopSessionsWait: Invalid protocol message received.",
                );
                *err_ret = ErrSeverity::Fatal;
                break;
            },
        }

        let stoptime = get_time_of_day(&cntrl.ctx).unwrap_or_default();
        let (err, num_sessions) = stop_send_sessions(cntrl, acceptval);
        *err_ret = (*err_ret).min(err);
        if (*err_ret as i32) < (ErrSeverity::Warning as i32) {
            break;
        }
        let err = stop_recv_sessions(cntrl, &stoptime, !readstop, acceptval);
        *err_ret = (*err_ret).min(err);
        if (*err_ret as i32) < (ErrSeverity::Warning as i32) {
            break;
        }
        if readstop {
            let err = read_stop_sessions(cntrl, retn_on_intr, acceptval, &stoptime);
            *err_ret = (*err_ret).min(err);
        } else if !clean_up_sessions(cntrl, acceptval, &stoptime) {
            *err_ret = ErrSeverity::Fatal;
        }

        if (*err_ret as i32) < (ErrSeverity::Warning as i32) {
            *acceptval = AcceptType::Failure;
        }
        if readstop
            && (*err_ret as i32) >= (ErrSeverity::Warning as i32)
            && !(cntrl.twoway && cntrl.server)
        {
            let err = write_stop_sessions(cntrl, retn_on_intr, *acceptval, num_sessions);
            *err_ret = (*err_ret).min(err);
        }

        while let Some(t) = cntrl.tests.pop() {
            let e = test_session_free_unlinked(cntrl, Box::new(t), *acceptval);
            *err_ret = (*err_ret).min(e);
        }

        if (*err_ret as i32) < (ErrSeverity::Warning as i32) {
            *acceptval = AcceptType::Failure;
            fail_control_session(cntrl, ErrSeverity::Fatal);
            return -1;
        } else if !readstop {
            fail_control_session(cntrl, ErrSeverity::Fatal);
            return -1;
        }
        cntrl.state &= !STATE_TEST;
        return 0;
    }

    // Error path: free remaining sessions.
    if (*err_ret as i32) < (ErrSeverity::Warning as i32) {
        *acceptval = AcceptType::Failure;
    }
    while let Some(t) = cntrl.tests.pop() {
        let e = test_session_free_unlinked(cntrl, Box::new(t), *acceptval);
        *err_ret = (*err_ret).min(e);
    }
    if (*err_ret as i32) < (ErrSeverity::Warning as i32) {
        *acceptval = AcceptType::Failure;
        fail_control_session(cntrl, ErrSeverity::Fatal);
        return -1;
    } else if !readstop {
        fail_control_session(cntrl, ErrSeverity::Fatal);
        return -1;
    }
    cntrl.state &= !STATE_TEST;
    0
}

// ---------------------------------------------------------------------------
// Session data-file header / records (api.c)
// ---------------------------------------------------------------------------

/// Portable session header used for `.owp` files (`OWPSessionHeaderRec`).
#[derive(Clone, Debug, Default)]
pub struct SessionHeader {
    pub header: bool,
    pub version: u32,
    pub rec_size: u32,
    pub twoway: bool,
    pub finished: SessionFinishedType,
    pub next_seqno: u32,
    pub num_skiprecs: u32,
    pub num_datarecs: u32,
    pub oset_skiprecs: u64,
    pub oset_datarecs: u64,
    pub conf_sender: bool,
    pub conf_receiver: bool,
    pub sid: Sid,
    pub sender: Option<SocketAddr>,
    pub receiver: Option<SocketAddr>,
    pub test_spec: TestSpec,
}

/// Internal `_OWPSessionHeaderInitialRec`.
#[derive(Clone, Debug, Default)]
struct SessionHeaderInitial {
    header: bool,
    version: u32,
    rec_size: u32,
    finished: SessionFinishedType,
    next_seqno: u32,
    num_skiprecs: u32,
    num_datarecs: u32,
    oset_skiprecs: u64,
    oset_datarecs: u64,
    hdr_len: u64,
    file_size: u64,
}

const fn datarec_size_for_version(version: u32) -> u32 {
    let tw = (version & OWP_VERSION_TWOWAY) != 0;
    let ver = version & !OWP_VERSION_TWOWAY;
    match (tw, ver) {
        (true, _) => OWP_DATAREC_TWV3_SIZE as u32,
        (false, 0 | 2) => OWP_DATARECV2_SIZE as u32,
        _ => OWP_DATARECV3_SIZE as u32,
    }
}

const fn session_finished_from_u32(val: u32) -> SessionFinishedType {
    match val {
        1 => SessionFinishedType::Normal,
        2 => SessionFinishedType::Incomplete,
        _ => SessionFinishedType::Error,
    }
}

/// `GetSessionFinishedType` — invalid `val` logs FATAL then returns Error (C).
#[must_use]
pub fn get_session_finished_type(ctx: &Context, val: u32) -> SessionFinishedType {
    match val {
        0 => SessionFinishedType::Error,
        1 => SessionFinishedType::Normal,
        2 => SessionFinishedType::Incomplete,
        _ => {
            ctx.error(
                ErrSeverity::Fatal,
                ErrType::Invalid,
                &format!("GetSessionFinishedType: Invalid val {val}"),
            );
            SessionFinishedType::Error
        },
    }
}

const fn session_finished_to_u32(f: SessionFinishedType) -> u32 {
    match f {
        SessionFinishedType::Error => 0,
        SessionFinishedType::Normal => 1,
        SessionFinishedType::Incomplete => 2,
    }
}

fn to_owamp_tspec(ts: &TestSpec) -> OwampTestSpec {
    OwampTestSpec {
        start_time: ts.start_time,
        loss_timeout: ts.loss_timeout,
        type_p: ts.type_p,
        packet_size_padding: ts.packet_size_padding,
        npackets: ts.npackets,
        slots: ts
            .slots
            .iter()
            .map(|s| match s.slot_type {
                SlotType::RandExp => OwampSlot::RandExp(OwampSlotRandExp { mean: s.time }),
                _ => OwampSlot::Literal(OwampSlotLiteral { offset: s.time }),
            })
            .collect(),
    }
}

fn decode_data_rec_from_buf(version: u32, buf: &[u8]) -> Option<DataRec> {
    let decoded = crate::endpoint::decode_data_record(version & !OWP_VERSION_TWOWAY, buf).ok()?;
    Some(DataRec {
        seq_no: decoded.seq_no,
        send: decoded.send,
        recv: decoded.recv,
        ttl: decoded.ttl,
    })
}

/// `_OWPReadDataHeaderInitial`
fn read_data_header_initial(fp: &mut (impl Read + Seek)) -> Option<SessionHeaderInitial> {
    let file_size = fp.seek(SeekFrom::End(0)).ok()?;
    if file_size < 16 {
        return None;
    }
    fp.seek(SeekFrom::Start(0)).ok()?;

    let mut magic = [0u8; 4];
    fp.read_exact(&mut magic).ok()?;
    if magic != OWP_MAGIC_BYTES {
        return None;
    }

    let mut u32b = [0u8; 4];
    fp.read_exact(&mut u32b).ok()?;
    let version = u32::from_be_bytes(u32b);

    let mut phdr = SessionHeaderInitial {
        version,
        header: true,
        file_size,
        ..Default::default()
    };

    match version {
        0 => {
            phdr.header = false;
            let mut osetb = [0u8; 8];
            fp.read_exact(&mut osetb).ok()?;
            phdr.hdr_len = u64::from_be_bytes(osetb);
            phdr.rec_size = OWP_DATARECV2_SIZE as u32;
            phdr.oset_datarecs = phdr.hdr_len;
            if phdr.hdr_len <= file_size {
                phdr.num_datarecs = ((file_size - phdr.hdr_len) / u64::from(phdr.rec_size)) as u32;
            }
            return Some(phdr);
        },
        2 => {
            let mut osetb = [0u8; 8];
            fp.read_exact(&mut osetb).ok()?;
            phdr.hdr_len = u64::from_be_bytes(osetb);
            phdr.rec_size = OWP_DATARECV2_SIZE as u32;
        },
        3 => {
            phdr.rec_size = OWP_DATARECV3_SIZE as u32;
        },
        v if v == (OWP_VERSION_TWOWAY | 3) => {
            phdr.rec_size = OWP_DATAREC_TWV3_SIZE as u32;
        },
        _ => return None,
    }

    fp.read_exact(&mut u32b).ok()?;
    phdr.finished = session_finished_from_u32(u32::from_be_bytes(u32b));

    if version < 3 {
        phdr.oset_skiprecs = 0;
        phdr.num_skiprecs = 0;
        phdr.oset_datarecs = phdr.hdr_len;
        if phdr.hdr_len <= file_size {
            phdr.num_datarecs = ((file_size - phdr.hdr_len) / u64::from(phdr.rec_size)) as u32;
        }
        phdr.next_seqno = 0;
        return Some(phdr);
    }

    fp.read_exact(&mut u32b).ok()?;
    phdr.next_seqno = u32::from_be_bytes(u32b);
    fp.read_exact(&mut u32b).ok()?;
    phdr.num_skiprecs = u32::from_be_bytes(u32b);
    fp.read_exact(&mut u32b).ok()?;
    phdr.num_datarecs = u32::from_be_bytes(u32b);
    let mut osetb = [0u8; 8];
    fp.read_exact(&mut osetb).ok()?;
    phdr.oset_skiprecs = u64::from_be_bytes(osetb);
    fp.read_exact(&mut osetb).ok()?;
    phdr.oset_datarecs = u64::from_be_bytes(osetb);
    phdr.hdr_len = phdr.oset_datarecs;
    Some(phdr)
}

/// `_OWPWriteDataHeaderFinished`
pub fn write_data_header_finished(
    fp: &mut (impl Write + Seek),
    finished: SessionFinishedType,
    next_seqno: u32,
) -> bool {
    let fin = session_finished_to_u32(finished);
    if fin > 2 {
        return false;
    }
    if fp.seek(SeekFrom::Start(8)).is_err() {
        return false;
    }
    if fp.write_all(&fin.to_be_bytes()).is_err() {
        return false;
    }
    if fp.write_all(&next_seqno.to_be_bytes()).is_err() {
        return false;
    }
    let _ = fp.flush();
    true
}

/// `OWPWriteDataHeaderNumSkipRecs`
pub fn write_data_header_num_skip_recs(
    fp: &mut (impl Read + Write + Seek),
    num_skiprecs: u32,
) -> bool {
    let Some(phrec) = read_data_header_initial(fp) else {
        return false;
    };
    if phrec.version < 3 {
        return false;
    }
    if phrec.num_skiprecs != 0 || phrec.oset_skiprecs != 0 {
        return false;
    }
    // num_skiprecs at offset 16
    if fp.seek(SeekFrom::Start(16)).is_err() {
        return false;
    }
    if fp.write_all(&num_skiprecs.to_be_bytes()).is_err() {
        return false;
    }
    // oset_skiprecs at offset 24
    let oset_skip = phrec.oset_datarecs + u64::from(phrec.rec_size) * u64::from(phrec.num_datarecs);
    if fp.seek(SeekFrom::Start(24)).is_err() {
        return false;
    }
    fp.write_all(&oset_skip.to_be_bytes()).is_ok()
}

/// `OWPWriteDataHeaderNumDataRecs`
pub fn write_data_header_num_data_recs(
    fp: &mut (impl Read + Write + Seek),
    num_datarecs: u32,
) -> bool {
    let Some(phrec) = read_data_header_initial(fp) else {
        return false;
    };
    if phrec.version < 3 {
        return false;
    }
    if phrec.oset_datarecs < phrec.oset_skiprecs {
        return false;
    }
    // num_datarecs at offset 20
    if fp.seek(SeekFrom::Start(20)).is_err() {
        return false;
    }
    fp.write_all(&num_datarecs.to_be_bytes()).is_ok()
}

/// `OWPWriteDataHeader` — write magic/version/meta + `TestRequest` preamble + slots.
pub fn write_data_header(fp: &mut dyn Write, hdr: &SessionHeader) -> bool {
    let (Some(sender), Some(receiver)) = (hdr.sender, hdr.receiver) else {
        return false;
    };
    let proto_tspec = context_tspec_to_proto(&hdr.test_spec);
    let Ok(preamble) = TestRequestPreamble::from_test_spec(
        false, // always encode as one-way so nslots/npackets are present
        if hdr.twoway { true } else { hdr.conf_sender },
        hdr.conf_receiver,
        false,
        Some(&hdr.sid),
        sender,
        receiver,
        &proto_tspec,
    ) else {
        return false;
    };
    let mut pre_buf = [0u8; OWP_TEST_REQUEST_PREAMBLE_SIZE];
    if preamble.encode(&mut pre_buf).is_err() {
        return false;
    }

    let rec_size = if hdr.rec_size == 0 {
        OWP_DATAREC_SIZE as u32
    } else {
        hdr.rec_size
    };

    let slots_bytes = 16u64 * (u64::from(hdr.test_spec.nslots) + 1);
    let oset = 4u64 // magic incl. NUL
        + 4 // version
        + 4 // finished
        + 4 // next_seqno
        + 4 // num_skiprecs
        + 4 // num_datarecs
        + 8 // oset_skip
        + 8 // oset_data
        + OWP_TEST_REQUEST_PREAMBLE_SIZE as u64
        + slots_bytes;

    let (skip_oset, data_oset) = if hdr.num_skiprecs > 0 {
        (
            oset,
            oset + u64::from(hdr.num_skiprecs) * OWP_SKIPREC_SIZE as u64,
        )
    } else {
        let data = oset;
        let skip = if hdr.num_datarecs > 0 {
            oset + u64::from(hdr.num_datarecs) * u64::from(rec_size)
        } else {
            0
        };
        (skip, data)
    };

    let ver = (if hdr.twoway { OWP_VERSION_TWOWAY } else { 0 }) | 3;
    // C defaults to INCOMPLETE; only 0/1 override.
    let finished = match hdr.finished {
        SessionFinishedType::Error => 0u32,
        SessionFinishedType::Normal => 1,
        SessionFinishedType::Incomplete => 2,
    };

    let write_u32 = |fp: &mut dyn Write, v: u32| fp.write_all(&v.to_be_bytes());
    let write_u64 = |fp: &mut dyn Write, v: u64| fp.write_all(&v.to_be_bytes());

    if fp.write_all(&OWP_MAGIC_BYTES).is_err() {
        return false;
    }
    if write_u32(fp, ver).is_err()
        || write_u32(fp, finished).is_err()
        || write_u32(fp, hdr.next_seqno).is_err()
        || write_u32(fp, hdr.num_skiprecs).is_err()
        || write_u32(fp, hdr.num_datarecs).is_err()
        || write_u64(fp, skip_oset).is_err()
        || write_u64(fp, data_oset).is_err()
    {
        return false;
    }
    if fp.write_all(&pre_buf).is_err() {
        return false;
    }
    for slot in &hdr.test_spec.slots {
        let mut sbuf = [0u8; SLOT_SIZE];
        if encode_slot(&mut sbuf, &slot_to_proto(slot)).is_err() || fp.write_all(&sbuf).is_err() {
            return false;
        }
    }
    let zero = [0u8; 16];
    fp.write_all(&zero).is_ok()
}

/// `OWPWriteDataRecord`
pub fn write_data_record(fp: &mut dyn Write, rec: &DataRec) -> bool {
    let mut buf = [0u8; OWP_DATAREC_SIZE];
    let erec = crate::owamp::OwampDataRec {
        seq_no: rec.seq_no,
        send: rec.send,
        recv: rec.recv,
        ttl: rec.ttl,
    };
    if crate::endpoint::encode_data_record(&mut buf, &erec).is_err() {
        return false;
    }
    fp.write_all(&buf).is_ok()
}

/// `OWPWriteTWDataRecord`
pub fn write_tw_data_record(fp: &mut dyn Write, rec: &TwDataRec) -> bool {
    let mut buf = [0u8; OWP_DATAREC_TWV3_SIZE];
    let erec = crate::owamp::OwampTwDataRec {
        sent: crate::owamp::OwampDataRec {
            seq_no: rec.sent.seq_no,
            send: rec.sent.send,
            recv: rec.sent.recv,
            ttl: rec.sent.ttl,
        },
        reflected: crate::owamp::OwampDataRec {
            seq_no: rec.reflected.seq_no,
            send: rec.reflected.send,
            recv: rec.reflected.recv,
            ttl: rec.reflected.ttl,
        },
    };
    if crate::endpoint::encode_tw_data_record(&mut buf, &erec).is_err() {
        return false;
    }
    fp.write_all(&buf).is_ok()
}

/// `OWPReadDataHeader` — returns number of data records (0 on failure).
///
/// Does **not** load slots (see [`read_data_header_slots`]), matching `api.c`.
pub fn read_data_header(fp: &mut (impl Read + Seek), hdr: &mut SessionHeader) -> u32 {
    hdr.header = false;
    let Some(phrec) = read_data_header_initial(fp) else {
        return 0;
    };

    hdr.version = phrec.version;
    hdr.twoway = (phrec.version & OWP_VERSION_TWOWAY) != 0;
    hdr.rec_size = phrec.rec_size;
    hdr.finished = phrec.finished;

    let ver_plain = phrec.version & !OWP_VERSION_TWOWAY;
    if ver_plain >= 2 || phrec.version >= 2 {
        let mut pre = [0u8; OWP_TEST_REQUEST_PREAMBLE_SIZE];
        if fp.read_exact(&mut pre).is_err() {
            return 0;
        }
        let Ok(preamble) = TestRequestPreamble::decode(&pre, false, false) else {
            return 0;
        };
        hdr.conf_sender = preamble.conf_sender;
        hdr.conf_receiver = preamble.conf_receiver;
        hdr.sid = preamble.sid;
        hdr.sender = Some(preamble.sender);
        hdr.receiver = Some(preamble.receiver);
        hdr.test_spec = TestSpec {
            start_time: preamble.start_time,
            loss_timeout: preamble.loss_timeout,
            type_p: preamble.type_p,
            packet_size_padding: preamble.packet_size_padding,
            npackets: preamble.npackets,
            nslots: preamble.nslots,
            slots: Vec::new(),
        };
        hdr.header = true;
    }

    if fp.seek(SeekFrom::Start(phrec.hdr_len)).is_err() {
        return 0;
    }

    if phrec.hdr_len > phrec.file_size {
        return 0;
    }
    let max_by_size = ((phrec.file_size - phrec.hdr_len) / u64::from(hdr.rec_size.max(1))) as u32;
    hdr.next_seqno = phrec.next_seqno;
    hdr.num_skiprecs = phrec.num_skiprecs;
    hdr.oset_skiprecs = phrec.oset_skiprecs;
    hdr.oset_datarecs = phrec.oset_datarecs;
    if phrec.num_datarecs > max_by_size {
        return 0;
    }
    if phrec.finished != SessionFinishedType::Normal || hdr.twoway {
        hdr.num_datarecs = max_by_size;
    } else {
        hdr.num_datarecs = phrec.num_datarecs;
    }
    hdr.num_datarecs
}

/// `OWPReadDataHeaderSlots`
pub fn read_data_header_slots(
    fp: &mut (impl Read + Seek),
    nslots: u32,
    slots: &mut Vec<crate::context::Slot>,
) -> bool {
    let Some(phrec) = read_data_header_initial(fp) else {
        return false;
    };
    if phrec.version < 2 {
        return false;
    }

    let (slot_off, hdr_off) = if phrec.version == 2 {
        (132u64, phrec.hdr_len)
    } else {
        let mut hdr_off = phrec.oset_skiprecs.min(phrec.oset_datarecs);
        if hdr_off == 0 {
            hdr_off = phrec.oset_skiprecs.max(phrec.oset_datarecs);
        }
        (152u64, hdr_off)
    };

    if hdr_off < slot_off {
        return false;
    }
    let mut fileslots = hdr_off - slot_off;
    if fileslots % 16 != 0 {
        return false;
    }
    fileslots /= 16;
    if fileslots == 0 {
        return false;
    }
    fileslots -= 1; // integrity zero block
    if fileslots as u32 != nslots {
        return false;
    }

    if fp.seek(SeekFrom::Start(slot_off)).is_err() {
        return false;
    }
    slots.clear();
    slots.reserve(nslots as usize);
    for _ in 0..nslots {
        let mut sbuf = [0u8; SLOT_SIZE];
        if fp.read_exact(&mut sbuf).is_err() {
            return false;
        }
        match decode_slot(&sbuf) {
            Ok(ps) => slots.push(slot_from_proto(ps)),
            Err(_) => return false,
        }
    }
    let mut zero = [0u8; 16];
    if fp.read_exact(&mut zero).is_err() || zero != [0u8; 16] {
        return false;
    }
    true
}

/// `OWPParseRecords` — iterate decoded one-way records.
pub fn parse_records(
    fp: &mut dyn Read,
    nrecs: u32,
    version: u32,
    mut each: impl FnMut(&DataRec) -> bool,
) -> ErrSeverity {
    let size = datarec_size_for_version(version) as usize;
    let mut buf = vec![0u8; size.max(OWP_MAXDATAREC_SIZE)];
    for _ in 0..nrecs {
        if fp.read_exact(&mut buf[..size]).is_err() {
            return ErrSeverity::Fatal;
        }
        let Some(rec) = decode_data_rec_from_buf(version, &buf[..size]) else {
            return ErrSeverity::Fatal;
        };
        if !each(&rec) {
            break;
        }
    }
    ErrSeverity::Ok
}

/// `OWPParseTWRecords`
pub fn parse_tw_records(
    fp: &mut dyn Read,
    nrecs: u32,
    version: u32,
    mut each: impl FnMut(&TwDataRec) -> bool,
) -> ErrSeverity {
    let size = OWP_DATAREC_TWV3_SIZE;
    let mut buf = vec![0u8; size];
    for _ in 0..nrecs {
        if fp.read_exact(&mut buf).is_err() {
            return ErrSeverity::Fatal;
        }
        let Ok(decoded) = crate::endpoint::decode_tw_data_record(version, &buf) else {
            return ErrSeverity::Fatal;
        };
        let rec = TwDataRec {
            sent: DataRec {
                seq_no: decoded.sent.seq_no,
                send: decoded.sent.send,
                recv: decoded.sent.recv,
                ttl: decoded.sent.ttl,
            },
            reflected: DataRec {
                seq_no: decoded.reflected.seq_no,
                send: decoded.reflected.send,
                recv: decoded.reflected.recv,
                ttl: decoded.reflected.ttl,
            },
        };
        if !each(&rec) {
            break;
        }
    }
    ErrSeverity::Ok
}

/// `OWPReadDataSkips`
pub fn read_data_skips(fp: &mut dyn Read, nskips: u32, skips: &mut Vec<SkipRec>) -> ErrSeverity {
    skips.clear();
    let mut buf = [0u8; OWP_SKIPREC_SIZE];
    for _ in 0..nskips {
        if fp.read_exact(&mut buf).is_err() {
            return ErrSeverity::Fatal;
        }
        skips.push(SkipRec {
            begin: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            end: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        });
    }
    ErrSeverity::Ok
}

// ---------------------------------------------------------------------------
// CleanDataRecs / GetMaxRecv / CleanUpSessions
// ---------------------------------------------------------------------------

/// State for [`get_max_recv`] (`_maxrecv_rec`).
#[derive(Clone, Debug, Default)]
pub struct MaxRecvRec {
    pub found: bool,
    pub index: u32,
    pub maxrecv: u32,
    pub badlost: u32,
    pub index_badlost: u32,
}

/// `GetMaxRecv` — `parse_records` callback used by `CleanUpSessions`.
#[allow(clippy::suspicious_operation_groupings)] // both compares use `mrec.maxrecv`, not `rec`
pub fn get_max_recv(rec: &DataRec, mrec: &mut MaxRecvRec) -> bool {
    if !is_lost_record(rec) {
        mrec.found = true;
        mrec.maxrecv = mrec.maxrecv.max(rec.seq_no);
    } else if rec.seq_no > mrec.maxrecv && mrec.badlost < mrec.maxrecv {
        mrec.badlost = rec.seq_no;
        mrec.index_badlost = mrec.index;
    }
    mrec.index = mrec.index.wrapping_add(1);
    true // continue
}

/// Directory used for `CleanDataRecs` mkstemp (same dir as `fname`, else TMPDIR/`/tmp`).
fn clean_temp_dir(fname: &Path) -> PathBuf {
    if let Some(parent) = fname.parent() {
        if !parent.as_os_str().is_empty() {
            return parent.to_path_buf();
        }
    }
    std::env::var_os("TMPDIR").map_or_else(
        || PathBuf::from(crate::owampP::OWP_DEFAULT_TMPDIR),
        PathBuf::from,
    )
}

/// Advance schedule to `next_seqno` send-time; prefer `tsession.sctx` when present.
fn schedule_thresh_time(
    ctx: &Context,
    tsession: &mut TestSession,
    next_seqno: u32,
) -> Option<OwampNum64> {
    let mut thresh_r = tsession.test_spec.start_time;
    if let Some(ref mut sctx) = tsession.sctx {
        if !sctx.reset() {
            ctx.error(
                ErrSeverity::Fatal,
                ErrType::Unknown,
                "_OWPCleanDataRecs: SchedulecontextReset(): FAILED",
            );
            return None;
        }
        for _ in 0..next_seqno {
            thresh_r = OwampNum64(thresh_r.0.wrapping_add(sctx.generate_next_delta()?.0));
        }
        return Some(thresh_r);
    }
    let ow_tspec = to_owamp_tspec(&tsession.test_spec);
    let Ok(mut sctx) = crate::schedule::ScheduleContext::create(&tsession.sid, &ow_tspec) else {
        ctx.error(
            ErrSeverity::Fatal,
            ErrType::Unknown,
            "_OWPCleanDataRecs: SchedulecontextReset(): FAILED",
        );
        return None;
    };
    let _ = sctx.reset(None, None);
    for _ in 0..next_seqno {
        match sctx.generate_next_delta() {
            Ok(d) => thresh_r = OwampNum64(thresh_r.0.wrapping_add(d.0)),
            Err(_) => return None,
        }
    }
    Some(thresh_r)
}

/// `_OWPCleanDataRecs` on an explicit `File` (mkstemp / copy / ftruncate).
///
/// Returns `(max_recv, off_start)` on success.
pub fn clean_data_recs(
    ctx: &Context,
    tsession: &mut TestSession,
    fp: &mut File,
    next_seqno: u32,
    stoptime: &OwampTimeStamp,
) -> Option<(u32, u64)> {
    let fname = tsession
        .endpoint
        .as_ref()
        .map(|e| e.fname.clone())
        .unwrap_or_default();
    clean_data_recs_on(ctx, tsession, fp, &fname, next_seqno, stoptime)
}

/// Clean using `Endpoint.datafile` when present (takes/restores the file).
pub fn clean_data_recs_file(
    ctx: &Context,
    tsession: &mut TestSession,
    next_seqno: u32,
    stoptime: &OwampTimeStamp,
) -> Option<(u32, u64)> {
    let mut fp = tsession.endpoint.as_mut()?.datafile.take()?;
    let fname = tsession
        .endpoint
        .as_ref()
        .map(|e| e.fname.clone())
        .unwrap_or_default();
    let result = clean_data_recs_on(ctx, tsession, &mut fp, &fname, next_seqno, stoptime);
    if let Some(ep) = tsession.endpoint.as_mut() {
        ep.datafile = Some(fp);
    }
    result
}

#[allow(clippy::too_many_lines)] // C-parity body
fn clean_data_recs_on(
    ctx: &Context,
    tsession: &mut TestSession,
    fp: &mut File,
    fname: &Path,
    mut next_seqno: u32,
    stoptime: &OwampTimeStamp,
) -> Option<(u32, u64)> {
    let mut max_recv = 0u32;

    let Some(mut fhdr) = read_data_header_initial(fp) else {
        ctx.error(
            ErrSeverity::Fatal,
            ErrType::Unknown,
            "_OWPCleanDataRecs: Failed",
        );
        return None;
    };

    if fhdr.oset_datarecs > fhdr.file_size {
        return None;
    }
    let toff = fhdr.file_size - fhdr.oset_datarecs;
    if toff % u64::from(fhdr.rec_size) != 0 {
        ctx.error(
            ErrSeverity::Fatal,
            ErrType::Invalid,
            "_OWPCleanDataRecs: Invalid records",
        );
        return None;
    }
    fhdr.num_datarecs = (toff / u64::from(fhdr.rec_size)) as u32;
    let mut num_recs = fhdr.num_datarecs;

    if num_recs == 0 {
        if !write_data_header_num_data_recs(fp, 0) {
            return None;
        }
        return Some((0, 0));
    }

    if next_seqno == 0xffff_ffff {
        next_seqno = tsession.test_spec.npackets;
    }
    if next_seqno > tsession.test_spec.npackets {
        ctx.error(
            ErrSeverity::Fatal,
            ErrType::Unknown,
            &format!("_OWPCleanDataRecs: Invalid 'next_seqno': {next_seqno}"),
        );
        return None;
    }

    let mut thresh_r = schedule_thresh_time(ctx, tsession, next_seqno)?;
    if thresh_r.cmp_num(stoptime.owptime) > 0 {
        thresh_r = stoptime.owptime;
    }
    thresh_r = num64_sub(
        thresh_r,
        num64_mult(tsession.test_spec.loss_timeout, ulong_to_num64(2)),
    );

    let mut high_i = fhdr.num_datarecs;
    let mut high_r = stoptime.owptime;
    let mut low_i = 0u32;

    if fp.seek(SeekFrom::Start(fhdr.oset_datarecs)).is_err() {
        return None;
    }
    let mut rbuf = vec![0u8; fhdr.rec_size as usize];
    if fp.read_exact(&mut rbuf).is_err() {
        return None;
    }
    let rec0 = decode_data_rec_from_buf(fhdr.version, &rbuf)?;
    let mut low_r = if is_lost_record(&rec0) {
        OwampNum64(
            rec0.send
                .owptime
                .0
                .wrapping_add(tsession.test_spec.loss_timeout.0),
        )
    } else {
        rec0.recv.owptime
    };

    if low_r.cmp_num(thresh_r) < 0 {
        while high_i - low_i > 1 {
            let range = num64_sub(high_r, low_r);
            let mid_i = if range.0 == 0 {
                low_i + (high_i - low_i) / 2
            } else {
                let portion = num64_sub(thresh_r, low_r);
                let mut mid = low_i
                    + ((num64_to_double(portion) * f64::from(high_i - low_i))
                        / num64_to_double(range)) as u32;
                if mid == low_i {
                    mid += 1;
                }
                mid
            };
            let mid_off = fhdr.oset_datarecs + u64::from(mid_i) * u64::from(fhdr.rec_size);
            if fp.seek(SeekFrom::Start(mid_off)).is_err() {
                return None;
            }
            if fp.read_exact(&mut rbuf).is_err() {
                return None;
            }
            let rec = decode_data_rec_from_buf(fhdr.version, &rbuf)?;
            let mid_r = if is_lost_record(&rec) {
                OwampNum64(
                    rec.send
                        .owptime
                        .0
                        .wrapping_add(tsession.test_spec.loss_timeout.0),
                )
            } else {
                rec.recv.owptime
            };
            if mid_r.cmp_num(thresh_r) < 0 {
                low_i = mid_i;
                low_r = mid_r;
            } else {
                high_i = mid_i;
                high_r = mid_r;
            }
        }
    }

    let off_start = fhdr.oset_datarecs + u64::from(low_i) * u64::from(fhdr.rec_size);
    let keep_thresh = num64_sub(stoptime.owptime, tsession.test_spec.loss_timeout);

    // C path: write kept records; on first deletion open mkstemp and copy prefix.
    if fp.seek(SeekFrom::Start(off_start)).is_err() {
        return None;
    }
    let mut wfp: Option<File> = None;
    for j in low_i..fhdr.num_datarecs {
        if fp.read_exact(&mut rbuf).is_err() {
            return None;
        }
        let rec = decode_data_rec_from_buf(fhdr.version, &rbuf)?;
        if rec.seq_no >= next_seqno && !is_lost_record(&rec) {
            ctx.error(
                ErrSeverity::Fatal,
                ErrType::Invalid,
                "_OWPCleanDataRecs: Invalid data record (seq_no too large)",
            );
            return None;
        }
        // C keeps when seq < next_seqno AND send <= (stop - loss_timeout).
        // Successfully received records are always kept: encrypted/debug send
        // stamps can land slightly after schedule, and a large loss_timeout
        // then falsely prunes real hits via keep_thresh.
        let keep = rec.seq_no < next_seqno
            && (!is_lost_record(&rec) || rec.send.owptime.cmp_num(keep_thresh) <= 0);
        if keep {
            max_recv = max_recv.max(rec.seq_no);
            if let Some(ref mut w) = wfp {
                if w.write_all(&rbuf).is_err() {
                    return None;
                }
            }
            // else: still in-place on original (C: wfp==rfp keep is a no-op)
        } else {
            num_recs -= 1;
            if wfp.is_none() {
                let dir = clean_temp_dir(fname);
                let Ok(mut tmp) = crate::endpoint::mkstemp_unlinked(&dir) else {
                    ctx.error(
                        ErrSeverity::Fatal,
                        ErrType::Unknown,
                        "_OWPCleanDataRecs: mkstemp failed",
                    );
                    return None;
                };
                let prefix = fhdr.oset_datarecs + u64::from(j) * u64::from(fhdr.rec_size);
                if crate::endpoint::copy_file_bytes(&tmp, fp, prefix).is_err() {
                    ctx.error(
                        ErrSeverity::Fatal,
                        ErrType::Unknown,
                        "_OWPCleanDataRecs: Unable to copy session data",
                    );
                    return None;
                }
                if tmp.seek(SeekFrom::End(0)).is_err() {
                    return None;
                }
                wfp = Some(tmp);
            }
        }
    }

    if let Some(ref mut w) = wfp {
        if crate::endpoint::copy_file_overwrite(fp, w).is_err() {
            ctx.error(
                ErrSeverity::Fatal,
                ErrType::Unknown,
                "_OWPCleanDataRecs: Unable to copy session data back",
            );
            return None;
        }
    }

    if !write_data_header_num_data_recs(fp, num_recs) {
        return None;
    }
    Some((max_recv, off_start))
}

/// `_OWPCleanUpSessions` — incomplete-control-connection cleanup.
///
/// # Panics
///
/// Panics if an internal invariant from the C port is violated.
pub fn clean_up_sessions(
    cntrl: &mut Control,
    acceptval: &mut AcceptType,
    stoptime: &OwampTimeStamp,
) -> bool {
    *acceptval = AcceptType::Accept;
    // C: TWAMP server/client short-circuit (no one-way recv file cleanup).
    if cntrl.twoway {
        return true;
    }

    let n = cntrl.tests.len();
    for i in 0..n {
        let Some(ep) = cntrl.tests[i].endpoint.as_ref() else {
            cntrl.ctx.error(
                ErrSeverity::Fatal,
                ErrType::Invalid,
                "_OWPCleanUpSessions: no endpoint state!",
            );
            *acceptval = AcceptType::Failure;
            return false;
        };
        if ep.send {
            continue;
        }
        let has_df = cntrl.tests[i]
            .endpoint
            .as_ref()
            .and_then(|e| e.datafile.as_ref())
            .is_some();
        if !has_df {
            continue;
        }

        let ctx = cntrl.ctx.clone();
        let stop = *stoptime;
        let ok = {
            let t = &mut cntrl.tests[i];
            let mut fp = t.endpoint.as_mut().unwrap().datafile.take().unwrap();
            let locked = crate::endpoint::flock_write_lock(&fp).is_ok();
            let cleaned = if locked {
                clean_data_recs(&ctx, t, &mut fp, 0xffff_ffff, &stop)
            } else {
                None
            };
            let result = match cleaned {
                None => {
                    if locked {
                        let _ = crate::endpoint::flock_unlock(&fp);
                    }
                    false
                },
                Some((max_recv, off_start)) => {
                    // After CleanDataRecs, strip trailing "bad lost" like C GetMaxRecv path.
                    let mut ok = true;
                    if let Some(fhdr) = read_data_header_initial(&mut fp) {
                        if fhdr.num_datarecs > 0 {
                            let mut mrec = MaxRecvRec::default();
                            if fp.seek(SeekFrom::Start(fhdr.oset_datarecs)).is_ok() {
                                let _ = parse_records(
                                    &mut fp,
                                    fhdr.num_datarecs,
                                    fhdr.version,
                                    |rec| get_max_recv(rec, &mut mrec),
                                );
                            }
                            if !mrec.found {
                                let _ = fp.set_len(fhdr.oset_datarecs);
                                ok = write_data_header_num_data_recs(&mut fp, 0);
                            } else if mrec.badlost > mrec.maxrecv {
                                // Truncate after last good / before first bad-lost beyond max.
                                let keep = mrec.index_badlost;
                                let new_len =
                                    fhdr.oset_datarecs + u64::from(keep) * u64::from(fhdr.rec_size);
                                ok = fp.set_len(new_len).is_ok()
                                    && write_data_header_num_data_recs(&mut fp, keep);
                            }
                        }
                        if ok {
                            ok = write_data_header_finished(
                                &mut fp,
                                SessionFinishedType::Incomplete,
                                max_recv.saturating_add(1),
                            );
                        }
                    } else {
                        ok = false;
                    }
                    let _ = off_start;
                    let _ = crate::endpoint::flock_unlock(&fp);
                    ok
                },
            };
            t.endpoint.as_mut().unwrap().datafile = Some(fp);
            result
        };
        if !ok {
            cntrl.ctx.error(
                ErrSeverity::Fatal,
                ErrType::Unknown,
                "_OWPCleanUpSessions: Failed",
            );
            *acceptval = AcceptType::Failure;
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// EffectiveCapability — no-op when libcap is unavailable (matches C `#ifndef HAVE_LIBCAP`)
// ---------------------------------------------------------------------------

/// Without libcap, C simply omits capability toggles around `SO_BINDTODEVICE`.
/// Returning `true` keeps callers unblocked; no warning spam.
const fn set_effective_capability(_ctx: &Context, _capability_name: &str, _set: bool) -> bool {
    true
}

/// `OWPAddEffectiveCapability` — no-op without libcap.
#[must_use]
pub const fn add_effective_capability(ctx: &Context, capability_name: &str) -> bool {
    set_effective_capability(ctx, capability_name, true)
}

/// `OWPRemoveEffectiveCapability` — no-op without libcap.
#[must_use]
pub const fn remove_effective_capability(ctx: &Context, capability_name: &str) -> bool {
    set_effective_capability(ctx, capability_name, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithm64::ulong_to_num64;
    use crate::context::Slot;
    use std::io::Cursor;

    #[test]
    fn get_session_finished_type_matches_c() {
        let ctx = Context::create().unwrap();
        assert_eq!(
            get_session_finished_type(&ctx, 0),
            SessionFinishedType::Error
        );
        assert_eq!(
            get_session_finished_type(&ctx, 1),
            SessionFinishedType::Normal
        );
        assert_eq!(
            get_session_finished_type(&ctx, 2),
            SessionFinishedType::Incomplete
        );
        assert_eq!(
            get_session_finished_type(&ctx, 99),
            SessionFinishedType::Error
        );
    }

    #[test]
    fn payload_sizes() {
        assert_eq!(test_payload_size(OWP_MODE_OPEN, 0), 14);
        assert_eq!(test_payload_size(OWP_MODE_ENCRYPTED, 10), 58);
        assert_eq!(test_tw_payload_size(OWP_MODE_OPEN, 0), 41);
    }

    #[test]
    fn port_range() {
        let mut pr = crate::context::PortRange::default();
        assert!(parse_port_range("5000-5010", &mut pr));
        assert_eq!(pr.low, 5_000);
        assert_eq!(pr.high, 5_010);
    }

    #[test]
    fn accept_session_wire_layout() {
        let msg = ProtoAcceptSession {
            accept: crate::protocol::AcceptType::Accept,
            port: 5_001,
            sid: [0xab; 16],
            hmac: [0; 16],
        };
        let mut buf = [0u8; ACCEPT_SESSION_SIZE];
        msg.encode(&mut buf).unwrap();
        assert_eq!(buf[0], 0);
        assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 5_001);
        assert_eq!(&buf[4..20], &[0xab; 16]);
    }

    #[test]
    fn data_header_roundtrip_minimal() {
        let hdr = SessionHeader {
            header: true,
            version: 3,
            rec_size: OWP_DATAREC_SIZE as u32,
            twoway: false,
            finished: SessionFinishedType::Normal,
            next_seqno: 2,
            num_skiprecs: 0,
            num_datarecs: 0, // no body yet — matches endpoint-receiver init
            oset_skiprecs: 0,
            oset_datarecs: 0,
            conf_sender: false,
            conf_receiver: true,
            sid: [7u8; 16],
            sender: Some("127.0.0.1:9000".parse().unwrap()),
            receiver: Some("127.0.0.1:0".parse().unwrap()),
            test_spec: TestSpec {
                start_time: ulong_to_num64(1),
                loss_timeout: ulong_to_num64(2),
                type_p: 0,
                packet_size_padding: 0,
                npackets: 1,
                nslots: 1,
                slots: vec![Slot {
                    slot_type: SlotType::Literal,
                    time: ulong_to_num64(1),
                }],
            },
        };
        let mut buf = Vec::new();
        assert!(write_data_header(&mut buf, &hdr));
        assert_eq!(&buf[0..4], &OWP_MAGIC_BYTES);
        assert_eq!(u32::from_be_bytes(buf[4..8].try_into().unwrap()), 3);
        assert_eq!(u32::from_be_bytes(buf[8..12].try_into().unwrap()), 1);
        assert_eq!(u32::from_be_bytes(buf[12..16].try_into().unwrap()), 2);

        let mut cur = Cursor::new(buf.clone());
        let mut out = SessionHeader::default();
        let n = read_data_header(&mut cur, &mut out);
        assert!(out.header);
        assert_eq!(out.sid, [7u8; 16]);
        assert_eq!(out.test_spec.npackets, 1);
        assert_eq!(out.test_spec.nslots, 1);
        assert_eq!(out.finished, SessionFinishedType::Normal);
        assert_eq!(out.next_seqno, 2);
        assert_eq!(n, 0);

        let mut slots = Vec::new();
        assert!(read_data_header_slots(&mut cur, 1, &mut slots));
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].time, ulong_to_num64(1));

        // Patch helpers: finished / num fields
        let mut cur2 = Cursor::new(buf);
        assert!(write_data_header_finished(
            &mut cur2,
            SessionFinishedType::Incomplete,
            9
        ));
        assert!(write_data_header_num_data_recs(&mut cur2, 0));
        let mut out2 = SessionHeader::default();
        let _ = read_data_header(&mut cur2, &mut out2);
        assert_eq!(out2.finished, SessionFinishedType::Incomplete);
        assert_eq!(out2.next_seqno, 9);
    }

    #[test]
    fn socket_interface_bind_non_linux_smoke() {
        use std::os::fd::AsRawFd;
        let ctx = Context::create().unwrap();
        let control = Control::alloc(&ctx, false).unwrap();
        let cntrl = control.borrow();
        let sock = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .expect("socket");
        let fd = sock.as_raw_fd();
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            assert!(socket_interface_bind(&cntrl, fd, "lo0"));
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            assert!(!socket_interface_bind(
                &cntrl,
                fd,
                "owamp-definitely-not-an-iface"
            ));
        }
    }

    #[test]
    fn get_max_recv_tracks_lost() {
        let mut m = MaxRecvRec::default();
        let good = DataRec {
            seq_no: 5,
            send: OwampTimeStamp {
                owptime: OwampNum64(1),
                sync: false,
                multiplier: 0,
                scale: 0,
            },
            recv: OwampTimeStamp {
                owptime: OwampNum64(2),
                sync: false,
                multiplier: 0,
                scale: 0,
            },
            ttl: 64,
        };
        assert!(get_max_recv(&good, &mut m));
        assert!(m.found);
        assert_eq!(m.maxrecv, 5);
        let lost = DataRec {
            seq_no: 7,
            send: good.send,
            recv: OwampTimeStamp::default(),
            ttl: 0,
        };
        assert!(get_max_recv(&lost, &mut m));
        assert_eq!(m.badlost, 7);
    }

    #[test]
    fn stop_sessions_header_wire() {
        let hdr = StopSessionsHeader {
            accept: crate::protocol::AcceptType::Accept,
            num_sessions: 2,
        };
        let mut buf = [0u8; STOP_SESSIONS_HEADER_SIZE];
        hdr.encode(&mut buf).unwrap();
        assert_eq!(buf[0], 3);
        assert_eq!(buf[1], 0);
        assert_eq!(u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]), 2);
    }

    #[test]
    fn endpoint_skiprec_and_datafile_fields() {
        let mut ep = Endpoint::new(true, false, -1);
        assert!(ep.skiprec_fd.is_none());
        assert!(ep.datafile.is_none());
        assert!(ep.fname.as_os_str().is_empty());
        let skip = crate::endpoint::anon_skip_file().unwrap();
        ep.skiprec_fd = Some(skip);
        let mut ipc = Vec::new();
        ipc.extend_from_slice(&3u32.to_be_bytes());
        ipc.extend_from_slice(&1u32.to_be_bytes());
        ipc.extend_from_slice(&1u32.to_be_bytes());
        ipc.extend_from_slice(&1u32.to_be_bytes());
        {
            let f = ep.skiprec_fd.as_mut().unwrap();
            f.write_all(&ipc).unwrap();
            f.flush().unwrap();
        }
        ep.skiprecsize = ipc.len() as u64;
        assert_eq!(ep.skiprecsize, 16);
    }

    #[test]
    #[allow(clippy::too_many_lines)] // C-parity fixture setup
    fn clean_data_recs_keeps_hits_drops_late_lost() {
        let path =
            std::env::temp_dir().join(format!("owamp-clean-test-{}.owp", std::process::id()));
        let mut fp = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();

        let sid = [0x11u8; 16];
        let tspec = TestSpec {
            start_time: ulong_to_num64(100),
            loss_timeout: ulong_to_num64(10),
            type_p: 0,
            packet_size_padding: 0,
            npackets: 4,
            nslots: 1,
            slots: vec![Slot {
                slot_type: SlotType::Literal,
                time: ulong_to_num64(1),
            }],
        };
        let hdr = SessionHeader {
            header: true,
            version: 3,
            rec_size: OWP_DATAREC_SIZE as u32,
            twoway: false,
            finished: SessionFinishedType::Incomplete,
            next_seqno: 0,
            num_skiprecs: 0,
            num_datarecs: 0,
            oset_skiprecs: 0,
            oset_datarecs: 0,
            conf_sender: false,
            conf_receiver: true,
            sid,
            sender: Some("127.0.0.1:9000".parse().unwrap()),
            receiver: Some("127.0.0.1:0".parse().unwrap()),
            test_spec: tspec.clone(),
        };
        assert!(write_data_header(&mut fp, &hdr));
        let data_off = fp.stream_position().unwrap();
        fp.seek(SeekFrom::Start(20)).unwrap();
        fp.write_all(&3u32.to_be_bytes()).unwrap();
        fp.seek(SeekFrom::Start(32)).unwrap();
        fp.write_all(&data_off.to_be_bytes()).unwrap();
        fp.seek(SeekFrom::Start(data_off)).unwrap();

        let stamp = |t: u32| OwampTimeStamp {
            owptime: ulong_to_num64(t),
            sync: true,
            multiplier: 1,
            scale: 0,
        };
        // seq0 hit early, seq1 hit late (kept), seq2 lost late (dropped via keep_thresh).
        let records = [
            crate::owamp::OwampDataRec {
                seq_no: 0,
                send: stamp(101),
                recv: stamp(101),
                ttl: 64,
            },
            crate::owamp::OwampDataRec {
                seq_no: 1,
                send: stamp(200),
                recv: stamp(200),
                ttl: 64,
            },
            crate::owamp::OwampDataRec {
                seq_no: 2,
                send: stamp(200),
                recv: crate::owamp::OwampTimeStamp {
                    owptime: OwampNum64::ZERO,
                    sync: false,
                    multiplier: 1,
                    scale: 64,
                },
                ttl: 255,
            },
        ];
        for erec in &records {
            let mut b = vec![0u8; OWP_DATAREC_SIZE];
            crate::endpoint::encode_data_record(&mut b, erec).unwrap();
            fp.write_all(&b).unwrap();
        }
        fp.flush().unwrap();

        let ctx = Context::create().unwrap();
        let sender = Addr::by_node("127.0.0.1", Some("9000"));
        let receiver = Addr::by_node("127.0.0.1", Some("0"));
        let mut ts = TestSession::new(sender, false, receiver, true, &tspec).unwrap();
        ts.sid = sid;
        ts.sctx = context::ScheduleContext::create(&ctx, &sid, &tspec);
        ts.endpoint = Some({
            let mut ep = Endpoint::new(false, false, -1);
            ep.fname = path.clone();
            ep
        });

        // stop=120, loss=10 → keep_thresh=110. Late lost (send=200) drops;
        // late hit (send=200) stays.
        let stop = stamp(120);
        let (max_recv, _) = clean_data_recs(&ctx, &mut ts, &mut fp, 3, &stop).unwrap();
        assert_eq!(max_recv, 1);
        let ph = read_data_header_initial(&mut fp).unwrap();
        assert_eq!(ph.num_datarecs, 2);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn effective_capability_noop_without_libcap() {
        let ctx = Context::create().unwrap();
        assert!(add_effective_capability(&ctx, "cap_net_raw"));
        assert!(remove_effective_capability(&ctx, "cap_net_raw"));
    }

    #[test]
    fn clean_up_sessions_skips_without_datafile() {
        let ctx = Context::create().unwrap();
        let cntrl_rc = Control::alloc(&ctx, false).unwrap();
        let mut cntrl = cntrl_rc.borrow_mut();
        cntrl.twoway = false;
        let tspec = TestSpec {
            npackets: 1,
            nslots: 1,
            slots: vec![Slot {
                slot_type: SlotType::Literal,
                time: ulong_to_num64(1),
            }],
            ..Default::default()
        };
        let mut ts = TestSession::new(
            Addr::by_node("a", None),
            true,
            Addr::by_node("b", None),
            false,
            &tspec,
        )
        .unwrap();
        ts.endpoint = Some(Endpoint::new(true, false, -1));
        cntrl.tests.push(*ts);
        let mut aval = AcceptType::Invalid;
        let stop = OwampTimeStamp::default();
        assert!(clean_up_sessions(&mut cntrl, &mut aval, &stop));
        assert_eq!(aval, AcceptType::Accept);
    }

    #[test]
    fn sessions_stay_active_after_start_until_worker_finishes() {
        let ctx = Context::create().unwrap();
        let cntrl_rc = Control::alloc(&ctx, false).unwrap();
        let mut cntrl = cntrl_rc.borrow_mut();
        let tspec = TestSpec {
            npackets: 1,
            nslots: 1,
            slots: vec![Slot {
                slot_type: SlotType::Literal,
                time: ulong_to_num64(1),
            }],
            ..Default::default()
        };
        let mut ts = TestSession::new(
            Addr::by_node("127.0.0.1", Some("0")),
            true,
            Addr::by_node("127.0.0.1", Some("9")),
            false,
            &tspec,
        )
        .unwrap();
        // Idle worker (no EndpointState): stays active for ~30ms after start.
        let mut ep = Endpoint::new(true, false, -1);
        assert_eq!(ep.poll_status(), AcceptType::Invalid);
        ep.start().unwrap();
        ts.endpoint = Some(ep);
        cntrl.tests.push(*ts);

        let (active, _) = sessions_active(&cntrl);
        assert!(
            active >= 1,
            "session must remain active immediately after StartSessions"
        );

        // Wait for the idle worker to finish.
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
        while sessions_active(&cntrl).0 > 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
            if let Some(ep) = cntrl.tests[0].endpoint.as_mut() {
                ep.reap_if_finished();
            }
        }
        let (active_after, aval) = sessions_active(&cntrl);
        assert_eq!(active_after, 0, "session must finish after worker exits");
        assert_eq!(aval, AcceptType::Accept);
    }

    #[test]
    fn endpoint_stop_joins_running_worker() {
        let mut ep = Endpoint::new(false, false, -1);
        ep.start().unwrap();
        assert_eq!(ep.poll_status(), AcceptType::Invalid);
        let mut aval = AcceptType::Accept;
        ep.stop(&mut aval);
        assert_ne!(ep.poll_status(), AcceptType::Invalid);
        assert_eq!(aval, ep.poll_status());
    }

    #[test]
    fn endpoint_init_wires_port_range_from_context() {
        let ctx = Context::create().unwrap();
        assert!(ctx.set_test_port_range(PortRange {
            low: 45_100,
            high: 45_120,
        }));
        let cntrl_rc = Control::alloc(&ctx, false).unwrap();
        cntrl_rc.borrow_mut().mode = OWP_MODE_OPEN;
        let cntrl = cntrl_rc.borrow();
        let tspec = TestSpec {
            npackets: 1,
            nslots: 1,
            slots: vec![Slot {
                slot_type: SlotType::Literal,
                time: ulong_to_num64(1),
            }],
            ..Default::default()
        };
        let sender = Addr::by_sockaddr(
            "127.0.0.1:0".parse().unwrap(),
            libc::SOCK_DGRAM,
            libc::IPPROTO_UDP,
        );
        let receiver = Addr::by_sockaddr(
            "127.0.0.1:9".parse().unwrap(),
            libc::SOCK_DGRAM,
            libc::IPPROTO_UDP,
        );
        let mut ts = TestSession::new(sender.clone(), true, receiver, false, &tspec).unwrap();
        let mut aval = AcceptType::Invalid;
        assert!(endpoint_init(
            &cntrl, &mut ts, &sender, None, &mut aval, true
        ));
        assert_eq!(aval, AcceptType::Accept);
        let port = ts.sender.as_ref().map_or(0, Addr::port);
        assert!((45_100..=45_120).contains(&port));
    }

    #[test]
    fn endpoint_init_open_file_callback_when_fp_none() {
        let ctx = Context::create().unwrap();
        let path =
            std::env::temp_dir().join(format!("owamp-openfile-cb-{}.owp", std::process::id()));
        // Pre-create so the callback can open it.
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        let path_cb = path.clone();
        ctx.set_open_file(Box::new(move |_cntrl, _closure, _sid, fname| {
            *fname = path_cb.clone();
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path_cb)
                .ok()
        }));
        let cntrl_rc = Control::alloc(&ctx, false).unwrap();
        cntrl_rc.borrow_mut().mode = OWP_MODE_OPEN;
        let cntrl = cntrl_rc.borrow();
        let tspec = TestSpec {
            npackets: 1,
            nslots: 1,
            slots: vec![Slot {
                slot_type: SlotType::Literal,
                time: ulong_to_num64(1),
            }],
            ..Default::default()
        };
        let sender = Addr::by_sockaddr(
            "127.0.0.1:9".parse().unwrap(),
            libc::SOCK_DGRAM,
            libc::IPPROTO_UDP,
        );
        let receiver = Addr::by_sockaddr(
            "127.0.0.1:0".parse().unwrap(),
            libc::SOCK_DGRAM,
            libc::IPPROTO_UDP,
        );
        let mut ts = TestSession::new(sender, false, receiver.clone(), true, &tspec).unwrap();
        let mut aval = AcceptType::Invalid;
        assert!(endpoint_init(
            &cntrl, &mut ts, &receiver, None, &mut aval, false
        ));
        assert_eq!(aval, AcceptType::Accept);
        let ep = ts.endpoint.as_ref().unwrap();
        assert!(ep.datafile.is_some() || ep.fbuff_size == 0 || ep.userfile.is_some());
        assert_eq!(ep.fname, path);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn endpoint_init_receiver_fails_without_fp_or_openfile() {
        let ctx = Context::create().unwrap();
        let cntrl_rc = Control::alloc(&ctx, false).unwrap();
        cntrl_rc.borrow_mut().mode = OWP_MODE_OPEN;
        let cntrl = cntrl_rc.borrow();
        let tspec = TestSpec {
            npackets: 1,
            nslots: 1,
            slots: vec![Slot {
                slot_type: SlotType::Literal,
                time: ulong_to_num64(1),
            }],
            ..Default::default()
        };
        let sender = Addr::by_sockaddr(
            "127.0.0.1:9".parse().unwrap(),
            libc::SOCK_DGRAM,
            libc::IPPROTO_UDP,
        );
        let receiver = Addr::by_sockaddr(
            "127.0.0.1:0".parse().unwrap(),
            libc::SOCK_DGRAM,
            libc::IPPROTO_UDP,
        );
        let mut ts = TestSession::new(sender, false, receiver.clone(), true, &tspec).unwrap();
        let mut aval = AcceptType::Accept;
        assert!(!endpoint_init(
            &cntrl, &mut ts, &receiver, None, &mut aval, false
        ));
        assert_eq!(aval, AcceptType::Failure);
    }

    fn unix_socket_pair() -> [i32; 2] {
        let mut fds = [0i32; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
            0
        );
        fds
    }

    fn detach_socket(cntrl: &mut Control) {
        cntrl.sockfd = -1;
    }

    #[test]
    fn session_sid_alloc_free_and_fail_control() {
        let ctx = Context::create().unwrap();
        {
            let fail_rc = Control::alloc(&ctx, false).unwrap();
            let mut fail = fail_rc.borrow_mut();
            assert_eq!(
                fail_control_session(&mut fail, ErrSeverity::Warning),
                ErrSeverity::Warning
            );
            assert_eq!(fail.state, STATE_INVALID);
            drop(fail);
            let _ = Control::close_rc(fail_rc);
        }

        let cntrl_rc = Control::alloc(&ctx, false).unwrap();
        let mut cntrl = cntrl_rc.borrow_mut();
        let tspec = TestSpec {
            npackets: 2,
            nslots: 1,
            slots: vec![Slot {
                slot_type: SlotType::Literal,
                time: ulong_to_num64(5),
            }],
            ..Default::default()
        };
        let sender = Addr::by_node("127.0.0.1", Some("4001"));
        let receiver = Addr::by_node("127.0.0.1", Some("4002"));
        let ts = test_session_alloc(&cntrl, sender, true, receiver, false, &tspec).expect("alloc");
        let sid = ts.sid;
        cntrl.state = STATE_REQUEST;
        cntrl.tests.push(*ts);
        assert_eq!(
            test_session_free(&mut cntrl, &sid, AcceptType::Accept),
            ErrSeverity::Ok
        );
        assert!(cntrl.tests.is_empty());

        let mut ts2 = test_session_alloc(
            &cntrl,
            Addr::by_sockaddr(
                "10.0.0.1:9".parse().unwrap(),
                libc::SOCK_DGRAM,
                libc::IPPROTO_UDP,
            ),
            false,
            Addr::by_sockaddr(
                "192.0.2.1:9".parse().unwrap(),
                libc::SOCK_DGRAM,
                libc::IPPROTO_UDP,
            ),
            true,
            &tspec,
        )
        .expect("alloc2");
        assert_eq!(create_sid(&cntrl, &mut ts2), 0);
        assert_eq!(&ts2.sid[0..4], &[192, 0, 2, 1]);
        assert_ne!(&ts2.sid[4..12], &[0u8; 8]);
        assert_ne!(&ts2.sid[12..16], &[0u8; 4]);
    }

    #[test]
    fn parse_port_range_single_and_reject() {
        let mut pr = PortRange::default();
        assert!(parse_port_range("8612", &mut pr));
        assert_eq!((pr.low, pr.high), (8_612, 8_612));
        assert!(!parse_port_range("90000-1", &mut pr));
        assert!(!parse_port_range("a-b", &mut pr));
    }

    #[test]
    #[allow(clippy::too_many_lines)] // C-parity fixture setup
    fn data_file_records_skips_and_header_patches() {
        let path =
            std::env::temp_dir().join(format!("owamp-datarec-test-{}.owp", std::process::id()));
        let mut fp = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();

        let sid = [0x33u8; 16];
        let tspec = TestSpec {
            start_time: ulong_to_num64(1),
            loss_timeout: ulong_to_num64(2),
            type_p: 0,
            packet_size_padding: 0,
            npackets: 2,
            nslots: 1,
            slots: vec![Slot {
                slot_type: SlotType::Literal,
                time: ulong_to_num64(42),
            }],
        };
        let hdr = SessionHeader {
            header: true,
            version: 3,
            rec_size: OWP_DATARECV3_SIZE as u32,
            twoway: false,
            finished: SessionFinishedType::Incomplete,
            next_seqno: 0,
            num_skiprecs: 0,
            num_datarecs: 0,
            oset_skiprecs: 0,
            oset_datarecs: 0,
            conf_sender: false,
            conf_receiver: true,
            sid,
            sender: Some("127.0.0.1:1".parse().unwrap()),
            receiver: Some("127.0.0.1:2".parse().unwrap()),
            test_spec: tspec,
        };
        assert!(write_data_header(&mut fp, &hdr));
        fp.flush().unwrap();

        let stamp = |t: u32| OwampTimeStamp {
            owptime: ulong_to_num64(t),
            sync: true,
            multiplier: 1,
            scale: 0,
        };
        let recs = [
            DataRec {
                seq_no: 0,
                send: stamp(10),
                recv: stamp(11),
                ttl: 64,
            },
            DataRec {
                seq_no: 1,
                send: stamp(20),
                recv: stamp(21),
                ttl: 55,
            },
        ];
        for r in &recs {
            assert!(write_data_record(&mut fp, r));
        }
        fp.flush().unwrap();
        assert!(write_data_header_num_data_recs(&mut fp, 2));

        let mut hdr_out = SessionHeader::default();
        assert_eq!(read_data_header(&mut fp, &mut hdr_out), 2);
        assert_eq!(hdr_out.sid, sid);
        assert_eq!(hdr_out.test_spec.nslots, 1);

        let ph = read_data_header_initial(&mut fp).unwrap();
        assert_eq!(ph.num_datarecs, 2);
        fp.seek(SeekFrom::Start(ph.oset_datarecs)).unwrap();
        let mut seen = Vec::new();
        assert_eq!(
            parse_records(&mut fp, 2, 3, |r| {
                seen.push((r.seq_no, r.ttl));
                true
            }),
            ErrSeverity::Ok
        );
        assert_eq!(seen, [(0, 64), (1, 55)]);

        let mut slots = Vec::new();
        assert!(read_data_header_slots(&mut fp, 1, &mut slots));
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].time, ulong_to_num64(42));

        let skip_wire = {
            let mut b = [0u8; OWP_SKIPREC_SIZE];
            b[0..4].copy_from_slice(&1u32.to_be_bytes());
            b[4..8].copy_from_slice(&3u32.to_be_bytes());
            b
        };
        let mut skips = Vec::new();
        let mut skip_cur = std::io::Cursor::new(skip_wire);
        assert_eq!(
            read_data_skips(&mut skip_cur, 1, &mut skips),
            ErrSeverity::Ok
        );
        assert_eq!((skips[0].begin, skips[0].end), (1, 3));

        let tw_path = std::env::temp_dir().join(format!("owamp-twrec-{}.owp", std::process::id()));
        let mut tw_fp = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tw_path)
            .unwrap();
        let tw_hdr = SessionHeader {
            rec_size: OWP_DATAREC_TWV3_SIZE as u32,
            twoway: true,
            ..hdr
        };
        assert!(write_data_header(&mut tw_fp, &tw_hdr));
        let tw = TwDataRec {
            sent: recs[0],
            reflected: recs[1],
        };
        assert!(write_tw_data_record(&mut tw_fp, &tw));
        tw_fp.flush().unwrap();
        let mut tw_hdr = SessionHeader::default();
        assert_eq!(read_data_header(&mut tw_fp, &mut tw_hdr), 1);
        assert!(tw_hdr.twoway);
        let tph = read_data_header_initial(&mut tw_fp).unwrap();
        let mut tw_seen = 0u32;
        tw_fp.seek(SeekFrom::Start(tph.oset_datarecs)).unwrap();
        assert_eq!(
            parse_tw_records(&mut tw_fp, 1, OWP_VERSION_TWOWAY | 3, |r| {
                assert_eq!(r.sent.seq_no, 0);
                assert_eq!(r.reflected.seq_no, 1);
                tw_seen += 1;
                true
            }),
            ErrSeverity::Ok
        );
        assert_eq!(tw_seen, 1);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tw_path);
    }

    #[test]
    fn control_channel_greeting_setup_start_open() {
        let fds = unix_socket_pair();
        let ctx = Context::create().unwrap();
        let modes = OWP_MODE_OPEN | OWP_MODE_AUTHENTICATED | OWP_MODE_ENCRYPTED;
        let challenge = [0x11u8; 16];
        let salt = [0x22u8; 16];
        let count = 1_024u32;

        let server_rc = Control::alloc(&ctx, false).unwrap();
        {
            let mut s = server_rc.borrow_mut();
            s.sockfd = fds[0];
            assert_eq!(
                write_server_greeting(&mut s, None, modes, &challenge, &salt, count),
                ErrSeverity::Ok
            );
            assert!(s.is_setup());
        }

        let client_rc = Control::alloc(&ctx, false).unwrap();
        let (mut mode_out, mut ch, mut sl, mut ct) = (0u32, [0u8; 16], [0u8; 16], 0u32);
        {
            let mut c = client_rc.borrow_mut();
            c.sockfd = fds[1];
            assert_eq!(
                read_server_greeting(&mut c, None, &mut mode_out, &mut ch, &mut sl, &mut ct),
                ErrSeverity::Ok
            );
            assert_eq!(mode_out, modes);
            assert_eq!(ch, challenge);
            assert_eq!(sl, salt);
            assert_eq!(ct, count);
            c.mode = OWP_MODE_OPEN;
        }

        let token = [0u8; 64];
        {
            let mut c = client_rc.borrow_mut();
            assert_eq!(write_setup_response(&mut c, None, &token), ErrSeverity::Ok);
        }

        {
            let mut s = server_rc.borrow_mut();
            let (mut md, mut tok, mut civ) = (0u32, [0u8; 64], [0u8; 16]);
            assert_eq!(
                read_setup_response(&mut s, None, &mut md, &mut tok, &mut civ),
                ErrSeverity::Ok
            );
            assert_eq!(md, OWP_MODE_OPEN);
            assert_eq!(tok, token);
            s.mode = OWP_MODE_OPEN;
        }

        let uptime = OwampNum64(0x1234_5678_9abc_def0);
        {
            let mut s = server_rc.borrow_mut();
            assert_eq!(
                write_server_start(&mut s, None, AcceptType::Accept, uptime),
                ErrSeverity::Ok
            );
            assert!(s.is_request());
        }

        let mut accept = AcceptType::Invalid;
        let mut up_out = OwampNum64::ZERO;
        {
            let mut c = client_rc.borrow_mut();
            assert_eq!(
                read_server_start(&mut c, None, &mut accept, &mut up_out),
                ErrSeverity::Ok
            );
            assert_eq!(accept, AcceptType::Accept);
            assert_eq!(up_out, uptime);
        }

        detach_socket(&mut server_rc.borrow_mut());
        detach_socket(&mut client_rc.borrow_mut());
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        let _ = Control::close_rc(server_rc);
        let _ = Control::close_rc(client_rc);
        ctx.free();
    }

    #[test]
    fn control_start_sessions_and_ack_socketpair() {
        use crate::context::STATE_START_SESSIONS;

        let fds = unix_socket_pair();
        let ctx = Context::create().unwrap();

        let client_rc = Control::alloc(&ctx, false).unwrap();
        let server_rc = Control::alloc(&ctx, false).unwrap();
        {
            let mut c = client_rc.borrow_mut();
            c.sockfd = fds[1];
            c.mode = OWP_MODE_OPEN;
            c.state = STATE_REQUEST | context::STATE_TEST;
            assert_eq!(write_start_sessions(&mut c, None), ErrSeverity::Ok);
        }

        {
            let mut s = server_rc.borrow_mut();
            s.sockfd = fds[0];
            s.mode = OWP_MODE_OPEN;
            s.state = STATE_REQUEST | STATE_START_SESSIONS;
            assert_eq!(read_fully(s.sockfd, &mut s.msg[..16]), 16);
            assert_eq!(read_start_sessions(&mut s, None), ErrSeverity::Ok);
        }

        {
            let mut s = server_rc.borrow_mut();
            assert_eq!(
                write_start_ack(&mut s, None, AcceptType::Accept),
                ErrSeverity::Ok
            );
        }

        let mut aval = AcceptType::Invalid;
        {
            let mut c = client_rc.borrow_mut();
            assert_eq!(read_start_ack(&mut c, None, &mut aval), ErrSeverity::Ok);
            assert_eq!(aval, AcceptType::Accept);
        }

        detach_socket(&mut client_rc.borrow_mut());
        detach_socket(&mut server_rc.borrow_mut());
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        let _ = Control::close_rc(client_rc);
        let _ = Control::close_rc(server_rc);
        ctx.free();
    }

    #[test]
    fn control_test_request_and_accept_session_socketpair() {
        use crate::context::{STATE_ACCEPT_SESSION, STATE_TEST_REQUEST};

        let fds = unix_socket_pair();
        let ctx = Context::create().unwrap();
        let sid = [0x44u8; 16];
        let tspec = TestSpec {
            start_time: ulong_to_num64(9),
            loss_timeout: ulong_to_num64(8),
            type_p: 0,
            packet_size_padding: 14,
            npackets: 1,
            nslots: 1,
            slots: vec![Slot {
                slot_type: SlotType::Literal,
                time: ulong_to_num64(100),
            }],
        };
        let sender: SocketAddr = "10.0.0.1:5001".parse().unwrap();
        let receiver: SocketAddr = "10.0.0.2:5002".parse().unwrap();

        let client_rc = Control::alloc(&ctx, false).unwrap();
        {
            let mut c = client_rc.borrow_mut();
            c.sockfd = fds[1];
            c.mode = OWP_MODE_OPEN;
            c.state = STATE_REQUEST | STATE_TEST;
            assert_eq!(
                write_test_request(
                    &mut c,
                    None,
                    Some(sender),
                    Some(receiver),
                    true,
                    false,
                    false,
                    Some(&sid),
                    &tspec
                ),
                ErrSeverity::Ok
            );
        }

        let server_rc = Control::alloc(&ctx, false).unwrap();
        let mut accept = AcceptType::Invalid;
        {
            let mut s = server_rc.borrow_mut();
            s.sockfd = fds[0];
            s.mode = OWP_MODE_OPEN;
            s.state = STATE_REQUEST | STATE_TEST_REQUEST;
            assert_eq!(read_fully(s.sockfd, &mut s.msg[..16]), 16);
            let ts = read_test_request(&mut s, None, &mut accept).expect("read_test_request");
            assert_eq!(accept, AcceptType::Accept);
            assert_eq!(ts.sid, sid);
            assert_eq!(ts.test_spec.nslots, 1);
            assert_eq!(ts.test_spec.slots[0].time, ulong_to_num64(100));
        }

        let mut port = 0u16;
        let mut got_sid = [0u8; 16];
        {
            let mut s = server_rc.borrow_mut();
            s.state = STATE_REQUEST | STATE_ACCEPT_SESSION;
            assert_eq!(
                write_accept_session(&mut s, None, AcceptType::Accept, 8_613, Some(&sid)),
                ErrSeverity::Ok
            );
        }
        {
            let mut c = client_rc.borrow_mut();
            assert_eq!(
                read_accept_session(&mut c, None, &mut accept, &mut port, Some(&mut got_sid)),
                ErrSeverity::Ok
            );
            assert_eq!(accept, AcceptType::Accept);
            assert_eq!(port, 8_613);
            assert_eq!(got_sid, sid);
        }

        detach_socket(&mut client_rc.borrow_mut());
        detach_socket(&mut server_rc.borrow_mut());
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        let _ = Control::close_rc(client_rc);
        let _ = Control::close_rc(server_rc);
        ctx.free();
    }

    #[test]
    fn control_fetch_session_and_ack_socketpair() {
        use crate::context::STATE_FETCH_SESSION;

        let fds = unix_socket_pair();
        let ctx = Context::create().unwrap();
        let sid = [0x55u8; 16];

        let client_rc = Control::alloc(&ctx, false).unwrap();
        {
            let mut c = client_rc.borrow_mut();
            c.sockfd = fds[1];
            c.mode = OWP_MODE_OPEN;
            c.state = STATE_REQUEST;
            assert_eq!(
                write_fetch_session(&mut c, None, 1, 99, &sid),
                ErrSeverity::Ok
            );
        }

        let server_rc = Control::alloc(&ctx, false).unwrap();
        {
            let mut s = server_rc.borrow_mut();
            s.sockfd = fds[0];
            s.mode = OWP_MODE_OPEN;
            s.state = STATE_REQUEST | STATE_FETCH_SESSION;
            assert_eq!(read_fully(s.sockfd, &mut s.msg[..16]), 16);
            assert_eq!(receive_blocks_intr(&mut s, &mut [0u8; 32], 2), 2);
        }

        let mut accept = AcceptType::Invalid;
        let (mut finished, mut next, mut nskip, mut ndata) = (0u8, 0u32, 0u32, 0u32);
        {
            let mut s = server_rc.borrow_mut();
            s.state = STATE_REQUEST | crate::context::STATE_FETCH_ACK;
            let mut buf = [0u8; FETCH_ACK_SIZE];
            {
                let ack = ProtoFetchAck {
                    accept: crate::protocol::AcceptType::Accept,
                    finished: 1,
                    next_seqno: 7,
                    num_skiprecs: 2,
                    num_datarecs: 5,
                    hmac: [0u8; 16],
                };
                ack.encode(&mut buf).unwrap();
            }
            assert_eq!(send_blocks_intr(&mut s, &mut buf, 2), 2);
        }
        {
            let mut c = client_rc.borrow_mut();
            assert_eq!(
                read_fetch_ack(
                    &mut c,
                    None,
                    &mut accept,
                    &mut finished,
                    &mut next,
                    &mut nskip,
                    &mut ndata
                ),
                ErrSeverity::Ok
            );
            assert_eq!(accept, AcceptType::Accept);
            assert_eq!(finished, 1);
            assert_eq!((next, nskip, ndata), (7, 2, 5));
        }

        detach_socket(&mut client_rc.borrow_mut());
        detach_socket(&mut server_rc.borrow_mut());
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        let _ = Control::close_rc(client_rc);
        let _ = Control::close_rc(server_rc);
        ctx.free();
    }
}
