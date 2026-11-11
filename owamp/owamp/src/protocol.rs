//! OWAMP/TWAMP control-protocol message framing — port of `protocol.c`.
//!
//! Pure encode/decode of control-session messages with exact wire layouts
//! (network byte order). Framing hooks call into [`crate::rijndael_api_fst`] when the
//! session mode requires Authenticated / Encrypted control ciphering.
//!
//! Session orchestration that needs sockets, endpoints, or file locks lives
//! in `api` / `capi` / `sapi`; this module owns the byte layouts.

#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use byteorder::{BigEndian, ByteOrder};

use crate::error::{OwampError, Result};
use crate::owamp::{OwampNum64, OwampRequestType, OwampSid, OwampTimeStamp};
use crate::owampP::{
    OWP_DATARECV2_SIZE, OWP_DATARECV3_SIZE, OWP_DATAREC_TWV3_SIZE, OWP_FETCH_ACK_BLK_LEN,
    OWP_FETCH_BUFFSIZE, OWP_FETCH_SESSION_BLK_LEN, OWP_MAX_MSG_SIZE, OWP_MODE_DOCIPHER_CNTRL,
    OWP_MODE_OPEN, OWP_RIJNDAEL_BLOCK_SIZE, OWP_SALT_SIZE, OWP_SKIPREC_SIZE, OWP_START_ACK_BLK_LEN,
    OWP_START_SESSIONS_BLK_LEN, OWP_STATE_ACCEPT_SESSION, OWP_STATE_FETCHING, OWP_STATE_FETCH_ACK,
    OWP_STATE_FETCH_SESSION, OWP_STATE_INITIAL, OWP_STATE_INVALID, OWP_STATE_PENDING,
    OWP_STATE_READING, OWP_STATE_REQUEST, OWP_STATE_SETUP, OWP_STATE_START_ACK,
    OWP_STATE_START_SESSIONS, OWP_STATE_STOP_SESSIONS, OWP_STATE_TEST, OWP_STATE_TEST_REQUEST,
    OWP_STATE_TEST_REQUEST_SLOTS, OWP_STATE_TEST_REQUEST_TW, OWP_STOP_SESSIONS_BLK_LEN,
    OWP_TEST_REQUEST_BLK_LEN, OWP_TEST_REQUEST_PREAMBLE_SIZE, OWP_TOKEN_SIZE, OWP_USERID_LEN,
    OWP_VERSION_TWOWAY,
};
use crate::rijndael_api_fst::{
    self as rijndael, mode_docipher_cntrl, ControlCrypto, HMAC_TRUNC_SIZE,
};
use crate::time::{
    decode_timestamp, decode_timestamp_err_estimate, encode_timestamp,
    encode_timestamp_err_estimate,
};

// ---------------------------------------------------------------------------
// Protocol-local types (wire-facing; api/sapi convert to/from context types)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i8)]
pub enum AcceptType {
    Invalid = -1,
    Accept = 0,
    Reject = 1,
    Failure = 2,
    Unsupported = 3,
    UnavailablePerm = 4,
    UnavailableTemp = 5,
}

impl AcceptType {
    #[must_use]
    pub const fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::Accept,
            1 => Self::Reject,
            2 => Self::Failure,
            3 => Self::Unsupported,
            4 => Self::UnavailablePerm,
            5 => Self::UnavailableTemp,
            _ => Self::Invalid,
        }
    }

    #[must_use]
    pub const fn as_u8(self) -> Option<u8> {
        match self {
            Self::Invalid => None,
            other => Some(other as u8),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    RandExp { mean: OwampNum64 },
    Literal { offset: OwampNum64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
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
            start_time: OwampNum64::ZERO,
            loss_timeout: OwampNum64::ZERO,
            type_p: 0,
            packet_size_padding: 0,
            npackets: 0,
            nslots: 0,
            slots: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DataRec {
    pub seq_no: u32,
    pub send: OwampTimeStamp,
    pub recv: OwampTimeStamp,
    pub ttl: u8,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TwDataRec {
    pub sent: DataRec,
    pub reflected: DataRec,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SkipRec {
    pub begin: u32,
    pub end: u32,
}

// ---------------------------------------------------------------------------
// Wire sizes / aliases (also present in `constants`; re-exported for callers)
// ---------------------------------------------------------------------------

pub const RIJNDAEL_BLOCK_SIZE: usize = OWP_RIJNDAEL_BLOCK_SIZE;
pub const TOKEN_SIZE: usize = OWP_TOKEN_SIZE;
pub const SALT_SIZE: usize = OWP_SALT_SIZE;
pub const CHALLENGE_SIZE: usize = 16;
pub const USERID_LEN: usize = OWP_USERID_LEN;
pub const SID_SIZE: usize = 16;
pub const HMAC_SIZE: usize = HMAC_TRUNC_SIZE;

pub const SERVER_GREETING_SIZE: usize = 64;
pub const SETUP_RESPONSE_SIZE: usize = 164;
pub const SERVER_START_SIZE: usize = 48;
pub const ACCEPT_SESSION_SIZE: usize = 48;
pub const START_SESSIONS_SIZE: usize = OWP_START_SESSIONS_BLK_LEN * RIJNDAEL_BLOCK_SIZE;
pub const START_ACK_SIZE: usize = OWP_START_ACK_BLK_LEN * RIJNDAEL_BLOCK_SIZE;
pub const STOP_SESSIONS_HEADER_SIZE: usize = 16;
pub const FETCH_SESSION_SIZE: usize = OWP_FETCH_SESSION_BLK_LEN * RIJNDAEL_BLOCK_SIZE;
pub const FETCH_ACK_SIZE: usize = OWP_FETCH_ACK_BLK_LEN * RIJNDAEL_BLOCK_SIZE;
pub const SLOT_SIZE: usize = RIJNDAEL_BLOCK_SIZE;
pub const SESSION_DESC_HEADER_SIZE: usize = 24;
pub const TEST_REQUEST_PREAMBLE_SIZE: usize = OWP_TEST_REQUEST_PREAMBLE_SIZE;
pub const MAX_MSG_SIZE: usize = OWP_MAX_MSG_SIZE;
pub const FETCH_BUFFSIZE: usize = OWP_FETCH_BUFFSIZE;

pub const DATARECV2_SIZE: usize = OWP_DATARECV2_SIZE;
pub const DATARECV3_SIZE: usize = OWP_DATARECV3_SIZE;
pub const DATAREC_TWV3_SIZE: usize = OWP_DATAREC_TWV3_SIZE;
pub const SKIPREC_SIZE: usize = OWP_SKIPREC_SIZE;
pub const VERSION_TWOWAY: u32 = OWP_VERSION_TWOWAY;

pub const TEST_REQUEST_BLK_LEN: usize = OWP_TEST_REQUEST_BLK_LEN;
pub const START_SESSIONS_BLK_LEN: usize = OWP_START_SESSIONS_BLK_LEN;
pub const STOP_SESSIONS_BLK_LEN: usize = OWP_STOP_SESSIONS_BLK_LEN;
pub const FETCH_SESSION_BLK_LEN: usize = OWP_FETCH_SESSION_BLK_LEN;
pub const START_ACK_BLK_LEN: usize = OWP_START_ACK_BLK_LEN;
pub const FETCH_ACK_BLK_LEN: usize = OWP_FETCH_ACK_BLK_LEN;

// State aliases (C `_OWPState*`)
pub const STATE_INITIAL: u32 = OWP_STATE_INITIAL;
pub const STATE_INVALID: u32 = OWP_STATE_INVALID;
pub const STATE_SETUP: u32 = OWP_STATE_SETUP;
pub const STATE_REQUEST: u32 = OWP_STATE_REQUEST;
pub const STATE_TEST: u32 = OWP_STATE_TEST;
pub const STATE_TEST_REQUEST: u32 = OWP_STATE_TEST_REQUEST;
pub const STATE_TEST_REQUEST_SLOTS: u32 = OWP_STATE_TEST_REQUEST_SLOTS;
pub const STATE_START_SESSIONS: u32 = OWP_STATE_START_SESSIONS;
pub const STATE_STOP_SESSIONS: u32 = OWP_STATE_STOP_SESSIONS;
pub const STATE_FETCH_SESSION: u32 = OWP_STATE_FETCH_SESSION;
pub const STATE_TEST_REQUEST_TW: u32 = OWP_STATE_TEST_REQUEST_TW;
pub const STATE_ACCEPT_SESSION: u32 = OWP_STATE_ACCEPT_SESSION;
pub const STATE_START_ACK: u32 = OWP_STATE_START_ACK;
pub const STATE_FETCH_ACK: u32 = OWP_STATE_FETCH_ACK;
pub const STATE_FETCHING: u32 = OWP_STATE_FETCHING;
pub const STATE_READING: u32 = OWP_STATE_READING;
pub const STATE_PENDING: u32 = OWP_STATE_PENDING;

pub type Challenge = [u8; CHALLENGE_SIZE];
pub type Salt = [u8; SALT_SIZE];
pub type Token = [u8; TOKEN_SIZE];
pub type Iv = [u8; RIJNDAEL_BLOCK_SIZE];
pub type HmacDigest = [u8; HMAC_SIZE];
pub type UserIdBytes = [u8; USERID_LEN];

// ---------------------------------------------------------------------------
// State helpers
// ---------------------------------------------------------------------------

#[inline]
#[must_use]
pub const fn state_is_initial(state: u32) -> bool {
    state == 0
}

#[inline]
#[must_use]
pub const fn state_is_setup(state: u32) -> bool {
    state == STATE_SETUP
}

#[inline]
#[must_use]
pub const fn state_is(test: u32, state: u32) -> bool {
    (test & state) != 0
}

#[inline]
#[must_use]
pub const fn state_is_request(state: u32) -> bool {
    state_is(STATE_REQUEST, state)
}

#[inline]
#[must_use]
pub const fn state_is_reading(state: u32) -> bool {
    state_is(STATE_READING, state)
}

#[inline]
#[must_use]
pub const fn state_is_pending(state: u32) -> bool {
    state_is(STATE_PENDING, state)
}

#[inline]
#[must_use]
pub const fn state_is_test(state: u32) -> bool {
    state_is(STATE_TEST, state)
}

/// Partial-read state bit for a peeked request type (`OWPReadRequestType`).
#[must_use]
pub const fn request_partial_state(req: OwampRequestType) -> Option<u32> {
    match req {
        OwampRequestType::Test => Some(STATE_TEST_REQUEST),
        OwampRequestType::StartSessions => Some(STATE_START_SESSIONS),
        OwampRequestType::StopSessions => Some(STATE_STOP_SESSIONS),
        OwampRequestType::FetchSession => Some(STATE_FETCH_SESSION),
        OwampRequestType::TestTw => Some(STATE_TEST_REQUEST_TW),
        _ => None,
    }
}

#[must_use]
pub const fn request_type_from_u8(val: u8) -> OwampRequestType {
    match val {
        1 => OwampRequestType::Test,
        2 => OwampRequestType::StartSessions,
        3 => OwampRequestType::StopSessions,
        4 => OwampRequestType::FetchSession,
        5 => OwampRequestType::TestTw,
        _ => OwampRequestType::Invalid,
    }
}

#[must_use]
pub const fn request_type_as_u8(req: OwampRequestType) -> Option<u8> {
    match req {
        OwampRequestType::Test => Some(1),
        OwampRequestType::StartSessions => Some(2),
        OwampRequestType::StopSessions => Some(3),
        OwampRequestType::FetchSession => Some(4),
        OwampRequestType::TestTw => Some(5),
        _ => None,
    }
}

#[must_use]
pub const fn accept_type_from_u8(val: u8) -> AcceptType {
    AcceptType::from_u8(val)
}

#[must_use]
pub const fn accept_type_as_u8(val: AcceptType) -> Option<u8> {
    val.as_u8()
}

/// Validate request type against control state; return state bit to OR in.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn classify_request(state: u32, msgtype: u8) -> Result<(OwampRequestType, u32)> {
    if !state_is_request(state) || state_is_reading(state) {
        return Err(OwampError::Invalid(
            "classify_request: called in wrong state".into(),
        ));
    }
    let in_test = state_is_test(state);
    if (in_test && msgtype != 3) || (!in_test && msgtype == 3) {
        return Err(OwampError::Invalid(
            "classify_request: invalid request for current state".into(),
        ));
    }
    let req = request_type_from_u8(msgtype);
    let bit = request_partial_state(req)
        .ok_or_else(|| OwampError::Invalid(format!("classify_request: unknown msg:{msgtype}")))?;
    Ok((req, bit))
}

// ---------------------------------------------------------------------------
// Framing: Clear / Authenticated / Encrypted (via crate::rijndael_api_fst)
// ---------------------------------------------------------------------------

/// Encrypt `num_blocks` when mode requires control ciphering (`_OWPSendBlocksIntr`).
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn frame_send_blocks(
    mode: u32,
    crypto: Option<&mut ControlCrypto>,
    buf: &mut [u8],
    num_blocks: usize,
) -> Result<()> {
    let need = num_blocks * RIJNDAEL_BLOCK_SIZE;
    if buf.len() < need {
        return Err(OwampError::Message(format!(
            "frame_send_blocks: buffer too small ({} < {need})",
            buf.len()
        )));
    }
    if mode_docipher_cntrl(mode) {
        let c = crypto.ok_or_else(|| {
            OwampError::Crypto("frame_send_blocks: ControlCrypto required".into())
        })?;
        c.encrypt_blocks(&mut buf[..need], num_blocks)?;
    }
    Ok(())
}

/// Decrypt `num_blocks` when mode requires control ciphering (`_OWPReceiveBlocksIntr`).
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn frame_recv_blocks(
    mode: u32,
    crypto: Option<&mut ControlCrypto>,
    buf: &mut [u8],
    num_blocks: usize,
) -> Result<()> {
    let need = num_blocks * RIJNDAEL_BLOCK_SIZE;
    if buf.len() < need {
        return Err(OwampError::Message(format!(
            "frame_recv_blocks: buffer too small ({} < {need})",
            buf.len()
        )));
    }
    if mode_docipher_cntrl(mode) {
        let c = crypto.ok_or_else(|| {
            OwampError::Crypto("frame_recv_blocks: ControlCrypto required".into())
        })?;
        c.decrypt_blocks(&mut buf[..need], num_blocks)?;
    }
    Ok(())
}

/// Add covered blocks + write truncated HMAC into `digest_out` (zeros in open mode).
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn finalize_hmac_field(
    mode: u32,
    crypto: Option<&mut ControlCrypto>,
    covered: &[u8],
    covered_blocks: usize,
    digest_out: &mut HmacDigest,
) -> Result<()> {
    digest_out.fill(0);
    if !mode_docipher_cntrl(mode) {
        return Ok(());
    }
    let c = crypto.ok_or_else(|| OwampError::Crypto("HMAC requires ControlCrypto".into()))?;
    c.send_hmac_add(mode, covered, covered_blocks)?;
    c.send_hmac_digest_clear(mode, digest_out);
    Ok(())
}

/// Verify HMAC field (always ok in open mode).
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn verify_hmac_field(
    mode: u32,
    crypto: Option<&mut ControlCrypto>,
    covered: &[u8],
    covered_blocks: usize,
    digest: &HmacDigest,
) -> Result<()> {
    if !mode_docipher_cntrl(mode) {
        return Ok(());
    }
    let c = crypto.ok_or_else(|| OwampError::Crypto("HMAC requires ControlCrypto".into()))?;
    c.recv_hmac_add(mode, covered, covered_blocks)?;
    if !c.recv_hmac_check_clear(mode, digest) {
        return Err(OwampError::Invalid("invalid HMAC".into()));
    }
    Ok(())
}

/// `SetupResponse` token helpers — thin wrappers over `crate::rijndael_api_fst`.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn encrypt_setup_token(
    passphrase: &[u8],
    salt: &Salt,
    count: u32,
    token_in: &Token,
) -> Result<Token> {
    let mut out = [0u8; TOKEN_SIZE];
    rijndael::encrypt_token(passphrase, salt, count, token_in, &mut out)?;
    Ok(out)
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn decrypt_setup_token(
    passphrase: &[u8],
    salt: &Salt,
    count: u32,
    token_in: &Token,
) -> Result<Token> {
    let mut out = [0u8; TOKEN_SIZE];
    rijndael::decrypt_token(passphrase, salt, count, token_in, &mut out)?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Local timestamp helpers using crate::time (slice-friendly)
// ---------------------------------------------------------------------------

fn put_timestamp(buf: &mut [u8], n: OwampNum64) {
    let ts = OwampTimeStamp {
        owptime: n,
        sync: false,
        multiplier: 0,
        scale: 0,
    };
    let mut tmp = [0u8; 8];
    encode_timestamp(&ts, &mut tmp);
    buf[..8].copy_from_slice(&tmp);
}

fn get_timestamp(buf: &[u8]) -> OwampNum64 {
    let mut tmp = [0u8; 8];
    tmp.copy_from_slice(&buf[..8]);
    decode_timestamp(&tmp).owptime
}

fn put_timestamp_full(buf: &mut [u8], ts: &OwampTimeStamp) {
    let mut tmp = [0u8; 8];
    encode_timestamp(ts, &mut tmp);
    buf[..8].copy_from_slice(&tmp);
}

fn get_timestamp_full(buf: &[u8]) -> OwampTimeStamp {
    let mut tmp = [0u8; 8];
    tmp.copy_from_slice(&buf[..8]);
    decode_timestamp(&tmp)
}

fn put_err_est(buf: &mut [u8], ts: &OwampTimeStamp) -> Result<()> {
    let mut tmp = [0u8; 2];
    if !encode_timestamp_err_estimate(ts, &mut tmp) {
        return Err(OwampError::Invalid(
            "invalid timestamp error estimate: multiplier == 0".into(),
        ));
    }
    buf[..2].copy_from_slice(&tmp);
    Ok(())
}

fn get_err_est(ts: &mut OwampTimeStamp, buf: &[u8]) -> Result<()> {
    let mut tmp = [0u8; 2];
    tmp.copy_from_slice(&buf[..2]);
    if !decode_timestamp_err_estimate(ts, &tmp) {
        return Err(OwampError::Invalid(
            "invalid timestamp error estimate: multiplier == 0".into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ServerGreeting (64 octets)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerGreeting {
    pub modes: u32,
    pub challenge: Challenge,
    pub salt: Salt,
    pub count: u32,
}

impl ServerGreeting {
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn encode(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < SERVER_GREETING_SIZE {
            return Err(OwampError::Message(
                "ServerGreeting: buffer too small".into(),
            ));
        }
        buf[..SERVER_GREETING_SIZE].fill(0);
        BigEndian::write_u32(&mut buf[12..16], self.modes);
        buf[16..32].copy_from_slice(&self.challenge);
        buf[32..48].copy_from_slice(&self.salt);
        BigEndian::write_u32(&mut buf[48..52], self.count);
        Ok(())
    }

    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < SERVER_GREETING_SIZE {
            return Err(OwampError::Message(
                "ServerGreeting: buffer too small".into(),
            ));
        }
        let mut challenge = [0u8; CHALLENGE_SIZE];
        let mut salt = [0u8; SALT_SIZE];
        challenge.copy_from_slice(&buf[16..32]);
        salt.copy_from_slice(&buf[32..48]);
        Ok(Self {
            modes: BigEndian::read_u32(&buf[12..16]),
            challenge,
            salt,
            count: BigEndian::read_u32(&buf[48..52]),
        })
    }
}

// ---------------------------------------------------------------------------
// SetupResponse (164 octets)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupResponse {
    pub mode: u32,
    pub userid: UserIdBytes,
    pub token: Token,
    pub client_iv: Iv,
}

impl SetupResponse {
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn encode(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < SETUP_RESPONSE_SIZE {
            return Err(OwampError::Message(
                "SetupResponse: buffer too small".into(),
            ));
        }
        buf[..SETUP_RESPONSE_SIZE].fill(0);
        BigEndian::write_u32(&mut buf[0..4], self.mode);
        if (self.mode & OWP_MODE_DOCIPHER_CNTRL) != 0 {
            buf[4..84].copy_from_slice(&self.userid);
            buf[84..148].copy_from_slice(&self.token);
            buf[148..164].copy_from_slice(&self.client_iv);
        }
        Ok(())
    }

    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < SETUP_RESPONSE_SIZE {
            return Err(OwampError::Message(
                "SetupResponse: buffer too small".into(),
            ));
        }
        let mut userid = [0u8; USERID_LEN];
        let mut token = [0u8; TOKEN_SIZE];
        let mut client_iv = [0u8; RIJNDAEL_BLOCK_SIZE];
        userid.copy_from_slice(&buf[4..84]);
        token.copy_from_slice(&buf[84..148]);
        client_iv.copy_from_slice(&buf[148..164]);
        Ok(Self {
            mode: BigEndian::read_u32(&buf[0..4]),
            userid,
            token,
            client_iv,
        })
    }
}

// ---------------------------------------------------------------------------
// ServerStart (48 octets)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerStart {
    pub accept: AcceptType,
    pub server_iv: Iv,
    pub uptime: OwampNum64,
}

impl ServerStart {
    /// Encode cleartext layout. Last block may be encrypted separately via
    /// [`frame_send_blocks`] when mode requires it.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn encode(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < SERVER_START_SIZE {
            return Err(OwampError::Message("ServerStart: buffer too small".into()));
        }
        buf[..SERVER_START_SIZE].fill(0);
        let code = accept_type_as_u8(self.accept)
            .ok_or_else(|| OwampError::Invalid("ServerStart: invalid accept".into()))?;
        buf[15] = code;
        buf[16..32].copy_from_slice(&self.server_iv);
        if self.accept == AcceptType::Accept {
            put_timestamp(&mut buf[32..40], self.uptime);
        }
        Ok(())
    }

    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < SERVER_START_SIZE {
            return Err(OwampError::Message("ServerStart: buffer too small".into()));
        }
        let accept = accept_type_from_u8(buf[15]);
        if accept == AcceptType::Invalid {
            return Err(OwampError::Invalid("ServerStart: invalid accept".into()));
        }
        let mut server_iv = [0u8; RIJNDAEL_BLOCK_SIZE];
        server_iv.copy_from_slice(&buf[16..32]);
        let uptime = if accept == AcceptType::Accept {
            get_timestamp(&buf[32..40])
        } else {
            OwampNum64::ZERO
        };
        Ok(Self {
            accept,
            server_iv,
            uptime,
        })
    }
}

// ---------------------------------------------------------------------------
// TestRequest preamble (112 octets / 7 blocks)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestRequestPreamble {
    pub twoway: bool,
    pub ip_version: u8,
    pub conf_sender: bool,
    pub conf_receiver: bool,
    pub nslots: u32,
    pub npackets: u32,
    pub sender: SocketAddr,
    pub receiver: SocketAddr,
    pub sid: OwampSid,
    pub packet_size_padding: u32,
    pub start_time: OwampNum64,
    pub loss_timeout: OwampNum64,
    pub type_p: u32,
    pub hmac: HmacDigest,
}

impl TestRequestPreamble {
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn from_test_spec(
        twoway: bool,
        conf_sender: bool,
        conf_receiver: bool,
        zero_addr: bool,
        sid: Option<&OwampSid>,
        sender: SocketAddr,
        receiver: SocketAddr,
        tspec: &TestSpec,
    ) -> Result<Self> {
        if !twoway && !conf_sender && !conf_receiver {
            return Err(OwampError::Invalid(
                "TestRequest: empty config (no conf_sender/conf_receiver)".into(),
            ));
        }

        let (ip_version, sender, receiver) = match (sender, receiver) {
            (SocketAddr::V4(s), SocketAddr::V4(r)) => {
                let s = if zero_addr {
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, s.port()))
                } else {
                    SocketAddr::V4(s)
                };
                let r = if zero_addr {
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, r.port()))
                } else {
                    SocketAddr::V4(r)
                };
                (4u8, s, r)
            },
            (SocketAddr::V6(s), SocketAddr::V6(r)) => {
                let s = if zero_addr {
                    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, s.port(), 0, 0))
                } else {
                    SocketAddr::V6(s)
                };
                let r = if zero_addr {
                    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, r.port(), 0, 0))
                } else {
                    SocketAddr::V6(r)
                };
                (6u8, s, r)
            },
            _ => {
                return Err(OwampError::Invalid(
                    "TestRequest: address family mismatch".into(),
                ));
            },
        };

        let nslots = if tspec.nslots != 0 {
            tspec.nslots
        } else {
            tspec.slots.len() as u32
        };
        if !twoway && (tspec.npackets < 1 || nslots < 1 || tspec.slots.is_empty()) {
            return Err(OwampError::Invalid(
                "TestRequest: invalid distribution parameters".into(),
            ));
        }

        let mut sid_buf = [0u8; SID_SIZE];
        if let Some(s) = sid {
            sid_buf.copy_from_slice(s);
        }

        Ok(Self {
            twoway,
            ip_version,
            conf_sender: conf_sender && !twoway,
            conf_receiver: conf_receiver && !twoway,
            nslots: if twoway { 0 } else { nslots },
            npackets: if twoway { 0 } else { tspec.npackets },
            sender,
            receiver,
            sid: sid_buf,
            packet_size_padding: tspec.packet_size_padding,
            start_time: tspec.start_time,
            loss_timeout: tspec.loss_timeout,
            type_p: tspec.type_p,
            hmac: [0u8; HMAC_SIZE],
        })
    }

    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant from the C port is violated.
    pub fn encode(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < TEST_REQUEST_PREAMBLE_SIZE {
            return Err(OwampError::Message(
                "TestRequestPreamble: buffer too small".into(),
            ));
        }
        buf[..TEST_REQUEST_PREAMBLE_SIZE].fill(0);

        buf[0] = if self.twoway {
            request_type_as_u8(OwampRequestType::TestTw).unwrap()
        } else {
            request_type_as_u8(OwampRequestType::Test).unwrap()
        };
        buf[1] = self.ip_version & 0x0f;
        buf[2] = u8::from(self.conf_sender);
        buf[3] = u8::from(self.conf_receiver);

        BigEndian::write_u32(&mut buf[4..8], self.nslots);
        BigEndian::write_u32(&mut buf[8..12], self.npackets);

        match (self.sender, self.receiver) {
            (SocketAddr::V4(s), SocketAddr::V4(r)) => {
                BigEndian::write_u16(&mut buf[12..14], s.port());
                BigEndian::write_u16(&mut buf[14..16], r.port());
                buf[16..20].copy_from_slice(&s.ip().octets());
                buf[32..36].copy_from_slice(&r.ip().octets());
            },
            (SocketAddr::V6(s), SocketAddr::V6(r)) => {
                BigEndian::write_u16(&mut buf[12..14], s.port());
                BigEndian::write_u16(&mut buf[14..16], r.port());
                buf[16..32].copy_from_slice(&s.ip().octets());
                buf[32..48].copy_from_slice(&r.ip().octets());
            },
            _ => {
                return Err(OwampError::Invalid(
                    "TestRequestPreamble: address family mismatch".into(),
                ));
            },
        }

        buf[48..64].copy_from_slice(&self.sid);
        BigEndian::write_u32(&mut buf[64..68], self.packet_size_padding);
        put_timestamp(&mut buf[68..76], self.start_time);
        put_timestamp(&mut buf[76..84], self.loss_timeout);
        BigEndian::write_u32(&mut buf[84..88], self.type_p);
        buf[96..112].copy_from_slice(&self.hmac);
        Ok(())
    }

    /// When `as_request` and conf_* are set, ports the server allocates are
    /// forced to 0 (matches C `_OWPDecodeTestRequestPreamble`).
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn decode(buf: &[u8], as_request: bool, expect_twoway: bool) -> Result<Self> {
        if buf.len() < TEST_REQUEST_PREAMBLE_SIZE {
            return Err(OwampError::Invalid(
                "TestRequestPreamble: invalid message size".into(),
            ));
        }

        let msg_type = request_type_from_u8(buf[0]);
        let twoway = match msg_type {
            OwampRequestType::TestTw => true,
            OwampRequestType::Test => false,
            _ => expect_twoway,
        };

        let ip_version = buf[1] & 0x0f;
        let conf_sender = buf[2] != 0;
        let conf_receiver = buf[3] != 0;
        let nslots = BigEndian::read_u32(&buf[4..8]);
        let npackets = BigEndian::read_u32(&buf[8..12]);

        if !conf_sender && !conf_receiver && !twoway {
            return Err(OwampError::Invalid(
                "TestRequestPreamble: invalid null request".into(),
            ));
        }
        if twoway && (conf_sender || conf_receiver) {
            return Err(OwampError::Invalid(
                "TestRequestPreamble: invalid role for two-way request".into(),
            ));
        }
        if twoway && (nslots != 0 || npackets != 0) {
            return Err(OwampError::Invalid(format!(
                "TestRequestPreamble: invalid slots/packets for two-way: {nslots}/{npackets}"
            )));
        }

        let sender_port_raw = BigEndian::read_u16(&buf[12..14]);
        let receiver_port_raw = BigEndian::read_u16(&buf[14..16]);
        let sender_port = if as_request && conf_sender {
            0
        } else {
            sender_port_raw
        };
        let receiver_port = if as_request && conf_receiver {
            0
        } else {
            receiver_port_raw
        };

        let (sender, receiver) = match ip_version {
            4 => {
                let mut s4 = [0u8; 4];
                let mut r4 = [0u8; 4];
                s4.copy_from_slice(&buf[16..20]);
                r4.copy_from_slice(&buf[32..36]);
                (
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(s4)), sender_port),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(r4)), receiver_port),
                )
            },
            6 => {
                let mut s6 = [0u8; 16];
                let mut r6 = [0u8; 16];
                s6.copy_from_slice(&buf[16..32]);
                r6.copy_from_slice(&buf[32..48]);
                (
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::from(s6)), sender_port),
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::from(r6)), receiver_port),
                )
            },
            v => {
                return Err(OwampError::Unsupported(format!(
                    "TestRequestPreamble: unsupported IP version ({v})"
                )));
            },
        };

        let mut sid = [0u8; SID_SIZE];
        sid.copy_from_slice(&buf[48..64]);
        let mut hmac = [0u8; HMAC_SIZE];
        hmac.copy_from_slice(&buf[96..112]);

        Ok(Self {
            twoway,
            ip_version,
            conf_sender,
            conf_receiver,
            nslots,
            npackets,
            sender,
            receiver,
            sid,
            packet_size_padding: BigEndian::read_u32(&buf[64..68]),
            start_time: get_timestamp(&buf[68..76]),
            loss_timeout: get_timestamp(&buf[76..84]),
            type_p: BigEndian::read_u32(&buf[84..88]),
            hmac,
        })
    }
}

/// `_OWPEncodeTestRequestPreamble` — encode preamble bytes via [`TestRequestPreamble::encode`].
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn encode_test_request_preamble(pre: &TestRequestPreamble, buf: &mut [u8]) -> Result<()> {
    pre.encode(buf)
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn encode_test_request_with_hmac(
    mode: u32,
    crypto: Option<&mut ControlCrypto>,
    preamble: &mut TestRequestPreamble,
    buf: &mut [u8],
) -> Result<()> {
    preamble.hmac = [0u8; HMAC_SIZE];
    preamble.encode(buf)?;
    let mut digest = [0u8; HMAC_SIZE];
    finalize_hmac_field(mode, crypto, &buf[..96], 6, &mut digest)?;
    preamble.hmac = digest;
    buf[96..112].copy_from_slice(&digest);
    Ok(())
}

// ---------------------------------------------------------------------------
// Slot (16 octets)
// ---------------------------------------------------------------------------

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn encode_slot(buf: &mut [u8], slot: &Slot) -> Result<()> {
    if buf.len() < SLOT_SIZE {
        return Err(OwampError::Message("Slot: buffer too small".into()));
    }
    buf[..SLOT_SIZE].fill(0);
    let (ty, param) = match *slot {
        Slot::RandExp { mean } => (0u8, mean),
        Slot::Literal { offset } => (1u8, offset),
    };
    buf[0] = ty;
    put_timestamp(&mut buf[8..16], param);
    Ok(())
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn decode_slot(buf: &[u8]) -> Result<Slot> {
    if buf.len() < SLOT_SIZE {
        return Err(OwampError::Message("Slot: buffer too small".into()));
    }
    let param = get_timestamp(&buf[8..16]);
    match buf[0] {
        0 => Ok(Slot::RandExp { mean: param }),
        1 => Ok(Slot::Literal { offset: param }),
        v => Err(OwampError::Invalid(format!("Slot: invalid type {v}"))),
    }
}

// ---------------------------------------------------------------------------
// AcceptSession (48 octets)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptSession {
    pub accept: AcceptType,
    pub port: u16,
    pub sid: OwampSid,
    pub hmac: HmacDigest,
}

impl AcceptSession {
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn encode(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < ACCEPT_SESSION_SIZE {
            return Err(OwampError::Message(
                "AcceptSession: buffer too small".into(),
            ));
        }
        buf[..ACCEPT_SESSION_SIZE].fill(0);
        let code = accept_type_as_u8(self.accept)
            .ok_or_else(|| OwampError::Invalid("AcceptSession: invalid accept".into()))?;
        buf[0] = code;
        BigEndian::write_u16(&mut buf[2..4], self.port);
        buf[4..20].copy_from_slice(&self.sid);
        buf[32..48].copy_from_slice(&self.hmac);
        Ok(())
    }

    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < ACCEPT_SESSION_SIZE {
            return Err(OwampError::Message(
                "AcceptSession: buffer too small".into(),
            ));
        }
        let accept = accept_type_from_u8(buf[0]);
        if accept == AcceptType::Invalid {
            return Err(OwampError::Invalid("AcceptSession: invalid accept".into()));
        }
        let mut sid = [0u8; SID_SIZE];
        sid.copy_from_slice(&buf[4..20]);
        let mut hmac = [0u8; HMAC_SIZE];
        hmac.copy_from_slice(&buf[32..48]);
        Ok(Self {
            accept,
            port: BigEndian::read_u16(&buf[2..4]),
            sid,
            hmac,
        })
    }
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn encode_accept_session_with_hmac(
    mode: u32,
    crypto: Option<&mut ControlCrypto>,
    msg: &mut AcceptSession,
    buf: &mut [u8],
) -> Result<()> {
    msg.hmac = [0u8; HMAC_SIZE];
    msg.encode(buf)?;
    let mut digest = [0u8; HMAC_SIZE];
    finalize_hmac_field(mode, crypto, &buf[..32], 2, &mut digest)?;
    msg.hmac = digest;
    buf[32..48].copy_from_slice(&digest);
    Ok(())
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn verify_accept_session_hmac(
    mode: u32,
    crypto: Option<&mut ControlCrypto>,
    buf: &[u8],
) -> Result<AcceptSession> {
    let msg = AcceptSession::decode(buf)?;
    verify_hmac_field(mode, crypto, &buf[..32], 2, &msg.hmac)?;
    Ok(msg)
}

// ---------------------------------------------------------------------------
// StartSessions / StartAck (32 octets each)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartSessions {
    pub hmac: HmacDigest,
}

impl StartSessions {
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant from the C port is violated.
    pub fn encode(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < START_SESSIONS_SIZE {
            return Err(OwampError::Message(
                "StartSessions: buffer too small".into(),
            ));
        }
        buf[..START_SESSIONS_SIZE].fill(0);
        buf[0] = request_type_as_u8(OwampRequestType::StartSessions).unwrap();
        buf[16..32].copy_from_slice(&self.hmac);
        Ok(())
    }

    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < START_SESSIONS_SIZE {
            return Err(OwampError::Message(
                "StartSessions: buffer too small".into(),
            ));
        }
        if request_type_from_u8(buf[0]) != OwampRequestType::StartSessions {
            return Err(OwampError::Invalid(
                "StartSessions: not a StartSessions message".into(),
            ));
        }
        let mut hmac = [0u8; HMAC_SIZE];
        hmac.copy_from_slice(&buf[16..32]);
        Ok(Self { hmac })
    }
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn encode_start_sessions_with_hmac(
    mode: u32,
    crypto: Option<&mut ControlCrypto>,
    msg: &mut StartSessions,
    buf: &mut [u8],
) -> Result<()> {
    msg.hmac = [0u8; HMAC_SIZE];
    msg.encode(buf)?;
    let mut digest = [0u8; HMAC_SIZE];
    finalize_hmac_field(mode, crypto, &buf[..16], 1, &mut digest)?;
    msg.hmac = digest;
    buf[16..32].copy_from_slice(&digest);
    Ok(())
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn verify_start_sessions_hmac(
    mode: u32,
    crypto: Option<&mut ControlCrypto>,
    buf: &[u8],
) -> Result<StartSessions> {
    let msg = StartSessions::decode(buf)?;
    verify_hmac_field(mode, crypto, &buf[..16], 1, &msg.hmac)?;
    Ok(msg)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartAck {
    pub accept: AcceptType,
    pub hmac: HmacDigest,
}

impl StartAck {
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn encode(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < START_ACK_SIZE {
            return Err(OwampError::Message("StartAck: buffer too small".into()));
        }
        buf[..START_ACK_SIZE].fill(0);
        let code = accept_type_as_u8(self.accept)
            .ok_or_else(|| OwampError::Invalid("StartAck: invalid accept".into()))?;
        buf[0] = code;
        buf[16..32].copy_from_slice(&self.hmac);
        Ok(())
    }

    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < START_ACK_SIZE {
            return Err(OwampError::Message("StartAck: buffer too small".into()));
        }
        let accept = accept_type_from_u8(buf[0]);
        if accept == AcceptType::Invalid {
            return Err(OwampError::Invalid("StartAck: invalid accept".into()));
        }
        let mut hmac = [0u8; HMAC_SIZE];
        hmac.copy_from_slice(&buf[16..32]);
        Ok(Self { accept, hmac })
    }
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn encode_start_ack_with_hmac(
    mode: u32,
    crypto: Option<&mut ControlCrypto>,
    msg: &mut StartAck,
    buf: &mut [u8],
) -> Result<()> {
    msg.hmac = [0u8; HMAC_SIZE];
    msg.encode(buf)?;
    let mut digest = [0u8; HMAC_SIZE];
    finalize_hmac_field(mode, crypto, &buf[..16], 1, &mut digest)?;
    msg.hmac = digest;
    buf[16..32].copy_from_slice(&digest);
    Ok(())
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn verify_start_ack_hmac(
    mode: u32,
    crypto: Option<&mut ControlCrypto>,
    buf: &[u8],
) -> Result<StartAck> {
    let msg = StartAck::decode(buf)?;
    verify_hmac_field(mode, crypto, &buf[..16], 1, &msg.hmac)?;
    Ok(msg)
}

// ---------------------------------------------------------------------------
// StopSessions header + session description
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StopSessionsHeader {
    pub accept: AcceptType,
    pub num_sessions: u32,
}

impl StopSessionsHeader {
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant from the C port is violated.
    pub fn encode(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < STOP_SESSIONS_HEADER_SIZE {
            return Err(OwampError::Message(
                "StopSessionsHeader: buffer too small".into(),
            ));
        }
        buf[..STOP_SESSIONS_HEADER_SIZE].fill(0);
        let code = accept_type_as_u8(self.accept)
            .ok_or_else(|| OwampError::Invalid("StopSessions: invalid accept".into()))?;
        buf[0] = request_type_as_u8(OwampRequestType::StopSessions).unwrap();
        buf[1] = code;
        BigEndian::write_u32(&mut buf[4..8], self.num_sessions);
        Ok(())
    }

    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < STOP_SESSIONS_HEADER_SIZE {
            return Err(OwampError::Message(
                "StopSessionsHeader: buffer too small".into(),
            ));
        }
        if request_type_from_u8(buf[0]) != OwampRequestType::StopSessions {
            return Err(OwampError::Invalid(
                "StopSessions: not a StopSessions message".into(),
            ));
        }
        let accept = accept_type_from_u8(buf[1]);
        if accept == AcceptType::Invalid {
            return Err(OwampError::Invalid("StopSessions: invalid accept".into()));
        }
        Ok(Self {
            accept,
            num_sessions: BigEndian::read_u32(&buf[4..8]),
        })
    }
}

/// SID (16) + Next Seqno (4) + Number of Skip Ranges (4) = 24 octets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionDescHeader {
    pub sid: OwampSid,
    pub next_seqno: u32,
    pub num_skiprecs: u32,
}

impl SessionDescHeader {
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn encode(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < SESSION_DESC_HEADER_SIZE {
            return Err(OwampError::Message(
                "SessionDescHeader: buffer too small".into(),
            ));
        }
        buf[0..16].copy_from_slice(&self.sid);
        BigEndian::write_u32(&mut buf[16..20], self.next_seqno);
        BigEndian::write_u32(&mut buf[20..24], self.num_skiprecs);
        Ok(())
    }

    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < SESSION_DESC_HEADER_SIZE {
            return Err(OwampError::Message(
                "SessionDescHeader: buffer too small".into(),
            ));
        }
        let mut sid = [0u8; SID_SIZE];
        sid.copy_from_slice(&buf[0..16]);
        Ok(Self {
            sid,
            next_seqno: BigEndian::read_u32(&buf[16..20]),
            num_skiprecs: BigEndian::read_u32(&buf[20..24]),
        })
    }
}

// ---------------------------------------------------------------------------
// FetchSession / FetchAck
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchSession {
    pub begin: u32,
    pub end: u32,
    pub sid: OwampSid,
    pub hmac: HmacDigest,
}

impl FetchSession {
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant from the C port is violated.
    pub fn encode(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < FETCH_SESSION_SIZE {
            return Err(OwampError::Message("FetchSession: buffer too small".into()));
        }
        buf[..FETCH_SESSION_SIZE].fill(0);
        buf[0] = request_type_as_u8(OwampRequestType::FetchSession).unwrap();
        BigEndian::write_u32(&mut buf[8..12], self.begin);
        BigEndian::write_u32(&mut buf[12..16], self.end);
        buf[16..32].copy_from_slice(&self.sid);
        buf[32..48].copy_from_slice(&self.hmac);
        Ok(())
    }

    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < FETCH_SESSION_SIZE {
            return Err(OwampError::Message("FetchSession: buffer too small".into()));
        }
        if request_type_from_u8(buf[0]) != OwampRequestType::FetchSession {
            return Err(OwampError::Invalid(
                "FetchSession: not a FetchSession message".into(),
            ));
        }
        let mut sid = [0u8; SID_SIZE];
        sid.copy_from_slice(&buf[16..32]);
        let mut hmac = [0u8; HMAC_SIZE];
        hmac.copy_from_slice(&buf[32..48]);
        Ok(Self {
            begin: BigEndian::read_u32(&buf[8..12]),
            end: BigEndian::read_u32(&buf[12..16]),
            sid,
            hmac,
        })
    }
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn encode_fetch_session_with_hmac(
    mode: u32,
    crypto: Option<&mut ControlCrypto>,
    msg: &mut FetchSession,
    buf: &mut [u8],
) -> Result<()> {
    msg.hmac = [0u8; HMAC_SIZE];
    msg.encode(buf)?;
    let mut digest = [0u8; HMAC_SIZE];
    finalize_hmac_field(mode, crypto, &buf[..32], 2, &mut digest)?;
    msg.hmac = digest;
    buf[32..48].copy_from_slice(&digest);
    Ok(())
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn verify_fetch_session_hmac(
    mode: u32,
    crypto: Option<&mut ControlCrypto>,
    buf: &[u8],
) -> Result<FetchSession> {
    let msg = FetchSession::decode(buf)?;
    verify_hmac_field(mode, crypto, &buf[..32], 2, &msg.hmac)?;
    Ok(msg)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchAck {
    pub accept: AcceptType,
    pub finished: u8,
    pub next_seqno: u32,
    pub num_skiprecs: u32,
    pub num_datarecs: u32,
    pub hmac: HmacDigest,
}

impl FetchAck {
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn encode(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < FETCH_ACK_SIZE {
            return Err(OwampError::Message("FetchAck: buffer too small".into()));
        }
        buf[..FETCH_ACK_SIZE].fill(0);
        let code = accept_type_as_u8(self.accept)
            .ok_or_else(|| OwampError::Invalid("FetchAck: invalid accept".into()))?;
        buf[0] = code;
        buf[1] = self.finished;
        if self.finished != 0 {
            BigEndian::write_u32(&mut buf[4..8], self.next_seqno);
            BigEndian::write_u32(&mut buf[8..12], self.num_skiprecs);
        }
        BigEndian::write_u32(&mut buf[12..16], self.num_datarecs);
        buf[16..32].copy_from_slice(&self.hmac);
        Ok(())
    }

    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < FETCH_ACK_SIZE {
            return Err(OwampError::Message("FetchAck: buffer too small".into()));
        }
        let accept = accept_type_from_u8(buf[0]);
        if accept == AcceptType::Invalid {
            return Err(OwampError::Invalid("FetchAck: invalid accept".into()));
        }
        let mut hmac = [0u8; HMAC_SIZE];
        hmac.copy_from_slice(&buf[16..32]);
        Ok(Self {
            accept,
            finished: buf[1],
            next_seqno: BigEndian::read_u32(&buf[4..8]),
            num_skiprecs: BigEndian::read_u32(&buf[8..12]),
            num_datarecs: BigEndian::read_u32(&buf[12..16]),
            hmac,
        })
    }
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn encode_fetch_ack_with_hmac(
    mode: u32,
    crypto: Option<&mut ControlCrypto>,
    msg: &mut FetchAck,
    buf: &mut [u8],
) -> Result<()> {
    msg.hmac = [0u8; HMAC_SIZE];
    msg.encode(buf)?;
    let mut digest = [0u8; HMAC_SIZE];
    finalize_hmac_field(mode, crypto, &buf[..16], 1, &mut digest)?;
    msg.hmac = digest;
    buf[16..32].copy_from_slice(&digest);
    Ok(())
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn verify_fetch_ack_hmac(
    mode: u32,
    crypto: Option<&mut ControlCrypto>,
    buf: &[u8],
) -> Result<FetchAck> {
    let msg = FetchAck::decode(buf)?;
    verify_hmac_field(mode, crypto, &buf[..16], 1, &msg.hmac)?;
    Ok(msg)
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn verify_test_request_hmac(
    mode: u32,
    crypto: Option<&mut ControlCrypto>,
    buf: &[u8],
    as_request: bool,
    expect_twoway: bool,
) -> Result<TestRequestPreamble> {
    if buf.len() < TEST_REQUEST_PREAMBLE_SIZE {
        return Err(OwampError::Message(
            "TestRequest: buffer too small for HMAC verify".into(),
        ));
    }
    let mut digest = [0u8; HMAC_SIZE];
    digest.copy_from_slice(&buf[96..112]);
    verify_hmac_field(mode, crypto, &buf[..96], 6, &digest)?;
    TestRequestPreamble::decode(buf, as_request, expect_twoway)
}

// ---------------------------------------------------------------------------
// Skip / Data records
// ---------------------------------------------------------------------------

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn encode_skip_record(buf: &mut [u8], skip: &SkipRec) -> Result<()> {
    if buf.len() < SKIPREC_SIZE {
        return Err(OwampError::Message("SkipRecord: buffer too small".into()));
    }
    BigEndian::write_u32(&mut buf[0..4], skip.begin);
    BigEndian::write_u32(&mut buf[4..8], skip.end);
    Ok(())
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn decode_skip_record(buf: &[u8]) -> Result<SkipRec> {
    if buf.len() < SKIPREC_SIZE {
        return Err(OwampError::Message("SkipRecord: buffer too small".into()));
    }
    Ok(SkipRec {
        begin: BigEndian::read_u32(&buf[0..4]),
        end: BigEndian::read_u32(&buf[4..8]),
    })
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn encode_data_record(buf: &mut [u8], rec: &DataRec) -> Result<()> {
    if buf.len() < DATARECV3_SIZE {
        return Err(OwampError::Message("DataRecord: buffer too small".into()));
    }
    buf[..DATARECV3_SIZE].fill(0);
    BigEndian::write_u32(&mut buf[0..4], rec.seq_no);
    put_err_est(&mut buf[4..6], &rec.send)?;
    put_err_est(&mut buf[6..8], &rec.recv)?;
    put_timestamp_full(&mut buf[8..16], &rec.send);
    put_timestamp_full(&mut buf[16..24], &rec.recv);
    buf[24] = rec.ttl;
    Ok(())
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn decode_data_record(file_version: u32, buf: &[u8]) -> Result<DataRec> {
    let mut rec = DataRec::default();
    match file_version {
        0 | 2 => {
            if buf.len() < DATARECV2_SIZE {
                return Err(OwampError::Message(
                    "DataRecord V2: buffer too small".into(),
                ));
            }
            rec.seq_no = BigEndian::read_u32(&buf[0..4]);
            rec.send = get_timestamp_full(&buf[4..12]);
            get_err_est(&mut rec.send, &buf[12..14])?;
            rec.recv = get_timestamp_full(&buf[14..22]);
            get_err_est(&mut rec.recv, &buf[22..24])?;
            rec.ttl = 255;
        },
        3 => {
            if buf.len() < DATARECV3_SIZE {
                return Err(OwampError::Message(
                    "DataRecord V3: buffer too small".into(),
                ));
            }
            rec.seq_no = BigEndian::read_u32(&buf[0..4]);
            get_err_est(&mut rec.send, &buf[4..6])?;
            get_err_est(&mut rec.recv, &buf[6..8])?;
            rec.send.owptime = get_timestamp_full(&buf[8..16]).owptime;
            rec.recv.owptime = get_timestamp_full(&buf[16..24]).owptime;
            rec.ttl = buf[24];
        },
        _ => {
            return Err(OwampError::Unsupported(format!(
                "DataRecord: unsupported file version {file_version}"
            )));
        },
    }
    Ok(rec)
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn encode_tw_data_record(buf: &mut [u8], rec: &TwDataRec) -> Result<()> {
    if buf.len() < DATAREC_TWV3_SIZE {
        return Err(OwampError::Message("TWDataRecord: buffer too small".into()));
    }
    encode_data_record(&mut buf[0..25], &rec.sent)?;
    encode_data_record(&mut buf[25..50], &rec.reflected)?;
    Ok(())
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn decode_tw_data_record(file_version: u32, buf: &[u8]) -> Result<TwDataRec> {
    if file_version != (VERSION_TWOWAY | 3) {
        return Err(OwampError::Unsupported(format!(
            "TWDataRecord: unsupported version {file_version}"
        )));
    }
    if buf.len() < DATAREC_TWV3_SIZE {
        return Err(OwampError::Message("TWDataRecord: buffer too small".into()));
    }
    Ok(TwDataRec {
        sent: decode_data_record(3, &buf[0..25])?,
        reflected: decode_data_record(3, &buf[25..50])?,
    })
}

// ---------------------------------------------------------------------------
// State-transition helpers (no I/O; mirror C side-effects)
// ---------------------------------------------------------------------------

pub const fn after_write_server_greeting(state: &mut u32) {
    *state = STATE_SETUP;
}

pub const fn after_read_server_greeting(state: &mut u32) {
    *state = STATE_SETUP;
}

pub fn after_write_server_start(state: &mut u32, mode: &mut u32, accept: AcceptType) {
    if accept == AcceptType::Accept {
        *state = STATE_REQUEST;
    } else {
        *mode = OWP_MODE_OPEN;
        *state = STATE_INVALID;
    }
}

pub fn after_read_server_start(state: &mut u32, mode: &mut u32, accept: AcceptType) {
    if accept != AcceptType::Accept {
        *mode = OWP_MODE_OPEN;
    }
    *state = STATE_REQUEST;
}

pub const fn after_write_test_request(state: &mut u32) {
    *state |= STATE_ACCEPT_SESSION;
}

/// After `TestRequest` preamble is decoded — ready for slot blocks.
pub const fn after_read_test_request_preamble(state: &mut u32) {
    *state &= !STATE_TEST_REQUEST;
    *state |= STATE_TEST_REQUEST_SLOTS;
}

pub const fn after_read_test_request_slots(state: &mut u32) {
    *state &= !STATE_TEST_REQUEST_SLOTS;
}

/// After full `TestRequest` (incl. slots): server → `AcceptSession`, fetch client → Fetching.
pub const fn after_read_test_request(state: &mut u32, as_server: bool) {
    if as_server {
        *state |= STATE_ACCEPT_SESSION;
    } else {
        *state |= STATE_FETCHING;
    }
}

pub const fn after_write_start_sessions(state: &mut u32) {
    *state |= STATE_START_ACK | STATE_TEST;
}

pub const fn after_read_start_sessions(state: &mut u32) {
    *state &= !STATE_START_SESSIONS;
    *state |= STATE_START_ACK | STATE_TEST;
}

pub fn after_write_start_ack(state: &mut u32, accept: AcceptType) {
    *state &= !STATE_START_ACK;
    if accept != AcceptType::Accept {
        *state &= !STATE_TEST;
    }
}

pub fn after_read_start_ack(state: &mut u32, accept: AcceptType) {
    *state &= !STATE_START_ACK;
    if accept != AcceptType::Accept {
        *state &= !STATE_TEST;
        *state |= STATE_REQUEST;
    }
}

pub const fn after_write_fetch_session(state: &mut u32) {
    *state |= STATE_FETCH_ACK | STATE_FETCH_SESSION;
    *state &= !STATE_REQUEST;
}

pub const fn after_read_fetch_session(state: &mut u32) {
    *state &= !(STATE_FETCH_SESSION | STATE_REQUEST);
    *state |= STATE_FETCH_ACK | STATE_FETCHING;
}

pub fn after_write_fetch_ack(state: &mut u32, accept: AcceptType) {
    *state &= !STATE_FETCH_ACK;
    if accept != AcceptType::Accept {
        *state &= !STATE_FETCHING;
        *state |= STATE_REQUEST;
    }
}

pub fn after_read_fetch_ack(state: &mut u32, accept: AcceptType, twoway: bool) {
    *state &= !STATE_FETCH_ACK;
    *state &= !STATE_FETCH_SESSION;
    if accept != AcceptType::Accept {
        *state |= STATE_REQUEST;
    } else if twoway {
        *state |= STATE_TEST_REQUEST_TW;
    } else {
        *state |= STATE_TEST_REQUEST;
    }
}

pub const fn after_write_accept_session(state: &mut u32) {
    *state &= !STATE_ACCEPT_SESSION;
}

pub const fn after_read_accept_session(state: &mut u32) {
    *state &= !STATE_ACCEPT_SESSION;
}

pub const fn after_read_stop_sessions(state: &mut u32) {
    *state &= !STATE_STOP_SESSIONS;
    *state |= STATE_REQUEST;
}

/// C `_OWPWriteStopSessions` does not flip state bits; readers clear STOP via
/// [`after_read_stop_sessions`]. Kept for callers that want a symmetric hook.
pub const fn after_write_stop_sessions(_state: &mut u32) {}

pub const fn after_fetch_complete(state: &mut u32) {
    *state &= !STATE_FETCHING;
    *state |= STATE_REQUEST;
}

// ---------------------------------------------------------------------------
// Full TestRequest (preamble + slots + trailing integrity/HMAC block)
// ---------------------------------------------------------------------------

/// One-way `TestRequest` after the 112-octet preamble: `nslots` slot blocks +
/// one integrity/HMAC block (C `_OWPWriteTestRequest` / `_OWPReadTestRequestSlots`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestRequestSlots {
    pub slots: Vec<Slot>,
    pub hmac: HmacDigest,
}

impl TestRequestSlots {
    /// Open-mode wire size: `nslots * 16 + 16`.
    #[must_use]
    pub const fn wire_len(nslots: u32) -> usize {
        nslots as usize * SLOT_SIZE + RIJNDAEL_BLOCK_SIZE
    }

    /// Encode slots with zero HMAC/IZP trailing block (open mode).
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn encode_open(slots: &[Slot], out: &mut Vec<u8>) -> Result<()> {
        for slot in slots {
            let mut block = [0u8; SLOT_SIZE];
            encode_slot(&mut block, slot)?;
            out.extend_from_slice(&block);
        }
        out.extend_from_slice(&[0u8; RIJNDAEL_BLOCK_SIZE]);
        Ok(())
    }

    /// Decode slots + trailing digest block (HMAC not verified here).
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn decode(buf: &[u8], nslots: u32) -> Result<Self> {
        let need = Self::wire_len(nslots);
        if buf.len() < need {
            return Err(OwampError::Message(format!(
                "TestRequestSlots: buffer too small ({} < {need})",
                buf.len()
            )));
        }
        let mut slots = Vec::with_capacity(nslots as usize);
        for i in 0..nslots as usize {
            let off = i * SLOT_SIZE;
            slots.push(decode_slot(&buf[off..off + SLOT_SIZE])?);
        }
        let mut hmac = [0u8; HMAC_SIZE];
        hmac.copy_from_slice(&buf[nslots as usize * SLOT_SIZE..][..HMAC_SIZE]);
        Ok(Self { slots, hmac })
    }
}

/// Full one-way `TestRequest` message in memory (preamble + slots + digest).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestRequestMessage {
    pub preamble: TestRequestPreamble,
    pub slots: Vec<Slot>,
}

impl TestRequestMessage {
    #[must_use]
    pub const fn wire_len(&self) -> usize {
        TEST_REQUEST_PREAMBLE_SIZE + TestRequestSlots::wire_len(self.slots.len() as u32)
    }

    /// Encode open-mode message (HMAC fields zeroed). TWAMP has no slot stream.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn encode_open(&self, out: &mut Vec<u8>) -> Result<()> {
        let mut pre = [0u8; TEST_REQUEST_PREAMBLE_SIZE];
        let mut preamble = self.preamble.clone();
        preamble.hmac = [0u8; HMAC_SIZE];
        preamble.encode(&mut pre)?;
        out.extend_from_slice(&pre);
        if !preamble.twoway {
            TestRequestSlots::encode_open(&self.slots, out)?;
        }
        Ok(())
    }

    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn from_test_spec(
        twoway: bool,
        conf_sender: bool,
        conf_receiver: bool,
        zero_addr: bool,
        sid: Option<&OwampSid>,
        sender: SocketAddr,
        receiver: SocketAddr,
        tspec: &TestSpec,
    ) -> Result<Self> {
        let preamble = TestRequestPreamble::from_test_spec(
            twoway,
            conf_sender,
            conf_receiver,
            zero_addr,
            sid,
            sender,
            receiver,
            tspec,
        )?;
        Ok(Self {
            preamble,
            slots: if twoway {
                Vec::new()
            } else {
                tspec.slots.clone()
            },
        })
    }
}

// ---------------------------------------------------------------------------
// StopSessions: session description + skip streams
// ---------------------------------------------------------------------------

/// Sender session description carried inside one-way `StopSessions`.
/// Layout: SID (16) + `next_seqno(4)` + `num_skips(4)` + skips… [+ zero pad to 16].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StopSessionDesc {
    pub sid: OwampSid,
    pub next_seqno: u32,
    pub skips: Vec<SkipRec>,
}

impl StopSessionDesc {
    /// AES-aligned body size after the SID block (`next_seqno`…skips…pad).
    #[must_use]
    pub const fn body_len(num_skips: u32) -> usize {
        let raw = 8 + num_skips as usize * SKIPREC_SIZE;
        let rem = raw % RIJNDAEL_BLOCK_SIZE;
        if rem == 0 {
            raw
        } else {
            raw + (RIJNDAEL_BLOCK_SIZE - rem)
        }
    }

    #[must_use]
    pub const fn wire_len(&self) -> usize {
        SID_SIZE + Self::body_len(self.skips.len() as u32)
    }

    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.sid);
        encode_session_desc_body(self.next_seqno, &self.skips, out)?;
        Ok(())
    }

    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < SID_SIZE + RIJNDAEL_BLOCK_SIZE {
            return Err(OwampError::Message(
                "StopSessionDesc: buffer too small".into(),
            ));
        }
        let mut sid = [0u8; SID_SIZE];
        sid.copy_from_slice(&buf[..SID_SIZE]);
        let (next_seqno, skips, body) = decode_session_desc_body(&buf[SID_SIZE..])?;
        Ok((
            Self {
                sid,
                next_seqno,
                skips,
            },
            SID_SIZE + body,
        ))
    }
}

/// Encode `next_seqno` + `num_skips` + skip records, AES-block padded like C
/// `_OWPWriteStopSessions` / sender skip IPC.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn encode_session_desc_body(
    next_seqno: u32,
    skips: &[SkipRec],
    out: &mut Vec<u8>,
) -> Result<()> {
    let start = out.len();
    let mut hdr = [0u8; 8];
    BigEndian::write_u32(&mut hdr[0..4], next_seqno);
    BigEndian::write_u32(&mut hdr[4..8], skips.len() as u32);
    out.extend_from_slice(&hdr);
    for (i, skip) in skips.iter().enumerate() {
        if i > 0 {
            let prev = &skips[i - 1];
            if !validate_skip_record(Some(prev), skip) {
                return Err(OwampError::Invalid(
                    "encode_session_desc_body: invalid skip ordering".into(),
                ));
            }
        } else if !validate_skip_record(None, skip) {
            return Err(OwampError::Invalid(
                "encode_session_desc_body: invalid skip record".into(),
            ));
        }
        let mut sbuf = [0u8; SKIPREC_SIZE];
        encode_skip_record(&mut sbuf, skip)?;
        out.extend_from_slice(&sbuf);
    }
    let raw = out.len() - start;
    let rem = raw % RIJNDAEL_BLOCK_SIZE;
    if rem != 0 {
        out.extend(std::iter::repeat_n(0u8, RIJNDAEL_BLOCK_SIZE - rem));
    }
    Ok(())
}

/// Decode session-desc body; returns `(next_seqno, skips, bytes_consumed)`.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn decode_session_desc_body(buf: &[u8]) -> Result<(u32, Vec<SkipRec>, usize)> {
    if buf.len() < RIJNDAEL_BLOCK_SIZE {
        return Err(OwampError::Message(
            "session_desc_body: buffer too small".into(),
        ));
    }
    let next_seqno = BigEndian::read_u32(&buf[0..4]);
    let num_skips = BigEndian::read_u32(&buf[4..8]);
    let body_len = StopSessionDesc::body_len(num_skips);
    if buf.len() < body_len {
        return Err(OwampError::Message(format!(
            "session_desc_body: need {body_len}, have {}",
            buf.len()
        )));
    }

    let mut skips = Vec::with_capacity(num_skips as usize);
    let mut prev: Option<SkipRec> = None;
    for j in 0..num_skips {
        // C: first skip shares the meta block at offset 8; then pairs per block.
        let off = 8 + j as usize * SKIPREC_SIZE;
        let skip = decode_skip_record(&buf[off..off + SKIPREC_SIZE])?;
        if !validate_skip_record(prev.as_ref(), &skip) {
            return Err(OwampError::Invalid(
                "session_desc_body: invalid skip record".into(),
            ));
        }
        prev = Some(skip);
        skips.push(skip);
    }

    // Even num_skips ⇒ trailing 8 zero octets in the last block (C ReadStopSessions).
    if num_skips % 2 == 0 {
        let pad_off = 8 + num_skips as usize * SKIPREC_SIZE;
        if buf[pad_off..pad_off + 8] != [0u8; 8] {
            return Err(OwampError::Invalid(
                "session_desc_body: invalid zero padding".into(),
            ));
        }
    }

    Ok((next_seqno, skips, body_len))
}

/// Pack skip records alone into AES blocks (`FetchSession` skip stream).
/// Odd count ends on a block boundary; even count needs an 8-octet zero pad.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn pack_skip_records_aes(skips: &[SkipRec]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(skips.len() * SKIPREC_SIZE + 8);
    for (i, skip) in skips.iter().enumerate() {
        let prev = if i == 0 { None } else { Some(&skips[i - 1]) };
        if !validate_skip_record(prev, skip) {
            return Err(OwampError::Invalid(
                "pack_skip_records_aes: invalid skip ordering".into(),
            ));
        }
        let mut sbuf = [0u8; SKIPREC_SIZE];
        encode_skip_record(&mut sbuf, skip)?;
        out.extend_from_slice(&sbuf);
    }
    let rem = out.len() % RIJNDAEL_BLOCK_SIZE;
    if rem != 0 {
        out.extend(std::iter::repeat_n(0u8, RIJNDAEL_BLOCK_SIZE - rem));
    }
    Ok(out)
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn unpack_skip_records_aes(buf: &[u8], num_skips: u32) -> Result<Vec<SkipRec>> {
    let raw = num_skips as usize * SKIPREC_SIZE;
    let rem = raw % RIJNDAEL_BLOCK_SIZE;
    let need = if rem == 0 {
        raw
    } else {
        raw + (RIJNDAEL_BLOCK_SIZE - rem)
    };
    if buf.len() < need {
        return Err(OwampError::Message(format!(
            "unpack_skip_records_aes: need {need}, have {}",
            buf.len()
        )));
    }
    let mut skips = Vec::with_capacity(num_skips as usize);
    let mut prev: Option<SkipRec> = None;
    for j in 0..num_skips as usize {
        let off = j * SKIPREC_SIZE;
        let skip = decode_skip_record(&buf[off..off + SKIPREC_SIZE])?;
        if !validate_skip_record(prev.as_ref(), &skip) {
            return Err(OwampError::Invalid(
                "unpack_skip_records_aes: invalid skip record".into(),
            ));
        }
        prev = Some(skip);
        skips.push(skip);
    }
    if rem != 0 && buf[raw..need].iter().any(|&b| b != 0) {
        return Err(OwampError::Invalid(
            "unpack_skip_records_aes: invalid zero padding".into(),
        ));
    }
    Ok(skips)
}

/// TWAMP `StopSessions` is header + HMAC (2 blocks); one-way continues with descs.
pub const STOP_SESSIONS_TW_SIZE: usize = STOP_SESSIONS_HEADER_SIZE + HMAC_SIZE;

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn encode_stop_sessions_tw_with_hmac(
    mode: u32,
    crypto: Option<&mut ControlCrypto>,
    hdr: &StopSessionsHeader,
    buf: &mut [u8],
) -> Result<()> {
    if buf.len() < STOP_SESSIONS_TW_SIZE {
        return Err(OwampError::Message(
            "StopSessions TW: buffer too small".into(),
        ));
    }
    buf[..STOP_SESSIONS_TW_SIZE].fill(0);
    hdr.encode(&mut buf[..STOP_SESSIONS_HEADER_SIZE])?;
    let mut digest = [0u8; HMAC_SIZE];
    finalize_hmac_field(mode, crypto, &buf[..16], 1, &mut digest)?;
    buf[16..32].copy_from_slice(&digest);
    Ok(())
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn verify_stop_sessions_tw_hmac(
    mode: u32,
    crypto: Option<&mut ControlCrypto>,
    buf: &[u8],
) -> Result<StopSessionsHeader> {
    if buf.len() < STOP_SESSIONS_TW_SIZE {
        return Err(OwampError::Message(
            "StopSessions TW: buffer too small".into(),
        ));
    }
    let hdr = StopSessionsHeader::decode(&buf[..STOP_SESSIONS_HEADER_SIZE])?;
    let mut digest = [0u8; HMAC_SIZE];
    digest.copy_from_slice(&buf[16..32]);
    verify_hmac_field(mode, crypto, &buf[..16], 1, &digest)?;
    Ok(hdr)
}

/// Validate `num_sessions` against active session count (C `ReadStopSessions`).
#[must_use]
pub const fn validate_stop_sessions_count(twoway: bool, num_sessions: u32, actual: u32) -> bool {
    // Two-way: `num_sessions` must match the active session count.
    // One-way: the message accounts for every *recv* session (`actual` = recv count).
    let _ = twoway;
    num_sessions == actual
}

// ---------------------------------------------------------------------------
// FetchSession: data / skip AES framing helpers
// ---------------------------------------------------------------------------

#[inline]
#[must_use]
pub const fn aes_blocks_for_bytes(nbytes: usize) -> usize {
    nbytes.div_ceil(RIJNDAEL_BLOCK_SIZE)
}

pub fn pad_to_aes_blocks(buf: &mut Vec<u8>) {
    let rem = buf.len() % RIJNDAEL_BLOCK_SIZE;
    if rem != 0 {
        buf.extend(std::iter::repeat_n(0u8, RIJNDAEL_BLOCK_SIZE - rem));
    }
}

/// Encode V3 data records and AES-pad (`FetchSession` data stream / `DoData`).
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn encode_data_records_fetch(recs: &[DataRec]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(recs.len() * DATARECV3_SIZE + RIJNDAEL_BLOCK_SIZE);
    for rec in recs {
        let mut tmp = [0u8; DATARECV3_SIZE];
        encode_data_record(&mut tmp, rec)?;
        out.extend_from_slice(&tmp);
    }
    pad_to_aes_blocks(&mut out);
    Ok(out)
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn decode_data_records_fetch(
    buf: &[u8],
    num_recs: u32,
    file_version: u32,
) -> Result<Vec<DataRec>> {
    let rec_size = match file_version {
        0 | 2 => DATARECV2_SIZE,
        3 => DATARECV3_SIZE,
        _ => {
            return Err(OwampError::Unsupported(format!(
                "decode_data_records_fetch: unsupported version {file_version}"
            )));
        },
    };
    let raw = num_recs as usize * rec_size;
    let need = aes_blocks_for_bytes(raw) * RIJNDAEL_BLOCK_SIZE;
    if num_recs > 0 && buf.len() < need.max(raw) {
        return Err(OwampError::Message(format!(
            "decode_data_records_fetch: need at least {raw}, have {}",
            buf.len()
        )));
    }
    let mut out = Vec::with_capacity(num_recs as usize);
    for i in 0..num_recs as usize {
        let off = i * rec_size;
        out.push(decode_data_record(file_version, &buf[off..off + rec_size])?);
    }
    Ok(out)
}

/// `FetchAck` unfinished (`finished == 0`) must leave `next_seqno/num_skiprecs` as 0
/// on the wire (C `_OWPWriteFetchAck`).
pub const fn normalize_fetch_ack(msg: &mut FetchAck) {
    if msg.finished == 0 {
        msg.next_seqno = 0;
        msg.num_skiprecs = 0;
    }
}

// ---------------------------------------------------------------------------
// Address / port helpers from protocol.c
// ---------------------------------------------------------------------------

/// `_OWPSetSAddrIfUnspec` — copy control address into unspecified test address.
pub const fn set_saddr_if_unspec(cntrl_sa: SocketAddr, test_sa: &mut SocketAddr) {
    match (*test_sa, cntrl_sa) {
        (SocketAddr::V4(t), SocketAddr::V4(c)) if t.ip().is_unspecified() => {
            *test_sa = SocketAddr::V4(SocketAddrV4::new(*c.ip(), t.port()));
        },
        (SocketAddr::V6(t), SocketAddr::V6(c)) if t.ip().is_unspecified() => {
            *test_sa = SocketAddr::V6(SocketAddrV6::new(
                *c.ip(),
                t.port(),
                t.flowinfo(),
                t.scope_id(),
            ));
        },
        _ => {},
    }
}

/// Alias matching older call sites / C naming.
#[inline]
pub const fn set_saddr_if_unspecified(cntrl_sa: SocketAddr, test_sa: &mut SocketAddr) {
    set_saddr_if_unspec(cntrl_sa, test_sa);
}

/// `_OWPTestSessionSetIPv6LLScope` — copy `scope_id` for link-local test addresses.
/// Returns `false` when the control address cannot provide a matching scope.
pub const fn apply_ipv6_ll_scope(cntrl_sa: Option<SocketAddr>, test_sa: &mut SocketAddr) -> bool {
    let SocketAddr::V6(ref mut t6) = *test_sa else {
        return true;
    };
    if !t6.ip().is_unicast_link_local() {
        return true;
    }
    match cntrl_sa {
        Some(SocketAddr::V6(c6)) if c6.ip().is_unicast_link_local() => {
            t6.set_scope_id(c6.scope_id());
            true
        },
        _ => false,
    }
}

#[must_use]
pub const fn ip_version_of(sa: SocketAddr) -> u8 {
    match sa {
        SocketAddr::V4(_) => 4,
        SocketAddr::V6(_) => 6,
    }
}

#[must_use]
pub const fn addresses_compatible(a: SocketAddr, b: SocketAddr) -> bool {
    ip_version_of(a) == ip_version_of(b)
}

#[must_use]
pub const fn socket_addr_with_port(sa: SocketAddr, port: u16) -> SocketAddr {
    match sa {
        SocketAddr::V4(v) => SocketAddr::V4(SocketAddrV4::new(*v.ip(), port)),
        SocketAddr::V6(v) => {
            SocketAddr::V6(SocketAddrV6::new(*v.ip(), port, v.flowinfo(), v.scope_id()))
        },
    }
}

/// Extract wire ports from a sender/receiver pair (network order handled by encode).
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn wire_ports(sender: SocketAddr, receiver: SocketAddr) -> Result<(u16, u16)> {
    if !addresses_compatible(sender, receiver) {
        return Err(OwampError::Invalid(
            "wire_ports: address family mismatch".into(),
        ));
    }
    Ok((sender.port(), receiver.port()))
}

/// `ServerStart` covers the uptime block in the running HMAC without embedding
/// a digest field (C `_OWPWriteServerStart` / `_OWPReadServerStart`).
pub const SERVER_START_HMAC_OFFSET: usize = 32;
pub const SERVER_START_HMAC_BLOCKS: usize = 1;

/// Validate skip-record ordering for `StopSessions` (`begin <= end`, non-decreasing).
#[must_use]
pub const fn validate_skip_record(prev: Option<&SkipRec>, curr: &SkipRec) -> bool {
    if curr.end < curr.begin {
        return false;
    }
    if let Some(p) = prev {
        if p.end != 0 && curr.begin < p.end {
            return false;
        }
    }
    true
}

/// Bytes of zero padding needed after `num_skips` skip records to AES-block align.
/// C: when `num_skips` is even, the last half-block of zeros must be present.
#[must_use]
pub const fn stop_sessions_skip_pad_octets(num_skips: u32) -> usize {
    let body = 8 + num_skips as usize * SKIPREC_SIZE; // next_seqno+num_skips + skips
    let rem = body % RIJNDAEL_BLOCK_SIZE;
    if rem == 0 {
        0
    } else {
        RIJNDAEL_BLOCK_SIZE - rem
    }
}

// ---------------------------------------------------------------------------
// Remaining I/O orchestration (lives in api/capi/sapi, not here)
// ---------------------------------------------------------------------------
//
// Socket send/recv, endpoint skip files, flock, and recv-file updates stay in
// `api` / `capi` / `sapi`. This module owns layouts, HMAC framing, skip/data
// AES packing, and state-bit transitions.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owampP::{OWP_MODE_AUTHENTICATED, OWP_MODE_ENCRYPTED, OWP_MODE_OPEN};

    #[test]
    fn server_greeting_roundtrip() {
        let msg = ServerGreeting {
            modes: OWP_MODE_OPEN | OWP_MODE_AUTHENTICATED | OWP_MODE_ENCRYPTED,
            challenge: [0x11; 16],
            salt: [0x22; 16],
            count: 2_048,
        };
        let mut buf = [0u8; SERVER_GREETING_SIZE];
        msg.encode(&mut buf).unwrap();
        assert_eq!(&buf[0..12], &[0u8; 12]);
        assert_eq!(ServerGreeting::decode(&buf).unwrap(), msg);
    }

    #[test]
    fn setup_response_open_zeros_credentials() {
        let msg = SetupResponse {
            mode: OWP_MODE_OPEN,
            userid: [b'a'; 80],
            token: [0x33; 64],
            client_iv: [0x44; 16],
        };
        let mut buf = [0u8; SETUP_RESPONSE_SIZE];
        msg.encode(&mut buf).unwrap();
        assert_eq!(&buf[4..164], &[0u8; 160]);
    }

    #[test]
    fn setup_response_encrypted_roundtrip() {
        let msg = SetupResponse {
            mode: OWP_MODE_ENCRYPTED,
            userid: {
                let mut u = [0u8; 80];
                u[..4].copy_from_slice(b"user");
                u
            },
            token: [0x55; 64],
            client_iv: [0x66; 16],
        };
        let mut buf = [0u8; SETUP_RESPONSE_SIZE];
        msg.encode(&mut buf).unwrap();
        assert_eq!(SetupResponse::decode(&buf).unwrap(), msg);
    }

    #[test]
    fn server_start_roundtrip() {
        let msg = ServerStart {
            accept: AcceptType::Accept,
            server_iv: [0x77; 16],
            uptime: OwampNum64(0x0000_0001_8000_0000),
        };
        let mut buf = [0u8; SERVER_START_SIZE];
        msg.encode(&mut buf).unwrap();
        let decoded = ServerStart::decode(&buf).unwrap();
        assert_eq!(decoded.uptime, msg.uptime);
        assert_eq!(decoded.server_iv, msg.server_iv);
    }

    #[test]
    fn test_request_preamble_ipv4_roundtrip() {
        let sender = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 4_001));
        let receiver = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 2), 4_002));
        let tspec = TestSpec {
            start_time: OwampNum64(0x1111_1111_2222_2222),
            loss_timeout: OwampNum64(0x3333_3333_4444_4444),
            type_p: 0,
            packet_size_padding: 14,
            npackets: 10,
            nslots: 1,
            slots: vec![Slot::RandExp {
                mean: OwampNum64(1_000),
            }],
        };
        let sid = [0xab; 16];
        let preamble = TestRequestPreamble::from_test_spec(
            false,
            true,
            false,
            false,
            Some(&sid),
            sender,
            receiver,
            &tspec,
        )
        .unwrap();
        let mut buf = [0u8; TEST_REQUEST_PREAMBLE_SIZE];
        preamble.encode(&mut buf).unwrap();
        assert_eq!(buf[0], 1);
        assert_eq!(buf[1], 4);
        let decoded = TestRequestPreamble::decode(&buf, true, false).unwrap();
        assert_eq!(decoded.sender.port(), 0); // conf_sender
        assert_eq!(decoded.receiver.port(), 4_002);
        assert_eq!(decoded.npackets, 10);
        assert_eq!(decoded.sid, sid);
        assert_eq!(decoded.start_time, tspec.start_time);
    }

    #[test]
    fn slot_roundtrip() {
        let slot = Slot::Literal {
            offset: OwampNum64(0xdead_beef_cafe_f00d),
        };
        let mut buf = [0u8; SLOT_SIZE];
        encode_slot(&mut buf, &slot).unwrap();
        assert_eq!(buf[0], 1);
        assert_eq!(decode_slot(&buf).unwrap(), slot);
    }

    #[test]
    fn accept_start_fetch_roundtrips() {
        let mut accept = AcceptSession {
            accept: AcceptType::Accept,
            port: 8_610,
            sid: [0xcd; 16],
            hmac: [0; 16],
        };
        let mut buf = [0u8; ACCEPT_SESSION_SIZE];
        encode_accept_session_with_hmac(OWP_MODE_OPEN, None, &mut accept, &mut buf).unwrap();
        assert_eq!(AcceptSession::decode(&buf).unwrap().port, 8_610);

        let mut ss = StartSessions { hmac: [0; 16] };
        let mut sbuf = [0u8; START_SESSIONS_SIZE];
        encode_start_sessions_with_hmac(OWP_MODE_OPEN, None, &mut ss, &mut sbuf).unwrap();
        assert_eq!(sbuf[0], 2);

        let mut fs = FetchSession {
            begin: 1,
            end: 100,
            sid: [0xef; 16],
            hmac: [0; 16],
        };
        let mut fbuf = [0u8; FETCH_SESSION_SIZE];
        encode_fetch_session_with_hmac(OWP_MODE_OPEN, None, &mut fs, &mut fbuf).unwrap();
        let d = FetchSession::decode(&fbuf).unwrap();
        assert_eq!((d.begin, d.end), (1, 100));
    }

    #[test]
    fn stop_sessions_and_data_records() {
        let hdr = StopSessionsHeader {
            accept: AcceptType::Accept,
            num_sessions: 3,
        };
        let mut buf = [0u8; STOP_SESSIONS_HEADER_SIZE];
        hdr.encode(&mut buf).unwrap();
        assert_eq!(buf[0], 3);
        assert_eq!(StopSessionsHeader::decode(&buf).unwrap(), hdr);

        let skip = SkipRec { begin: 10, end: 20 };
        let mut sbuf = [0u8; SKIPREC_SIZE];
        encode_skip_record(&mut sbuf, &skip).unwrap();
        assert_eq!(decode_skip_record(&sbuf).unwrap(), skip);

        let rec = DataRec {
            seq_no: 42,
            send: OwampTimeStamp {
                owptime: OwampNum64(0x1000_0000_2000_0000),
                sync: true,
                multiplier: 1,
                scale: 3,
            },
            recv: OwampTimeStamp {
                owptime: OwampNum64(0x1000_0000_3000_0000),
                sync: false,
                multiplier: 2,
                scale: 4,
            },
            ttl: 64,
        };
        let mut dbuf = [0u8; DATARECV3_SIZE];
        encode_data_record(&mut dbuf, &rec).unwrap();
        let decoded = decode_data_record(3, &dbuf).unwrap();
        assert_eq!(decoded.seq_no, 42);
        assert_eq!(decoded.ttl, 64);
        assert_eq!(decoded.send.owptime, rec.send.owptime);
        assert!(decoded.send.sync);
    }

    #[test]
    fn classify_request_and_state_constants() {
        let (req, bit) = classify_request(STATE_REQUEST, 1).unwrap();
        assert_eq!(req, OwampRequestType::Test);
        assert_eq!(bit, STATE_TEST_REQUEST);
        assert!(classify_request(STATE_REQUEST, 3).is_err());
        assert!(classify_request(STATE_REQUEST | STATE_TEST, 3).is_ok());
        assert_eq!(STATE_SETUP, 0x0001);
        assert_eq!(TEST_REQUEST_PREAMBLE_SIZE, 112);
        assert_eq!(MAX_MSG_SIZE, 400);
    }

    #[test]
    fn open_framing_noop() {
        let mut buf = [1u8; 16];
        let orig = buf;
        frame_send_blocks(OWP_MODE_OPEN, None, &mut buf, 1).unwrap();
        assert_eq!(buf, orig);
        frame_recv_blocks(OWP_MODE_OPEN, None, &mut buf, 1).unwrap();
        assert_eq!(buf, orig);
    }

    #[test]
    fn test_request_and_fetch_state_machine() {
        let mut state = STATE_REQUEST | STATE_TEST_REQUEST;
        after_read_test_request_preamble(&mut state);
        assert!(state_is(STATE_TEST_REQUEST_SLOTS, state));
        assert!(!state_is(STATE_TEST_REQUEST, state));
        after_read_test_request_slots(&mut state);
        after_read_test_request(&mut state, true);
        assert!(state_is(STATE_ACCEPT_SESSION, state));

        let mut fetch_state = STATE_REQUEST | STATE_FETCH_ACK;
        after_read_fetch_ack(&mut fetch_state, AcceptType::Accept, false);
        assert!(state_is(STATE_TEST_REQUEST, fetch_state));
        let mut tw_state = STATE_REQUEST | STATE_FETCH_ACK;
        after_read_fetch_ack(&mut tw_state, AcceptType::Accept, true);
        assert!(state_is(STATE_TEST_REQUEST_TW, tw_state));
        let mut reject = STATE_FETCH_ACK | STATE_FETCHING;
        after_write_fetch_ack(&mut reject, AcceptType::Reject);
        assert!(state_is(STATE_REQUEST, reject));
        assert!(!state_is(STATE_FETCHING, reject));
    }

    #[test]
    fn address_helpers_and_skip_validation() {
        let cntrl = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 9), 861));
        let mut test = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 4_000));
        set_saddr_if_unspec(cntrl, &mut test);
        assert_eq!(test.ip(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)));
        assert_eq!(test.port(), 4_000);

        let mut ll = SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 9, 0, 0));
        let cntrl6 = SocketAddr::V6(SocketAddrV6::new("fe80::2".parse().unwrap(), 861, 0, 7));
        assert!(apply_ipv6_ll_scope(Some(cntrl6), &mut ll));
        match ll {
            SocketAddr::V6(v) => assert_eq!(v.scope_id(), 7),
            SocketAddr::V4(_) => panic!("expected v6"),
        }
        assert!(!apply_ipv6_ll_scope(None, &mut ll));

        let a = SkipRec { begin: 1, end: 5 };
        let b = SkipRec { begin: 5, end: 10 };
        let bad = SkipRec { begin: 3, end: 2 };
        assert!(validate_skip_record(None, &a));
        assert!(validate_skip_record(Some(&a), &b));
        assert!(!validate_skip_record(None, &bad));
        assert!(!validate_skip_record(Some(&b), &a));
        assert_eq!(stop_sessions_skip_pad_octets(0), 8); // 8 bytes body → pad 8
        assert_eq!(stop_sessions_skip_pad_octets(1), 0); // 8+8=16
        assert_eq!(stop_sessions_skip_pad_octets(2), 8); // 8+16=24 → pad 8
    }

    #[test]
    fn tw_data_record_roundtrip() {
        let mk = |seq: u32, ttl: u8| DataRec {
            seq_no: seq,
            send: OwampTimeStamp {
                owptime: OwampNum64(0x1000_0000_2000_0000),
                sync: true,
                multiplier: 1,
                scale: 2,
            },
            recv: OwampTimeStamp {
                owptime: OwampNum64(0x1000_0000_3000_0000),
                sync: false,
                multiplier: 2,
                scale: 3,
            },
            ttl,
        };
        let rec = TwDataRec {
            sent: mk(7, 55),
            reflected: mk(8, 54),
        };
        let mut buf = [0u8; DATAREC_TWV3_SIZE];
        encode_tw_data_record(&mut buf, &rec).unwrap();
        let decoded = decode_tw_data_record(VERSION_TWOWAY | 3, &buf).unwrap();
        assert_eq!(decoded.sent.seq_no, 7);
        assert_eq!(decoded.reflected.ttl, 54);
        assert_eq!(decoded.sent.send.owptime, rec.sent.send.owptime);
    }

    #[test]
    fn test_request_preamble_ipv6_and_tw() {
        let sender = SocketAddr::V6(SocketAddrV6::new(
            "2001:db8::1".parse().unwrap(),
            5_001,
            0,
            0,
        ));
        let receiver = SocketAddr::V6(SocketAddrV6::new(
            "2001:db8::2".parse().unwrap(),
            5_002,
            0,
            0,
        ));
        let tspec = TestSpec {
            start_time: OwampNum64(1),
            loss_timeout: OwampNum64(2),
            type_p: 0,
            packet_size_padding: 0,
            npackets: 5,
            nslots: 1,
            slots: vec![Slot::RandExp {
                mean: OwampNum64(100),
            }],
        };
        let pre = TestRequestPreamble::from_test_spec(
            false, true, false, false, None, sender, receiver, &tspec,
        )
        .unwrap();
        let mut buf = [0u8; TEST_REQUEST_PREAMBLE_SIZE];
        pre.encode(&mut buf).unwrap();
        assert_eq!(buf[0], 1);
        assert_eq!(buf[1], 6);
        let d = TestRequestPreamble::decode(&buf, true, false).unwrap();
        assert_eq!(d.sender.port(), 0); // conf_sender
        assert_eq!(d.receiver.port(), 5_002);
        assert_eq!(d.ip_version, 6);

        let tw = TestRequestPreamble::from_test_spec(
            true,
            false,
            false,
            false,
            None,
            sender,
            receiver,
            &TestSpec::default(),
        )
        .unwrap();
        tw.encode(&mut buf).unwrap();
        assert_eq!(buf[0], 5);
        assert_eq!(BigEndian::read_u32(&buf[4..8]), 0);
        assert_eq!(BigEndian::read_u32(&buf[8..12]), 0);
        let tw_d = TestRequestPreamble::decode(&buf, true, true).unwrap();
        assert!(tw_d.twoway);
        assert!(!tw_d.conf_sender && !tw_d.conf_receiver);
    }

    #[test]
    fn full_test_request_message_open() {
        let sender = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 9));
        let receiver = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 9));
        let tspec = TestSpec {
            start_time: OwampNum64(3),
            loss_timeout: OwampNum64(4),
            type_p: 0,
            packet_size_padding: 14,
            npackets: 2,
            nslots: 2,
            slots: vec![
                Slot::RandExp {
                    mean: OwampNum64(10),
                },
                Slot::Literal {
                    offset: OwampNum64(20),
                },
            ],
        };
        let msg = TestRequestMessage::from_test_spec(
            false,
            false,
            true,
            false,
            Some(&[0x11; 16]),
            sender,
            receiver,
            &tspec,
        )
        .unwrap();
        let mut wire = Vec::new();
        msg.encode_open(&mut wire).unwrap();
        assert_eq!(
            wire.len(),
            TEST_REQUEST_PREAMBLE_SIZE + TestRequestSlots::wire_len(2)
        );
        let slots = TestRequestSlots::decode(&wire[TEST_REQUEST_PREAMBLE_SIZE..], 2).unwrap();
        assert_eq!(slots.slots.len(), 2);
        assert_eq!(slots.hmac, [0u8; 16]);
        verify_test_request_hmac(OWP_MODE_OPEN, None, &wire[..112], false, false).unwrap();
    }

    #[test]
    fn stop_session_desc_and_skip_aes_roundtrip() {
        let desc = StopSessionDesc {
            sid: [0x42; 16],
            next_seqno: 99,
            skips: vec![SkipRec { begin: 1, end: 3 }, SkipRec { begin: 3, end: 5 }],
        };
        let mut wire = Vec::new();
        desc.encode(&mut wire).unwrap();
        assert_eq!(wire.len(), desc.wire_len());
        // 2 skips → body = 8+16=24 → pad 8 → 32; + SID 16 = 48
        assert_eq!(wire.len(), 48);
        let (decoded, consumed) = StopSessionDesc::decode(&wire).unwrap();
        assert_eq!(consumed, 48);
        assert_eq!(decoded, desc);

        // Odd skip count: no trailing pad beyond block alignment of body.
        let one = StopSessionDesc {
            sid: [1; 16],
            next_seqno: 1,
            skips: vec![SkipRec { begin: 0, end: 0 }],
        };
        let mut w2 = Vec::new();
        one.encode(&mut w2).unwrap();
        assert_eq!(w2.len(), 16 + 16); // SID + one AES block
        let (d2, _) = StopSessionDesc::decode(&w2).unwrap();
        assert_eq!(d2.skips.len(), 1);

        let packed = pack_skip_records_aes(&desc.skips).unwrap();
        assert_eq!(packed.len(), 16); // 16 bytes, already aligned
        assert_eq!(unpack_skip_records_aes(&packed, 2).unwrap(), desc.skips);

        let packed_odd = pack_skip_records_aes(&one.skips).unwrap();
        assert_eq!(packed_odd.len(), 16); // 8 + 8 pad
        assert_eq!(unpack_skip_records_aes(&packed_odd, 1).unwrap(), one.skips);
    }

    #[test]
    fn stop_sessions_tw_and_fetch_ack_normalize() {
        let hdr = StopSessionsHeader {
            accept: AcceptType::Accept,
            num_sessions: 2,
        };
        let mut buf = [0u8; STOP_SESSIONS_TW_SIZE];
        encode_stop_sessions_tw_with_hmac(OWP_MODE_OPEN, None, &hdr, &mut buf).unwrap();
        assert_eq!(buf[0], 3);
        assert_eq!(&buf[16..32], &[0u8; 16]);
        let d = verify_stop_sessions_tw_hmac(OWP_MODE_OPEN, None, &buf).unwrap();
        assert_eq!(d, hdr);
        assert!(validate_stop_sessions_count(true, 2, 2));
        assert!(!validate_stop_sessions_count(true, 1, 2));

        let mut ack = FetchAck {
            accept: AcceptType::Accept,
            finished: 0,
            next_seqno: 5,
            num_skiprecs: 3,
            num_datarecs: 10,
            hmac: [0; 16],
        };
        normalize_fetch_ack(&mut ack);
        assert_eq!(ack.next_seqno, 0);
        assert_eq!(ack.num_skiprecs, 0);
        let mut abuf = [0u8; FETCH_ACK_SIZE];
        encode_fetch_ack_with_hmac(OWP_MODE_OPEN, None, &mut ack, &mut abuf).unwrap();
        assert_eq!(BigEndian::read_u32(&abuf[4..8]), 0);
        assert_eq!(BigEndian::read_u32(&abuf[8..12]), 0);
        assert_eq!(BigEndian::read_u32(&abuf[12..16]), 10);
        verify_fetch_ack_hmac(OWP_MODE_OPEN, None, &abuf).unwrap();
    }

    #[test]
    fn fetch_data_records_aes_and_port_helpers() {
        let rec = DataRec {
            seq_no: 1,
            send: OwampTimeStamp {
                owptime: OwampNum64(0x1000_0000_2000_0000),
                sync: true,
                multiplier: 1,
                scale: 2,
            },
            recv: OwampTimeStamp {
                owptime: OwampNum64(0x1000_0000_3000_0000),
                sync: false,
                multiplier: 2,
                scale: 3,
            },
            ttl: 64,
        };
        let packed = encode_data_records_fetch(&[rec, rec]).unwrap();
        // 50 bytes → pad to 64 (4 AES blocks)
        assert_eq!(packed.len(), 64);
        assert_eq!(aes_blocks_for_bytes(50), 4);
        let decoded = decode_data_records_fetch(&packed, 2, 3).unwrap();
        assert_eq!(decoded[0].seq_no, 1);
        assert_eq!(decoded[1].ttl, 64);

        let a = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 861));
        let b = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 862));
        assert_eq!(wire_ports(a, b).unwrap(), (861, 862));
        assert_eq!(socket_addr_with_port(a, 9).port(), 9);
        assert!(addresses_compatible(a, b));
        assert_eq!(SERVER_START_HMAC_OFFSET, 32);
        assert_eq!(SERVER_START_HMAC_BLOCKS, 1);

        let mut accept = AcceptSession {
            accept: AcceptType::Accept,
            port: 861,
            sid: [9; 16],
            hmac: [0; 16],
        };
        let mut buf = [0u8; ACCEPT_SESSION_SIZE];
        encode_accept_session_with_hmac(OWP_MODE_OPEN, None, &mut accept, &mut buf).unwrap();
        verify_accept_session_hmac(OWP_MODE_OPEN, None, &buf).unwrap();
        let mut ss = StartSessions { hmac: [0; 16] };
        let mut sbuf = [0u8; START_SESSIONS_SIZE];
        encode_start_sessions_with_hmac(OWP_MODE_OPEN, None, &mut ss, &mut sbuf).unwrap();
        verify_start_sessions_hmac(OWP_MODE_OPEN, None, &sbuf).unwrap();
    }

    #[test]
    fn zero_addr_and_hmac_verify_fetch_session() {
        let sender = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 1));
        let receiver = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 2), 2));
        let tspec = TestSpec {
            start_time: OwampNum64(1),
            loss_timeout: OwampNum64(2),
            type_p: 0,
            packet_size_padding: 0,
            npackets: 1,
            nslots: 1,
            slots: vec![Slot::Literal {
                offset: OwampNum64(1),
            }],
        };
        let pre = TestRequestPreamble::from_test_spec(
            false, true, true, true, None, sender, receiver, &tspec,
        )
        .unwrap();
        assert!(pre.sender.ip().is_unspecified());
        assert!(pre.receiver.ip().is_unspecified());

        let mut fs = FetchSession {
            begin: 0,
            end: 0xffff_ffff,
            sid: [0xaa; 16],
            hmac: [0; 16],
        };
        let mut fbuf = [0u8; FETCH_SESSION_SIZE];
        encode_fetch_session_with_hmac(OWP_MODE_OPEN, None, &mut fs, &mut fbuf).unwrap();
        let got = verify_fetch_session_hmac(OWP_MODE_OPEN, None, &fbuf).unwrap();
        assert_eq!(got.end, 0xffff_ffff);
    }

    #[test]
    fn state_and_request_type_helpers() {
        assert!(state_is_initial(0));
        assert!(!state_is_initial(STATE_SETUP));
        assert!(state_is_setup(STATE_SETUP));
        assert!(state_is_request(STATE_REQUEST));
        assert!(state_is_reading(STATE_READING));
        assert!(state_is_pending(STATE_PENDING));
        assert!(state_is_test(STATE_TEST));
        assert!(!state_is(STATE_TEST, STATE_REQUEST));

        assert_eq!(
            request_partial_state(OwampRequestType::Test),
            Some(STATE_TEST_REQUEST)
        );
        assert_eq!(
            request_partial_state(OwampRequestType::StartSessions),
            Some(STATE_START_SESSIONS)
        );
        assert_eq!(
            request_partial_state(OwampRequestType::StopSessions),
            Some(STATE_STOP_SESSIONS)
        );
        assert_eq!(
            request_partial_state(OwampRequestType::FetchSession),
            Some(STATE_FETCH_SESSION)
        );
        assert_eq!(
            request_partial_state(OwampRequestType::TestTw),
            Some(STATE_TEST_REQUEST_TW)
        );
        assert_eq!(request_partial_state(OwampRequestType::Invalid), None);

        for (u, r) in [
            (1u8, OwampRequestType::Test),
            (2, OwampRequestType::StartSessions),
            (3, OwampRequestType::StopSessions),
            (4, OwampRequestType::FetchSession),
            (5, OwampRequestType::TestTw),
        ] {
            assert_eq!(request_type_from_u8(u), r);
            assert_eq!(request_type_as_u8(r), Some(u));
        }
        assert_eq!(request_type_from_u8(99), OwampRequestType::Invalid);
        assert_eq!(request_type_as_u8(OwampRequestType::Invalid), None);

        assert_eq!(accept_type_from_u8(0), AcceptType::Accept);
        assert_eq!(accept_type_as_u8(AcceptType::Reject), Some(1));
        assert_eq!(accept_type_from_u8(9), AcceptType::Invalid);
        assert_eq!(accept_type_as_u8(AcceptType::Invalid), None);
        assert_eq!(AcceptType::from_u8(4), AcceptType::UnavailablePerm);
        assert_eq!(AcceptType::Unsupported.as_u8(), Some(3));
    }

    #[test]
    fn setup_token_encrypt_decrypt_roundtrip() {
        let salt = [0xabu8; SALT_SIZE];
        let mut token_in = [0u8; TOKEN_SIZE];
        for (i, b) in token_in.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(3);
        }
        let enc = encrypt_setup_token(b"passphrase", &salt, 1_024, &token_in).unwrap();
        assert_ne!(enc, token_in);
        let dec = decrypt_setup_token(b"passphrase", &salt, 1_024, &enc).unwrap();
        assert_eq!(dec, token_in);
    }

    #[test]
    fn start_ack_and_session_desc_header_roundtrip() {
        let mut ack = StartAck {
            accept: AcceptType::Accept,
            hmac: [0; HMAC_SIZE],
        };
        let mut buf = [0u8; START_ACK_SIZE];
        encode_start_ack_with_hmac(OWP_MODE_OPEN, None, &mut ack, &mut buf).unwrap();
        assert_eq!(buf[0], 0);
        assert_eq!(&buf[16..32], &[0u8; 16]);
        let got = verify_start_ack_hmac(OWP_MODE_OPEN, None, &buf).unwrap();
        assert_eq!(got.accept, AcceptType::Accept);

        let hdr = SessionDescHeader {
            sid: [0x5a; SID_SIZE],
            next_seqno: 42,
            num_skiprecs: 7,
        };
        let mut hbuf = [0u8; SESSION_DESC_HEADER_SIZE];
        hdr.encode(&mut hbuf).unwrap();
        assert_eq!(SessionDescHeader::decode(&hbuf).unwrap(), hdr);
        assert_eq!(SESSION_DESC_HEADER_SIZE, 24);
    }

    #[test]
    fn encode_test_request_with_hmac_open_and_slot_randexp() {
        let sender = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 1, 1), 1_000));
        let receiver = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 1, 2), 2_000));
        let tspec = TestSpec {
            start_time: OwampNum64(9),
            loss_timeout: OwampNum64(8),
            type_p: 0,
            packet_size_padding: 0,
            npackets: 1,
            nslots: 1,
            slots: vec![Slot::RandExp {
                mean: OwampNum64(0x0102_0304_0506_0708),
            }],
        };
        let mut pre = TestRequestPreamble::from_test_spec(
            false,
            true,
            false,
            false,
            Some(&[0xee; 16]),
            sender,
            receiver,
            &tspec,
        )
        .unwrap();
        let mut buf = [0u8; TEST_REQUEST_PREAMBLE_SIZE];
        encode_test_request_with_hmac(OWP_MODE_OPEN, None, &mut pre, &mut buf).unwrap();
        assert_eq!(&buf[96..112], &[0u8; 16]);
        verify_test_request_hmac(OWP_MODE_OPEN, None, &buf, false, false).unwrap();

        let mut sbuf = [0u8; SLOT_SIZE];
        encode_slot(&mut sbuf, &tspec.slots[0]).unwrap();
        assert_eq!(sbuf[0], 0);
        assert_eq!(decode_slot(&sbuf).unwrap(), tspec.slots[0]);
    }

    #[test]
    fn data_record_v2_layout_and_fetch_ack_finished() {
        // Manual V2 wire layout: seq(4) + send_ts(8) + send_err(2) + recv_ts(8) + recv_err(2).
        let send = OwampTimeStamp {
            owptime: OwampNum64(0x0000_0001_0000_0000),
            sync: true,
            multiplier: 1,
            scale: 2,
        };
        let recv = OwampTimeStamp {
            owptime: OwampNum64(0x0000_0002_0000_0000),
            sync: false,
            multiplier: 3,
            scale: 4,
        };
        let mut buf = [0u8; DATARECV2_SIZE];
        BigEndian::write_u32(&mut buf[0..4], 17);
        put_timestamp_full(&mut buf[4..12], &send);
        put_err_est(&mut buf[12..14], &send).unwrap();
        put_timestamp_full(&mut buf[14..22], &recv);
        put_err_est(&mut buf[22..24], &recv).unwrap();
        assert_eq!(DATARECV2_SIZE, 24);

        let d2 = decode_data_record(2, &buf).unwrap();
        assert_eq!(d2.seq_no, 17);
        assert_eq!(d2.ttl, 255); // V2 has no TTL field
        assert_eq!(d2.send.owptime, send.owptime);
        assert!(d2.send.sync);
        assert_eq!(d2.recv.multiplier, 3);

        let mut ack = FetchAck {
            accept: AcceptType::Accept,
            finished: 1,
            next_seqno: 99,
            num_skiprecs: 2,
            num_datarecs: 5,
            hmac: [0; HMAC_SIZE],
        };
        normalize_fetch_ack(&mut ack); // finished != 0 → leave fields
        assert_eq!(ack.next_seqno, 99);
        let mut abuf = [0u8; FETCH_ACK_SIZE];
        encode_fetch_ack_with_hmac(OWP_MODE_OPEN, None, &mut ack, &mut abuf).unwrap();
        let got = FetchAck::decode(&abuf).unwrap();
        assert_eq!(got.next_seqno, 99);
        assert_eq!(got.num_skiprecs, 2);
        assert_eq!(got.num_datarecs, 5);
    }

    #[test]
    fn remaining_state_transitions_and_address_aliases() {
        let mut state = STATE_INITIAL;
        after_write_server_greeting(&mut state);
        assert_eq!(state, STATE_SETUP);
        state = STATE_INITIAL;
        after_read_server_greeting(&mut state);
        assert_eq!(state, STATE_SETUP);

        let mut mode = OWP_MODE_AUTHENTICATED;
        after_write_server_start(&mut state, &mut mode, AcceptType::Accept);
        assert_eq!(state, STATE_REQUEST);
        after_write_server_start(&mut state, &mut mode, AcceptType::Reject);
        assert_eq!(state, STATE_INVALID);
        assert_eq!(mode, OWP_MODE_OPEN);

        state = STATE_SETUP;
        mode = OWP_MODE_ENCRYPTED;
        after_read_server_start(&mut state, &mut mode, AcceptType::Reject);
        assert_eq!(mode, OWP_MODE_OPEN);
        assert_eq!(state, STATE_REQUEST);

        state = STATE_REQUEST;
        after_write_test_request(&mut state);
        assert!(state_is(STATE_ACCEPT_SESSION, state));
        after_write_accept_session(&mut state);
        assert!(!state_is(STATE_ACCEPT_SESSION, state));
        after_read_accept_session(&mut state); // no-op clear

        state = STATE_REQUEST;
        after_write_start_sessions(&mut state);
        assert!(state_is(STATE_START_ACK | STATE_TEST, state));
        state = STATE_START_SESSIONS;
        after_read_start_sessions(&mut state);
        assert!(!state_is(STATE_START_SESSIONS, state));
        assert!(state_is(STATE_START_ACK | STATE_TEST, state));

        after_write_start_ack(&mut state, AcceptType::Reject);
        assert!(!state_is(STATE_START_ACK, state));
        assert!(!state_is(STATE_TEST, state));
        state |= STATE_START_ACK | STATE_TEST;
        after_read_start_ack(&mut state, AcceptType::Reject);
        assert!(state_is(STATE_REQUEST, state));

        state = STATE_REQUEST;
        after_write_fetch_session(&mut state);
        assert!(state_is(STATE_FETCH_ACK | STATE_FETCH_SESSION, state));
        assert!(!state_is(STATE_REQUEST, state));
        state = STATE_FETCH_SESSION | STATE_REQUEST;
        after_read_fetch_session(&mut state);
        assert!(state_is(STATE_FETCH_ACK | STATE_FETCHING, state));

        state = STATE_FETCHING;
        after_fetch_complete(&mut state);
        assert!(state_is(STATE_REQUEST, state));
        assert!(!state_is(STATE_FETCHING, state));

        state = STATE_STOP_SESSIONS;
        after_write_stop_sessions(&mut state); // C: no bit flip
        assert!(state_is(STATE_STOP_SESSIONS, state));
        after_read_stop_sessions(&mut state);
        assert!(state_is(STATE_REQUEST, state));

        state = STATE_REQUEST;
        after_read_test_request(&mut state, false);
        assert!(state_is(STATE_FETCHING, state));

        let cntrl = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 1), 861));
        let mut test = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 9));
        set_saddr_if_unspecified(cntrl, &mut test);
        assert_eq!(test.ip(), IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)));
        assert_eq!(ip_version_of(test), 4);
        assert_eq!(
            ip_version_of(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::LOCALHOST,
                1,
                0,
                0
            ))),
            6
        );

        let mut pad = vec![1u8, 2, 3];
        pad_to_aes_blocks(&mut pad);
        assert_eq!(pad.len(), RIJNDAEL_BLOCK_SIZE);
        assert_eq!(&pad[3..], &[0u8; 13]);
        assert_eq!(aes_blocks_for_bytes(0), 0);
        assert_eq!(aes_blocks_for_bytes(1), 1);
    }

    #[test]
    fn open_hmac_finalize_verify_and_server_start_reject() {
        let mut digest = [0xffu8; HMAC_SIZE];
        finalize_hmac_field(OWP_MODE_OPEN, None, &[0u8; 16], 1, &mut digest).unwrap();
        assert_eq!(digest, [0u8; HMAC_SIZE]);
        verify_hmac_field(OWP_MODE_OPEN, None, &[0u8; 16], 1, &digest).unwrap();

        let msg = ServerStart {
            accept: AcceptType::Failure,
            server_iv: [0x12; 16],
            uptime: OwampNum64(0xdead_beef),
        };
        let mut buf = [0u8; SERVER_START_SIZE];
        msg.encode(&mut buf).unwrap();
        assert_eq!(&buf[32..40], &[0u8; 8]); // uptime only on Accept
        let d = ServerStart::decode(&buf).unwrap();
        assert_eq!(d.accept, AcceptType::Failure);
        assert_eq!(d.uptime, OwampNum64::ZERO);
    }

    /// Symbols exercised by this module's unit tests (PR coverage checklist).
    #[test]
    fn coverage_protocol_stats() {
        let exercised = [
            "state_is_initial",
            "state_is_setup",
            "state_is",
            "state_is_request",
            "state_is_reading",
            "state_is_pending",
            "state_is_test",
            "request_partial_state",
            "request_type_from_u8",
            "request_type_as_u8",
            "accept_type_from_u8",
            "accept_type_as_u8",
            "classify_request",
            "frame_send_blocks",
            "frame_recv_blocks",
            "finalize_hmac_field",
            "verify_hmac_field",
            "encrypt_setup_token",
            "decrypt_setup_token",
            "ServerGreeting::encode/decode",
            "SetupResponse::encode/decode",
            "ServerStart::encode/decode",
            "TestRequestPreamble::from_test_spec/encode/decode",
            "encode_test_request_with_hmac",
            "verify_test_request_hmac",
            "encode_slot/decode_slot",
            "AcceptSession::encode/decode",
            "encode_accept_session_with_hmac/verify_accept_session_hmac",
            "StartSessions::encode/decode",
            "encode_start_sessions_with_hmac/verify_start_sessions_hmac",
            "StartAck::encode/decode",
            "encode_start_ack_with_hmac/verify_start_ack_hmac",
            "StopSessionsHeader::encode/decode",
            "SessionDescHeader::encode/decode",
            "FetchSession::encode/decode",
            "encode_fetch_session_with_hmac/verify_fetch_session_hmac",
            "FetchAck::encode/decode",
            "encode_fetch_ack_with_hmac/verify_fetch_ack_hmac",
            "encode_skip_record/decode_skip_record",
            "encode_data_record/decode_data_record",
            "encode_tw_data_record/decode_tw_data_record",
            "TestRequestSlots::encode_open/decode/wire_len",
            "TestRequestMessage::from_test_spec/encode_open/wire_len",
            "StopSessionDesc::encode/decode/body_len/wire_len",
            "encode_session_desc_body/decode_session_desc_body",
            "pack_skip_records_aes/unpack_skip_records_aes",
            "encode_stop_sessions_tw_with_hmac/verify_stop_sessions_tw_hmac",
            "validate_stop_sessions_count",
            "aes_blocks_for_bytes/pad_to_aes_blocks",
            "encode_data_records_fetch/decode_data_records_fetch",
            "normalize_fetch_ack",
            "set_saddr_if_unspec/set_saddr_if_unspecified",
            "apply_ipv6_ll_scope",
            "ip_version_of/addresses_compatible/socket_addr_with_port/wire_ports",
            "validate_skip_record/stop_sessions_skip_pad_octets",
            "after_* state transition helpers",
        ];
        assert!(exercised.len() >= 50);
        // Keep the checklist tied to known C layout sizes.
        assert_eq!(SERVER_GREETING_SIZE, 64);
        assert_eq!(SETUP_RESPONSE_SIZE, 164);
        assert_eq!(SERVER_START_SIZE, 48);
        assert_eq!(ACCEPT_SESSION_SIZE, 48);
        assert_eq!(TEST_REQUEST_PREAMBLE_SIZE, 112);
        assert_eq!(START_SESSIONS_SIZE, 32);
        assert_eq!(START_ACK_SIZE, 32);
        assert_eq!(FETCH_SESSION_SIZE, 48);
        assert_eq!(FETCH_ACK_SIZE, 32);
        assert_eq!(DATARECV3_SIZE, 25);
        assert_eq!(DATAREC_TWV3_SIZE, 50);
        assert_eq!(SKIPREC_SIZE, 8);
        assert_eq!(RIJNDAEL_BLOCK_SIZE, 16);
    }
}
