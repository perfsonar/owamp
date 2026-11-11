//! Test-packet send/receive endpoint logic — port of `endpoint.c`.
//!
//! Behavioural parity with the C implementation for:
//! - `EndpointAlloc` / `EndpointClear` / `EndpointFree` lifecycle
//! - `run_sender` / `run_receiver` / `run_tw_test` / `run_reflector` cores
//! - UDP socket setup, send/recv, TTL ancillary data
//! - Lost-packet / skip tracking
//! - AES/HMAC on test packets (`crate::rijndael_api_fst`)
//! - Data-file reopen / record write paths
//! - Signal flags used by endpoint children
//!
//! Process fork/wait plumbing is approximated by worker threads:
//! [`EndpointChildSignals`] (USR1/USR2/INT atomics) replace POSIX signals,
//! `run_endpoint_live` plays the child role after `StartSessions`, and the
//! control-plane `context::Endpoint` polls completion like `waitpid(WNOHANG)`.
//! Packet I/O uses real sockets in live mode or callbacks in unit tests.

use std::cell::Cell;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write as IoWrite};
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use byteorder::{BigEndian, ByteOrder};
use socket2::{Domain, Protocol, Socket, Type};

use crate::api::{write_data_header, SessionFinishedType, SessionHeader};
use crate::arithm64::{double_to_num64, num64_to_double, num64_to_timespec, TimeSpec};
use crate::context::{self, Slot, SlotType};
use crate::owamp::{
    OwampAcceptType, OwampDataRec, OwampNum64, OwampPortRange, OwampSid, OwampSkipRec, OwampSlot,
    OwampTestSpec, OwampTimeStamp, OwampTwDataRec,
};
use crate::owampP::{
    OWP_DATARECV2_SIZE, OWP_DATARECV3_SIZE, OWP_DATAREC_SIZE, OWP_DATAREC_TWV3_SIZE,
    OWP_DEFAULT_FUZZTIME, OWP_DEFAULT_TMPDIR, OWP_MODE_AUTHENTICATED, OWP_MODE_ENCRYPTED,
    OWP_MODE_OPEN, OWP_SKIPFILE_FMT, OWP_SKIPREC_SIZE, OWP_VERSION_TWOWAY,
    TWP_DEFAULT_TEST_TIMEOUT, TWP_MODE_MIXED,
};
use crate::rijndael_api_fst::{
    block_decrypt, block_encrypt, derive_test_aes_key_bytes, derive_test_hmac_key,
    mode_docipher_test, zero_iv, AesKey, HmacSha1Ctx, AES_KEY_SIZE, HMAC_KEY_SIZE, HMAC_TRUNC_SIZE,
};
use crate::schedule::{num64_add, test_packet_rate, ScheduleContext};
use crate::stats::is_lost_record;
use crate::time::{
    decode_timestamp, decode_timestamp_err_estimate, encode_timestamp,
    encode_timestamp_err_estimate, get_timespec, timestamp_to_timespec,
};
use crate::{OwampError, Result};

// ---------------------------------------------------------------------------
// Data-record sizes (aliases to constants)
// ---------------------------------------------------------------------------

pub const DATAREC_V2_SIZE: usize = OWP_DATARECV2_SIZE;
pub const DATAREC_V3_SIZE: usize = OWP_DATARECV3_SIZE;
pub const DATAREC_TW_V3_SIZE: usize = OWP_DATAREC_TWV3_SIZE;
pub const DATAREC_SIZE: usize = OWP_DATAREC_SIZE;
pub const SKIPREC_SIZE: usize = OWP_SKIPREC_SIZE;
pub const VERSION_TWOWAY: u32 = OWP_VERSION_TWOWAY;

const IP4_HDR: usize = 20;
const IP6_HDR: usize = 40;
const UDP_HDR: usize = 8;
const PACKBUFF_ALLOC_FACTOR: f64 = 2.0;

pub type DataRec = OwampDataRec;
pub type TwDataRec = OwampTwDataRec;
pub type SkipRec = OwampSkipRec;
pub type TestSpec = OwampTestSpec;

// ---------------------------------------------------------------------------
// Child-process signal flags (`owp_usr1` / `owp_usr2` / `owp_int` / `owp_alrm`)
//
// Thread-local so unit tests can run in parallel without cross-talk. In a real
// forked child there is only one thread, matching the C globals.
// ---------------------------------------------------------------------------

thread_local! {
    static OWP_USR1: Cell<bool> = const { Cell::new(false) };
    static OWP_USR2: Cell<bool> = const { Cell::new(false) };
    static OWP_INT: Cell<bool> = const { Cell::new(false) };
    static OWP_ALRM: Cell<bool> = const { Cell::new(false) };
}

/// Shared kick/stop flags for endpoint worker threads (stand-in for POSIX signals
/// delivered to a forked child). Bridged into the thread-local flags used by
/// `run_*` loops.
#[derive(Debug, Default)]
pub struct EndpointChildSignals {
    pub usr1: AtomicBool,
    pub usr2: AtomicBool,
    pub int: AtomicBool,
    pub alrm: AtomicBool,
}

impl EndpointChildSignals {
    /// Copy Arc flags into the thread-local signal cells used by run loops.
    pub fn bridge_to_thread_local(&self) {
        if self.usr1.load(Ordering::Acquire) {
            signal_set_usr1();
        }
        if self.usr2.load(Ordering::Acquire) {
            signal_set_usr2();
        }
        if self.int.load(Ordering::Acquire) {
            signal_set_int();
        }
        if self.alrm.load(Ordering::Acquire) {
            signal_set_alrm();
        }
    }
}

/// Reset child signal flags before waiting for `StartSessions` / `StopSessions`.
pub fn signals_reset() {
    OWP_USR1.with(|c| c.set(false));
    OWP_USR2.with(|c| c.set(false));
    OWP_INT.with(|c| c.set(false));
    OWP_ALRM.with(|c| c.set(false));
}

pub fn signal_set_usr1() {
    OWP_USR1.with(|c| c.set(true));
}
pub fn signal_set_usr2() {
    OWP_USR2.with(|c| c.set(true));
}
pub fn signal_set_int() {
    OWP_INT.with(|c| c.set(true));
}
pub fn signal_set_alrm() {
    OWP_ALRM.with(|c| c.set(true));
}

pub fn signal_usr1() -> bool {
    OWP_USR1.with(std::cell::Cell::get)
}
pub fn signal_usr2() -> bool {
    OWP_USR2.with(std::cell::Cell::get)
}
pub fn signal_int() -> bool {
    OWP_INT.with(std::cell::Cell::get)
}
pub fn signal_alrm() -> bool {
    OWP_ALRM.with(std::cell::Cell::get)
}

/// `sig_catch` — map POSIX-like signal numbers onto the endpoint flags.
pub fn sig_catch(signo: i32) {
    match signo {
        libc::SIGUSR1 => signal_set_usr1(),
        libc::SIGUSR2 => signal_set_usr2(),
        libc::SIGINT => signal_set_int(),
        libc::SIGALRM => signal_set_alrm(),
        _ => {},
    }
}

/// Wait until Start (USR1), Stop (USR2) or Interrupt — mirrors child `sigsuspend` loop.
#[must_use]
pub fn wait_for_session_kickoff() -> OwampAcceptType {
    loop {
        if signal_int() || signal_usr2() {
            return OwampAcceptType::Reject;
        }
        if signal_usr1() {
            return OwampAcceptType::Accept;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

// ---------------------------------------------------------------------------
// Data-record encode / decode (protocol.c helpers used by endpoint)
// ---------------------------------------------------------------------------

/// Encode err-estimate bytes; fall back like C when multiplier is unset
/// (TW open-mode receive stamps carry no estimate on the wire).
const fn encode_err_estimate_or_fallback(stamp: &OwampTimeStamp, err: &mut [u8; 2]) {
    if encode_timestamp_err_estimate(stamp, err) {
        return;
    }
    let mut fb = *stamp;
    fb.multiplier = 0xff;
    fb.scale = 0x3f;
    fb.sync = false;
    let _ = encode_timestamp_err_estimate(&fb, err);
}

/// Encode a v3 (25-octet) data record (`_OWPEncodeDataRecord`).
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn encode_data_record(buf: &mut [u8], rec: &OwampDataRec) -> Result<()> {
    if buf.len() < DATAREC_V3_SIZE {
        return Err(OwampError::Message(
            "encode_data_record: buffer too small".into(),
        ));
    }
    buf[..DATAREC_V3_SIZE].fill(0);
    BigEndian::write_u32(&mut buf[0..4], rec.seq_no);

    let mut err = [0u8; 2];
    encode_err_estimate_or_fallback(&rec.send, &mut err);
    buf[4..6].copy_from_slice(&err);
    encode_err_estimate_or_fallback(&rec.recv, &mut err);
    buf[6..8].copy_from_slice(&err);

    let mut ts = [0u8; 8];
    encode_timestamp(&rec.send, &mut ts);
    buf[8..16].copy_from_slice(&ts);
    encode_timestamp(&rec.recv, &mut ts);
    buf[16..24].copy_from_slice(&ts);
    buf[24] = rec.ttl;
    Ok(())
}

/// Decode a data record; `file_version` is 0/2 (24 B) or 3 (25 B).
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn decode_data_record(file_version: u32, buf: &[u8]) -> Result<OwampDataRec> {
    let mut rec = OwampDataRec::default();
    match file_version {
        0 | 2 => {
            if buf.len() < DATAREC_V2_SIZE {
                return Err(OwampError::Message("v2 record truncated".into()));
            }
            rec.seq_no = BigEndian::read_u32(&buf[0..4]);
            let mut ts8 = [0u8; 8];
            ts8.copy_from_slice(&buf[4..12]);
            rec.send = decode_timestamp(&ts8);
            let mut err2 = [0u8; 2];
            err2.copy_from_slice(&buf[12..14]);
            if !decode_timestamp_err_estimate(&mut rec.send, &err2) {
                return Err(OwampError::Message("invalid send err".into()));
            }
            ts8.copy_from_slice(&buf[14..22]);
            rec.recv = decode_timestamp(&ts8);
            err2.copy_from_slice(&buf[22..24]);
            if !decode_timestamp_err_estimate(&mut rec.recv, &err2) {
                return Err(OwampError::Message("invalid recv err".into()));
            }
            rec.ttl = 255;
        },
        3 => {
            if buf.len() < DATAREC_V3_SIZE {
                return Err(OwampError::Message("v3 record truncated".into()));
            }
            rec.seq_no = BigEndian::read_u32(&buf[0..4]);
            let mut err2 = [0u8; 2];
            err2.copy_from_slice(&buf[4..6]);
            if !decode_timestamp_err_estimate(&mut rec.send, &err2) {
                return Err(OwampError::Message("invalid send err".into()));
            }
            err2.copy_from_slice(&buf[6..8]);
            if !decode_timestamp_err_estimate(&mut rec.recv, &err2) {
                return Err(OwampError::Message("invalid recv err".into()));
            }
            let mut ts8 = [0u8; 8];
            ts8.copy_from_slice(&buf[8..16]);
            rec.send.owptime = decode_timestamp(&ts8).owptime;
            ts8.copy_from_slice(&buf[16..24]);
            rec.recv.owptime = decode_timestamp(&ts8).owptime;
            rec.ttl = buf[24];
        },
        _ => {
            return Err(OwampError::Message(format!(
                "unsupported datarec version {file_version}"
            )));
        },
    }
    Ok(rec)
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn encode_tw_data_record(buf: &mut [u8], rec: &OwampTwDataRec) -> Result<()> {
    if buf.len() < DATAREC_TW_V3_SIZE {
        return Err(OwampError::Message("tw record buffer too small".into()));
    }
    encode_data_record(&mut buf[0..25], &rec.sent)?;
    encode_data_record(&mut buf[25..50], &rec.reflected)?;
    Ok(())
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn decode_tw_data_record(file_version: u32, buf: &[u8]) -> Result<OwampTwDataRec> {
    if file_version != (VERSION_TWOWAY | 3) {
        return Err(OwampError::Message("unsupported tw datarec version".into()));
    }
    if buf.len() < DATAREC_TW_V3_SIZE {
        return Err(OwampError::Message("tw record truncated".into()));
    }
    Ok(OwampTwDataRec {
        sent: decode_data_record(3, &buf[0..25])?,
        reflected: decode_data_record(3, &buf[25..50])?,
    })
}

#[must_use]
pub const fn datarec_size_for_version(file_version: u32) -> Option<usize> {
    match file_version {
        0 | 2 => Some(DATAREC_V2_SIZE),
        3 => Some(DATAREC_V3_SIZE),
        v if v == (VERSION_TWOWAY | 3) => Some(DATAREC_TW_V3_SIZE),
        _ => None,
    }
}

/// `_OWPWriteDataHeaderFinished` — patch finished + `next_seqno` at header offset 8.
///
/// `finished`: 0 = Error, 1 = Normal, 2 = Incomplete (matches `OWPSessionFinishedType`).
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn write_data_header_finished_bytes(
    fp: &mut (impl IoWrite + Seek),
    finished: u32,
    next_seqno: u32,
) -> Result<()> {
    if finished > 2 {
        return Err(OwampError::Message(
            "write_data_header_finished: invalid finished".into(),
        ));
    }
    fp.seek(SeekFrom::Start(8))
        .map_err(|e| OwampError::Message(format!("seek finished: {e}")))?;
    fp.write_all(&finished.to_be_bytes())
        .map_err(|e| OwampError::Message(format!("write finished: {e}")))?;
    fp.write_all(&next_seqno.to_be_bytes())
        .map_err(|e| OwampError::Message(format!("write next_seqno: {e}")))?;
    let _ = fp.flush();
    Ok(())
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn write_data_record_bytes(fp: &mut dyn IoWrite, rec: &OwampDataRec) -> Result<()> {
    let mut buf = [0u8; DATAREC_SIZE];
    encode_data_record(&mut buf, rec)?;
    fp.write_all(&buf)
        .map_err(|e| OwampError::Message(format!("write_data_record: {e}")))
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn write_tw_data_record_bytes(fp: &mut dyn IoWrite, rec: &OwampTwDataRec) -> Result<()> {
    let mut buf = [0u8; DATAREC_TW_V3_SIZE];
    encode_tw_data_record(&mut buf, rec)?;
    fp.write_all(&buf)
        .map_err(|e| OwampError::Message(format!("write_tw_data_record: {e}")))
}

// ---------------------------------------------------------------------------
// Payload / packet sizing (api.c)
// ---------------------------------------------------------------------------

#[must_use]
pub const fn test_payload_size(mode: u32, padding: u32) -> usize {
    let msg = match mode {
        OWP_MODE_OPEN | TWP_MODE_MIXED => 14,
        OWP_MODE_AUTHENTICATED | OWP_MODE_ENCRYPTED => 48,
        _ => 0,
    };
    msg + padding as usize
}

#[must_use]
pub const fn test_tw_payload_size(mode: u32, padding: u32) -> usize {
    let msg = match mode {
        OWP_MODE_OPEN | TWP_MODE_MIXED => 41,
        OWP_MODE_AUTHENTICATED | OWP_MODE_ENCRYPTED => 112,
        _ => 0,
    };
    msg + padding as usize
}

#[must_use]
pub const fn test_packet_size(af_inet6: bool, mode: u32, padding: u32) -> usize {
    let hdr = if af_inet6 {
        IP6_HDR + UDP_HDR
    } else {
        IP4_HDR + UDP_HDR
    };
    let payload = test_payload_size(mode, padding);
    if payload == 0 {
        0
    } else {
        payload + hdr
    }
}

#[must_use]
pub const fn test_tw_packet_size(af_inet6: bool, mode: u32, padding: u32) -> usize {
    let hdr = if af_inet6 {
        IP6_HDR + UDP_HDR
    } else {
        IP4_HDR + UDP_HDR
    };
    let payload = test_tw_payload_size(mode, padding);
    if payload == 0 {
        0
    } else {
        payload + hdr
    }
}

/// Offsets of mutable fields inside an OWAMP one-way test payload.
#[derive(Clone, Copy, Debug)]
pub struct PayloadLayout {
    pub seq_offset: usize,
    pub tstamp_offset: usize,
    pub tstamperr_offset: usize,
    pub hmac_offset: Option<usize>,
    pub padding_offset: usize,
    pub total_len: usize,
}

impl PayloadLayout {
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn for_mode(mode: u32, padding: u32) -> Result<Self> {
        let total = test_payload_size(mode, padding);
        if total == 0 {
            return Err(OwampError::Message("bogus mode bits".into()));
        }
        Ok(match mode {
            OWP_MODE_OPEN | TWP_MODE_MIXED => Self {
                seq_offset: 0,
                tstamp_offset: 4,
                tstamperr_offset: 12,
                hmac_offset: None,
                padding_offset: 14,
                total_len: total,
            },
            OWP_MODE_AUTHENTICATED | OWP_MODE_ENCRYPTED => Self {
                seq_offset: 0,
                tstamp_offset: 16,
                tstamperr_offset: 24,
                hmac_offset: Some(32),
                padding_offset: 48,
                total_len: total,
            },
            _ => return Err(OwampError::Message("bogus mode bits".into())),
        })
    }
}

/// TWAMP reflector / client reply field offsets (after reflection rewrite).
#[derive(Clone, Copy, Debug)]
pub struct TwReplyLayout {
    pub seq_offset: usize,
    pub tstamp_offset: usize,
    pub tstamperr_offset: usize,
    pub rcv_tstamp_offset: usize,
    pub snd_seq_offset: usize,
    pub snd_tstamp_offset: usize,
    pub snd_tstamperr_offset: usize,
    pub snd_ttl_offset: usize,
    pub hmac_offset: Option<usize>,
    pub padding_offset: usize,
    pub total_len: usize,
    /// Cleartext staging length before encrypt (0 for open).
    pub clear_len: usize,
}

impl TwReplyLayout {
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn for_mode(mode: u32, padding: u32) -> Result<Self> {
        let total = test_tw_payload_size(mode, padding);
        if total == 0 {
            return Err(OwampError::Message("bogus tw mode bits".into()));
        }
        Ok(match mode {
            OWP_MODE_OPEN | TWP_MODE_MIXED => Self {
                seq_offset: 0,
                tstamp_offset: 4,
                tstamperr_offset: 12,
                rcv_tstamp_offset: 16,
                snd_seq_offset: 24,
                snd_tstamp_offset: 28,
                snd_tstamperr_offset: 36,
                snd_ttl_offset: 40,
                hmac_offset: None,
                padding_offset: 41,
                total_len: total,
                clear_len: 0,
            },
            OWP_MODE_AUTHENTICATED | OWP_MODE_ENCRYPTED => Self {
                seq_offset: 0,
                tstamp_offset: 16,
                tstamperr_offset: 24,
                rcv_tstamp_offset: 32,
                snd_seq_offset: 48,
                snd_tstamp_offset: 64,
                snd_tstamperr_offset: 72,
                snd_ttl_offset: 80,
                hmac_offset: Some(96),
                padding_offset: 112,
                total_len: total,
                clear_len: 96,
            },
            _ => return Err(OwampError::Message("bogus tw mode bits".into())),
        })
    }
}

/// Build an OPEN-mode plaintext test packet (seq + stamp + err + zero pad).
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn build_open_payload(
    layout: &PayloadLayout,
    seq: u32,
    stamp: &OwampTimeStamp,
) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; layout.total_len];
    BigEndian::write_u32(&mut buf[layout.seq_offset..], seq);
    let mut ts = [0u8; 8];
    encode_timestamp(stamp, &mut ts);
    buf[layout.tstamp_offset..layout.tstamp_offset + 8].copy_from_slice(&ts);
    let mut err = [0u8; 2];
    if !encode_timestamp_err_estimate(stamp, &mut err) {
        return Err(OwampError::Message("invalid timestamp error".into()));
    }
    buf[layout.tstamperr_offset..layout.tstamperr_offset + 2].copy_from_slice(&err);
    Ok(buf)
}

// ---------------------------------------------------------------------------
// AES / HMAC test-packet crypto (run_sender / run_receiver / reflector)
// ---------------------------------------------------------------------------

/// Endpoint session keys derived from SID + control keys (RFC 4656 §4.1).
#[derive(Clone)]
pub struct EndpointCrypto {
    pub aes_bytes: [u8; AES_KEY_SIZE],
    pub aes: AesKey,
    /// TWAMP reply direction AES key (encrypt for reflector, decrypt for client).
    pub aes_tw_reply: AesKey,
    pub hmac_key: [u8; HMAC_KEY_SIZE],
}

impl EndpointCrypto {
    /// `_OWPEndpointInitHook` crypto block.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn derive(
        sid: &OwampSid,
        control_aes_key: &[u8; AES_KEY_SIZE],
        control_hmac_key: &[u8; HMAC_KEY_SIZE],
    ) -> Result<Self> {
        let aes_bytes = derive_test_aes_key_bytes(sid, control_aes_key);
        let hmac_key = derive_test_hmac_key(sid, control_hmac_key)?;
        let aes = AesKey::from_bytes(&aes_bytes);
        Ok(Self {
            aes_bytes,
            aes: aes.clone(),
            aes_tw_reply: aes,
            hmac_key,
        })
    }

    fn hmac(&self) -> Result<HmacSha1Ctx> {
        HmacSha1Ctx::new(&self.hmac_key)
    }
}

/// Seal a one-way test packet into `payload` (matches `run_sender` encrypt path).
///
/// For OPEN/MIXED: plaintext layout. For AUTH: encrypt first block (seq), leave
/// timestamp plaintext. For ENCRYPTED: encrypt both blocks after timestamp is set.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn seal_one_way_packet(
    mode: u32,
    crypto: Option<&EndpointCrypto>,
    payload: &mut [u8],
    seq: u32,
    stamp: &OwampTimeStamp,
) -> Result<()> {
    let layout = PayloadLayout::for_mode(
        mode,
        (payload.len().saturating_sub(48).min(u32::MAX as usize)) as u32,
    )
    .or_else(|_| PayloadLayout::for_mode(mode, 0))?;
    if payload.len() < layout.total_len.min(14) {
        return Err(OwampError::Message("payload too short to seal".into()));
    }

    let mut err = [0u8; 2];
    if !encode_timestamp_err_estimate(stamp, &mut err) {
        let mut fallback = *stamp;
        fallback.multiplier = 0xff;
        fallback.scale = 0x3f;
        fallback.sync = false;
        let _ = encode_timestamp_err_estimate(&fallback, &mut err);
    }
    let mut ts = [0u8; 8];
    encode_timestamp(stamp, &mut ts);

    if !mode_docipher_test(mode) {
        BigEndian::write_u32(&mut payload[0..4], seq);
        payload[4..12].copy_from_slice(&ts);
        payload[12..14].copy_from_slice(&err);
        return Ok(());
    }

    let crypto = crypto.ok_or_else(|| OwampError::Message("seal requires crypto".into()))?;
    let mut clr = [0u8; 32];
    BigEndian::write_u32(&mut clr[0..4], seq);

    if mode & OWP_MODE_ENCRYPTED != 0 {
        clr[16..24].copy_from_slice(&ts);
        clr[24..26].copy_from_slice(&err);
    } else {
        // Authenticated: timestamp stays in the clear at payload[16..]
        payload[16..24].copy_from_slice(&ts);
        payload[24..26].copy_from_slice(&err);
    }

    let mut hmac = crypto.hmac()?;
    hmac.update(&clr[0..16]);

    let mut iv = zero_iv();
    block_encrypt(&mut iv, &crypto.aes, &clr[0..16], &mut payload[0..16])?;

    if mode & OWP_MODE_ENCRYPTED != 0 {
        hmac.update(&clr[16..32]);
        block_encrypt(&mut iv, &crypto.aes, &clr[16..32], &mut payload[16..32])?;
    }

    let mut digest = [0u8; HMAC_TRUNC_SIZE];
    hmac.finish_truncated_clear(&mut digest);
    payload[32..48].copy_from_slice(&digest);
    Ok(())
}

/// Decrypt / verify a one-way test packet in place; returns `(seq, send_stamp)`.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn open_one_way_packet(
    mode: u32,
    crypto: Option<&EndpointCrypto>,
    payload: &mut [u8],
) -> Result<(u32, OwampTimeStamp)> {
    if !mode_docipher_test(mode) {
        return parse_open_payload(payload);
    }
    let crypto = crypto.ok_or_else(|| OwampError::Message("open requires crypto".into()))?;
    if payload.len() < 48 {
        return Err(OwampError::Message("auth payload too short".into()));
    }

    let wire_hmac: [u8; HMAC_TRUNC_SIZE] = payload[32..48]
        .try_into()
        .map_err(|_| OwampError::Message("hmac slice".into()))?;

    let mut iv = zero_iv();
    let mut first = [0u8; 16];
    first.copy_from_slice(&payload[0..16]);
    block_decrypt(&mut iv, &crypto.aes, &first, &mut payload[0..16])?;

    let mut hmac = crypto.hmac()?;
    hmac.update(&payload[0..16]);

    if mode & OWP_MODE_ENCRYPTED != 0 {
        let mut second = [0u8; 16];
        second.copy_from_slice(&payload[16..32]);
        block_decrypt(&mut iv, &crypto.aes, &second, &mut payload[16..32])?;
        hmac.update(&payload[16..32]);
    }

    if !hmac.check_truncated_clear(&wire_hmac) {
        return Err(OwampError::Message(
            "invalid HMAC on received packet".into(),
        ));
    }
    parse_auth_payload(payload)
}

/// Build a TWAMP reflector reply from a decrypted inbound one-way packet.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn build_reflector_reply(
    mode: u32,
    crypto: Option<&EndpointCrypto>,
    inbound_plain: &[u8],
    inbound_ttl: u8,
    reply_seq: u32,
    recv_stamp: &OwampTimeStamp,
    reflect_stamp: &OwampTimeStamp,
    padding_len: usize,
) -> Result<Vec<u8>> {
    let layout = TwReplyLayout::for_mode(mode, padding_len as u32)?;
    let mut payload = vec![0u8; layout.total_len];

    let (snd_seq, snd_stamp) = if mode_docipher_test(mode) {
        parse_auth_payload(inbound_plain)?
    } else {
        parse_open_payload(inbound_plain)?
    };
    let mut snd_ts = [0u8; 8];
    encode_timestamp(&snd_stamp, &mut snd_ts);
    let mut snd_err = [0u8; 2];
    let _ = encode_timestamp_err_estimate(&snd_stamp, &mut snd_err);

    let mut rcv_ts = [0u8; 8];
    encode_timestamp(recv_stamp, &mut rcv_ts);
    let mut ref_ts = [0u8; 8];
    encode_timestamp(reflect_stamp, &mut ref_ts);
    let mut ref_err = [0u8; 2];
    if !encode_timestamp_err_estimate(reflect_stamp, &mut ref_err) {
        let mut fb = *reflect_stamp;
        fb.multiplier = 0xff;
        fb.scale = 0x3f;
        fb.sync = false;
        let _ = encode_timestamp_err_estimate(&fb, &mut ref_err);
    }

    if !mode_docipher_test(mode) {
        BigEndian::write_u32(&mut payload[layout.seq_offset..], reply_seq);
        payload[layout.tstamp_offset..layout.tstamp_offset + 8].copy_from_slice(&ref_ts);
        payload[layout.tstamperr_offset..layout.tstamperr_offset + 2].copy_from_slice(&ref_err);
        payload[layout.rcv_tstamp_offset..layout.rcv_tstamp_offset + 8].copy_from_slice(&rcv_ts);
        BigEndian::write_u32(&mut payload[layout.snd_seq_offset..], snd_seq);
        payload[layout.snd_tstamp_offset..layout.snd_tstamp_offset + 8].copy_from_slice(&snd_ts);
        payload[layout.snd_tstamperr_offset..layout.snd_tstamperr_offset + 2]
            .copy_from_slice(&snd_err);
        payload[layout.snd_ttl_offset] = inbound_ttl;
        return Ok(payload);
    }

    let crypto =
        crypto.ok_or_else(|| OwampError::Message("reflector reply needs crypto".into()))?;
    let mut clr = [0u8; 96];
    BigEndian::write_u32(&mut clr[0..4], reply_seq);
    if mode & OWP_MODE_ENCRYPTED != 0 {
        clr[16..24].copy_from_slice(&ref_ts);
        clr[24..26].copy_from_slice(&ref_err);
        clr[32..40].copy_from_slice(&rcv_ts);
        BigEndian::write_u32(&mut clr[48..52], snd_seq);
        clr[64..72].copy_from_slice(&snd_ts);
        clr[72..74].copy_from_slice(&snd_err);
        clr[80] = inbound_ttl;
    } else {
        // Authenticated: only first block encrypted; rest in the clear on wire.
        payload[16..24].copy_from_slice(&ref_ts);
        payload[24..26].copy_from_slice(&ref_err);
        payload[32..40].copy_from_slice(&rcv_ts);
        BigEndian::write_u32(&mut payload[48..52], snd_seq);
        payload[64..72].copy_from_slice(&snd_ts);
        payload[72..74].copy_from_slice(&snd_err);
        payload[80] = inbound_ttl;
    }

    let mut hmac = crypto.hmac()?;
    hmac.update(&clr[0..16]);
    let mut iv = zero_iv();
    block_encrypt(
        &mut iv,
        &crypto.aes_tw_reply,
        &clr[0..16],
        &mut payload[0..16],
    )?;

    if mode & OWP_MODE_ENCRYPTED != 0 {
        hmac.update(&clr[16..96]);
        block_encrypt(
            &mut iv,
            &crypto.aes_tw_reply,
            &clr[16..96],
            &mut payload[16..96],
        )?;
    }

    let mut digest = [0u8; HMAC_TRUNC_SIZE];
    hmac.finish_truncated_clear(&mut digest);
    payload[96..112].copy_from_slice(&digest);
    Ok(payload)
}

// ---------------------------------------------------------------------------
// Skip / lost-packet tracking
// ---------------------------------------------------------------------------

///
/// # Panics
///
/// Panics if an internal invariant from the C port is violated.
pub fn encode_skip_record(buf: &mut [u8], skip: &OwampSkipRec) {
    assert!(buf.len() >= SKIPREC_SIZE);
    BigEndian::write_u32(&mut buf[0..4], skip.begin);
    BigEndian::write_u32(&mut buf[4..8], skip.end);
}

#[must_use]
pub fn decode_skip_record(buf: &[u8]) -> OwampSkipRec {
    OwampSkipRec {
        begin: BigEndian::read_u32(&buf[0..4]),
        end: BigEndian::read_u32(&buf[4..8]),
    }
}

/// Sender-side skip list: coalesces consecutive late packets (`skip()`).
#[derive(Clone, Debug, Default)]
pub struct SkipList {
    pub skips: Vec<OwampSkipRec>,
}

impl SkipList {
    pub fn note_skip(&mut self, seq: u32) {
        if let Some(last) = self.skips.last_mut() {
            if last.end + 1 == seq || last.end == seq {
                last.end = seq;
                return;
            }
        }
        self.skips.push(OwampSkipRec {
            begin: seq,
            end: seq,
        });
    }

    /// Serialize like `run_sender` IPC: `next_seq` + `num_skips` + skip records.
    pub fn encode_ipc(&self, next_seq: u32, out: &mut Vec<u8>) {
        out.extend_from_slice(&next_seq.to_be_bytes());
        out.extend_from_slice(&(self.skips.len() as u32).to_be_bytes());
        for s in &self.skips {
            let mut buf = [0u8; SKIPREC_SIZE];
            encode_skip_record(&mut buf, s);
            out.extend_from_slice(&buf);
        }
    }
}

/// Receiver lost-packet node (`OWPLostPacketRec`).
#[derive(Clone, Debug)]
pub struct LostPacket {
    pub seq: u32,
    pub relative: OwampNum64,
    /// Cumulative offset from test start (`node->absolute` / sender schedule).
    pub cumulative: OwampNum64,
    pub absolute: Duration,
    /// C `hit` — packet was received and accepted.
    pub seen: bool,
    /// C `sent` — TWAMP client marked the outbound packet as sent.
    pub sent: bool,
}

/// Sliding window used by the receiver to declare losses after `loss_timeout`.
#[derive(Debug, Default)]
pub struct LostPacketBuffer {
    by_seq: HashMap<u32, LostPacket>,
    order: Vec<u32>,
    pub npackets: u32,
    pub start_time: OwampNum64,
    pub twoway: bool,
}

impl LostPacketBuffer {
    #[must_use]
    pub fn with_capacity_hint(n: usize) -> Self {
        Self {
            by_seq: HashMap::with_capacity(n),
            order: Vec::with_capacity(n),
            ..Default::default()
        }
    }

    pub fn insert(&mut self, pkt: LostPacket) {
        let seq = pkt.seq;
        if self.by_seq.insert(seq, pkt).is_none() {
            self.order.push(seq);
        }
    }

    pub fn mark_seen(&mut self, seq: u32) -> bool {
        if let Some(p) = self.by_seq.get_mut(&seq) {
            p.seen = true;
            true
        } else {
            false
        }
    }

    pub fn mark_sent(&mut self, seq: u32) -> bool {
        if let Some(p) = self.by_seq.get_mut(&seq) {
            p.sent = true;
            true
        } else {
            false
        }
    }

    pub fn get_mut(&mut self, seq: u32) -> Option<&mut LostPacket> {
        self.by_seq.get_mut(&seq)
    }

    #[must_use]
    pub fn begin_seq(&self) -> Option<u32> {
        self.order.first().copied()
    }

    /// Ensure nodes `[begin..=seq]` exist, generating schedule deltas as needed
    /// (`get_node` growth path).
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant from the C port is violated.
    pub fn ensure_through(
        &mut self,
        seq: u32,
        schedule: &mut ScheduleContext,
        session_start: Duration,
    ) -> Result<&LostPacket> {
        if self.order.is_empty() {
            return Err(OwampError::Message("lost buffer empty".into()));
        }
        while *self.order.last().unwrap() < seq {
            let prev = self.by_seq.get(self.order.last().unwrap()).unwrap().clone();
            let relative = num64_add(prev.relative, schedule.generate_next_delta()?);
            let absolute =
                session_start + Duration::from_secs_f64(num64_to_double(relative).max(0.0));
            let next = LostPacket {
                seq: prev.seq + 1,
                relative,
                cumulative: relative,
                absolute,
                seen: false,
                sent: false,
            };
            self.insert(next);
        }
        self.by_seq
            .get(&seq)
            .ok_or_else(|| OwampError::Message("lost node missing".into()))
    }

    /// Flush packets whose absolute deadline is before `now` (`flush_lost`).
    ///
    /// Lost records use `start_time + relative` as presumed send time and a
    /// zero recv owptime (OWAMP lost-record convention).
    pub fn flush_lost(
        &mut self,
        now: Duration,
        loss_timeout: Duration,
        send_stamp_for: impl Fn(u32) -> OwampTimeStamp,
    ) -> Vec<OwampDataRec> {
        let mut lost = Vec::new();
        let mut keep = Vec::new();
        for seq in self.order.drain(..) {
            if let Some(pkt) = self.by_seq.remove(&seq) {
                if self.twoway && !pkt.sent {
                    keep.push(pkt);
                    continue;
                }
                let deadline = pkt.absolute + loss_timeout;
                if !pkt.seen && now > deadline {
                    let mut send = send_stamp_for(seq);
                    if send.owptime.0 == 0 && self.start_time.0 != 0 {
                        send = OwampTimeStamp {
                            owptime: self.start_time + pkt.cumulative,
                            sync: false,
                            multiplier: 1,
                            scale: 64,
                        };
                    }
                    lost.push(OwampDataRec {
                        seq_no: seq,
                        send,
                        // C flush_lost: zero recv time, valid err estimate for encoding.
                        recv: lost_record_recv_stamp(),
                        ttl: 255,
                    });
                } else if !pkt.seen || self.twoway {
                    // Keep unseen that are not yet due; also keep hit nodes until
                    // flushed past (C frees after writing hits as well when due).
                    if pkt.seen {
                        // C frees hit nodes once past timeout without rewriting.
                        // Drop them here once due.
                        if now > deadline {
                            continue;
                        }
                    }
                    keep.push(pkt);
                }
            }
        }
        for pkt in keep {
            self.order.push(pkt.seq);
            self.by_seq.insert(pkt.seq, pkt);
        }
        lost
    }

    /// C-faithful flush return: `<0` error, `>0` test complete, `0` more work.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn flush_lost_status(
        &mut self,
        now: Duration,
        loss_timeout: Duration,
        force: bool,
        send_stamp_for: impl Fn(u32) -> OwampTimeStamp,
        mut on_lost: impl FnMut(&OwampDataRec) -> Result<()>,
    ) -> Result<i32> {
        let mut curr = now;
        loop {
            let Some(&begin_seq) = self.order.first() else {
                return Ok(1);
            };
            let Some(begin) = self.by_seq.get(&begin_seq).cloned() else {
                return Ok(1);
            };
            if self.twoway && !begin.sent {
                break;
            }
            let expect = begin.absolute + loss_timeout;
            if force {
                curr = expect + loss_timeout;
            }
            if expect >= curr {
                break;
            }
            if !begin.seen {
                let mut send = send_stamp_for(begin.seq);
                if send.owptime.0 == 0 {
                    send = OwampTimeStamp {
                        owptime: self.start_time + begin.cumulative,
                        sync: false,
                        multiplier: 1,
                        scale: 64,
                    };
                }
                let rec = OwampDataRec {
                    seq_no: begin.seq,
                    send,
                    recv: lost_record_recv_stamp(),
                    ttl: 255,
                };
                on_lost(&rec)?;
            }
            self.by_seq.remove(&begin_seq);
            self.order.remove(0);
            if self.order.is_empty() {
                if begin.seq + 1 < self.npackets {
                    // Caller should extend via ensure_through before next flush.
                    return Ok(0);
                }
                return Ok(1);
            }
        }
        Ok(0)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.by_seq.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_seq.is_empty()
    }

    /// Remove one node (`free_node`).
    pub fn remove(&mut self, seq: u32) -> Option<LostPacket> {
        self.order.retain(|&s| s != seq);
        self.by_seq.remove(&seq)
    }
}

// ---------------------------------------------------------------------------
// C-name aliases (`endpoint.c`)
// ---------------------------------------------------------------------------

/// `LostFree` — drop all lost-packet nodes.
pub fn lost_free(buf: &mut LostPacketBuffer) {
    *buf = LostPacketBuffer::default();
}

/// `SkipFree` — drop skip-list allocations.
pub fn skip_free(skips: &mut SkipList) {
    *skips = SkipList::default();
}

/// `CmpLostPacket` — I2Datum-style inequality (0 = equal in C hash sense → here `false`).
#[must_use]
pub const fn cmp_lost_packet(a: u32, b: u32) -> bool {
    a != b
}

/// `HashLostPacket` — low 16 bits of sequence number.
#[must_use]
pub const fn hash_lost_packet(seq: u32) -> u32 {
    seq & 0xffff
}

/// `_OWPEndpointFree` / `EndpointFree`
#[must_use]
pub fn endpoint_free(ep: EndpointState, aval: OwampAcceptType) -> OwampAcceptType {
    ep.free(aval)
}

/// `alloc_node` — insert a new lost-packet slot.
pub fn alloc_node(
    buf: &mut LostPacketBuffer,
    seq: u32,
    npackets: u32,
    relative: OwampNum64,
    absolute: Duration,
) -> bool {
    if seq >= npackets {
        return false;
    }
    if let Some(&end) = buf.order.last() {
        if seq <= end {
            return false;
        }
    }
    buf.insert(LostPacket {
        seq,
        relative,
        cumulative: relative,
        absolute,
        seen: false,
        sent: false,
    });
    true
}

/// `free_node` — remove one lost-packet slot from the hash.
pub fn free_node(buf: &mut LostPacketBuffer, seq: u32) {
    let _ = buf.remove(seq);
}

/// `get_node` — fetch or extend the lost-packet chain through `seq`.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn get_node<'a>(
    buf: &'a mut LostPacketBuffer,
    seq: u32,
    schedule: &mut ScheduleContext,
    session_start: Duration,
) -> Result<&'a LostPacket> {
    buf.ensure_through(seq, schedule, session_start)
}

/// `skip` — extend the skip list for a late sender packet.
pub fn skip(skips: &mut SkipList, seq: u32) {
    skips.note_skip(seq);
}

/// `flush_lost` — C entry point into the lost-packet buffer flush logic.
pub fn flush_lost(
    buf: &mut LostPacketBuffer,
    now: Duration,
    loss_timeout: Duration,
    send_stamp_for: impl Fn(u32) -> OwampTimeStamp,
) -> Vec<OwampDataRec> {
    buf.flush_lost(now, loss_timeout, send_stamp_for)
}

/// `anon_file` — unlinked skip-record temp file (`anon_skip_file`).
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn anon_file() -> io::Result<File> {
    anon_skip_file()
}

/// `recvfromttl` — receive datagram plus best-effort TTL / hop limit.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn recvfromttl(sock: &UdpSocket, buf: &mut [u8]) -> Result<(usize, SocketAddr, u8)> {
    udp_recvfrom_ttl(sock, buf)
}

/// `sig_nothing` — SIGCHLD no-op used around endpoint fork.
pub const fn sig_nothing(signo: i32) {
    let _ = signo == libc::SIGCHLD;
}

#[must_use]
pub fn lost_buffer_prealloc_count(tspec: &OwampTestSpec) -> usize {
    let rate = test_packet_rate(tspec);
    let timeout = num64_to_double(tspec.loss_timeout).max(0.0);
    ((rate * timeout * PACKBUFF_ALLOC_FACTOR) as usize).max(100)
}

// ---------------------------------------------------------------------------
// Data-file reopen (`reopen_datafile`) / anonymous skip file (`anon_file`)
// ---------------------------------------------------------------------------

/// Dup the underlying fd and `fdopen` equivalent — buffered independent FILE*.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn reopen_datafile(infp: &File) -> io::Result<File> {
    let fd = infp.as_raw_fd();
    let newfd = unsafe { libc::dup(fd) };
    if newfd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(newfd) })
}

/// Create an unlinked temp file for skip-record IPC (`anon_file`).
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn anon_skip_file() -> io::Result<File> {
    let tmpdir = std::env::var_os("TMPDIR").unwrap_or_else(|| OWP_DEFAULT_TMPDIR.into());
    let mut path = PathBuf::from(tmpdir);
    path.push(OWP_SKIPFILE_FMT);
    let template = path.to_string_lossy().into_owned();
    let mut ctemplate = std::ffi::CString::new(template)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "skip template"))?
        .into_bytes_with_nul();
    let fd = unsafe { libc::mkstemp(ctemplate.as_mut_ptr() as *mut libc::c_char) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let _ = unsafe { libc::unlink(ctemplate.as_ptr() as *const libc::c_char) };
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Create an unlinked temp file named `owamp.XXXXXXXX` under `dir` (`CleanDataRecs`).
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn mkstemp_unlinked(dir: &std::path::Path) -> io::Result<File> {
    let mut path = dir.to_path_buf();
    path.push("owamp.XXXXXXXX");
    let template = path.to_string_lossy().into_owned();
    let mut ctemplate = std::ffi::CString::new(template)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "mkstemp template"))?
        .into_bytes_with_nul();
    let fd = unsafe { libc::mkstemp(ctemplate.as_mut_ptr() as *mut libc::c_char) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let _ = unsafe { libc::unlink(ctemplate.as_ptr() as *const libc::c_char) };
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Copy the first `nbytes` of `src` into `dst` starting at offset 0 (`I2CopyFile` subset).
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn copy_file_bytes(dst: &File, src: &File, nbytes: u64) -> io::Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};
    let mut src = src.try_clone()?;
    let mut dst = dst.try_clone()?;
    src.seek(SeekFrom::Start(0))?;
    dst.seek(SeekFrom::Start(0))?;
    let mut remaining = nbytes;
    let mut buf = vec![0u8; 64 * 1024];
    while remaining > 0 {
        let n = remaining.min(buf.len() as u64) as usize;
        src.read_exact(&mut buf[..n])?;
        dst.write_all(&buf[..n])?;
        remaining -= n as u64;
    }
    dst.flush()?;
    Ok(())
}

/// Whole-file rewrite: copy `src` over `dst` from offset 0 (`I2CopyFile` after clean).
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn copy_file_overwrite(dst: &File, src: &File) -> io::Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};
    let mut src = src.try_clone()?;
    let mut dst = dst.try_clone()?;
    let len = src.seek(SeekFrom::End(0))?;
    src.seek(SeekFrom::Start(0))?;
    dst.seek(SeekFrom::Start(0))?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut remaining = len;
    while remaining > 0 {
        let n = remaining.min(buf.len() as u64) as usize;
        src.read_exact(&mut buf[..n])?;
        dst.write_all(&buf[..n])?;
        remaining -= n as u64;
    }
    dst.set_len(len)?;
    dst.flush()?;
    Ok(())
}

/// POSIX `fcntl` write-lock (`F_SETLKW` / `F_WRLCK`) for session data files.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn flock_write_lock(fp: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        let mut flk: libc::flock = unsafe { std::mem::zeroed() };
        flk.l_type = libc::F_WRLCK;
        flk.l_whence = libc::SEEK_SET as i16;
        flk.l_start = 0;
        flk.l_len = 0;
        let rc = unsafe { libc::fcntl(fp.as_raw_fd(), libc::F_SETLKW, &flk) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = fp;
        Ok(())
    }
}

/// POSIX `fcntl` unlock (`F_UNLCK`).
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn flock_unlock(fp: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        let mut flk: libc::flock = unsafe { std::mem::zeroed() };
        flk.l_type = libc::F_UNLCK;
        flk.l_whence = libc::SEEK_SET as i16;
        flk.l_start = 0;
        flk.l_len = 0;
        let rc = unsafe { libc::fcntl(fp.as_raw_fd(), libc::F_SETLKW, &flk) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = fp;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// UDP socket setup / send / recv with TTL
// ---------------------------------------------------------------------------

const fn domain_for(addr: SocketAddr) -> Domain {
    match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    }
}

/// Bind options mirroring `_OWPEndpointInit` port selection.
#[derive(Clone, Copy, Debug, Default)]
pub struct TestSocketBindOpts {
    pub portrange: Option<OwampPortRange>,
    /// TWAMP reflector/server: requested port outside range is ignored; on
    /// `EADDRINUSE` walk the configured (or dynamic `port..=u16::MAX`) range.
    pub twamp_server: bool,
}

/// Bind a UDP test socket with optional port-range walk (`_OWPEndpointInit`).
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn create_test_udp_socket(
    local: SocketAddr,
    portrange: Option<OwampPortRange>,
) -> Result<(Socket, SocketAddr)> {
    create_test_udp_socket_ex(
        local,
        TestSocketBindOpts {
            portrange,
            twamp_server: false,
        },
    )
}

/// Full C port-selection parity including TWAMP-server range walk.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn create_test_udp_socket_ex(
    local: SocketAddr,
    opts: TestSocketBindOpts,
) -> Result<(Socket, SocketAddr)> {
    let sock = Socket::new(domain_for(local), Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| OwampError::Message(format!("socket(): {e}")))?;
    // C `_OWPEndpointInit` does not set SO_REUSEADDR on test sockets (only the
    // control listener does). Keeping reuse off is required for TWAMP on
    // localhost: client and server must not share the same UDP port, so the
    // reflector walks to the next free port on EADDRINUSE.

    let mut port = local.port();
    let mut portrange = opts.portrange;

    // TWAMP server: requested port outside configured range → treat as unset.
    if opts.twamp_server && port != 0 {
        if let Some(pr) = portrange {
            if port < pr.low || port > pr.high {
                port = 0;
            }
        }
    }

    let (first, low, range) = if port != 0 {
        let mut range = 0u32;
        if opts.twamp_server {
            if portrange.is_none() {
                // C: dynamic range from requested port to ~0 (u16::MAX).
                portrange = Some(OwampPortRange {
                    low: port,
                    high: u16::MAX,
                });
            }
            if let Some(pr) = portrange {
                if pr.high < pr.low {
                    return Err(OwampError::Message("Invalid port range specified".into()));
                }
                range = u32::from(pr.high) - u32::from(pr.low) + 1;
            }
        }
        let pr = portrange.unwrap_or(OwampPortRange {
            low: port,
            high: port,
        });
        (port, pr.low, range)
    } else if let Some(pr) = portrange {
        if pr.high < pr.low {
            return Err(OwampError::Message("Invalid port range specified".into()));
        }
        let range = u32::from(pr.high) - u32::from(pr.low) + 1;
        let r: u32 = rand::random();
        let first = pr
            .low
            .wrapping_add(((f64::from(r) / f64::from(0xffff_ffff_u32)) * f64::from(range)) as u16);
        (first, pr.low, range)
    } else {
        (0, 0, 0)
    };

    let mut p = first;
    loop {
        let mut try_addr = local;
        try_addr.set_port(p);
        match sock.bind(&try_addr.into()) {
            Ok(()) => break,
            Err(e) => {
                // C: only walk when portrange is set AND range != 0 AND EADDRINUSE.
                if range == 0 || e.kind() != io::ErrorKind::AddrInUse {
                    return Err(OwampError::Message(format!("bind({try_addr}): {e}")));
                }
                let off = u32::from(p.wrapping_sub(low));
                p = low.wrapping_add(((off + 1) % range) as u16);
                if p == first {
                    return Err(OwampError::Message("Full port range exhausted".into()));
                }
            },
        }
    }

    let bound = sock
        .local_addr()
        .map_err(|e| OwampError::Message(format!("getsockname(): {e}")))?
        .as_socket()
        .ok_or_else(|| OwampError::Message("getsockname: not IP".into()))?;
    Ok((sock, bound))
}

/// Compare peer to expected remote (`I2SockAddrEqual(..., I2SADDR_ALL)`).
///
/// Test-request addresses often use port `0` (any port); only the IP must match then.
#[must_use]
pub fn peer_addr_matches(expected: Option<SocketAddr>, peer: SocketAddr) -> bool {
    match expected {
        None => true,
        Some(e) => {
            if e.ip() != peer.ip() {
                return false;
            }
            if e.port() == 0 {
                true
            } else {
                e.port() == peer.port()
            }
        },
    }
}

/// Compute C `fbuff` size: ~1s of records, capped by `st_blksize`; 0 = unbuffered.
#[must_use]
pub fn compute_fbuff_size(rate: f64, datafile: &File) -> usize {
    let size = (rate * DATAREC_SIZE as f64) as usize;
    if size < DATAREC_SIZE {
        return 0;
    }
    let blk = fstat_blksize(datafile).unwrap_or(size);
    size.min(blk)
}

fn fstat_blksize(fp: &File) -> io::Result<usize> {
    #[cfg(unix)]
    {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::fstat(fp.as_raw_fd(), &mut st) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(st.st_blksize as usize)
    }
    #[cfg(not(unix))]
    {
        let _ = fp;
        Ok(DATAREC_SIZE * 64)
    }
}

/// Enlarge RCVBUF and request TTL / hop-limit ancillary data.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn configure_receiver_socket(sock: &Socket, need: usize, local: SocketAddr) -> Result<()> {
    let cur = sock.recv_buffer_size().unwrap_or(0);
    if cur < need {
        sock.set_recv_buffer_size(need)
            .map_err(|e| OwampError::Message(format!("setsockopt(RCVBUF): {e}")))?;
    }
    match local {
        SocketAddr::V4(_) => {
            // IP_RECVTTL
            let on: libc::c_int = 1;
            let rc = unsafe {
                libc::setsockopt(
                    sock.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_RECVTTL,
                    &on as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&on) as libc::socklen_t,
                )
            };
            if rc != 0 {
                return Err(OwampError::Message(format!(
                    "setsockopt(IP_RECVTTL): {}",
                    io::Error::last_os_error()
                )));
            }
        },
        SocketAddr::V6(_) => {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            {
                let on: libc::c_int = 1;
                let rc = unsafe {
                    libc::setsockopt(
                        sock.as_raw_fd(),
                        libc::IPPROTO_IPV6,
                        libc::IPV6_RECVHOPLIMIT,
                        &on as *const _ as *const libc::c_void,
                        std::mem::size_of_val(&on) as libc::socklen_t,
                    )
                };
                if rc != 0 {
                    return Err(OwampError::Message(format!(
                        "setsockopt(IPV6_RECVHOPLIMIT): {}",
                        io::Error::last_os_error()
                    )));
                }
            }
        },
    }
    Ok(())
}

/// Enlarge SNDBUF and set TTL/hoplimit to 255 (sender / TWAMP).
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn configure_sender_socket(
    sock: &Socket,
    need: usize,
    local: SocketAddr,
    type_p: u32,
) -> Result<()> {
    let cur = sock.send_buffer_size().unwrap_or(0);
    if cur < need {
        sock.set_send_buffer_size(need)
            .map_err(|e| OwampError::Message(format!("setsockopt(SNDBUF): {e}")))?;
    }
    let ttl: libc::c_int = 255;
    match local {
        SocketAddr::V4(_) => {
            let rc = unsafe {
                libc::setsockopt(
                    sock.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_TTL,
                    &ttl as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&ttl) as libc::socklen_t,
                )
            };
            if rc != 0 {
                return Err(OwampError::Message(format!(
                    "setsockopt(IP_TTL): {}",
                    io::Error::last_os_error()
                )));
            }
            if type_p != 0 {
                if type_p & !0x3f00_0000 != 0 {
                    return Err(OwampError::Message("Unsupported TypeP requested".into()));
                }
                let mut tos = ((type_p >> 24) as u8) & 0x3f;
                tos <<= 2;
                let tos_i = libc::c_int::from(tos);
                let rc = unsafe {
                    libc::setsockopt(
                        sock.as_raw_fd(),
                        libc::IPPROTO_IP,
                        libc::IP_TOS,
                        &tos_i as *const _ as *const libc::c_void,
                        std::mem::size_of_val(&tos_i) as libc::socklen_t,
                    )
                };
                if rc != 0 {
                    return Err(OwampError::Message(format!(
                        "setsockopt(IP_TOS): {}",
                        io::Error::last_os_error()
                    )));
                }
            }
        },
        SocketAddr::V6(_) => {
            let rc = unsafe {
                libc::setsockopt(
                    sock.as_raw_fd(),
                    libc::IPPROTO_IPV6,
                    libc::IPV6_UNICAST_HOPS,
                    &ttl as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&ttl) as libc::socklen_t,
                )
            };
            if rc != 0 {
                return Err(OwampError::Message(format!(
                    "setsockopt(IPV6_UNICAST_HOPS): {}",
                    io::Error::last_os_error()
                )));
            }
            if type_p != 0 {
                if type_p & !0x3f00_0000 != 0 {
                    return Err(OwampError::Message("Unsupported TypeP requested".into()));
                }
                let tclass = libc::c_int::from(((type_p >> 24) as u8) & 0x3f);
                // Prefer IPV6_TCLASS (RFC 3542); fall back to IP_TOS like C.
                #[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
                let (level, name) = (libc::IPPROTO_IPV6, libc::IPV6_TCLASS);
                #[cfg(not(any(
                    target_os = "linux",
                    target_os = "android",
                    target_os = "freebsd"
                )))]
                let (level, name) = (libc::IPPROTO_IP, libc::IP_TOS);
                let rc = unsafe {
                    libc::setsockopt(
                        sock.as_raw_fd(),
                        level,
                        name,
                        &tclass as *const _ as *const libc::c_void,
                        std::mem::size_of_val(&tclass) as libc::socklen_t,
                    )
                };
                if rc != 0 {
                    return Err(OwampError::Message(format!(
                        "setsockopt(IPV6_TCLASS/IP_TOS): {}",
                        io::Error::last_os_error()
                    )));
                }
            }
        },
    }
    Ok(())
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn socket_into_udp(sock: Socket) -> io::Result<UdpSocket> {
    Ok(unsafe { UdpSocket::from_raw_fd(sock.into_raw_fd()) })
}

/// `sendto` wrapper used by run loops.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn udp_sendto(sock: &UdpSocket, payload: &[u8], dest: SocketAddr) -> Result<usize> {
    match sock.send_to(payload, dest) {
        Ok(n) => Ok(n),
        Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => {
            Err(OwampError::Message("ENOBUFS".into()))
        },
        Err(e) => Err(OwampError::Message(format!("sendto: {e}"))),
    }
}

/// `recvfromttl` — receive datagram and best-effort extract IP TTL / hop limit.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn udp_recvfrom_ttl(sock: &UdpSocket, buf: &mut [u8]) -> Result<(usize, SocketAddr, u8)> {
    // macOS: prefer recv_from — some kernels lose datagrams with IP_RECVTTL recvmsg.
    #[cfg(target_os = "macos")]
    {
        let (n, peer) = sock
            .recv_from(buf)
            .map_err(|e| OwampError::Message(format!("recvfrom: {e}")))?;
        Ok((n, peer, 255))
    }
    #[cfg(not(target_os = "macos"))]
    {
        // Primary path: std recv (TTL default 255 when ancillary unavailable).
        // On Unix we also try recvmsg for TTL.
        #[cfg(unix)]
        {
            if let Ok(r) = recvmsg_with_ttl(sock.as_raw_fd(), buf) {
                return Ok(r);
            }
        }
        let (n, peer) = sock
            .recv_from(buf)
            .map_err(|e| OwampError::Message(format!("recvfrom: {e}")))?;
        Ok((n, peer, 255))
    }
}

#[cfg(unix)]
#[allow(dead_code)]
fn recvmsg_with_ttl(fd: RawFd, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, u8)> {
    use std::mem::{size_of, MaybeUninit};

    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut _,
        iov_len: buf.len(),
    };
    let mut peer_storage = MaybeUninit::<libc::sockaddr_storage>::uninit();
    let mut cmsg_buf = [0u8; 256];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = peer_storage.as_mut_ptr() as *mut _;
    msg.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
    msg.msg_controllen = cmsg_buf.len() as _;

    let rc = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    let peer_storage = unsafe { peer_storage.assume_init() };
    let peer = sockaddr_to_socketaddr(&peer_storage, msg.msg_namelen)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "peer addr"))?;

    let mut ttl: u8 = 255;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            let hdr = &*cmsg;
            if hdr.cmsg_level == libc::IPPROTO_IP
                && (hdr.cmsg_type == libc::IP_TTL || hdr.cmsg_type == libc::IP_RECVTTL)
            {
                let data = libc::CMSG_DATA(cmsg);
                // Linux IP_TTL is int; IP_RECVTTL often uchar
                if hdr.cmsg_type == libc::IP_RECVTTL {
                    ttl = *data;
                } else {
                    let mut v: libc::c_int = 0;
                    std::ptr::copy_nonoverlapping(
                        data,
                        &mut v as *mut _ as *mut u8,
                        size_of::<libc::c_int>(),
                    );
                    ttl = v as u8;
                }
            }
            #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
            if hdr.cmsg_level == libc::IPPROTO_IPV6 && hdr.cmsg_type == libc::IPV6_HOPLIMIT {
                let data = libc::CMSG_DATA(cmsg);
                let mut v: libc::c_int = 0;
                std::ptr::copy_nonoverlapping(
                    data,
                    &mut v as *mut _ as *mut u8,
                    size_of::<libc::c_int>(),
                );
                ttl = v as u8;
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    Ok((rc as usize, peer, ttl))
}

#[cfg(unix)]
#[allow(dead_code)]
fn sockaddr_to_socketaddr(sa: &libc::sockaddr_storage, len: libc::socklen_t) -> Option<SocketAddr> {
    let sock_addr = unsafe {
        socket2::SockAddr::try_init(|storage, sock_len| {
            let n = (len as usize).min(size_of_val(sa));
            std::ptr::copy_nonoverlapping(sa as *const _ as *const u8, storage as *mut u8, n);
            *sock_len = len;
            Ok(())
        })
        .ok()?
        .1
    };
    sock_addr.as_socket()
}

#[allow(dead_code)]
const fn size_of_val<T>(v: &T) -> usize {
    std::mem::size_of_val(v)
}

// ---------------------------------------------------------------------------
// Full endpoint record (OWPEndpointRec)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointRole {
    Sender,
    Receiver,
}

/// Full endpoint state corresponding to `OWPEndpointRec`.
pub struct EndpointState {
    pub role: EndpointRole,
    pub twoway: bool,
    pub mode: u32,
    pub sid: OwampSid,
    pub test_spec: OwampTestSpec,
    pub layout: PayloadLayout,
    pub schedule: ScheduleContext,
    pub skips: SkipList,
    pub lost_buf: LostPacketBuffer,
    pub records: Vec<OwampDataRec>,
    pub tw_records: Vec<OwampTwDataRec>,
    pub next_seq: u32,
    pub start: Instant,
    pub start_timespec: TimeSpec,
    pub enddelay: TimeSpec,
    pub payload: Vec<u8>,
    pub crypto: Option<EndpointCrypto>,
    pub sock: Option<UdpSocket>,
    pub local: Option<SocketAddr>,
    pub remote: Option<SocketAddr>,
    pub skiprec_fd: Option<File>,
    /// Size of skip IPC file after `finish_sender` (`skiprecsize`).
    pub skiprecsize: u64,
    /// User-opened session file (`userfile` / `_OWPOpenFile` or caller `fp`).
    pub userfile: Option<File>,
    pub datafile: Option<File>,
    /// Path of the user-opened session file (`fname`); empty when anonymous.
    pub fname: PathBuf,
    /// Buffer-size hint for datafile (`fbuff` / `setvbuf` in C; ~1s of records).
    /// `0` means unbuffered (flush after every record).
    pub fbuff_size: usize,
    /// Bytes written since last flush (software stand-in for `setvbuf` full buffer).
    pub fbuff_pending: usize,
    pub acceptval: OwampAcceptType,
    pub test_timeout_secs: u32,
    pub conf_sender: bool,
    pub conf_receiver: bool,
    /// `OWPChildWait` — pause briefly after spawn for debugger attach.
    pub child_wait: bool,
}

/// Alias kept for earlier call sites in this module's tests.
pub type Endpoint = EndpointState;
pub type TestEndpoint = EndpointState;

impl EndpointState {
    /// `EndpointAlloc` + schedule/layout init (without socket/file).
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn alloc(
        role: EndpointRole,
        mode: u32,
        sid: OwampSid,
        test_spec: OwampTestSpec,
        twoway: bool,
    ) -> Result<Self> {
        let layout = PayloadLayout::for_mode(mode, test_spec.packet_size_padding)?;
        let schedule = ScheduleContext::create(&sid, &test_spec)?;
        let mut payload_len = test_payload_size(mode, test_spec.packet_size_padding);
        if twoway {
            let tw = test_tw_payload_size(mode, 0);
            let ow = test_payload_size(mode, 0);
            payload_len = payload_len.max(payload_len + tw.saturating_sub(ow));
        }
        // C: OWPTimestampToTimespec(&ep->start, start_time) — Unix epoch, not NTP.
        let start_ts = timestamp_to_timespec(&OwampTimeStamp {
            owptime: test_spec.start_time,
            sync: false,
            multiplier: 1,
            scale: 0,
        })
        .unwrap_or_else(|| num64_to_timespec(test_spec.start_time));
        let enddelay = fuzz_to_timespec(OWP_DEFAULT_FUZZTIME);
        Ok(Self {
            role,
            twoway,
            mode,
            sid,
            test_spec,
            layout,
            schedule,
            skips: SkipList::default(),
            lost_buf: LostPacketBuffer::default(),
            records: Vec::new(),
            tw_records: Vec::new(),
            next_seq: 0,
            start: Instant::now(),
            start_timespec: start_ts,
            enddelay,
            payload: vec![0u8; payload_len],
            crypto: None,
            sock: None,
            local: None,
            remote: None,
            skiprec_fd: None,
            skiprecsize: 0,
            userfile: None,
            datafile: None,
            fname: PathBuf::new(),
            fbuff_size: 0,
            fbuff_pending: 0,
            acceptval: OwampAcceptType::Invalid,
            test_timeout_secs: TWP_DEFAULT_TEST_TIMEOUT,
            conf_sender: false,
            conf_receiver: false,
            child_wait: false,
        })
    }

    /// Convenience constructor matching the previous `TestEndpoint::new`.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn new(
        role: EndpointRole,
        mode: u32,
        sid: OwampSid,
        test_spec: OwampTestSpec,
    ) -> Result<Self> {
        Self::alloc(role, mode, sid, test_spec, false)
    }

    /// Install AES/HMAC keys (`_OWPEndpointInitHook` crypto).
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn setup_crypto(
        &mut self,
        control_aes: &[u8; AES_KEY_SIZE],
        control_hmac: &[u8; HMAC_KEY_SIZE],
    ) -> Result<()> {
        if mode_docipher_test(self.mode) {
            self.crypto = Some(EndpointCrypto::derive(
                &self.sid,
                control_aes,
                control_hmac,
            )?);
        }
        Ok(())
    }

    /// Drop socket / payload / crypto / lost-buffer — parent after fork (`EndpointClear`).
    pub fn clear(&mut self) {
        self.sock = None;
        self.payload.clear();
        self.payload.shrink_to_fit();
        self.crypto = None;
        self.lost_buf = LostPacketBuffer::default();
        self.skips = SkipList::default();
    }

    /// Full teardown (`EndpointFree`) — also closes skip/data/user files.
    #[must_use]
    pub fn free(mut self, aval: OwampAcceptType) -> OwampAcceptType {
        self.clear();
        if let Some(mut f) = self.skiprec_fd.take() {
            let _ = f.flush();
        }
        if let Some(mut f) = self.datafile.take() {
            let _ = f.flush();
            let _ = f.sync_all();
        }
        if let Some(mut f) = self.userfile.take() {
            let _ = f.flush();
            let _ = f.sync_all();
        }
        if aval == OwampAcceptType::Invalid {
            self.acceptval
        } else {
            aval
        }
    }

    /// Apply Context `OWPEndDelay` (seconds) onto `enddelay`.
    pub fn apply_end_delay(&mut self, secs: f64) {
        self.enddelay = fuzz_to_timespec(secs);
    }

    /// Bind UDP + configure buffers/TTL like `_OWPEndpointInit`.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn init_socket(
        &mut self,
        local: SocketAddr,
        remote: SocketAddr,
        portrange: Option<OwampPortRange>,
        is_server_reflector: bool,
    ) -> Result<()> {
        let af6 = matches!(local, SocketAddr::V6(_));
        let tpsize = if self.twoway {
            test_tw_packet_size(af6, self.mode, self.test_spec.packet_size_padding)
        } else {
            test_packet_size(af6, self.mode, self.test_spec.packet_size_padding)
        } + 128;
        let (sock, bound) = create_test_udp_socket_ex(
            local,
            TestSocketBindOpts {
                portrange,
                twamp_server: is_server_reflector,
            },
        )?;
        let send_side = self.role == EndpointRole::Sender;
        if self.twoway || !send_side {
            configure_receiver_socket(&sock, tpsize, bound)?;
        }
        if self.twoway || send_side {
            configure_sender_socket(&sock, tpsize, bound, self.test_spec.type_p)?;
        }
        if !self.twoway && send_side {
            self.skiprec_fd =
                Some(anon_skip_file().map_err(|e| OwampError::Message(format!("anon_file: {e}")))?);
        }
        if (self.twoway && !is_server_reflector) || (!self.twoway && !send_side) {
            let n = lost_buffer_prealloc_count(&self.test_spec);
            self.lost_buf = LostPacketBuffer::with_capacity_hint(n);
            self.lost_buf.npackets = self.test_spec.npackets;
            self.lost_buf.start_time = self.test_spec.start_time;
            self.lost_buf.twoway = self.twoway;
        }
        self.local = Some(bound);
        self.remote = Some(remote);
        self.sock = Some(socket_into_udp(sock).map_err(|e| OwampError::Message(e.to_string()))?);
        self.acceptval = OwampAcceptType::Accept;
        Ok(())
    }

    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn attach_datafile(&mut self, fp: &File) -> Result<()> {
        self.attach_datafile_path(fp, None::<PathBuf>)
    }

    /// Dup `fp` into `datafile` / `userfile` and optionally record `fname`
    /// (C `_OWPEndpointInit` recv path including `fbuff` / `setvbuf` sizing).
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn attach_datafile_path(
        &mut self,
        fp: &File,
        path: Option<impl Into<PathBuf>>,
    ) -> Result<()> {
        let df = reopen_datafile(fp)
            .map_err(|e| OwampError::Message(format!("reopen_datafile: {e}")))?;
        let rate = test_packet_rate(&self.test_spec);
        self.fbuff_size = compute_fbuff_size(rate, &df);
        self.fbuff_pending = 0;
        self.userfile = fp.try_clone().ok();
        self.datafile = Some(df);
        if let Some(p) = path {
            self.fname = p.into();
        }
        Ok(())
    }

    /// Write one data record and honour setvbuf-like flush policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn write_data_record_buffered(&mut self, rec: &OwampDataRec) -> Result<()> {
        let Some(ref mut f) = self.datafile else {
            return Ok(());
        };
        write_data_record_bytes(f, rec)?;
        self.fbuff_pending = self.fbuff_pending.saturating_add(DATAREC_SIZE);
        if self.fbuff_size == 0 || self.fbuff_pending >= self.fbuff_size {
            let _ = f.flush();
            self.fbuff_pending = 0;
        }
        Ok(())
    }

    /// Write one TW data record and honour setvbuf-like flush policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn write_tw_data_record_buffered(&mut self, rec: &OwampTwDataRec) -> Result<()> {
        let Some(ref mut f) = self.datafile else {
            return Ok(());
        };
        write_tw_data_record_bytes(f, rec)?;
        self.fbuff_pending = self.fbuff_pending.saturating_add(DATAREC_TW_V3_SIZE);
        if self.fbuff_size == 0 || self.fbuff_pending >= self.fbuff_size {
            let _ = f.flush();
            self.fbuff_pending = 0;
        }
        Ok(())
    }

    /// Write the data-header finished word at end of a recv/TW child loop
    /// (`_OWPWriteDataHeaderFinished`).
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn finish_datafile_header(&mut self, finished: u32) -> Result<()> {
        let Some(ref mut f) = self.datafile else {
            return Ok(());
        };
        write_data_header_finished_bytes(f, finished, self.next_seq)?;
        let _ = f.flush();
        self.fbuff_pending = 0;
        Ok(())
    }

    /// Record the user-visible session path (`fname`) for `CleanDataRecs` temp dir.
    pub fn set_fname(&mut self, path: impl Into<PathBuf>) {
        self.fname = path.into();
    }

    /// Persist skip IPC and record `skiprecsize` (`finish_sender` file tail).
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn flush_skiprec_ipc(&mut self) -> Result<()> {
        use std::io::{Seek, SeekFrom};
        let Some(ref mut fd) = self.skiprec_fd else {
            return Ok(());
        };
        fd.seek(SeekFrom::Start(0))
            .map_err(|e| OwampError::Message(format!("skiprec seek: {e}")))?;
        fd.set_len(0)
            .map_err(|e| OwampError::Message(format!("skiprec truncate: {e}")))?;
        let mut buf = Vec::new();
        self.skips.encode_ipc(self.next_seq, &mut buf);
        fd.write_all(&buf)
            .map_err(|e| OwampError::Message(format!("skiprec write: {e}")))?;
        let _ = fd.flush();
        self.skiprecsize = buf.len() as u64;
        Ok(())
    }

    /// Absolute send offsets (relative to session start) for every packet.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn plan_send_offsets(&mut self) -> Result<Vec<Duration>> {
        self.schedule.reset(None, None)?;
        let mut offsets = Vec::with_capacity(self.test_spec.npackets as usize);
        let mut acc = OwampNum64::ZERO;
        for _ in 0..self.test_spec.npackets {
            acc = num64_add(acc, self.schedule.generate_next_delta()?);
            let secs = num64_to_double(acc);
            offsets.push(Duration::from_secs_f64(secs.max(0.0)));
        }
        Ok(offsets)
    }

    /// Sender step: either skip (late) or emit a payload for `seq`.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn sender_try_send(
        &mut self,
        seq: u32,
        now: Duration,
        scheduled: Duration,
        loss_timeout: Duration,
        stamp: &OwampTimeStamp,
    ) -> Result<Option<Vec<u8>>> {
        if now > scheduled + loss_timeout {
            self.skips.note_skip(seq);
            self.next_seq = seq + 1;
            return Ok(None);
        }
        if now < scheduled {
            return Ok(None);
        }
        let mut buf = vec![0u8; self.layout.total_len];
        seal_one_way_packet(self.mode, self.crypto.as_ref(), &mut buf, seq, stamp)?;
        self.next_seq = seq + 1;
        Ok(Some(buf))
    }

    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn receiver_expect_next(&mut self, absolute: Duration) -> Result<()> {
        let seq = self.next_seq;
        let relative = self.schedule.generate_next_delta()?;
        self.lost_buf.insert(LostPacket {
            seq,
            relative,
            cumulative: relative,
            absolute,
            seen: false,
            sent: false,
        });
        self.next_seq = seq + 1;
        Ok(())
    }

    pub fn receiver_on_packet(
        &mut self,
        seq: u32,
        send: OwampTimeStamp,
        recv: OwampTimeStamp,
        ttl: u8,
    ) -> OwampDataRec {
        self.lost_buf.mark_seen(seq);
        let rec = OwampDataRec {
            seq_no: seq,
            send,
            recv,
            ttl,
        };
        self.records.push(rec);
        let _ = self.write_data_record_buffered(&rec);
        rec
    }

    pub fn receiver_flush_lost(
        &mut self,
        now: Duration,
        loss_timeout: Duration,
    ) -> Vec<OwampDataRec> {
        let start = self.test_spec.start_time;
        let relatives: HashMap<u32, OwampNum64> = self
            .lost_buf
            .by_seq
            .iter()
            .map(|(k, v)| (*k, v.cumulative))
            .collect();
        let lost = self
            .lost_buf
            .flush_lost(now, loss_timeout, |seq| OwampTimeStamp {
                owptime: start + relatives.get(&seq).copied().unwrap_or(OwampNum64::ZERO),
                sync: false,
                multiplier: 1,
                scale: 64,
            });
        for r in &lost {
            debug_assert!(is_lost_record(r));
            self.records.push(*r);
            let _ = self.write_data_record_buffered(r);
        }
        lost
    }

    #[must_use]
    pub fn packet_rate(&self) -> f64 {
        test_packet_rate(&self.test_spec)
    }

    /// Average wake fudge used by `run_receiver`: `MIN(2/rate, 1.0)` seconds.
    #[must_use]
    pub fn receiver_wake_fudge(&self) -> f64 {
        let rate = self.packet_rate();
        if rate <= 0.0 {
            return 1.0;
        }
        (2.0 / rate).min(1.0)
    }

    /// Spec §4.2 validity checks used by `run_receiver`.
    #[must_use]
    pub fn validate_received(
        &self,
        send: &OwampTimeStamp,
        recv: &OwampTimeStamp,
        expect_send: &OwampTimeStamp,
    ) -> bool {
        let timeout = self.test_spec.loss_timeout;
        if send.owptime.diff(recv.owptime) > timeout {
            return false;
        }
        if send.owptime.diff(expect_send.owptime) > timeout {
            return false;
        }
        true
    }
}

fn fuzz_to_timespec(enddelay: f64) -> TimeSpec {
    let mut sec = enddelay.trunc() as i64;
    let mut nsec = ((enddelay - sec as f64) * 1_000_000_000.0).trunc() as i64;
    if nsec >= 1_000_000_000 {
        sec += 1;
        nsec -= 1_000_000_000;
    }
    TimeSpec {
        tv_sec: sec,
        tv_nsec: nsec,
    }
}

/// Estimate disk space for a completed one-way session (`OWPTestDiskspace`).
#[must_use]
pub fn test_diskspace(npackets: u32, hdr_len: u64) -> u64 {
    hdr_len + u64::from(npackets) * DATAREC_SIZE as u64
}

/// Decode an OPEN-mode test payload into seq + send timestamp.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn parse_open_payload(buf: &[u8]) -> Result<(u32, OwampTimeStamp)> {
    if buf.len() < 14 {
        return Err(OwampError::Message("open payload too short".into()));
    }
    let seq = BigEndian::read_u32(&buf[0..4]);
    let mut ts = [0u8; 8];
    ts.copy_from_slice(&buf[4..12]);
    let mut stamp = decode_timestamp(&ts);
    let mut err = [0u8; 2];
    err.copy_from_slice(&buf[12..14]);
    if !decode_timestamp_err_estimate(&mut stamp, &err) {
        return Err(OwampError::Message("invalid open payload err".into()));
    }
    Ok((seq, stamp))
}

/// Decode authenticated/encrypted layout (seq at 0, stamp at 16, err at 24).
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn parse_auth_payload(buf: &[u8]) -> Result<(u32, OwampTimeStamp)> {
    if buf.len() < 26 {
        return Err(OwampError::Message("auth payload too short".into()));
    }
    let seq = BigEndian::read_u32(&buf[0..4]);
    let mut ts = [0u8; 8];
    ts.copy_from_slice(&buf[16..24]);
    let mut stamp = decode_timestamp(&ts);
    let mut err = [0u8; 2];
    err.copy_from_slice(&buf[24..26]);
    if !decode_timestamp_err_estimate(&mut stamp, &err) {
        return Err(OwampError::Message("invalid auth payload err".into()));
    }
    Ok((seq, stamp))
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn parse_payload(mode: u32, buf: &[u8]) -> Result<(u32, OwampTimeStamp)> {
    match mode {
        OWP_MODE_OPEN | TWP_MODE_MIXED => parse_open_payload(buf),
        OWP_MODE_AUTHENTICATED | OWP_MODE_ENCRYPTED => parse_auth_payload(buf),
        _ => Err(OwampError::Message("parse_payload: bogus mode".into())),
    }
}

// ---------------------------------------------------------------------------
// Run loops
// ---------------------------------------------------------------------------

/// Sender loop core from `run_sender` — drives schedule and emits payloads via `send_fn`.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn run_sender(
    ep: &mut EndpointState,
    mut now_fn: impl FnMut() -> Duration,
    mut stamp_fn: impl FnMut(u32) -> OwampTimeStamp,
    mut send_fn: impl FnMut(&[u8]) -> Result<()>,
) -> Result<u32> {
    let offsets = ep.plan_send_offsets()?;
    let loss = Duration::from_secs_f64(num64_to_double(ep.test_spec.loss_timeout).max(0.0));
    let mut sent = 0u32;
    for (seq, scheduled) in offsets.into_iter().enumerate() {
        if signal_int() || signal_usr2() {
            break;
        }
        let seq = seq as u32;
        let now = now_fn();
        let stamp = stamp_fn(seq);
        if let Some(payload) = ep.sender_try_send(seq, now, scheduled, loss, &stamp)? {
            match send_fn(&payload) {
                Err(e) if e.to_string().contains("ENOBUFS") => {
                    // retry once like C RETRY path
                    send_fn(&payload)?;
                },
                Err(e) => return Err(e),
                Ok(()) => {},
            }
            sent += 1;
        }
    }

    // Persist skip IPC like finish_sender
    ep.flush_skiprec_ipc()?;
    if signal_int() {
        ep.acceptval = OwampAcceptType::Failure;
        return Err(OwampError::Message("run_sender: interrupted".into()));
    }
    ep.acceptval = OwampAcceptType::Accept;
    Ok(sent)
}

fn owamp_tspec_to_context(ts: &OwampTestSpec) -> context::TestSpec {
    context::TestSpec {
        start_time: ts.start_time,
        loss_timeout: ts.loss_timeout,
        type_p: ts.type_p,
        packet_size_padding: ts.packet_size_padding,
        npackets: ts.npackets,
        nslots: ts.slots.len() as u32,
        slots: ts
            .slots
            .iter()
            .map(|s| match s {
                OwampSlot::RandExp(e) => Slot {
                    slot_type: SlotType::RandExp,
                    time: e.mean,
                },
                OwampSlot::Literal(l) => Slot {
                    slot_type: SlotType::Literal,
                    time: l.offset,
                },
            })
            .collect(),
    }
}

/// `OWPWriteDataHeader` before receiver/TW-client records (C `run_receiver` / `run_tw_test`).
fn write_session_datafile_header(ep: &mut EndpointState) -> Result<()> {
    let Some(ref mut f) = ep.datafile else {
        return Ok(());
    };
    let (sender, receiver) = match ep.role {
        EndpointRole::Receiver => (ep.remote, ep.local),
        EndpointRole::Sender => (ep.local, ep.remote),
    };
    let (Some(sender), Some(receiver)) = (sender, receiver) else {
        return Err(OwampError::Message(
            "write_session_datafile_header: missing sender/receiver".into(),
        ));
    };
    let (mut conf_sender, mut conf_receiver) = (ep.conf_sender, ep.conf_receiver);
    if !ep.twoway && !conf_sender && !conf_receiver {
        match ep.role {
            EndpointRole::Receiver => conf_receiver = true,
            EndpointRole::Sender => conf_sender = true,
        }
    }
    let hdr = SessionHeader {
        header: true,
        version: 3,
        rec_size: 0,
        twoway: ep.twoway,
        finished: SessionFinishedType::Incomplete,
        next_seqno: 0,
        num_skiprecs: 0,
        num_datarecs: 0,
        oset_skiprecs: 0,
        oset_datarecs: 0,
        conf_sender,
        conf_receiver,
        sid: ep.sid,
        sender: Some(sender),
        receiver: Some(receiver),
        test_spec: owamp_tspec_to_context(&ep.test_spec),
    };
    if !write_data_header(f, &hdr) {
        return Err(OwampError::Message(
            "write_session_datafile_header: failed".into(),
        ));
    }
    let _ = f.flush();
    ep.fbuff_pending = 0;
    Ok(())
}

/// Receiver loop core from `run_receiver`.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn run_receiver(
    ep: &mut EndpointState,
    mut now_fn: impl FnMut() -> Duration,
    mut recv_fn: impl FnMut() -> Result<Option<(u32, OwampTimeStamp, OwampTimeStamp, u8)>>,
) -> Result<Vec<OwampDataRec>> {
    write_session_datafile_header(ep)?;
    ep.schedule.reset(None, None)?;
    ep.next_seq = 0;
    ep.records.clear();
    ep.lost_buf = LostPacketBuffer::default();
    ep.lost_buf.npackets = ep.test_spec.npackets;
    ep.lost_buf.start_time = ep.test_spec.start_time;
    ep.skips = SkipList::default();

    let mut offsets = Vec::with_capacity(ep.test_spec.npackets as usize);
    let mut acc = OwampNum64::ZERO;
    for _ in 0..ep.test_spec.npackets {
        let relative = ep.schedule.generate_next_delta()?;
        acc = num64_add(acc, relative);
        let absolute = Duration::from_secs_f64(num64_to_double(acc).max(0.0));
        let seq = ep.next_seq;
        ep.lost_buf.insert(LostPacket {
            seq,
            // C stores cumulative schedule offset in `relative`.
            relative: acc,
            cumulative: acc,
            absolute,
            seen: false,
            sent: false,
        });
        ep.next_seq = seq + 1;
        offsets.push(absolute);
    }

    let loss = Duration::from_secs_f64(num64_to_double(ep.test_spec.loss_timeout).max(0.0));
    let wake = Duration::from_secs_f64(ep.receiver_wake_fudge());
    let end = offsets.last().copied().unwrap_or_default() + loss + wake;

    loop {
        if signal_int() {
            ep.acceptval = OwampAcceptType::Failure;
            return Err(OwampError::Message("run_receiver: interrupted".into()));
        }
        if signal_usr2() {
            let now = now_fn();
            let _ = ep.receiver_flush_lost(now + loss + loss, loss);
            break;
        }
        let now = now_fn();
        while let Some((seq, send, recv, ttl)) = recv_fn()? {
            // C: expect time from node->absolute (cumulative), matching sender_stamp_at_offset.
            let expect_rel = ep
                .lost_buf
                .by_seq
                .get(&seq)
                .map_or(OwampNum64::ZERO, |n| n.cumulative);
            let expect_send = OwampTimeStamp {
                owptime: ep.test_spec.start_time + expect_rel,
                sync: false,
                multiplier: 1,
                scale: 0,
            };
            if ep.test_spec.loss_timeout.0 != 0
                && ep.test_spec.start_time.0 != 0
                && !ep.validate_received(&send, &recv, &expect_send)
            {
                continue;
            }
            ep.receiver_on_packet(seq, send, recv, ttl);
        }
        let _ = ep.receiver_flush_lost(now, loss);
        if now >= end && ep.lost_buf.is_empty() {
            break;
        }
        if now >= end {
            let _ = ep.receiver_flush_lost(now + loss + Duration::from_secs(1), loss);
            break;
        }
    }
    // C run_receiver: write Incomplete finished bit; parent upgrades after StopSessions.
    let finished = if signal_int() { 0u32 } else { 2u32 };
    if let Err(e) = ep.finish_datafile_header(finished) {
        ep.acceptval = OwampAcceptType::Failure;
        return Err(e);
    }
    ep.acceptval = OwampAcceptType::Accept;
    Ok(ep.records.clone())
}

/// Reflector step for TWAMP: parse inbound payload and build a reflected OPEN reply.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn reflector_reply_open(
    layout: &PayloadLayout,
    inbound: &[u8],
    reflect_stamp: &OwampTimeStamp,
) -> Result<(u32, Vec<u8>)> {
    let (seq, _send) = parse_open_payload(inbound)?;
    let out = build_open_payload(layout, seq, reflect_stamp)?;
    Ok((seq, out))
}

/// `run_reflector` core — decrypt inbound, build TW reply, send via callback.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn run_reflector(
    ep: &mut EndpointState,
    mut recv_fn: impl FnMut() -> Result<Option<(Vec<u8>, u8, OwampTimeStamp)>>,
    mut stamp_fn: impl FnMut() -> OwampTimeStamp,
    mut send_fn: impl FnMut(&[u8]) -> Result<()>,
) -> Result<u32> {
    let mut i = 0u32;
    let pad = ep.test_spec.packet_size_padding as usize;
    loop {
        if signal_int() || signal_alrm() {
            ep.acceptval = OwampAcceptType::Failure;
            return Err(OwampError::Message(
                "run_reflector: timeout/interrupt".into(),
            ));
        }
        if signal_usr2() {
            break;
        }
        let Some((mut pkt, ttl, recv_stamp)) = recv_fn()? else {
            // idle poll
            continue;
        };
        // Decrypt inbound one-way packet
        let opened = match open_one_way_packet(ep.mode, ep.crypto.as_ref(), &mut pkt) {
            Ok(_) => pkt,
            Err(_) => continue, // bad HMAC / garbage — ignore like C
        };
        let reflect = stamp_fn();
        let reply = build_reflector_reply(
            ep.mode,
            ep.crypto.as_ref(),
            &opened,
            ttl,
            i,
            &recv_stamp,
            &reflect,
            pad,
        )?;
        match send_fn(&reply) {
            Err(e) if e.to_string().contains("ENOBUFS") => send_fn(&reply)?,
            Err(e) => return Err(e),
            Ok(()) => {},
        }
        i = i.wrapping_add(1);
    }
    ep.acceptval = OwampAcceptType::Accept;
    Ok(i)
}

/// `run_tw_test` core — send scheduled packets, wait for reflections, record TW data.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn run_tw_test(
    ep: &mut EndpointState,
    mut now_fn: impl FnMut() -> Duration,
    mut stamp_fn: impl FnMut(u32) -> OwampTimeStamp,
    mut send_fn: impl FnMut(&[u8]) -> Result<()>,
    mut recv_fn: impl FnMut() -> Result<Option<(Vec<u8>, u8, OwampTimeStamp)>>,
) -> Result<u32> {
    write_session_datafile_header(ep)?;
    ep.schedule.reset(None, None)?;
    ep.lost_buf = LostPacketBuffer::with_capacity_hint(lost_buffer_prealloc_count(&ep.test_spec));
    ep.lost_buf.npackets = ep.test_spec.npackets;
    ep.lost_buf.start_time = ep.test_spec.start_time;
    ep.lost_buf.twoway = true;
    ep.tw_records.clear();

    // Seed first lost-node
    let relative0 = ep.schedule.generate_next_delta()?;
    let abs0 = Duration::from_secs_f64(num64_to_double(relative0).max(0.0));
    ep.lost_buf.insert(LostPacket {
        seq: 0,
        relative: relative0,
        cumulative: relative0,
        absolute: abs0,
        seen: false,
        sent: false,
    });

    let loss = Duration::from_secs_f64(num64_to_double(ep.test_spec.loss_timeout).max(0.0));
    let mut sent = 0u32;
    let session_start = Duration::ZERO;

    for i in 0..ep.test_spec.npackets {
        if signal_int() || signal_usr2() {
            break;
        }
        let node = ep
            .lost_buf
            .ensure_through(i, &mut ep.schedule, session_start)?
            .clone();
        let scheduled = node.absolute;
        let now = now_fn();
        if now > scheduled + loss {
            // Missed send window — mark sent+hit so flush drops it (C behaviour).
            if let Some(n) = ep.lost_buf.get_mut(i) {
                n.sent = true;
                n.seen = true;
            }
            continue;
        }
        if now < scheduled {
            // In callback-driven tests the caller supplies "now"; no sleep.
            continue;
        }
        let stamp = stamp_fn(i);
        let mut buf = vec![0u8; ep.layout.total_len];
        seal_one_way_packet(ep.mode, ep.crypto.as_ref(), &mut buf, i, &stamp)?;
        match send_fn(&buf) {
            Err(e) if e.to_string().contains("ENOBUFS") => send_fn(&buf)?,
            Err(e) => return Err(e),
            Ok(()) => {},
        }
        if let Some(n) = ep.lost_buf.get_mut(i) {
            n.sent = true;
            n.absolute = now;
        }
        sent += 1;

        // Drain any available reflections quickly
        while let Some((mut pkt, ttl, recv_at)) = recv_fn()? {
            if open_tw_reply(ep.mode, ep.crypto.as_ref(), &mut pkt).is_err() {
                continue;
            }
            if let Ok(tw) = parse_tw_reply(ep.mode, &pkt, ttl, recv_at) {
                let seq = tw.sent.seq_no;
                ep.lost_buf.mark_seen(seq);
                ep.tw_records.push(tw);
                if let Some(ref mut f) = ep.datafile {
                    let _ = write_tw_data_record_bytes(f, &tw);
                }
            }
        }
        let start = ep.test_spec.start_time;
        let flushed_lost = ep.lost_buf.flush_lost(now_fn(), loss, |_| OwampTimeStamp {
            owptime: start,
            sync: false,
            multiplier: 1,
            scale: 64,
        });
        for r in flushed_lost {
            let tw = OwampTwDataRec {
                sent: r,
                reflected: OwampDataRec {
                    seq_no: 0,
                    send: r.recv,
                    recv: r.recv,
                    ttl: 255,
                },
            };
            ep.tw_records.push(tw);
        }
    }
    // C run_tw_test: Normal on success, Error on interrupt path.
    let finished = u32::from(!signal_int());
    if let Err(e) = ep.finish_datafile_header(finished) {
        ep.acceptval = OwampAcceptType::Failure;
        return Err(e);
    }
    ep.acceptval = if signal_int() {
        OwampAcceptType::Failure
    } else {
        OwampAcceptType::Accept
    };
    Ok(sent)
}

fn open_tw_reply(mode: u32, crypto: Option<&EndpointCrypto>, payload: &mut [u8]) -> Result<()> {
    if !mode_docipher_test(mode) {
        return Ok(());
    }
    let crypto = crypto.ok_or_else(|| OwampError::Message("tw reply crypto".into()))?;
    if payload.len() < 112 {
        return Err(OwampError::Message("tw reply too short".into()));
    }
    let wire_hmac: [u8; 16] = payload[96..112].try_into().unwrap();
    let mut iv = zero_iv();
    let mut first = [0u8; 16];
    first.copy_from_slice(&payload[0..16]);
    block_decrypt(&mut iv, &crypto.aes_tw_reply, &first, &mut payload[0..16])?;
    let mut hmac = crypto.hmac()?;
    hmac.update(&payload[0..16]);
    if mode & OWP_MODE_ENCRYPTED != 0 {
        let mut rest = [0u8; 80];
        rest.copy_from_slice(&payload[16..96]);
        block_decrypt(&mut iv, &crypto.aes_tw_reply, &rest, &mut payload[16..96])?;
        hmac.update(&payload[16..96]);
    }
    if !hmac.check_truncated_clear(&wire_hmac) {
        return Err(OwampError::Message("invalid TW HMAC".into()));
    }
    Ok(())
}

fn parse_tw_reply(
    mode: u32,
    payload: &[u8],
    _ttl: u8,
    client_recv: OwampTimeStamp,
) -> Result<OwampTwDataRec> {
    let layout = TwReplyLayout::for_mode(mode, 0)?;
    if payload.len() < layout.padding_offset {
        return Err(OwampError::Message("tw reply truncated".into()));
    }
    let reply_seq = BigEndian::read_u32(&payload[layout.seq_offset..]);
    let mut ts = [0u8; 8];
    ts.copy_from_slice(&payload[layout.tstamp_offset..layout.tstamp_offset + 8]);
    let mut reflect_send = decode_timestamp(&ts);
    let mut err = [0u8; 2];
    err.copy_from_slice(&payload[layout.tstamperr_offset..layout.tstamperr_offset + 2]);
    let _ = decode_timestamp_err_estimate(&mut reflect_send, &err);

    ts.copy_from_slice(&payload[layout.rcv_tstamp_offset..layout.rcv_tstamp_offset + 8]);
    let reflector_recv = decode_timestamp(&ts);

    let snd_seq = BigEndian::read_u32(&payload[layout.snd_seq_offset..]);
    ts.copy_from_slice(&payload[layout.snd_tstamp_offset..layout.snd_tstamp_offset + 8]);
    let mut orig_send = decode_timestamp(&ts);
    err.copy_from_slice(&payload[layout.snd_tstamperr_offset..layout.snd_tstamperr_offset + 2]);
    let _ = decode_timestamp_err_estimate(&mut orig_send, &err);
    let snd_ttl = payload[layout.snd_ttl_offset];

    Ok(OwampTwDataRec {
        sent: OwampDataRec {
            seq_no: snd_seq,
            send: orig_send,
            recv: reflector_recv,
            ttl: snd_ttl,
        },
        reflected: OwampDataRec {
            seq_no: reply_seq,
            send: reflect_send,
            recv: client_recv,
            ttl: 255,
        },
    })
}

/// Dispatch like the child after USR1 in `_OWPEndpointInitHook`.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn run_endpoint_child(ep: &mut EndpointState) -> Result<OwampAcceptType> {
    let kick = wait_for_session_kickoff();
    if kick != OwampAcceptType::Accept {
        ep.acceptval = kick;
        return Ok(kick);
    }
    run_endpoint_live(ep, &EndpointChildSignals::default())
}

/// Real-time UDP send/recv/reflector loop driven by a live socket.
///
/// Approximation vs C: runs in a worker thread instead of a forked child; stop
/// is delivered via [`EndpointChildSignals`] (USR1/USR2/INT atomics) bridged
/// into the thread-local flags the `run_*` cores already honour.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn run_endpoint_live(
    ep: &mut EndpointState,
    signals: &EndpointChildSignals,
) -> Result<OwampAcceptType> {
    signals.bridge_to_thread_local();
    if signal_int() || signal_usr2() {
        ep.acceptval = OwampAcceptType::Reject;
        return Ok(OwampAcceptType::Reject);
    }
    signals_reset();
    if ep.sock.is_none() {
        // No socket: treat as immediately complete (unit / policy-only sessions).
        ep.acceptval = OwampAcceptType::Accept;
        return Ok(OwampAcceptType::Accept);
    }

    let result = if ep.twoway {
        if ep.role == EndpointRole::Receiver {
            run_reflector_live(ep, signals)
        } else {
            run_tw_test_live(ep, signals)
        }
    } else if ep.role == EndpointRole::Sender {
        run_sender_live(ep, signals)
    } else {
        run_receiver_live(ep, signals)
    };

    match result {
        Ok(()) => {
            if signal_int() {
                ep.acceptval = OwampAcceptType::Failure;
            } else if ep.acceptval == OwampAcceptType::Invalid {
                ep.acceptval = OwampAcceptType::Accept;
            }
            Ok(ep.acceptval)
        },
        Err(e) => {
            let _ = ep.finish_datafile_header(0);
            ep.acceptval = OwampAcceptType::Failure;
            Err(e)
        },
    }
}

/// OWAMP lost records need encodable recv err estimate with zero owptime (C `*errest`).
const fn lost_record_recv_stamp() -> OwampTimeStamp {
    OwampTimeStamp {
        owptime: OwampNum64::ZERO,
        sync: false,
        multiplier: 1,
        scale: 64,
    }
}

fn stamp_now() -> OwampTimeStamp {
    if let Some(t) = crate::time::get_time_of_day() {
        return t;
    }
    // If NTP/timex fails, still produce a valid v3 err estimate (multiplier != 0).
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let ts = crate::arithm64::TimeSpec {
        tv_sec: dur.as_secs() as i64,
        tv_nsec: i64::from(dur.subsec_nanos()),
    };
    let mut tstamp = OwampTimeStamp::default();
    let _ = crate::time::timespec_to_timestamp(&mut tstamp, &ts, None, None);
    tstamp
}

/// Presumed send time for a packet at cumulative schedule offset (C `start_time + relative`).
#[allow(dead_code)] // used by schedule/lost helpers and kept for C parity call sites
fn sender_stamp_at_offset(ep: &EndpointState, scheduled: Duration) -> OwampTimeStamp {
    let rel = double_to_num64(scheduled.as_secs_f64());
    OwampTimeStamp {
        owptime: ep.test_spec.start_time + rel,
        sync: true,
        multiplier: 1,
        scale: 0,
    }
}

/// Elapsed time since session `start_time` (C `currtime - ep->start`).
///
/// When `start_time` is unset (unit tests), fall back to `origin.elapsed()`.
fn session_elapsed_parts(
    start_time: OwampNum64,
    start_timespec: TimeSpec,
    origin: Instant,
) -> Duration {
    if start_time.0 == 0 {
        return origin.elapsed();
    }
    let Some((now, _, _)) = get_timespec() else {
        return origin.elapsed();
    };
    let now_ns = now
        .tv_sec
        .saturating_mul(1_000_000_000)
        .saturating_add(now.tv_nsec);
    let start_ns = start_timespec
        .tv_sec
        .saturating_mul(1_000_000_000)
        .saturating_add(start_timespec.tv_nsec);
    if now_ns <= start_ns {
        Duration::ZERO
    } else {
        Duration::from_nanos((now_ns - start_ns) as u64)
    }
}

#[allow(dead_code)]
fn session_elapsed(ep: &EndpointState, origin: Instant) -> Duration {
    session_elapsed_parts(ep.test_spec.start_time, ep.start_timespec, origin)
}

fn sleep_until_session_offset(
    start_time: OwampNum64,
    start_timespec: TimeSpec,
    origin: Instant,
    target: Duration,
    signals: &EndpointChildSignals,
) {
    loop {
        signals.bridge_to_thread_local();
        if signal_int() || signal_usr2() {
            return;
        }
        let now = session_elapsed_parts(start_time, start_timespec, origin);
        if now >= target {
            return;
        }
        let left = target.saturating_sub(now);
        std::thread::sleep(left.min(Duration::from_millis(20)));
    }
}

/// Sender realtime loop: sleep until each scheduled offset, then sendto.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn run_sender_live(ep: &mut EndpointState, signals: &EndpointChildSignals) -> Result<()> {
    let offsets = ep.plan_send_offsets()?;
    let loss = Duration::from_secs_f64(num64_to_double(ep.test_spec.loss_timeout).max(0.0));
    let origin = Instant::now();
    let start_time = ep.test_spec.start_time;
    let start_timespec = ep.start_timespec;
    let remote = ep
        .remote
        .ok_or_else(|| OwampError::Message("no remote".into()))?;
    if remote.port() == 0 {
        return Err(OwampError::Message(
            "run_sender_live: remote UDP port is unset".into(),
        ));
    }

    for (seq, scheduled) in offsets.into_iter().enumerate() {
        signals.bridge_to_thread_local();
        if signal_int() || signal_usr2() {
            break;
        }
        let seq = seq as u32;
        sleep_until_session_offset(start_time, start_timespec, origin, scheduled, signals);
        signals.bridge_to_thread_local();
        if signal_int() || signal_usr2() {
            break;
        }
        let now = session_elapsed_parts(start_time, start_timespec, origin);
        // C stamps with actual wall-clock send time, not the schedule offset.
        let stamp = stamp_now();
        if let Some(payload) = ep.sender_try_send(seq, now, scheduled, loss, &stamp)? {
            let sock = ep
                .sock
                .as_ref()
                .ok_or_else(|| OwampError::Message("no sock".into()))?;
            match udp_sendto(sock, &payload, remote) {
                Err(e) if e.to_string().contains("ENOBUFS") => {
                    udp_sendto(sock, &payload, remote)?;
                },
                Err(e) => return Err(e),
                Ok(_) => {},
            }
        }
    }
    ep.flush_skiprec_ipc()?;
    if signal_int() {
        ep.acceptval = OwampAcceptType::Failure;
        return Err(OwampError::Message("run_sender_live: interrupted".into()));
    }
    ep.acceptval = OwampAcceptType::Accept;
    Ok(())
}

/// Receiver realtime loop: poll UDP, write data records, finish header.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn run_receiver_live(ep: &mut EndpointState, signals: &EndpointChildSignals) -> Result<()> {
    let origin = Instant::now();
    let start_time = ep.test_spec.start_time;
    let start_timespec = ep.start_timespec;
    let mode = ep.mode;
    let sock = ep
        .sock
        .as_ref()
        .ok_or_else(|| OwampError::Message("no sock".into()))?
        .try_clone()
        .map_err(|e| OwampError::Message(format!("receiver try_clone: {e}")))?;
    let _ = sock.set_read_timeout(Some(Duration::from_millis(50)));
    let mut recv_buf = vec![0u8; ep.payload.len().max(64) + 64];
    let crypto = ep.crypto.clone();
    let expected_peer = ep.remote;

    run_receiver(
        ep,
        || session_elapsed_parts(start_time, start_timespec, origin),
        || {
            signals.bridge_to_thread_local();
            if signal_int() || signal_usr2() {
                return Ok(None);
            }
            match udp_recvfrom_ttl(&sock, &mut recv_buf) {
                Ok((n, peer, ttl)) => {
                    // C run_receiver: verify peer before looking at packet.
                    if !peer_addr_matches(expected_peer, peer) {
                        return Ok(None);
                    }
                    let mut owned = recv_buf[..n].to_vec();
                    if mode_docipher_test(mode)
                        && open_one_way_packet(mode, crypto.as_ref(), &mut owned).is_err()
                    {
                        return Ok(None);
                    }
                    let Ok((seq, send)) = parse_payload(mode, &owned) else {
                        return Ok(None);
                    };
                    let recv = stamp_now();
                    Ok(Some((seq, send, recv, ttl)))
                },
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("TimedOut")
                        || msg.contains("WouldBlock")
                        || msg.contains("Resource temporarily")
                        || msg.contains("os error 35")
                        || msg.contains("os error 11")
                    {
                        Ok(None)
                    } else {
                        Err(e)
                    }
                },
            }
        },
    )?;
    Ok(())
}

/// TW client realtime loop.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
#[allow(clippy::too_many_lines)] // C-parity body
pub fn run_tw_test_live(ep: &mut EndpointState, signals: &EndpointChildSignals) -> Result<()> {
    let origin = Instant::now();
    let start_time = ep.test_spec.start_time;
    let start_timespec = ep.start_timespec;
    let remote = ep
        .remote
        .ok_or_else(|| OwampError::Message("no remote".into()))?;
    if remote.port() == 0 {
        return Err(OwampError::Message(
            "run_tw_test_live: remote UDP port is unset".into(),
        ));
    }
    let sock_fd = ep
        .sock
        .as_ref()
        .ok_or_else(|| OwampError::Message("no sock".into()))?
        .as_raw_fd();
    let sock = unsafe { UdpSocket::from_raw_fd(libc::dup(sock_fd)) };
    sock.set_read_timeout(Some(Duration::from_millis(20)))
        .map_err(|e| OwampError::Message(format!("set_read_timeout: {e}")))?;
    sock.set_nonblocking(false)
        .map_err(|e| OwampError::Message(format!("set_nonblocking: {e}")))?;
    let mut recv_buf = vec![0u8; ep.payload.len().max(128) + 64];

    let offsets = ep.plan_send_offsets()?;
    let loss = Duration::from_secs_f64(num64_to_double(ep.test_spec.loss_timeout).max(0.0));
    ep.schedule.reset(None, None)?;
    ep.lost_buf = LostPacketBuffer::with_capacity_hint(lost_buffer_prealloc_count(&ep.test_spec));
    ep.lost_buf.npackets = ep.test_spec.npackets;
    ep.lost_buf.start_time = ep.test_spec.start_time;
    ep.lost_buf.twoway = true;
    ep.tw_records.clear();
    // TW client writes the session header before records (C run_tw_test).
    write_session_datafile_header(ep)?;

    let relative0 = ep.schedule.generate_next_delta()?;
    let abs0 = Duration::from_secs_f64(num64_to_double(relative0).max(0.0));
    ep.lost_buf.insert(LostPacket {
        seq: 0,
        relative: relative0,
        cumulative: relative0,
        absolute: abs0,
        seen: false,
        sent: false,
    });

    for (i, scheduled) in offsets.into_iter().enumerate() {
        signals.bridge_to_thread_local();
        if signal_int() || signal_usr2() {
            break;
        }
        let i = i as u32;
        // Wait on wall-clock session elapsed (not a one-shot Instant countdown).
        while session_elapsed_parts(start_time, start_timespec, origin) < scheduled {
            signals.bridge_to_thread_local();
            if signal_int() || signal_usr2() {
                break;
            }
            if let Ok((n, peer, ttl)) = udp_recvfrom_ttl(&sock, &mut recv_buf) {
                if peer_addr_matches(Some(remote), peer) {
                    let mut pkt = recv_buf[..n].to_vec();
                    if open_tw_reply(ep.mode, ep.crypto.as_ref(), &mut pkt).is_ok() {
                        if let Ok(tw) = parse_tw_reply(ep.mode, &pkt, ttl, stamp_now()) {
                            ep.lost_buf.mark_seen(tw.sent.seq_no);
                            let _ = ep.write_tw_data_record_buffered(&tw);
                            ep.next_seq = ep.next_seq.max(tw.sent.seq_no + 1);
                            ep.tw_records.push(tw);
                        }
                    }
                }
            } else {
                // TimedOut / WouldBlock — keep waiting for schedule.
            }
        }
        signals.bridge_to_thread_local();
        if signal_int() || signal_usr2() {
            break;
        }
        let now = session_elapsed_parts(start_time, start_timespec, origin);
        if now > scheduled + loss {
            if let Some(n) = ep.lost_buf.get_mut(i) {
                n.sent = true;
                n.seen = true;
            }
            continue;
        }
        let _ = ep
            .lost_buf
            .ensure_through(i, &mut ep.schedule, Duration::ZERO)?;
        let stamp = stamp_now();
        let mut buf = vec![0u8; ep.layout.total_len];
        seal_one_way_packet(ep.mode, ep.crypto.as_ref(), &mut buf, i, &stamp)?;
        match udp_sendto(&sock, &buf, remote) {
            Err(e) if e.to_string().contains("ENOBUFS") => {
                udp_sendto(&sock, &buf, remote)?;
            },
            Err(e) => return Err(e),
            Ok(_) => {},
        }
        if let Some(n) = ep.lost_buf.get_mut(i) {
            n.sent = true;
            n.absolute = now;
        }

        // Drain reflections that arrive before the next send window (C RECEIVE).
        let start = ep.test_spec.start_time;
        let flushed_lost = ep.lost_buf.flush_lost(
            session_elapsed_parts(start_time, start_timespec, origin),
            loss,
            |_| OwampTimeStamp {
                owptime: start,
                sync: false,
                multiplier: 1,
                scale: 64,
            },
        );
        for r in flushed_lost {
            let tw = OwampTwDataRec {
                sent: r,
                reflected: OwampDataRec {
                    seq_no: 0,
                    send: r.recv,
                    recv: r.recv,
                    ttl: 255,
                },
            };
            let _ = ep.write_tw_data_record_buffered(&tw);
            ep.tw_records.push(tw);
        }
    }

    // Final wait: collect remaining reflections until loss_timeout after last send
    // (C finish_sender / flush_lost completion). Also stop early once every
    // sent packet has been seen (no need to sit out the full loss window).
    let wait_start = Instant::now();
    let wait_cap = loss.max(Duration::from_millis(50));
    while !signal_int()
        && !signal_usr2()
        && wait_start.elapsed() < wait_cap
        && !ep.lost_buf.is_empty()
    {
        let now = session_elapsed_parts(start_time, start_timespec, origin);
        let start = ep.test_spec.start_time;
        let flushed_lost = ep.lost_buf.flush_lost(now, loss, |_| OwampTimeStamp {
            owptime: start,
            sync: false,
            multiplier: 1,
            scale: 64,
        });
        for r in flushed_lost {
            let tw = OwampTwDataRec {
                sent: r,
                reflected: OwampDataRec {
                    seq_no: 0,
                    send: r.recv,
                    recv: r.recv,
                    ttl: 255,
                },
            };
            let _ = ep.write_tw_data_record_buffered(&tw);
            ep.next_seq = ep.next_seq.max(r.seq_no + 1);
            ep.tw_records.push(tw);
        }
        let seen_ok = ep
            .tw_records
            .iter()
            .filter(|t| t.sent.recv.owptime.0 != 0)
            .count();
        if seen_ok >= ep.test_spec.npackets as usize || ep.lost_buf.is_empty() {
            break;
        }
        if let Ok((n, peer, ttl)) = udp_recvfrom_ttl(&sock, &mut recv_buf) {
            if peer_addr_matches(Some(remote), peer) {
                let mut pkt = recv_buf[..n].to_vec();
                if open_tw_reply(ep.mode, ep.crypto.as_ref(), &mut pkt).is_ok() {
                    if let Ok(tw) = parse_tw_reply(ep.mode, &pkt, ttl, stamp_now()) {
                        ep.lost_buf.mark_seen(tw.sent.seq_no);
                        let _ = ep.write_tw_data_record_buffered(&tw);
                        ep.next_seq = ep.next_seq.max(tw.sent.seq_no + 1);
                        ep.tw_records.push(tw);
                    }
                }
            }
        }
    }
    // Force-flush anything still waiting past the wait window.
    {
        let now = session_elapsed_parts(start_time, start_timespec, origin)
            + loss
            + Duration::from_millis(1);
        let start = ep.test_spec.start_time;
        let flushed_lost = ep.lost_buf.flush_lost(now, loss, |_| OwampTimeStamp {
            owptime: start,
            sync: false,
            multiplier: 1,
            scale: 64,
        });
        for r in flushed_lost {
            let tw = OwampTwDataRec {
                sent: r,
                reflected: OwampDataRec {
                    seq_no: 0,
                    send: r.recv,
                    recv: r.recv,
                    ttl: 255,
                },
            };
            let _ = ep.write_tw_data_record_buffered(&tw);
            ep.next_seq = ep.next_seq.max(r.seq_no + 1);
            ep.tw_records.push(tw);
        }
    }

    let finished = u32::from(!signal_int());
    ep.finish_datafile_header(finished)?;
    ep.acceptval = if signal_int() {
        OwampAcceptType::Failure
    } else {
        OwampAcceptType::Accept
    };
    Ok(())
}

/// Reflector realtime loop — recv, build reply, sendto peer until Stop.
///
/// Implements C REFWAIT via `test_timeout_secs` (Context `TWPTestTimeout`): if no
/// valid peer packet arrives within that window the reflector fails like `owp_alrm`.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn run_reflector_live(ep: &mut EndpointState, signals: &EndpointChildSignals) -> Result<()> {
    let sock_fd = ep
        .sock
        .as_ref()
        .ok_or_else(|| OwampError::Message("no sock".into()))?
        .as_raw_fd();
    let sock = unsafe { UdpSocket::from_raw_fd(libc::dup(sock_fd)) };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(50)));
    let pad = ep.test_spec.packet_size_padding as usize;
    let mut recv_buf = vec![0u8; ep.payload.len().max(128) + 64];
    let mut i = 0u32;
    let configured_peer = ep.remote;
    let refwait = Duration::from_secs(u64::from(ep.test_timeout_secs.max(1)));
    let mut last_ok = Instant::now();
    loop {
        signals.bridge_to_thread_local();
        if signal_int() || signal_alrm() {
            ep.acceptval = OwampAcceptType::Failure;
            return Err(OwampError::Message(
                "run_reflector_live: timeout/interrupt".into(),
            ));
        }
        if signal_usr2() {
            break;
        }
        if last_ok.elapsed() >= refwait {
            ep.acceptval = OwampAcceptType::Failure;
            return Err(OwampError::Message(
                "run_reflector: Exiting due to REFWAIT timeout".into(),
            ));
        }
        match udp_recvfrom_ttl(&sock, &mut recv_buf) {
            Ok((n, from, ttl)) => {
                // C cancels REFWAIT after any successful recvfrom, then verifies peer.
                last_ok = Instant::now();
                if !peer_addr_matches(configured_peer, from) {
                    continue;
                }
                let mut pkt = recv_buf[..n].to_vec();
                let opened = match open_one_way_packet(ep.mode, ep.crypto.as_ref(), &mut pkt) {
                    Ok(_) => pkt,
                    Err(_) => continue,
                };
                let recv_stamp = stamp_now();
                let reflect = stamp_now();
                let reply = build_reflector_reply(
                    ep.mode,
                    ep.crypto.as_ref(),
                    &opened,
                    ttl,
                    i,
                    &recv_stamp,
                    &reflect,
                    pad,
                )?;
                if ep.datafile.is_some() {
                    let (seq, send) = parse_payload(ep.mode, &opened)
                        .unwrap_or_else(|_| (i, OwampTimeStamp::default()));
                    let rec = OwampDataRec {
                        seq_no: seq,
                        send,
                        recv: recv_stamp,
                        ttl,
                    };
                    let _ = ep.write_data_record_buffered(&rec);
                }
                // C sends the reply back to the verified peer address.
                match udp_sendto(&sock, &reply, from) {
                    Err(e) if e.to_string().contains("ENOBUFS") => {
                        udp_sendto(&sock, &reply, from)?;
                    },
                    Err(e) => return Err(e),
                    Ok(_) => {},
                }
                i = i.wrapping_add(1);
            },
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("TimedOut")
                    || msg.contains("WouldBlock")
                    || msg.contains("Resource temporarily")
                    || msg.contains("os error 35")
                    || msg.contains("os error 11")
                {
                    continue;
                }
                return Err(e);
            },
        }
    }
    let _ = ep.finish_datafile_header(1);
    ep.acceptval = OwampAcceptType::Accept;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithm64::{double_to_num64, ulong_to_num64};
    use crate::owamp::{OwampSlot, OwampSlotLiteral};

    fn stamp(secs: f64) -> OwampTimeStamp {
        OwampTimeStamp {
            owptime: double_to_num64(secs),
            sync: true,
            multiplier: 1,
            scale: 0,
        }
    }

    #[test]
    fn datarec_v3_roundtrip() {
        let rec = OwampDataRec {
            seq_no: 42,
            send: stamp(10.5),
            recv: stamp(10.6),
            ttl: 57,
        };
        let mut buf = [0u8; DATAREC_V3_SIZE];
        encode_data_record(&mut buf, &rec).unwrap();
        let decoded = decode_data_record(3, &buf).unwrap();
        assert_eq!(decoded.seq_no, 42);
        assert_eq!(decoded.ttl, 57);
        assert_eq!(decoded.send.owptime, rec.send.owptime);
        assert_eq!(decoded.recv.owptime, rec.recv.owptime);
        assert!(decoded.send.sync);
        assert_eq!(decoded.send.multiplier, 1);
    }

    #[test]
    fn datarec_v2_layout() {
        let mut buf = [0u8; DATAREC_V2_SIZE];
        BigEndian::write_u32(&mut buf[0..4], 7);
        let mut ts = [0u8; 8];
        encode_timestamp(&stamp(1.0), &mut ts);
        buf[4..12].copy_from_slice(&ts);
        let mut err = [0u8; 2];
        assert!(encode_timestamp_err_estimate(&stamp(1.0), &mut err));
        buf[12..14].copy_from_slice(&err);
        encode_timestamp(&stamp(1.1), &mut ts);
        buf[14..22].copy_from_slice(&ts);
        assert!(encode_timestamp_err_estimate(&stamp(1.1), &mut err));
        buf[22..24].copy_from_slice(&err);
        let rec = decode_data_record(2, &buf).unwrap();
        assert_eq!(rec.seq_no, 7);
        assert_eq!(rec.ttl, 255);
        assert_eq!(datarec_size_for_version(2), Some(24));
        assert_eq!(datarec_size_for_version(3), Some(25));
        assert_eq!(datarec_size_for_version(VERSION_TWOWAY | 3), Some(50));
    }

    #[test]
    fn skip_coalesce() {
        let mut skips = SkipList::default();
        skips.note_skip(1);
        skips.note_skip(2);
        skips.note_skip(5);
        assert_eq!(
            skips.skips,
            vec![
                OwampSkipRec { begin: 1, end: 2 },
                OwampSkipRec { begin: 5, end: 5 },
            ]
        );
        let mut buf = [0u8; 8];
        encode_skip_record(&mut buf, &skips.skips[0]);
        assert_eq!(decode_skip_record(&buf), skips.skips[0]);
    }

    #[test]
    fn sender_plan_and_late_skip() {
        let tspec = OwampTestSpec {
            npackets: 3,
            slots: vec![OwampSlot::Literal(OwampSlotLiteral {
                offset: ulong_to_num64(1),
            })],
            packet_size_padding: 0,
            loss_timeout: ulong_to_num64(1),
            ..Default::default()
        };
        let mut ep =
            TestEndpoint::new(EndpointRole::Sender, OWP_MODE_OPEN, [9u8; 16], tspec).unwrap();
        let offsets = ep.plan_send_offsets().unwrap();
        assert_eq!(offsets.len(), 3);
        let out = ep
            .sender_try_send(
                0,
                Duration::from_secs(10),
                offsets[0],
                Duration::from_secs(1),
                &stamp(10.0),
            )
            .unwrap();
        assert!(out.is_none());
        assert_eq!(ep.skips.skips.len(), 1);
    }

    #[test]
    fn sender_emits_open_payload() {
        let tspec = OwampTestSpec {
            npackets: 1,
            slots: vec![OwampSlot::Literal(OwampSlotLiteral {
                offset: ulong_to_num64(0),
            })],
            ..Default::default()
        };
        let mut ep =
            TestEndpoint::new(EndpointRole::Sender, OWP_MODE_OPEN, [0u8; 16], tspec).unwrap();
        let payload = ep
            .sender_try_send(
                0,
                Duration::from_secs(0),
                Duration::from_secs(0),
                Duration::from_secs(1),
                &stamp(5.0),
            )
            .unwrap()
            .unwrap();
        assert_eq!(payload.len(), 14);
        assert_eq!(BigEndian::read_u32(&payload[0..4]), 0);
    }

    #[test]
    fn lost_buffer_flush() {
        let mut buf = LostPacketBuffer::default();
        buf.insert(LostPacket {
            seq: 0,
            relative: OwampNum64::ZERO,
            cumulative: OwampNum64::ZERO,
            absolute: Duration::from_secs(0),
            seen: false,
            sent: false,
        });
        buf.insert(LostPacket {
            seq: 1,
            relative: OwampNum64::ZERO,
            cumulative: OwampNum64::ZERO,
            absolute: Duration::from_secs(0),
            seen: false,
            sent: false,
        });
        buf.mark_seen(1);
        let lost = buf.flush_lost(Duration::from_secs(5), Duration::from_secs(1), |_| {
            stamp(0.0)
        });
        assert_eq!(lost.len(), 1);
        assert_eq!(lost[0].seq_no, 0);
        assert!(is_lost_record(&lost[0]));
        assert!(buf.is_empty());
    }

    #[test]
    fn packet_sizes() {
        assert_eq!(test_payload_size(OWP_MODE_OPEN, 0), 14);
        assert_eq!(test_payload_size(OWP_MODE_ENCRYPTED, 10), 58);
        assert_eq!(test_packet_size(false, OWP_MODE_OPEN, 0), 14 + 20 + 8);
        assert_eq!(test_diskspace(100, 40), 40 + 100 * 25);
    }

    #[test]
    fn run_sender_emits_and_skips() {
        let tspec = OwampTestSpec {
            npackets: 2,
            slots: vec![OwampSlot::Literal(OwampSlotLiteral {
                offset: ulong_to_num64(0),
            })],
            loss_timeout: ulong_to_num64(1),
            ..Default::default()
        };
        let mut ep =
            TestEndpoint::new(EndpointRole::Sender, OWP_MODE_OPEN, [1u8; 16], tspec).unwrap();
        signals_reset();
        let mut payloads = Vec::new();
        let sent = run_sender(
            &mut ep,
            || Duration::from_secs(0),
            |_| stamp(1.0),
            |p| {
                payloads.push(p.to_vec());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(sent, 2);
        assert_eq!(payloads.len(), 2);
        let (seq, _) = parse_open_payload(&payloads[0]).unwrap();
        assert_eq!(seq, 0);
    }

    #[test]
    fn run_receiver_records_and_loss() {
        let tspec = OwampTestSpec {
            npackets: 2,
            slots: vec![OwampSlot::Literal(OwampSlotLiteral {
                offset: ulong_to_num64(0),
            })],
            loss_timeout: ulong_to_num64(1),
            ..Default::default()
        };
        let mut ep =
            TestEndpoint::new(EndpointRole::Receiver, OWP_MODE_OPEN, [2u8; 16], tspec).unwrap();
        signals_reset();
        let mut calls = 0u32;
        let recs = run_receiver(
            &mut ep,
            || Duration::from_secs(5),
            || {
                calls += 1;
                if calls == 1 {
                    Ok(Some((0, stamp(0.0), stamp(0.01), 64)))
                } else {
                    Ok(None)
                }
            },
        )
        .unwrap();
        assert!(recs.iter().any(|r| r.seq_no == 0 && !is_lost_record(r)));
        assert!(recs.iter().any(|r| r.seq_no == 1 && is_lost_record(r)));
    }

    #[test]
    fn encrypted_seal_open_roundtrip() {
        let sid = [0x11u8; 16];
        let ctrl_aes = [0x22u8; 16];
        let ctrl_hmac = [0x33u8; 32];
        let crypto = EndpointCrypto::derive(&sid, &ctrl_aes, &ctrl_hmac).unwrap();
        let mut payload = vec![0u8; 48];
        let s = stamp(12.34);
        seal_one_way_packet(OWP_MODE_ENCRYPTED, Some(&crypto), &mut payload, 7, &s).unwrap();
        // Ciphertext first block should not equal plaintext seq layout alone
        let (seq, got) =
            open_one_way_packet(OWP_MODE_ENCRYPTED, Some(&crypto), &mut payload).unwrap();
        assert_eq!(seq, 7);
        assert_eq!(got.owptime, s.owptime);
    }

    #[test]
    fn authenticated_seal_open_roundtrip() {
        let crypto = EndpointCrypto::derive(&[9u8; 16], &[8u8; 16], &[7u8; 32]).unwrap();
        let mut payload = vec![0u8; 48];
        let s = stamp(1.5);
        seal_one_way_packet(OWP_MODE_AUTHENTICATED, Some(&crypto), &mut payload, 3, &s).unwrap();
        let (seq, got) =
            open_one_way_packet(OWP_MODE_AUTHENTICATED, Some(&crypto), &mut payload).unwrap();
        assert_eq!(seq, 3);
        assert_eq!(got.owptime, s.owptime);
    }

    #[test]
    fn reflector_open_reply_fields() {
        let inbound = build_open_payload(
            &PayloadLayout::for_mode(OWP_MODE_OPEN, 0).unwrap(),
            5,
            &stamp(2.0),
        )
        .unwrap();
        let reply = build_reflector_reply(
            OWP_MODE_OPEN,
            None,
            &inbound,
            57,
            0,
            &stamp(2.01),
            &stamp(2.02),
            0,
        )
        .unwrap();
        assert_eq!(reply.len(), 41);
        assert_eq!(BigEndian::read_u32(&reply[0..4]), 0); // reply seq
        assert_eq!(BigEndian::read_u32(&reply[24..28]), 5); // original seq
        assert_eq!(reply[40], 57);
    }

    #[test]
    fn run_reflector_one_packet() {
        let tspec = OwampTestSpec {
            npackets: 1,
            slots: vec![OwampSlot::Literal(OwampSlotLiteral {
                offset: ulong_to_num64(0),
            })],
            ..Default::default()
        };
        let mut ep = EndpointState::alloc(
            EndpointRole::Receiver,
            OWP_MODE_OPEN,
            [3u8; 16],
            tspec,
            true,
        )
        .unwrap();
        let inbound = build_open_payload(&ep.layout, 9, &stamp(1.0)).unwrap();
        let mut phase = 0u32;
        let mut sent = Vec::new();
        signals_reset();
        let n = run_reflector(
            &mut ep,
            || {
                phase += 1;
                if phase == 1 {
                    Ok(Some((inbound.clone(), 64, stamp(1.01))))
                } else {
                    signal_set_usr2();
                    Ok(None)
                }
            },
            || stamp(1.02),
            |p| {
                sent.push(p.to_vec());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(n, 1);
        assert_eq!(sent.len(), 1);
        assert_eq!(BigEndian::read_u32(&sent[0][24..28]), 9);
    }

    #[test]
    fn endpoint_lifecycle_clear_free() {
        let tspec = OwampTestSpec {
            npackets: 1,
            slots: vec![OwampSlot::Literal(OwampSlotLiteral {
                offset: ulong_to_num64(0),
            })],
            ..Default::default()
        };
        let mut ep =
            EndpointState::alloc(EndpointRole::Sender, OWP_MODE_OPEN, [0u8; 16], tspec, false)
                .unwrap();
        assert_ne!(ep.payload, []);
        ep.clear();
        assert_eq!(ep.payload, []);
        let aval = ep.free(OwampAcceptType::Accept);
        assert_eq!(aval, OwampAcceptType::Accept);
    }

    #[test]
    fn signal_flags_kickoff() {
        signals_reset();
        signal_set_usr1();
        assert_eq!(wait_for_session_kickoff(), OwampAcceptType::Accept);
        signals_reset();
        signal_set_usr2();
        assert_eq!(wait_for_session_kickoff(), OwampAcceptType::Reject);
    }

    #[test]
    fn reopen_and_anon_files() {
        use std::io::{Read, Seek, SeekFrom, Write};
        let mut f = tempfile_or_tmp();
        f.write_all(b"hello-owamp").unwrap();
        f.flush().unwrap();
        let mut g = reopen_datafile(&f).unwrap();
        g.seek(SeekFrom::Start(0)).unwrap();
        let mut buf = vec![0u8; 11];
        g.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello-owamp");
        let skip = anon_skip_file().unwrap();
        assert!(skip.as_raw_fd() >= 0);
        flock_write_lock(&g).unwrap();
        flock_unlock(&g).unwrap();
    }

    #[test]
    fn flush_skiprec_ipc_size() {
        let tspec = OwampTestSpec {
            npackets: 3,
            slots: vec![OwampSlot::Literal(OwampSlotLiteral {
                offset: ulong_to_num64(1),
            })],
            ..Default::default()
        };
        let mut ep =
            TestEndpoint::new(EndpointRole::Sender, OWP_MODE_OPEN, [3u8; 16], tspec).unwrap();
        ep.skiprec_fd = Some(anon_skip_file().unwrap());
        ep.skips.note_skip(1);
        ep.skips.note_skip(2);
        ep.next_seq = 3;
        ep.flush_skiprec_ipc().unwrap();
        // next_seq(4) + nskips(4) + one coalesced skip(8) = 16
        assert_eq!(ep.skiprecsize, 16);
    }

    fn tempfile_or_tmp() -> File {
        use std::fs::OpenOptions;
        use std::sync::atomic::{AtomicU64, Ordering as AtmOrd};
        static N: AtomicU64 = AtomicU64::new(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "owamp-endpoint-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, AtmOrd::Relaxed)
        ));
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap()
    }

    #[test]
    fn udp_loopback_send_recv() {
        let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (sock_a, addr_a) = create_test_udp_socket(local, None).unwrap();
        let (sock_b, addr_b) = create_test_udp_socket(local, None).unwrap();
        configure_sender_socket(&sock_a, 2_048, addr_a, 0).unwrap();
        configure_receiver_socket(&sock_b, 2_048, addr_b).unwrap();
        let a = socket_into_udp(sock_a).unwrap();
        let b = socket_into_udp(sock_b).unwrap();
        b.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        udp_sendto(&a, b"ping", addr_b).unwrap();
        let mut buf = [0u8; 16];
        let (n, peer, _ttl) = udp_recvfrom_ttl(&b, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(peer.ip(), addr_a.ip());
    }

    #[test]
    fn write_data_header_finished_at_offset_8() {
        use std::io::{Read, Seek, SeekFrom, Write};
        let mut f = tempfile_or_tmp();
        f.write_all(&[0u8; 40]).unwrap();
        write_data_header_finished_bytes(&mut f, 2, 7).unwrap();
        f.seek(SeekFrom::Start(8)).unwrap();
        let mut buf = [0u8; 8];
        f.read_exact(&mut buf).unwrap();
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 2);
        assert_eq!(u32::from_be_bytes(buf[4..8].try_into().unwrap()), 7);
    }

    #[test]
    fn receiver_writes_finished_header_on_complete() {
        use std::io::{Read, Seek, SeekFrom, Write};
        let tspec = OwampTestSpec {
            npackets: 1,
            slots: vec![OwampSlot::Literal(OwampSlotLiteral {
                offset: ulong_to_num64(0),
            })],
            loss_timeout: ulong_to_num64(0),
            ..Default::default()
        };
        let mut ep =
            TestEndpoint::new(EndpointRole::Receiver, OWP_MODE_OPEN, [5u8; 16], tspec).unwrap();
        ep.local = Some("127.0.0.1:0".parse().unwrap());
        ep.remote = Some("127.0.0.1:1".parse().unwrap());
        let mut f = tempfile_or_tmp();
        f.write_all(&[0u8; 40]).unwrap();
        f.flush().unwrap();
        ep.datafile = Some(reopen_datafile(&f).unwrap());
        signals_reset();
        let _ = run_receiver(&mut ep, || Duration::from_secs(2), || Ok(None)).unwrap();
        // Incomplete (2) at end of receiver loop.
        let mut df = ep.datafile.take().unwrap();
        df.seek(SeekFrom::Start(8)).unwrap();
        let mut buf = [0u8; 4];
        df.read_exact(&mut buf).unwrap();
        assert_eq!(u32::from_be_bytes(buf), 2);
    }

    #[test]
    fn sender_receiver_live_loopback_records() {
        use std::sync::atomic::Ordering;
        use std::thread;
        use std::time::Duration;

        let sid = [0x42u8; 16];
        let tspec = OwampTestSpec {
            start_time: OwampNum64::ZERO,
            npackets: 2,
            slots: vec![OwampSlot::Literal(OwampSlotLiteral {
                offset: ulong_to_num64(0),
            })],
            loss_timeout: ulong_to_num64(10),
            ..Default::default()
        };
        let local: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let mut recv_ep = EndpointState::alloc(
            EndpointRole::Receiver,
            OWP_MODE_OPEN,
            sid,
            tspec.clone(),
            false,
        )
        .unwrap();
        recv_ep
            .init_socket(local, "127.0.0.1:0".parse().unwrap(), None, false)
            .unwrap();
        let recv_addr = recv_ep.local.unwrap();
        let mut df = tempfile_or_tmp();
        df.write_all(&[0u8; 40]).unwrap();
        recv_ep.attach_datafile(&df).unwrap();

        let mut send_ep =
            EndpointState::alloc(EndpointRole::Sender, OWP_MODE_OPEN, sid, tspec, false).unwrap();
        send_ep.init_socket(local, recv_addr, None, false).unwrap();

        let recv_signals = std::sync::Arc::new(EndpointChildSignals::default());
        let send_signals = std::sync::Arc::clone(&recv_signals);
        recv_signals.usr1.store(true, Ordering::Release);

        let handle = thread::spawn(move || {
            let r = run_receiver_live(&mut recv_ep, &recv_signals);
            (r, recv_ep.records.len())
        });

        thread::sleep(Duration::from_millis(30));
        send_signals.usr1.store(true, Ordering::Release);
        run_sender_live(&mut send_ep, &send_signals).unwrap();
        send_signals.usr2.store(true, Ordering::Release);
        let (r, nrec) = handle.join().unwrap();
        r.unwrap();
        assert!(nrec > 0, "expected received packets in loopback test");
    }

    #[test]
    fn sender_live_stays_running_then_finishes() {
        let tspec = OwampTestSpec {
            npackets: 1,
            slots: vec![OwampSlot::Literal(OwampSlotLiteral {
                offset: ulong_to_num64(0),
            })],
            loss_timeout: ulong_to_num64(1),
            ..Default::default()
        };
        let mut ep =
            EndpointState::alloc(EndpointRole::Sender, OWP_MODE_OPEN, [7u8; 16], tspec, false)
                .unwrap();
        let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let remote: SocketAddr = "127.0.0.1:9".parse().unwrap();
        ep.init_socket(local, remote, None, false).unwrap();
        ep.acceptval = OwampAcceptType::Invalid;
        let signals = EndpointChildSignals::default();
        signals.usr1.store(true, Ordering::Release);
        run_endpoint_live(&mut ep, &signals).unwrap();
        assert_eq!(ep.acceptval, OwampAcceptType::Accept);
        assert!(ep.skiprecsize >= 8);
    }

    #[test]
    fn port_range_bind_stays_inside_range() {
        let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let pr = OwampPortRange {
            low: 45_000,
            high: 45_010,
        };
        let (_sock, bound) = create_test_udp_socket(local, Some(pr)).unwrap();
        assert!(bound.port() >= pr.low && bound.port() <= pr.high);
    }

    #[test]
    fn twamp_server_ignores_port_outside_range() {
        // Requested 9 is outside [45000,45010] → treated as unset, bind in range.
        let local: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let pr = OwampPortRange {
            low: 45_000,
            high: 45_010,
        };
        let (_sock, bound) = create_test_udp_socket_ex(
            local,
            TestSocketBindOpts {
                portrange: Some(pr),
                twamp_server: true,
            },
        )
        .unwrap();
        assert!(bound.port() >= pr.low && bound.port() <= pr.high);
    }

    #[test]
    fn invalid_port_range_rejected() {
        let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let pr = OwampPortRange { low: 10, high: 5 };
        assert!(create_test_udp_socket(local, Some(pr)).is_err());
    }

    #[test]
    fn peer_addr_matches_requires_exact_socket() {
        let a: SocketAddr = "127.0.0.1:861".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:862".parse().unwrap();
        let any_port: SocketAddr = "127.0.0.1:0".parse().unwrap();
        assert!(peer_addr_matches(None, a));
        assert!(peer_addr_matches(Some(a), a));
        assert!(!peer_addr_matches(Some(a), b));
        assert!(peer_addr_matches(Some(any_port), b));
    }

    #[test]
    fn fbuff_unbuffered_when_rate_below_one() {
        let tspec = OwampTestSpec {
            // 1 packet with large literal offset → rate ≪ 1 pkt/s
            npackets: 1,
            slots: vec![OwampSlot::Literal(OwampSlotLiteral {
                offset: ulong_to_num64(10),
            })],
            ..Default::default()
        };
        let mut ep =
            TestEndpoint::new(EndpointRole::Receiver, OWP_MODE_OPEN, [1u8; 16], tspec).unwrap();
        let f = tempfile_or_tmp();
        ep.attach_datafile(&f).unwrap();
        assert_eq!(
            ep.fbuff_size, 0,
            "sub-1pps sessions are unbuffered like setvbuf(_IONBF)"
        );
    }

    #[test]
    fn fbuff_sizes_to_about_one_second() {
        // Literal 0.1s → ~10 pkt/s; fbuff ≈ 1s of records (capped by st_blksize).
        let tspec = OwampTestSpec {
            npackets: 100,
            slots: vec![OwampSlot::Literal(OwampSlotLiteral {
                offset: double_to_num64(0.1),
            })],
            ..Default::default()
        };
        let mut ep =
            TestEndpoint::new(EndpointRole::Receiver, OWP_MODE_OPEN, [2u8; 16], tspec).unwrap();
        let f = tempfile_or_tmp();
        ep.attach_datafile(&f).unwrap();
        // 10 pkt/s * 25 bytes ≈ 250, capped by st_blksize — at least one record.
        assert!(ep.fbuff_size >= DATAREC_SIZE);
    }

    #[test]
    fn buffered_write_flushes_when_pending_hits_size() {
        use std::io::{Read, Seek, SeekFrom};
        let tspec = OwampTestSpec {
            npackets: 10,
            slots: vec![OwampSlot::Literal(OwampSlotLiteral {
                offset: double_to_num64(0.01),
            })],
            ..Default::default()
        };
        let mut ep =
            TestEndpoint::new(EndpointRole::Receiver, OWP_MODE_OPEN, [4u8; 16], tspec).unwrap();
        let mut f = tempfile_or_tmp();
        ep.attach_datafile(&f).unwrap();
        // Force a tiny buffer so one record triggers flush.
        ep.fbuff_size = DATAREC_SIZE;
        let rec = OwampDataRec {
            seq_no: 1,
            send: stamp(1.0),
            recv: stamp(1.01),
            ttl: 64,
        };
        ep.write_data_record_buffered(&rec).unwrap();
        assert_eq!(ep.fbuff_pending, 0);
        // Re-read via original handle (same inode after reopen/dup).
        f.seek(SeekFrom::Start(0)).unwrap();
        let mut buf = vec![0u8; DATAREC_SIZE];
        f.read_exact(&mut buf).unwrap();
        assert_eq!(BigEndian::read_u32(&buf[0..4]), 1);
    }

    #[test]
    fn end_delay_from_seconds() {
        let tspec = OwampTestSpec {
            npackets: 1,
            slots: vec![OwampSlot::Literal(OwampSlotLiteral {
                offset: ulong_to_num64(0),
            })],
            ..Default::default()
        };
        let mut ep =
            TestEndpoint::new(EndpointRole::Sender, OWP_MODE_OPEN, [0u8; 16], tspec).unwrap();
        ep.apply_end_delay(2.5);
        assert_eq!(ep.enddelay.tv_sec, 2);
        assert!(ep.enddelay.tv_nsec > 0);
    }

    #[test]
    fn c_lost_cmp_hash_and_free() {
        assert!(!cmp_lost_packet(7, 7));
        assert!(cmp_lost_packet(7, 8));
        assert_eq!(hash_lost_packet(0x0001_2345), 0x2345);
        let mut buf = LostPacketBuffer::default();
        assert!(alloc_node(&mut buf, 0, 4, OwampNum64::ZERO, Duration::ZERO,));
        lost_free(&mut buf);
        assert!(buf.is_empty());
    }

    #[test]
    fn c_skip_free_and_skip_fn() {
        let mut skips = SkipList::default();
        skip(&mut skips, 4);
        skip(&mut skips, 5);
        assert_eq!(skips.skips.len(), 1);
        skip_free(&mut skips);
        assert_eq!(skips.skips, []);
    }

    #[test]
    fn c_alloc_free_get_node() {
        let mut buf = LostPacketBuffer::default();
        assert!(alloc_node(
            &mut buf,
            1,
            8,
            ulong_to_num64(1),
            Duration::from_secs(1),
        ));
        assert!(!alloc_node(
            &mut buf,
            0,
            8,
            OwampNum64::ZERO,
            Duration::ZERO,
        ));
        free_node(&mut buf, 1);
        assert!(buf.is_empty());

        let tspec = OwampTestSpec {
            npackets: 4,
            slots: vec![OwampSlot::Literal(OwampSlotLiteral {
                offset: ulong_to_num64(0),
            })],
            ..Default::default()
        };
        let mut ep =
            TestEndpoint::new(EndpointRole::Receiver, OWP_MODE_OPEN, [6u8; 16], tspec).unwrap();
        ep.lost_buf.insert(LostPacket {
            seq: 0,
            relative: OwampNum64::ZERO,
            cumulative: OwampNum64::ZERO,
            absolute: Duration::ZERO,
            seen: false,
            sent: false,
        });
        let node = get_node(&mut ep.lost_buf, 2, &mut ep.schedule, Duration::ZERO).unwrap();
        assert_eq!(node.seq, 2);
    }

    #[test]
    fn c_sig_nothing_and_sig_catch() {
        signals_reset();
        sig_nothing(libc::SIGCHLD);
        sig_nothing(99);
        sig_catch(libc::SIGUSR1);
        assert!(signal_usr1());
        signals_reset();
        sig_catch(libc::SIGINT);
        assert!(signal_int());
    }

    #[test]
    fn c_endpoint_free_wrapper() {
        let tspec = OwampTestSpec {
            npackets: 1,
            slots: vec![OwampSlot::Literal(OwampSlotLiteral {
                offset: ulong_to_num64(0),
            })],
            ..Default::default()
        };
        let ep = TestEndpoint::new(EndpointRole::Sender, OWP_MODE_OPEN, [8u8; 16], tspec).unwrap();
        let aval = endpoint_free(ep, OwampAcceptType::Accept);
        assert_eq!(aval, OwampAcceptType::Accept);
    }

    #[test]
    fn c_flush_lost_free_fn() {
        let mut buf = LostPacketBuffer::default();
        buf.insert(LostPacket {
            seq: 3,
            relative: OwampNum64::ZERO,
            cumulative: OwampNum64::ZERO,
            absolute: Duration::from_secs(0),
            seen: false,
            sent: false,
        });
        let lost = flush_lost(
            &mut buf,
            Duration::from_secs(10),
            Duration::from_secs(1),
            |_| stamp(0.0),
        );
        assert_eq!(lost.len(), 1);
        assert_eq!(lost[0].seq_no, 3);
    }

    #[test]
    fn c_anon_file_alias() {
        let f = anon_file().unwrap();
        assert!(f.as_raw_fd() >= 0);
    }

    #[test]
    fn c_recvfromttl_alias() {
        let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (sock_a, addr_a) = create_test_udp_socket(local, None).unwrap();
        let (sock_b, addr_b) = create_test_udp_socket(local, None).unwrap();
        configure_sender_socket(&sock_a, 2_048, addr_a, 0).unwrap();
        configure_receiver_socket(&sock_b, 2_048, addr_b).unwrap();
        let a = socket_into_udp(sock_a).unwrap();
        let b = socket_into_udp(sock_b).unwrap();
        b.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        udp_sendto(&a, b"x", addr_b).unwrap();
        let mut buf = [0u8; 4];
        let (n, _, _) = recvfromttl(&b, &mut buf).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn run_sender_interrupt_without_send() {
        let tspec = OwampTestSpec {
            npackets: 2,
            slots: vec![OwampSlot::Literal(OwampSlotLiteral {
                offset: ulong_to_num64(0),
            })],
            loss_timeout: ulong_to_num64(1),
            ..Default::default()
        };
        let mut ep =
            TestEndpoint::new(EndpointRole::Sender, OWP_MODE_OPEN, [1u8; 16], tspec).unwrap();
        signals_reset();
        signal_set_int();
        assert!(run_sender(
            &mut ep,
            || Duration::from_secs(0),
            |_| stamp(0.0),
            |_| Ok(()),
        )
        .is_err());
    }

    #[test]
    fn run_tw_test_open_one_packet() {
        let tspec = OwampTestSpec {
            npackets: 1,
            slots: vec![OwampSlot::Literal(OwampSlotLiteral {
                offset: ulong_to_num64(0),
            })],
            loss_timeout: ulong_to_num64(1),
            ..Default::default()
        };
        let mut ep =
            TestEndpoint::new(EndpointRole::Sender, OWP_MODE_OPEN, [4u8; 16], tspec).unwrap();
        signals_reset();
        let mut sent_payloads = 0u32;
        let n = run_tw_test(
            &mut ep,
            || Duration::from_secs(0),
            |_| stamp(1.0),
            |_| {
                sent_payloads += 1;
                Ok(())
            },
            || Ok(None),
        )
        .unwrap();
        assert_eq!(n, 1);
        assert_eq!(sent_payloads, 1);
    }
}
