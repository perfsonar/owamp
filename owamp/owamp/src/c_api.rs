//! Public C-parity surface — every customer-facing `owamp.h` name as `OWP*` / `TWP*`.
//!
//! Implementations stay in snake_case modules; this module is the 1:1 name bridge.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)] // C macro spellings (`OWPDetachProcesses`, …)
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::upper_case_acronyms)] // C typedefs (`OWPSID`, `OWPUserID`, …)
#![allow(clippy::pedantic)]
#![allow(clippy::nursery)]

use std::io::{Read, Seek, Write};

use crate::api::{self, SessionHeader};
use crate::arithm64::{self, TimeSpec, TimeVal};
use crate::capi;
use crate::context::{self, Addr, Context, Control, ErrHandle, ErrSeverity, ErrType, PortRange};
use crate::error;
use crate::owamp::{
    self, OwampAcceptType, OwampDataRec, OwampDelayType, OwampErrSeverity, OwampErrType,
    OwampNum64, OwampPacketSizeT, OwampPacketType, OwampRequestType, OwampSessionFinishedType,
    OwampSessionMode, OwampSid, OwampSkipRec, OwampSlot, OwampSlotType, OwampTestSpec,
    OwampTimeStamp, OwampTtlType, OwampTwDataRec, OwampUserId,
};
use crate::sapi;
use crate::schedule::{self, ExpContext, ScheduleContext};
use crate::stats::{self, Stats};
use crate::time;

// ---------------------------------------------------------------------------
// Typedefs (owamp.h)
// ---------------------------------------------------------------------------

/// C `intptr_t` boolean (`OWPBoolean`).
pub type OWPBoolean = isize;

pub type OWPNum64 = OwampNum64;
pub type OWPTimeStamp = OwampTimeStamp;
pub type OWPSID = OwampSid;
pub type OWPSequence = owamp::OwampSequence;
pub type OWPUserID = OwampUserId;
pub type OWPSessionMode = OwampSessionMode;
pub type OWPPacketSizeT = OwampPacketSizeT;
pub type OWPAcceptType = OwampAcceptType;
pub type OWPErrSeverity = OwampErrSeverity;
pub type OWPErrType = OwampErrType;
pub type OWPSlotType = OwampSlotType;
pub type OWPRequestType = OwampRequestType;
pub type OWPSessionFinishedType = OwampSessionFinishedType;
pub type OWPPacketType = OwampPacketType;
pub type OWPDelayType = OwampDelayType;
pub type OWPTtlType = OwampTtlType;
pub type OWPSlot = OwampSlot;
pub type OWPTestSpec = OwampTestSpec;
pub type OWPDataRec = OwampDataRec;
pub type OWPTwDataRec = OwampTwDataRec;
pub type OWPSkipRec = OwampSkipRec;
pub type OWPSessionHeader = SessionHeader;
pub type OWPPortRange = PortRange;

pub type OWPContext = Context;
pub type OWPControl = Control;
pub type OWPScheduleContext = ScheduleContext;
pub type OWPExpContext = ExpContext;
pub type OWPStats = Stats;

/// C `I2ErrHandle` stand-in.
pub type I2ErrHandle = ErrHandle;
/// C `I2Addr` stand-in.
pub type I2Addr = Addr;
/// Session files use `std::fs::File` instead of C `FILE*`.
pub type OWPFile = std::fs::File;

// ---------------------------------------------------------------------------
// Config-key / constant macros
// ---------------------------------------------------------------------------

/// Config-key macros from `owamp.h` (C spelling; snake aliases live in `owampP`).
pub const OWPCheckControlPolicy: &str = "OWPCheckControlPolicy";
pub const OWPCheckFetchPolicy: &str = "OWPCheckFetchPolicy";
pub const OWPCheckTestPolicy: &str = "OWPCheckTestPolicy";
pub const OWPCloseFile: &str = "OWPCloseFile";
pub const OWPDetachProcesses: &str = "OWPDetachProcesses";
pub const OWPEndDelay: &str = "OWPEndDelay";
pub const OWPGetPF: &str = "OWPGetPF";
pub const OWPInterruptIO: &str = "OWPInterruptIO";
pub const OWPIPv4Only: &str = "OWPIPv4Only";
pub const OWPIPv6Only: &str = "OWPIPv6Only";
pub const OWPKeyDerivationCount: &str = "OWPKeyDerivationCount";
pub const OWPOpenFile: &str = "OWPOpenFile";
pub const OWPTestComplete: &str = "OWPTestComplete";
pub const OWPTestPortRange: &str = "OWPTestPortRange";
pub const TWPTestTimeout: &str = "TWPTestTimeout";

/// `OWPChildWait` — DEBUG attach aid (always defined; C gated with `-DDEBUG`).
pub const OWPChildWait: &str = crate::owampP::OWP_CHILD_WAIT;
pub const OWP_TSTAMPFMT: &str = "%020u";

// ---------------------------------------------------------------------------
// Enumerators — C spellings from `owamp.h` (values identical)
// ---------------------------------------------------------------------------

pub const OWPErrFATAL: OWPErrSeverity = OwampErrSeverity::Fatal;
pub const OWPErrWARNING: OWPErrSeverity = OwampErrSeverity::Warning;
pub const OWPErrINFO: OWPErrSeverity = OwampErrSeverity::Info;
pub const OWPErrDEBUG: OWPErrSeverity = OwampErrSeverity::Debug;
pub const OWPErrOK: OWPErrSeverity = OwampErrSeverity::Ok;

pub const OWPErrUNKNOWN: OWPErrType = OwampErrType::Unknown;
pub const OWPErrPOLICY: OWPErrType = OwampErrType::Policy;
pub const OWPErrINVALID: OWPErrType = OwampErrType::Invalid;
pub const OWPErrUNSUPPORTED: OWPErrType = OwampErrType::Unsupported;

pub const OWP_CNTRL_INVALID: OWPAcceptType = OwampAcceptType::Invalid;
pub const OWP_CNTRL_ACCEPT: OWPAcceptType = OwampAcceptType::Accept;
pub const OWP_CNTRL_REJECT: OWPAcceptType = OwampAcceptType::Reject;
pub const OWP_CNTRL_FAILURE: OWPAcceptType = OwampAcceptType::Failure;
pub const OWP_CNTRL_UNSUPPORTED: OWPAcceptType = OwampAcceptType::Unsupported;
pub const OWP_CNTRL_UNAVAILABLE_PERM: OWPAcceptType = OwampAcceptType::UnavailablePerm;
pub const OWP_CNTRL_UNAVAILABLE_TEMP: OWPAcceptType = OwampAcceptType::UnavailableTemp;

pub const OWPSlotUnspecifiedType: OWPSlotType = OwampSlotType::Unspecified;
pub const OWPSlotRandExpType: OWPSlotType = OwampSlotType::RandExp;
pub const OWPSlotLiteralType: OWPSlotType = OwampSlotType::Literal;

pub const OWPReqInvalid: OWPRequestType = OwampRequestType::Invalid;
pub const OWPReqTest: OWPRequestType = OwampRequestType::Test;
pub const OWPReqStartSessions: OWPRequestType = OwampRequestType::StartSessions;
pub const OWPReqStopSessions: OWPRequestType = OwampRequestType::StopSessions;
pub const OWPReqFetchSession: OWPRequestType = OwampRequestType::FetchSession;
pub const OWPReqTestTW: OWPRequestType = OwampRequestType::TestTw;
pub const OWPReqSockClose: OWPRequestType = OwampRequestType::SockClose;
pub const OWPReqSockIntr: OWPRequestType = OwampRequestType::SockIntr;

pub const OWP_SESSION_FINISHED_ERROR: OWPSessionFinishedType = OwampSessionFinishedType::Error;
pub const OWP_SESSION_FINISHED_NORMAL: OWPSessionFinishedType = OwampSessionFinishedType::Normal;
pub const OWP_SESSION_FINISHED_INCOMPLETE: OWPSessionFinishedType =
    OwampSessionFinishedType::Incomplete;

pub const TWP_FWD_PKTS: OWPPacketType = OwampPacketType::FwdPkts;
pub const TWP_BCK_PKTS: OWPPacketType = OwampPacketType::BckPkts;
pub const OWP_PKTS: OWPPacketType = TWP_FWD_PKTS;

pub const OWP_DELAY: OWPDelayType = OwampDelayType::Delay;
pub const TWP_FWD_DELAY: OWPDelayType = OwampDelayType::FwdDelay;
pub const TWP_BCK_DELAY: OWPDelayType = OwampDelayType::BckDelay;
pub const TWP_PROC_DELAY: OWPDelayType = OwampDelayType::ProcDelay;

pub const TWP_FWD_TTL: OWPTtlType = OwampTtlType::FwdTtl;
pub const TWP_BCK_TTL: OWPTtlType = OwampTtlType::BckTtl;
pub const OWP_TTL: OWPTtlType = TWP_FWD_TTL;

fn bool_owp(v: bool) -> OWPBoolean {
    i32::from(v) as OWPBoolean
}

fn sev_to_owp(s: ErrSeverity) -> OWPErrSeverity {
    match s {
        ErrSeverity::Fatal => OwampErrSeverity::Fatal,
        ErrSeverity::Warning => OwampErrSeverity::Warning,
        ErrSeverity::Info => OwampErrSeverity::Info,
        ErrSeverity::Debug => OwampErrSeverity::Debug,
        ErrSeverity::Ok => OwampErrSeverity::Ok,
    }
}

fn owp_to_sev(s: OWPErrSeverity) -> ErrSeverity {
    match s {
        OwampErrSeverity::Fatal => ErrSeverity::Fatal,
        OwampErrSeverity::Warning => ErrSeverity::Warning,
        OwampErrSeverity::Info => ErrSeverity::Info,
        OwampErrSeverity::Debug => ErrSeverity::Debug,
        OwampErrSeverity::Ok => ErrSeverity::Ok,
    }
}

fn owp_to_etype(t: OWPErrType) -> ErrType {
    match t {
        OwampErrType::Unknown => ErrType::Unknown,
        OwampErrType::Policy => ErrType::Policy,
        OwampErrType::Invalid => ErrType::Invalid,
        OwampErrType::Unsupported => ErrType::Unsupported,
    }
}

// ---------------------------------------------------------------------------
// OWPNum64 macros
// ---------------------------------------------------------------------------

#[inline]
#[must_use]
pub const fn OWPNum64Add(x: OWPNum64, y: OWPNum64) -> OWPNum64 {
    OwampNum64(x.0.wrapping_add(y.0))
}

#[inline]
#[must_use]
pub const fn OWPNum64Sub(x: OWPNum64, y: OWPNum64) -> OWPNum64 {
    OwampNum64(x.0.wrapping_sub(y.0))
}

#[inline]
#[must_use]
pub fn OWPNum64Cmp(x: OWPNum64, y: OWPNum64) -> i32 {
    x.cmp_num(y)
}

#[inline]
#[must_use]
pub const fn OWPNum64Diff(x: OWPNum64, y: OWPNum64) -> OWPNum64 {
    x.diff(y)
}

#[inline]
#[must_use]
pub const fn OWPNum64Min(x: OWPNum64, y: OWPNum64) -> OWPNum64 {
    x.min(y)
}

#[inline]
#[must_use]
pub const fn OWPNum64Max(x: OWPNum64, y: OWPNum64) -> OWPNum64 {
    x.max(y)
}

// ---------------------------------------------------------------------------
// arithm64.c
// ---------------------------------------------------------------------------

#[inline]
#[must_use]
pub fn OWPNum64Mult(x: OWPNum64, y: OWPNum64) -> OWPNum64 {
    arithm64::num64_mult(x, y)
}

#[inline]
#[must_use]
pub fn OWPULongToNum64(a: u32) -> OWPNum64 {
    arithm64::ulong_to_num64(a)
}

#[inline]
#[must_use]
pub fn OWPNum64ToTimeval(from: OWPNum64) -> TimeVal {
    arithm64::num64_to_timeval(from)
}

#[inline]
#[must_use]
pub fn OWPTimevalToNum64(from: &TimeVal) -> OWPNum64 {
    arithm64::timeval_to_num64(from)
}

#[inline]
#[must_use]
pub fn OWPNum64ToTimespec(from: OWPNum64) -> TimeSpec {
    arithm64::num64_to_timespec(from)
}

#[inline]
#[must_use]
pub fn OWPTimespecToNum64(from: &TimeSpec) -> OWPNum64 {
    arithm64::timespec_to_num64(from)
}

#[inline]
#[must_use]
pub fn OWPNum64ToDouble(from: OWPNum64) -> f64 {
    arithm64::num64_to_double(from)
}

#[inline]
#[must_use]
pub fn OWPDoubleToNum64(from: f64) -> OWPNum64 {
    arithm64::double_to_num64(from)
}

#[inline]
#[must_use]
pub fn OWPUsecToNum64(usec: u32) -> OWPNum64 {
    arithm64::usec_to_num64(usec)
}

// ---------------------------------------------------------------------------
// time.c
// ---------------------------------------------------------------------------

#[inline]
#[must_use]
pub fn OWPGetTimeOfDay(_ctx: &OWPContext) -> Option<OWPTimeStamp> {
    time::get_time_of_day()
}

#[inline]
#[must_use]
pub fn OWPGetTimeStampError(tstamp: &OWPTimeStamp) -> f64 {
    time::get_timestamp_error(tstamp)
}

#[inline]
#[must_use]
pub fn OWPTimevalToTimestamp(tval: &TimeVal) -> Option<OWPTimeStamp> {
    time::timeval_to_timestamp(tval)
}

#[inline]
#[must_use]
pub fn OWPTimestampToTimeval(tstamp: &OWPTimeStamp) -> Option<TimeVal> {
    time::timestamp_to_timeval(tstamp)
}

/// `OWPTimespecToTimestamp` — fills `tstamp` in place (C out-param style).
#[must_use]
pub fn OWPTimespecToTimestamp(
    tstamp: &mut OWPTimeStamp,
    tspec: &TimeSpec,
    errest: Option<u32>,
    last_errest: Option<u32>,
) -> Option<OWPTimeStamp> {
    time::timespec_to_timestamp(tstamp, tspec, errest, last_errest)
}

#[inline]
#[must_use]
pub fn OWPTimestampToTimespec(tstamp: &OWPTimeStamp) -> Option<TimeSpec> {
    time::timestamp_to_timespec(tstamp)
}

// ---------------------------------------------------------------------------
// context / error
// ---------------------------------------------------------------------------

/// `OWPContextCreate` — `eh` accepted for signature parity.
#[must_use]
pub fn OWPContextCreate(_eh: I2ErrHandle) -> Option<OWPContext> {
    Context::create()
}

pub fn OWPContextFree(ctx: OWPContext) {
    ctx.free();
}

#[must_use]
pub fn OWPContextErrHandle(ctx: &OWPContext) -> I2ErrHandle {
    ctx.err_handle()
}

pub fn OWPError_(ctx: &OWPContext, severity: OWPErrSeverity, etype: OWPErrType, msg: &str) {
    ctx.error(owp_to_sev(severity), owp_to_etype(etype), msg);
}

#[must_use]
pub fn OWPReportLevelByName(name: &str) -> i32 {
    error::report_level_by_name(name).unwrap_or(-1)
}

/// Declared in `owamp.h`; not implemented upstream. Returns `-1`.
#[must_use]
pub const fn OWPErrorFD(_ctx: &OWPContext) -> i32 {
    -1
}

#[must_use]
pub fn OWPContextConfigSetF(ctx: &OWPContext, key: &str) -> OWPBoolean {
    bool_owp(ctx.config_set_f(key))
}

#[must_use]
pub fn OWPContextConfigGetF(ctx: &OWPContext, key: &str) -> OWPBoolean {
    bool_owp(ctx.config_get_f(key))
}

#[must_use]
pub fn OWPContextConfigSetU32(ctx: &OWPContext, key: &str, value: u32) -> OWPBoolean {
    bool_owp(ctx.config_set_u32(key, value))
}

#[must_use]
pub fn OWPContextConfigGetU32(ctx: &OWPContext, key: &str) -> Option<u32> {
    ctx.config_get_u32(key)
}

#[must_use]
pub fn OWPContextConfigSetV(ctx: &OWPContext, key: &str, ptr: usize) -> OWPBoolean {
    bool_owp(ctx.config_set_v(key, ptr))
}

#[must_use]
pub fn OWPContextConfigGetV(ctx: &OWPContext, key: &str) -> Option<usize> {
    ctx.config_get_v(key)
}

#[must_use]
pub fn OWPContextConfigDelete(ctx: &OWPContext, key: &str) -> OWPBoolean {
    bool_owp(ctx.config_delete(key))
}

#[must_use]
pub fn OWPControlConfigSetF(cntrl: &mut OWPControl, key: &str) -> OWPBoolean {
    bool_owp(cntrl.config_set_f(key))
}

#[must_use]
pub fn OWPControlConfigGetF(cntrl: &OWPControl, key: &str) -> OWPBoolean {
    bool_owp(cntrl.config_get_f(key))
}

#[must_use]
pub fn OWPControlConfigSetV(cntrl: &mut OWPControl, key: &str, ptr: usize) -> OWPBoolean {
    bool_owp(cntrl.config_set_v(key, ptr))
}

#[must_use]
pub fn OWPControlConfigGetV(cntrl: &OWPControl, key: &str) -> Option<usize> {
    cntrl.config_get_v(key)
}

#[must_use]
pub fn OWPControlConfigDelete(cntrl: &mut OWPControl, key: &str) -> OWPBoolean {
    bool_owp(cntrl.config_delete(key))
}

#[must_use]
pub fn OWPControlFD(cntrl: &OWPControl) -> i32 {
    cntrl.sockfd
}

#[must_use]
pub fn OWPControlIsTwoWay(cntrl: &OWPControl) -> OWPBoolean {
    bool_owp(cntrl.twoway)
}

#[must_use]
pub fn OWPGetContext(cntrl: &OWPControl) -> OWPContext {
    api::get_context(cntrl)
}

#[must_use]
pub fn OWPGetMode(cntrl: &OWPControl) -> OWPSessionMode {
    cntrl.mode
}

#[must_use]
pub fn OWPGetRTTBound(cntrl: &OWPControl) -> OWPNum64 {
    cntrl.rtt_bound
}

#[must_use]
pub fn OWPControlClose(cntrl: OWPControl) -> OWPErrSeverity {
    sev_to_owp(cntrl.close())
}

// ---------------------------------------------------------------------------
// schedule.c
// ---------------------------------------------------------------------------

#[must_use]
pub fn OWPScheduleContextCreate(
    _ctx: &OWPContext,
    sid: &OWPSID,
    tspec: &OWPTestSpec,
) -> Option<OWPScheduleContext> {
    ScheduleContext::create(sid, tspec).ok()
}

pub fn OWPScheduleContextFree(sctx: OWPScheduleContext) {
    sctx.free();
}

#[must_use]
pub fn OWPScheduleContextReset(
    sctx: &mut OWPScheduleContext,
    sid: Option<&OWPSID>,
    tspec: Option<&OWPTestSpec>,
) -> OWPErrSeverity {
    match sctx.reset(sid, tspec) {
        Ok(()) => OwampErrSeverity::Ok,
        Err(_) => OwampErrSeverity::Fatal,
    }
}

#[must_use]
pub fn OWPScheduleContextGenerateNextDelta(sctx: &mut OWPScheduleContext) -> Option<OWPNum64> {
    sctx.generate_next_delta().ok()
}

#[must_use]
pub fn OWPExpContextCreate(_ctx: &OWPContext, seed: &[u8; 16]) -> OWPExpContext {
    schedule::exp_context_create(seed)
}

#[must_use]
pub fn OWPExpContextNext(exp: &mut OWPExpContext) -> OWPNum64 {
    schedule::exp_context_next(exp)
}

pub fn OWPExpContextFree(exp: OWPExpContext) {
    schedule::exp_context_free(exp);
}

// ---------------------------------------------------------------------------
// capi / sapi / api
// ---------------------------------------------------------------------------

pub use capi::{
    control_open as OWPControlOpen, control_open_interface as OWPControlOpenInterface,
    delay as OWPDelay, fetch_session as OWPFetchSession, parse_port_range as OWPParsePortRange,
    session_request as OWPSessionRequest, start_sessions as OWPStartSessions,
    twp_control_open as TWPControlOpen, twp_control_open_interface as TWPControlOpenInterface,
};

pub use sapi::{
    control_accept as OWPControlAccept, process_fetch_session as OWPProcessFetchSession,
    process_start_sessions as OWPProcessStartSessions,
    process_test_request as OWPProcessTestRequest,
    process_test_request_tw as OWPProcessTestRequestTW, server_sock_create as OWPServerSockCreate,
    twp_control_accept as TWPControlAccept, twp_server_sock_create as TWPServerSockCreate,
    unexpected_request_type as OWPUnexpectedRequestType,
};

/// `OWPProcessStopSessions` — header-only in upstream C; wraps [`api::stop_sessions`].
pub fn OWPProcessStopSessions(cntrl: &mut OWPControl) -> ErrSeverity {
    let mut accept = context::AcceptType::Accept;
    api::stop_sessions(cntrl, None, &mut accept)
}

pub use api::{
    parse_records as OWPParseRecords, parse_tw_records as OWPParseTWRecords,
    read_data_header as OWPReadDataHeader, read_data_header_slots as OWPReadDataHeaderSlots,
    read_data_skips as OWPReadDataSkips, read_request_type as OWPReadRequestType,
    session_status as OWPSessionStatus, sessions_active as OWPSessionsActive,
    stop_sessions as OWPStopSessions, stop_sessions_wait as OWPStopSessionsWait,
    test_diskspace as OWPTestDiskspace, test_packet_bandwidth as OWPTestPacketBandwidth,
    test_packet_rate as OWPTestPacketRate, test_packet_size as OWPTestPacketSize,
    test_payload_size as OWPTestPayloadSize, test_tw_packet_size as OWPTestTWPacketSize,
    test_tw_payload_size as OWPTestTWPayloadSize, write_data_header as OWPWriteDataHeader,
    write_data_header_num_data_recs as OWPWriteDataHeaderNumDataRecs,
    write_data_header_num_skip_recs as OWPWriteDataHeaderNumSkipRecs,
    write_data_record as OWPWriteDataRecord, write_tw_data_record as OWPWriteTWDataRecord,
};

#[inline]
#[must_use]
pub const fn OWPIsLostRecord(rec: &OWPDataRec) -> bool {
    owamp::is_lost_record(rec)
}

// ---------------------------------------------------------------------------
// stats.c
// ---------------------------------------------------------------------------

#[must_use]
pub fn OWPStatsScaleFactor(scale: char) -> f32 {
    stats::scale_factor(scale).0
}

/// `OWPStatsCreate` — reads skips from `fp` when the header says they exist.
///
/// # Errors
///
/// Returns an error when the header/skips cannot be loaded.
pub fn OWPStatsCreate(
    _ctx: &OWPContext,
    fp: &mut (impl Read + Seek),
    hdr: &OWPSessionHeader,
    fromhost: Option<&str>,
    tohost: Option<&str>,
    scale: char,
    bucket_width: f64,
) -> crate::Result<OWPStats> {
    let mut skips_api = Vec::new();
    if hdr.num_skiprecs > 0 {
        let rc = api::read_data_skips(fp, hdr.num_skiprecs, &mut skips_api);
        if (rc as i32) < (ErrSeverity::Warning as i32) {
            return Err(crate::OwampError::Message(
                "OWPStatsCreate: Unable to read skip records from file".into(),
            ));
        }
    }
    let skips: Vec<OWPSkipRec> = skips_api
        .into_iter()
        .map(|s| OWPSkipRec {
            begin: s.begin,
            end: s.end,
        })
        .collect();
    Stats::create_from_header(hdr, fromhost, tohost, scale, bucket_width, skips)
}

pub fn OWPStatsFree(mut stats: OWPStats) {
    stats.free();
}

/// `OWPStatsParse`
///
/// # Errors
///
/// Returns an error when parsing fails.
pub fn OWPStatsParse(
    stats: &mut OWPStats,
    fp: &mut (impl Read + Seek),
    begin_oset: u64,
    first: u32,
    last: u32,
) -> crate::Result<()> {
    stats::stats_parse_file(stats, fp, begin_oset, first, last)
}

/// `OWPStatsPrintSummary`
pub fn OWPStatsPrintSummary(
    stats: &OWPStats,
    output: &mut dyn Write,
    percentiles: &[f32],
) -> OWPBoolean {
    bool_owp(stats.print_summary_to(output, percentiles, true).is_ok())
}

/// `OWPStatsPrintMachine`
pub fn OWPStatsPrintMachine(stats: &OWPStats, output: &mut dyn Write) -> OWPBoolean {
    bool_owp(stats.print_machine_to(output).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn num64_macros() {
        let a = OWPULongToNum64(2);
        let b = OWPULongToNum64(1);
        assert_eq!(OWPNum64Sub(a, b), b);
        assert_eq!(OWPNum64Cmp(a, b), 1);
        assert_eq!(OWPNum64Min(a, b), b);
        assert_eq!(OWPNum64Max(a, b), a);
    }

    #[test]
    fn context_create_free() {
        let ctx = OWPContextCreate(ErrHandle).expect("create");
        let _ = OWPContextErrHandle(&ctx);
        assert_eq!(OWPErrorFD(&ctx), -1);
        OWPContextFree(ctx);
    }

    #[test]
    fn child_wait_key() {
        assert_eq!(OWPChildWait, "OWPChildWait");
        assert_eq!(OWPDetachProcesses, "OWPDetachProcesses");
        assert_eq!(crate::owampP::OWP_CHILD_WAIT, OWPChildWait);
    }
}
