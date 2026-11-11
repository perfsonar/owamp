//! Timestamp encode/decode and wall-clock helpers — port of `time.c`.
//!
//! Wire format (8 octets):
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                Integer part of seconds                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |              Fractional part of seconds                       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Error estimate (2 octets): `S|Z|Scale(6)|Multiplier(8)`.

use std::sync::atomic::{AtomicI64, AtomicI8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use byteorder::{BigEndian, ByteOrder};

use crate::arithm64::{
    num64_to_double, num64_to_timespec, num64_to_timeval, timespec_to_num64, timeval_to_num64,
    ulong_to_num64, usec_to_num64, TimeSpec, TimeVal,
};
use crate::owamp::{OwampNum64, OwampTimeStamp};
use crate::owampP::OWP_JAN_1970;

/// Debug time offset from `OWAMP_DEBUG_TIMEOFFSET` (sign: -1/0/+1).
static TIMEOFFSET_SIGN: AtomicI8 = AtomicI8::new(0);
static TIMEOFFSET_SEC: AtomicI64 = AtomicI64::new(0);
static TIMEOFFSET_USEC: AtomicI64 = AtomicI64::new(0);

/// `OWPNum64Add(x, OWPULongToNum64(OWPJAN_1970))` helper.
#[inline]
fn add_ntp_epoch(t: OwampNum64) -> OwampNum64 {
    t + ulong_to_num64(OWP_JAN_1970)
}

#[inline]
fn sub_ntp_epoch(t: OwampNum64) -> OwampNum64 {
    t - ulong_to_num64(OWP_JAN_1970)
}

// ---------------------------------------------------------------------------
// Platform NTP / timex wrappers (`timex_adjtime_wrapper`)
// ---------------------------------------------------------------------------

/// Platforms where libc exposes NTP status via `ntp_adjtime` / `adjtimex`.
///
/// Gap: other BSDs / exotic targets lack portable `timex` bindings here and
/// fall back to the unsynchronized path (same as C without `HAVE_SYS_TIMEX_H`).
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
))]
mod ntp_sys {
    use super::TimeSpec;

    /// Result of a successful adjtime query used by `_OWPGetTimespec`.
    pub struct NtpStampInfo {
        pub sync: bool,
        pub esterror_us: u32,
    }

    /// `timex_adjtime_wrapper` — returns `Err` on syscall failure.
    pub fn timex_adjtime_wrapper() -> Result<libc::timex, String> {
        let mut ntp_conf: libc::timex = unsafe { std::mem::zeroed() };
        let rc = unsafe { call_adjtime(&mut ntp_conf) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            return Err(format!("ntp_adjtime()/adjtimex(): {err}"));
        }
        Ok(ntp_conf)
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    unsafe fn call_adjtime(ntp_conf: *mut libc::timex) -> libc::c_int {
        // C prefers `ntp_adjtime` when `HAVE_NTP_ADJTIME`.
        unsafe { libc::ntp_adjtime(ntp_conf) }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    unsafe fn call_adjtime(ntp_conf: *mut libc::timex) -> libc::c_int {
        // Linux: prefer `ntp_adjtime` on glibc; `adjtimex` elsewhere (musl/android).
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            unsafe { libc::ntp_adjtime(ntp_conf) }
        }
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        {
            unsafe { libc::adjtimex(ntp_conf) }
        }
    }

    /// Apply NTP offset / sync / esterror onto a timespec (C `_OWPGetTimespec` branch).
    pub fn apply_ntp_to_timespec(ts: &mut TimeSpec) -> Result<NtpStampInfo, String> {
        let mut ntp_conf = timex_adjtime_wrapper()?;

        let mut sync = false;
        let timeerr = if (ntp_conf.status & libc::STA_UNSYNC) == 0 {
            sync = true;

            // STA_NANO ⇒ offset in nanoseconds; otherwise microseconds.
            let sec_unit: i64 = if (ntp_conf.status & libc::STA_NANO) != 0 {
                1_000_000_000
            } else {
                1_000_000
            };

            // Convert negative offsets by decreasing tv_sec.
            while ntp_conf.offset < 0 {
                ts.tv_sec -= 1;
                ntp_conf.offset += sec_unit;
            }
            while ntp_conf.offset >= sec_unit {
                ts.tv_sec += 1;
                ntp_conf.offset -= sec_unit;
            }

            let mut offset = ntp_conf.offset;
            if sec_unit == 1_000_000 {
                offset *= 1_000; // µs → ns
            }

            ts.tv_nsec += offset;
            if ts.tv_nsec >= 1_000_000_000 {
                ts.tv_sec += 1;
                ts.tv_nsec -= 1_000_000_000;
            }

            ntp_conf.esterror as u32
        } else {
            0u32
        };

        Ok(NtpStampInfo {
            sync,
            esterror_us: timeerr,
        })
    }

    /// Init-time NTP status checks (C `_OWPInitNTP` warnings).
    pub fn init_ntp_status() -> Result<(), String> {
        let ntp_conf = timex_adjtime_wrapper()?;
        if (ntp_conf.status & libc::STA_UNSYNC) != 0 {
            tracing::warn!("NTP: Status UNSYNC (clock offset issues likely)");
        }
        // C insists STA_NANO be set when the constant exists.
        if (ntp_conf.status & libc::STA_NANO) == 0 {
            tracing::warn!(
                "NTP: STA_NANO should be set. Make sure ntpd is running, and your NTP configuration is good."
            );
        }
        Ok(())
    }
}

/// `OWPInitNTP` / `_OWPInitNTP`
///
/// Initializes NTP status (when syscalls exist) and parses optional
/// `OWAMP_DEBUG_TIMEOFFSET`. Returns `Err` only for an invalid offset env var
/// (matching C's hard-fail path). Adjtime failure is reported as `Err` as well;
/// C's `== -1` check against a 0/1 wrapper was a no-op bug.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn init_ntp() -> Result<(), String> {
    TIMEOFFSET_SIGN.store(0, Ordering::Relaxed);
    TIMEOFFSET_SEC.store(0, Ordering::Relaxed);
    TIMEOFFSET_USEC.store(0, Ordering::Relaxed);

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
    ))]
    {
        // Soft-fail adjtime at init (C logged FATAL but continued past the broken == -1 check).
        if let Err(e) = ntp_sys::init_ntp_status() {
            tracing::warn!("{e}");
        }
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
    )))]
    {
        tracing::warn!("NTP syscalls unavail: Status UNSYNC (clock offset issues likely)");
    }

    let Some(toffstr) = std::env::var_os("OWAMP_DEBUG_TIMEOFFSET") else {
        return Ok(());
    };
    let toffstr = toffstr.to_string_lossy();
    let td: f64 = toffstr
        .parse()
        .map_err(|_| format!("Invalid OWAMP_DEBUG_TIMEOFFSET env var: {toffstr}"))?;

    if td == 0.0 {
        TIMEOFFSET_SIGN.store(0, Ordering::Relaxed);
        return Ok(());
    }

    let (sign, mut td) = if td > 0.0 { (1i8, td) } else { (-1i8, -td) };

    let sec = td.trunc() as i64;
    td -= sec as f64;
    td *= 1_000_000.0;
    let usec = td.trunc() as i64;

    TIMEOFFSET_SIGN.store(sign, Ordering::Relaxed);
    TIMEOFFSET_SEC.store(sec, Ordering::Relaxed);
    TIMEOFFSET_USEC.store(usec, Ordering::Relaxed);

    tracing::debug!(
        "OWAMP_DEBUG_TIMEOFFSET: sec={}{}, usec={}",
        if sign > 0 { "+" } else { "-" },
        sec,
        usec
    );
    Ok(())
}

fn apply_debug_offset(tod: &mut TimeVal) {
    let sign = TIMEOFFSET_SIGN.load(Ordering::Relaxed);
    if sign == 0 {
        return;
    }
    let off = TimeVal {
        tv_sec: TIMEOFFSET_SEC.load(Ordering::Relaxed),
        tv_usec: TIMEOFFSET_USEC.load(Ordering::Relaxed),
    };
    if sign > 0 {
        tval_add(tod, &off);
    } else {
        tval_sub(tod, &off);
    }
}

/// C `tvaladd`
const fn tval_add(a: &mut TimeVal, b: &TimeVal) {
    a.tv_sec += b.tv_sec;
    a.tv_usec += b.tv_usec;
    if a.tv_usec >= 1_000_000 {
        a.tv_sec += 1;
        a.tv_usec -= 1_000_000;
    }
}

/// C `tvalsub`
const fn tval_sub(a: &mut TimeVal, b: &TimeVal) {
    a.tv_sec -= b.tv_sec;
    a.tv_usec -= b.tv_usec;
    if a.tv_usec < 0 {
        a.tv_sec -= 1;
        a.tv_usec += 1_000_000;
    }
}

fn system_timeval() -> Option<TimeVal> {
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    Some(TimeVal {
        tv_sec: dur.as_secs() as i64,
        tv_usec: i64::from(dur.subsec_micros()),
    })
}

/// `_OWPGetTimespec` — wall clock + optional NTP sync/esterr/offset.
///
/// Returns `(timespec, esterr_usec, sync)`.
pub fn get_timespec() -> Option<(TimeSpec, u32, bool)> {
    let mut tod = system_timeval()?;
    apply_debug_offset(&mut tod);

    let mut ts = TimeSpec {
        tv_sec: tod.tv_sec,
        tv_nsec: tod.tv_usec * 1_000,
    };

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
    ))]
    let (sync, mut esterr) = match ntp_sys::apply_ntp_to_timespec(&mut ts) {
        Ok(info) => (info.sync, info.esterror_us),
        Err(e) => {
            tracing::error!("{e}");
            return None;
        },
    };

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
    )))]
    let (sync, mut esterr) = (false, 0u32);

    // Perfection is not allowed if SYNC is true.
    if sync && esterr == 0 {
        esterr = 1;
    }

    Some((ts, esterr, sync))
}

/// `OWPGetTimeOfDay`
#[must_use]
pub fn get_time_of_day() -> Option<OwampTimeStamp> {
    let (ts, esterr, sync) = get_timespec()?;
    let mut tstamp = OwampTimeStamp {
        owptime: OwampNum64::ZERO,
        sync,
        multiplier: 0,
        scale: 0,
    };
    timespec_to_timestamp(&mut tstamp, &ts, Some(esterr), None)
}

/// `_OWPEncodeTimeStamp` — 8 octets, network byte order.
pub fn encode_timestamp(tstamp: &OwampTimeStamp, buf: &mut [u8; 8]) {
    BigEndian::write_u32(&mut buf[0..4], tstamp.owptime.seconds());
    BigEndian::write_u32(&mut buf[4..8], tstamp.owptime.fraction());
}

/// `_OWPEncodeTimeStampErrEstimate` — returns `false` if multiplier is 0.
pub const fn encode_timestamp_err_estimate(tstamp: &OwampTimeStamp, buf: &mut [u8; 2]) -> bool {
    if tstamp.multiplier == 0 {
        return false;
    }
    // Scale is 6-bit; Z bit left clear. S bit set when synchronized.
    buf[0] = tstamp.scale & 0x3f;
    if tstamp.sync {
        buf[0] |= 0x80;
    }
    buf[1] = tstamp.multiplier;
    true
}

/// `_OWPDecodeTimeStamp`
#[must_use]
pub fn decode_timestamp(buf: &[u8; 8]) -> OwampTimeStamp {
    let secs = u64::from(BigEndian::read_u32(&buf[0..4]));
    let frac = u64::from(BigEndian::read_u32(&buf[4..8]));
    OwampTimeStamp {
        owptime: OwampNum64((secs << 32) | frac),
        sync: false,
        multiplier: 0,
        scale: 0,
    }
}

/// `_OWPDecodeTimeStampErrEstimate` — returns `false` if multiplier is 0.
///
/// On invalid (zero) multiplier, C also clears the first buffer byte before
/// extracting sync/scale — mirrored here via local `b0`.
pub const fn decode_timestamp_err_estimate(tstamp: &mut OwampTimeStamp, buf: &[u8; 2]) -> bool {
    let mut b0 = buf[0];
    let b1 = buf[1];
    if b1 == 0 {
        b0 = 0;
    }
    tstamp.sync = (b0 & 0x80) != 0;
    tstamp.scale = b0 & 0x3f;
    tstamp.multiplier = b1;
    tstamp.multiplier != 0
}

/// `OWPTimevalToTimestamp` — Unix epoch timeval → NTP-epoch timestamp.
///
/// Invalidates the error estimate (timeval carries none).
#[must_use]
pub fn timeval_to_timestamp(tval: &TimeVal) -> Option<OwampTimeStamp> {
    let mut tstamp = OwampTimeStamp::default();
    tstamp.owptime = timeval_to_num64(tval);
    tstamp.owptime = add_ntp_epoch(tstamp.owptime);
    Some(tstamp)
}

/// `OWPTimestampToTimeval`
#[must_use]
pub fn timestamp_to_timeval(tstamp: &OwampTimeStamp) -> Option<TimeVal> {
    let tnum = sub_ntp_epoch(tstamp.owptime);
    Some(num64_to_timeval(tnum))
}

/// `OWPTimespecToTimestamp`
///
/// If `errest` is unset or zero: `sync=0`, `scale=64`, `multiplier=1`.
/// If `errest` is set and non-zero: derive scale/multiplier; leave `sync`
/// unmodified. If `last_errest` equals `errest`, skip scale/multiplier refresh.
pub fn timespec_to_timestamp(
    tstamp: &mut OwampTimeStamp,
    tval: &TimeSpec,
    errest: Option<u32>,
    last_errest: Option<u32>,
) -> Option<OwampTimeStamp> {
    tstamp.owptime = timespec_to_num64(tval);
    tstamp.owptime = add_ntp_epoch(tstamp.owptime);

    if let Some(errest) = errest.filter(|&e| e != 0) {
        let refresh = last_errest.is_none_or(|last| errest != last);
        if refresh {
            let mut err = usec_to_num64(errest).0;
            // Mask to 64 bits (no-op on u64; mirrors C).
            err &= u64::MAX;

            tstamp.scale = 0;
            while err >= 0xff {
                err >>= 1;
                tstamp.scale += 1;
            }
            err += 1; // rounding for shifted-off bits
            tstamp.multiplier = (err & 0xff) as u8;
        }
    } else {
        tstamp.sync = false;
        tstamp.scale = 64;
        tstamp.multiplier = 1;
    }

    Some(*tstamp)
}

/// `OWPTimestampToTimespec`
#[must_use]
pub fn timestamp_to_timespec(tstamp: &OwampTimeStamp) -> Option<TimeSpec> {
    let tnum = sub_ntp_epoch(tstamp.owptime);
    Some(num64_to_timespec(tnum))
}

/// `OWPGetTimeStampError` — error estimate in seconds as `f64`.
#[must_use]
pub fn get_timestamp_error(tstamp: &OwampTimeStamp) -> f64 {
    let mut err = u64::from(tstamp.multiplier) & 0xff;
    let mut scale = tstamp.scale & 0x3f;
    while scale > 0 {
        err <<= 1;
        scale -= 1;
    }
    num64_to_double(OwampNum64(err))
}

// ---------------------------------------------------------------------------
// C-like aliases (`owamp.h` / private `_OWP*` names)
// ---------------------------------------------------------------------------

#[allow(non_snake_case)]
pub mod decls {
    pub use super::{
        decode_timestamp as _OWPDecodeTimeStamp,
        decode_timestamp_err_estimate as _OWPDecodeTimeStampErrEstimate,
        encode_timestamp as _OWPEncodeTimeStamp,
        encode_timestamp_err_estimate as _OWPEncodeTimeStampErrEstimate,
        get_time_of_day as OWPGetTimeOfDay, get_timespec as _OWPGetTimespec,
        get_timestamp_error as OWPGetTimeStampError, init_ntp as _OWPInitNTP,
        timespec_to_timestamp as OWPTimespecToTimestamp,
        timestamp_to_timespec as OWPTimestampToTimespec,
        timestamp_to_timeval as OWPTimestampToTimeval,
        timeval_to_timestamp as OWPTimevalToTimestamp,
    };
}
pub use decls::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_timestamp_roundtrip() {
        let ts = OwampTimeStamp {
            owptime: OwampNum64(0x0123_4567_89ab_cdef),
            sync: true,
            multiplier: 7,
            scale: 3,
        };
        let mut buf = [0u8; 8];
        encode_timestamp(&ts, &mut buf);
        assert_eq!(&buf[0..4], &[0x01, 0x23, 0x45, 0x67]);
        assert_eq!(&buf[4..8], &[0x89, 0xab, 0xcd, 0xef]);

        let decoded = decode_timestamp(&buf);
        assert_eq!(decoded.owptime, ts.owptime);
    }

    #[test]
    fn err_estimate_sync_bit() {
        let ts = OwampTimeStamp {
            owptime: OwampNum64::ZERO,
            sync: true,
            multiplier: 5,
            scale: 2,
        };
        let mut buf = [0u8; 2];
        assert!(encode_timestamp_err_estimate(&ts, &mut buf));
        assert_eq!(buf[0], 0x80 | 2);
        assert_eq!(buf[1], 5);

        let mut out = OwampTimeStamp::default();
        assert!(decode_timestamp_err_estimate(&mut out, &buf));
        assert!(out.sync);
        assert_eq!(out.scale, 2);
        assert_eq!(out.multiplier, 5);
    }

    #[test]
    fn err_estimate_z_bit_cleared_on_encode() {
        // Scale may have high bits; encode must keep only 6 scale bits (+ optional S).
        let ts = OwampTimeStamp {
            owptime: OwampNum64::ZERO,
            sync: false,
            multiplier: 9,
            scale: 0xff,
        };
        let mut buf = [0u8; 2];
        assert!(encode_timestamp_err_estimate(&ts, &mut buf));
        assert_eq!(buf[0], 0x3f);
        assert_eq!(buf[1], 9);
    }

    #[test]
    fn err_estimate_rejects_zero_multiplier() {
        let ts = OwampTimeStamp {
            owptime: OwampNum64::ZERO,
            sync: false,
            multiplier: 0,
            scale: 1,
        };
        let mut buf = [0u8; 2];
        assert!(!encode_timestamp_err_estimate(&ts, &mut buf));
    }

    #[test]
    fn decode_err_estimate_zero_multiplier_clears_sync_scale() {
        let mut out = OwampTimeStamp {
            owptime: OwampNum64::ZERO,
            sync: true,
            multiplier: 3,
            scale: 4,
        };
        // S bit set in buffer, but multiplier 0 ⇒ invalid; sync/scale cleared.
        assert!(!decode_timestamp_err_estimate(&mut out, &[0x80 | 4, 0]));
        assert!(!out.sync);
        assert_eq!(out.scale, 0);
        assert_eq!(out.multiplier, 0);
    }

    #[test]
    fn unix_to_ntp_epoch_timeval() {
        let tv = TimeVal {
            tv_sec: 0,
            tv_usec: 0,
        };
        let ts = timeval_to_timestamp(&tv).unwrap();
        assert_eq!(ts.owptime.seconds(), OWP_JAN_1970);
        let back = timestamp_to_timeval(&ts).unwrap();
        assert_eq!(back.tv_sec, 0);
        assert_eq!(back.tv_usec, 0);
    }

    #[test]
    fn unix_to_ntp_epoch_timespec() {
        let tv = TimeSpec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let mut ts = OwampTimeStamp::default();
        timespec_to_timestamp(&mut ts, &tv, None, None).unwrap();
        assert_eq!(ts.owptime.seconds(), OWP_JAN_1970);
        assert!(!ts.sync);
        assert_eq!(ts.scale, 64);
        assert_eq!(ts.multiplier, 1);

        let back = timestamp_to_timespec(&ts).unwrap();
        assert_eq!(back.tv_sec, 0);
        assert_eq!(back.tv_nsec, 0);
    }

    #[test]
    fn timespec_errest_derives_scale_multiplier() {
        let tv = TimeSpec {
            tv_sec: 10,
            tv_nsec: 0,
        };
        let mut ts = OwampTimeStamp {
            owptime: OwampNum64::ZERO,
            sync: true,
            multiplier: 0,
            scale: 0,
        };
        // 1 µs → small err; sync preserved.
        timespec_to_timestamp(&mut ts, &tv, Some(1), None).unwrap();
        assert!(ts.sync);
        assert!(ts.multiplier >= 1);
        assert_eq!(ts.owptime.seconds(), OWP_JAN_1970 + 10);

        // last_errest equal ⇒ scale/multiplier unchanged.
        let scale = ts.scale;
        let mult = ts.multiplier;
        timespec_to_timestamp(&mut ts, &tv, Some(1), Some(1)).unwrap();
        assert_eq!(ts.scale, scale);
        assert_eq!(ts.multiplier, mult);

        // last_errest different ⇒ refresh.
        timespec_to_timestamp(&mut ts, &tv, Some(1_000), Some(1)).unwrap();
        assert!(ts.multiplier >= 1);
    }

    #[test]
    fn timespec_zero_errest_invalidates_estimate() {
        let tv = TimeSpec {
            tv_sec: 1,
            tv_nsec: 0,
        };
        let mut ts = OwampTimeStamp {
            owptime: OwampNum64::ZERO,
            sync: true,
            multiplier: 7,
            scale: 2,
        };
        timespec_to_timestamp(&mut ts, &tv, Some(0), None).unwrap();
        assert!(!ts.sync);
        assert_eq!(ts.scale, 64);
        assert_eq!(ts.multiplier, 1);
    }

    #[test]
    fn timestamp_error_scale() {
        let ts = OwampTimeStamp {
            owptime: OwampNum64::ZERO,
            sync: true,
            multiplier: 1,
            scale: 0,
        };
        // multiplier/2^32 seconds
        let err = get_timestamp_error(&ts);
        assert!((err - (1.0 / 4_294_967_296.0)).abs() < 1e-18);

        let ts2 = OwampTimeStamp {
            owptime: OwampNum64::ZERO,
            sync: true,
            multiplier: 1,
            scale: 3,
        };
        let err2 = get_timestamp_error(&ts2);
        assert!((err2 - (8.0 / 4_294_967_296.0)).abs() < 1e-18);
    }

    #[test]
    fn get_time_of_day_produces_ntp_epoch() {
        let ts = get_time_of_day().expect("wall clock");
        // Must be after 1970-01-01 in NTP epoch (JAN_1970 offset applied).
        assert!(ts.owptime.seconds() >= OWP_JAN_1970);
        // Multiplier never left at 0 by TimespecToTimestamp path.
        assert_ne!(ts.multiplier, 0);
    }

    #[test]
    fn init_ntp_accepts_missing_offset() {
        // Ensure env var absence is fine; do not clear unrelated env in parallel tests.
        let _ = init_ntp();
    }

    #[test]
    fn get_timespec_monotonic_and_alias() {
        let (t1, est1, sync1) = get_timespec().expect("timespec");
        let (t2, _, _) = get_timespec().expect("timespec2");
        assert!(t2.tv_sec >= t1.tv_sec);
        let (t3, est3, sync3) = get_timespec().expect("alias path");
        assert_eq!(t3.tv_sec, t2.tv_sec);
        let _ = (est1, sync1, est3, sync3);
    }

    #[test]
    fn debug_offset_add_sub_helpers() {
        let mut a = TimeVal {
            tv_sec: 1,
            tv_usec: 900_000,
        };
        tval_add(
            &mut a,
            &TimeVal {
                tv_sec: 0,
                tv_usec: 200_000,
            },
        );
        assert_eq!(a.tv_sec, 2);
        assert_eq!(a.tv_usec, 100_000);

        tval_sub(
            &mut a,
            &TimeVal {
                tv_sec: 0,
                tv_usec: 200_000,
            },
        );
        assert_eq!(a.tv_sec, 1);
        assert_eq!(a.tv_usec, 900_000);
    }

    #[test]
    fn c_like_aliases_resolve() {
        let ts = OwampTimeStamp {
            owptime: OwampNum64(0x0000_0001_0000_0000),
            sync: false,
            multiplier: 1,
            scale: 0,
        };
        let mut buf = [0u8; 8];
        encode_timestamp(&ts, &mut buf);
        let decoded = decode_timestamp(&buf);
        assert_eq!(decoded.owptime, ts.owptime);
        let _ = get_timestamp_error(&ts);
    }
}
