//! Public types from `owamp.h` / `owampP.h`.

use std::cmp::Ordering;
use std::ops::{Add, Sub};

use crate::owampP::OWP_USERID_LEN;

/// OWAMP 64-bit fixed-point time: 32-bit seconds + 32-bit fractional seconds.
///
/// Host byte order. MS 32 bits = seconds, LS 32 bits = fraction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OwampNum64(pub u64);

impl OwampNum64 {
    pub const ZERO: Self = Self(0);

    #[inline]
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    #[inline]
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }

    #[inline]
    #[must_use]
    pub const fn seconds(self) -> u32 {
        (self.0 >> 32) as u32
    }

    #[inline]
    #[must_use]
    pub const fn fraction(self) -> u32 {
        self.0 as u32
    }

    /// `OWPNum64Cmp` — `-1` / `0` / `1`.
    #[inline]
    #[must_use]
    pub fn cmp_num(self, other: Self) -> i32 {
        match self.0.cmp(&other.0) {
            Ordering::Less => -1,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        }
    }

    /// Absolute difference (`OWPNum64Diff`).
    #[inline]
    #[must_use]
    pub const fn diff(self, other: Self) -> Self {
        if self.0 > other.0 {
            Self(self.0 - other.0)
        } else {
            Self(other.0 - self.0)
        }
    }

    #[inline]
    #[must_use]
    pub const fn min(self, other: Self) -> Self {
        if self.0 < other.0 {
            self
        } else {
            other
        }
    }

    #[inline]
    #[must_use]
    pub const fn max(self, other: Self) -> Self {
        if self.0 > other.0 {
            self
        } else {
            other
        }
    }
}

impl Add for OwampNum64 {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self(self.0.wrapping_add(rhs.0))
    }
}

impl Sub for OwampNum64 {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self(self.0.wrapping_sub(rhs.0))
    }
}

impl From<u64> for OwampNum64 {
    #[inline]
    fn from(v: u64) -> Self {
        Self(v)
    }
}

impl From<OwampNum64> for u64 {
    #[inline]
    fn from(v: OwampNum64) -> Self {
        v.0
    }
}

/// Timestamp with sync / error-estimate fields (OWDP §5.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OwampTimeStamp {
    pub owptime: OwampNum64,
    pub sync: bool,
    pub multiplier: u8,
    pub scale: u8,
}

/// Error severity — values map to syslog priorities.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(i32)]
pub enum OwampErrSeverity {
    Fatal = 3,
    Warning = 4,
    Info = 6,
    Debug = 7,
    Ok = 8,
}

/// Error type classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum OwampErrType {
    Unknown = 0,
    Policy = 1,
    Invalid = 2,
    Unsupported = 3,
}

/// Accept / reject codes for control and session negotiation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum OwampAcceptType {
    Invalid = -1,
    Accept = 0,
    Reject = 1,
    Failure = 2,
    Unsupported = 3,
    UnavailablePerm = 4,
    UnavailableTemp = 5,
}

impl OwampAcceptType {
    #[must_use]
    pub const fn from_i32(v: i32) -> Option<Self> {
        Some(match v {
            -1 => Self::Invalid,
            0 => Self::Accept,
            1 => Self::Reject,
            2 => Self::Failure,
            3 => Self::Unsupported,
            4 => Self::UnavailablePerm,
            5 => Self::UnavailableTemp,
            _ => return None,
        })
    }
}

/// Control request message types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum OwampRequestType {
    Invalid = -1,
    Test = 1,
    StartSessions = 2,
    StopSessions = 3,
    FetchSession = 4,
    TestTw = 5,
    SockClose = 10,
    SockIntr = 11,
}

/// Session datafile finished flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum OwampSessionFinishedType {
    Error = 0,
    Normal = 1,
    Incomplete = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum OwampSlotType {
    Unspecified = -1,
    RandExp = 0,
    Literal = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwampSlotRandExp {
    pub mean: OwampNum64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwampSlotLiteral {
    pub offset: OwampNum64,
}

/// Slot union — all current slot types share a single time value used as mean delay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwampSlot {
    RandExp(OwampSlotRandExp),
    Literal(OwampSlotLiteral),
}

impl OwampSlot {
    #[must_use]
    pub const fn slot_type(&self) -> OwampSlotType {
        match self {
            Self::RandExp(_) => OwampSlotType::RandExp,
            Self::Literal(_) => OwampSlotType::Literal,
        }
    }

    #[must_use]
    pub const fn mean_delay(&self) -> OwampNum64 {
        match self {
            Self::RandExp(s) => s.mean,
            Self::Literal(s) => s.offset,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwampTestSpec {
    pub start_time: OwampNum64,
    pub loss_timeout: OwampNum64,
    pub type_p: u32,
    pub packet_size_padding: u32,
    pub npackets: u32,
    pub slots: Vec<OwampSlot>,
}

impl Default for OwampTestSpec {
    fn default() -> Self {
        Self {
            start_time: OwampNum64::ZERO,
            loss_timeout: OwampNum64::ZERO,
            type_p: 0,
            packet_size_padding: 0,
            npackets: 0,
            slots: Vec::new(),
        }
    }
}

pub type OwampPacketSizeT = u32;
pub type OwampSessionMode = u32;
pub type OwampSid = [u8; 16];
pub type OwampSequence = [u8; 4];
pub type OwampUserId = [u8; OWP_USERID_LEN + 1];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OwampPortRange {
    pub low: u16,
    pub high: u16,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OwampDataRec {
    pub seq_no: u32,
    pub send: OwampTimeStamp,
    pub recv: OwampTimeStamp,
    pub ttl: u8,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OwampTwDataRec {
    pub sent: OwampDataRec,
    pub reflected: OwampDataRec,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OwampSkipRec {
    pub begin: u32,
    pub end: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OwampPacketType {
    FwdPkts = 0,
    BckPkts = 1,
}

impl OwampPacketType {
    pub const OWP_PKTS: Self = Self::FwdPkts;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OwampDelayType {
    Delay = 0,
    FwdDelay = 1,
    BckDelay = 2,
    ProcDelay = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OwampTtlType {
    FwdTtl = 0,
    BckTtl = 1,
}

impl OwampTtlType {
    pub const OWP_TTL: Self = Self::FwdTtl;
}

/// One-way delay between send and recv timestamps (seconds as `f64`).
#[must_use]
pub fn owamp_delay(send_time: &OwampTimeStamp, recv_time: &OwampTimeStamp) -> f64 {
    crate::arithm64::num64_to_double(recv_time.owptime - send_time.owptime)
}

/// A record is lost when the recv timestamp is all zeros (protocol convention).
#[must_use]
pub const fn is_lost_record(rec: &OwampDataRec) -> bool {
    rec.recv.owptime.0 == 0 && !rec.recv.sync && rec.recv.multiplier == 0 && rec.recv.scale == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn num64_add_sub_diff() {
        let a = OwampNum64(0x0000_0002_8000_0000);
        let b = OwampNum64(0x0000_0001_4000_0000);
        assert_eq!((a + b).0, 0x0000_0003_c000_0000);
        assert_eq!((a - b).0, 0x0000_0001_4000_0000);
        assert_eq!(a.diff(b), a - b);
        assert_eq!(b.diff(a), a - b);
        assert_eq!(a.cmp_num(b), 1);
        assert_eq!(b.cmp_num(a), -1);
        assert_eq!(a.cmp_num(a), 0);
    }

    #[test]
    fn accept_type_roundtrip() {
        assert_eq!(OwampAcceptType::from_i32(0), Some(OwampAcceptType::Accept));
        assert_eq!(
            OwampAcceptType::from_i32(5),
            Some(OwampAcceptType::UnavailableTemp)
        );
        assert_eq!(OwampAcceptType::from_i32(99), None);
    }
}
