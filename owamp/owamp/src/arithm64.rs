//! Arithmetic and conversion for [`OwampNum64`] — port of `arithm64.c`.

use crate::owamp::OwampNum64;

const MASK32: u64 = 0xffff_ffff;
const BILLION: u64 = 1_000_000_000;
const MILLION: u64 = 1_000_000;
const EXP2POW32: u64 = 0x0001_0000_0000;

/// Portable timeval (matches C `struct timeval` fields used by OWAMP).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimeVal {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

/// Portable timespec (matches C `struct timespec` fields used by OWAMP).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimeSpec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

/// Knuth vol.2 Algorithm 4.3.1.M — fixed-point multiply of two Q32.32 values.
///
/// Allows overflow (wraps to the middle 64 bits of the 128-bit product).
#[must_use]
#[allow(clippy::many_single_char_names)] // mirrors C multi-limb multiply locals
pub fn num64_mult(x: OwampNum64, y: OwampNum64) -> OwampNum64 {
    let xdec = [x.0 & MASK32, (x.0 >> 32) & MASK32];
    let ydec = [y.0 & MASK32, (y.0 >> 32) & MASK32];
    let mut w = [0u64; 4];

    for j in 0..2 {
        let mut k = 0u64;
        let mut i = 0usize;
        loop {
            let t = k + xdec[i] * ydec[j] + w[i + j];
            w[i + j] = t % EXP2POW32;
            k = t / EXP2POW32;
            i += 1;
            if i < 2 {
                continue;
            }
            w[j + 2] = k;
            break;
        }
    }

    let mut ret = w[2];
    ret <<= 32;
    OwampNum64(w[1].wrapping_add(ret))
}

impl OwampNum64 {
    #[must_use]
    pub fn mult(self, other: Self) -> Self {
        num64_mult(self, other)
    }
}

/// `OWPULongToNum64` — place seconds in the MS 32 bits.
#[inline]
#[must_use]
pub fn ulong_to_num64(a: u32) -> OwampNum64 {
    OwampNum64(u64::from(a) << 32)
}

/// `OWPNum64ToTimespec`
#[must_use]
#[allow(clippy::similar_names)] // `tv_sec` / `tv_nsec` match timespec field names
pub const fn num64_to_timespec(from: OwampNum64) -> TimeSpec {
    let mut tv_sec = ((from.0 >> 32) & MASK32) as i64;
    let mut tv_nsec = (((from.0 & MASK32) * BILLION) >> 32) as i64;

    while tv_nsec >= BILLION as i64 {
        tv_sec += 1;
        tv_nsec -= BILLION as i64;
    }

    TimeSpec { tv_sec, tv_nsec }
}

/// `OWPTimespecToNum64`
#[must_use]
pub const fn timespec_to_num64(from: &TimeSpec) -> OwampNum64 {
    let mut sec = from.tv_sec as u64;
    let mut nsec = from.tv_nsec as u64;

    while nsec >= BILLION {
        sec = sec.wrapping_add(1);
        nsec -= BILLION;
    }

    let mut to = (sec & MASK32) << 32;
    to |= ((nsec << 32) / BILLION) & MASK32;
    OwampNum64(to)
}

/// `OWPNum64ToTimeval`
#[must_use]
#[allow(clippy::similar_names)] // `tv_sec` / `tv_usec` match timeval field names
pub const fn num64_to_timeval(from: OwampNum64) -> TimeVal {
    let mut tv_sec = ((from.0 >> 32) & MASK32) as i64;
    let mut tv_usec = (((from.0 & MASK32) * MILLION) >> 32) as i64;

    while tv_usec >= MILLION as i64 {
        tv_sec += 1;
        tv_usec -= MILLION as i64;
    }

    TimeVal { tv_sec, tv_usec }
}

/// `OWPTimevalToNum64`
#[must_use]
pub const fn timeval_to_num64(from: &TimeVal) -> OwampNum64 {
    let mut sec = from.tv_sec as u64;
    let mut usec = from.tv_usec as u64;

    while usec >= MILLION {
        sec = sec.wrapping_add(1);
        usec -= MILLION;
    }

    let mut to = (sec & MASK32) << 32;
    to |= ((usec << 32) / MILLION) & MASK32;
    OwampNum64(to)
}

/// `OWPNum64ToDouble`
#[inline]
#[must_use]
pub fn num64_to_double(from: OwampNum64) -> f64 {
    (from.0 as f64) / (EXP2POW32 as f64)
}

/// `OWPDoubleToNum64` — negative inputs become zero (C behaviour).
#[must_use]
pub fn double_to_num64(from: f64) -> OwampNum64 {
    if from < 0.0 {
        return OwampNum64::ZERO;
    }
    OwampNum64((from * EXP2POW32 as f64) as u64)
}

/// `OWPUsecToNum64`
#[inline]
#[must_use]
pub fn usec_to_num64(usec: u32) -> OwampNum64 {
    OwampNum64((u64::from(usec) << 32) / MILLION)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ulong_shift() {
        assert_eq!(ulong_to_num64(5).0, 5u64 << 32);
        assert_eq!(ulong_to_num64(5).seconds(), 5);
        assert_eq!(ulong_to_num64(5).fraction(), 0);
    }

    #[test]
    fn timespec_roundtrip_integer_seconds() {
        let ts = TimeSpec {
            tv_sec: 42,
            tv_nsec: 0,
        };
        let n = timespec_to_num64(&ts);
        assert_eq!(n.0, 42u64 << 32);
        let back = num64_to_timespec(n);
        assert_eq!(back.tv_sec, 42);
        assert_eq!(back.tv_nsec, 0);
    }

    #[test]
    fn timeval_half_second() {
        // 0.5 sec = 500_000 usec → fraction bits ≈ 0x8000_0000
        let tv = TimeVal {
            tv_sec: 0,
            tv_usec: 500_000,
        };
        let n = timeval_to_num64(&tv);
        assert_eq!(n.seconds(), 0);
        // ((500000 << 32) / 1e6) = 2147483648 = 0x80000000
        assert_eq!(n.fraction(), 0x8000_0000);

        let back = num64_to_timeval(n);
        assert_eq!(back.tv_sec, 0);
        assert_eq!(back.tv_usec, 500_000);
    }

    #[test]
    fn double_conversions() {
        let n = double_to_num64(1.5);
        assert_eq!(n.0, 0x0000_0001_8000_0000);
        let d = num64_to_double(n);
        assert!((d - 1.5).abs() < 1e-9);
        assert_eq!(double_to_num64(-1.0).0, 0);
    }

    #[test]
    fn usec_to_num64_one_second() {
        assert_eq!(usec_to_num64(1_000_000).0, 1u64 << 32);
    }

    #[test]
    fn mult_two_point_five() {
        // 2.0 * 2.5 = 5.0
        let two = ulong_to_num64(2);
        let two_point_five = OwampNum64(0x0000_0002_8000_0000);
        let prod = num64_mult(two, two_point_five);
        assert_eq!(prod.0, 0x0000_0005_0000_0000);
    }

    #[test]
    fn mult_fractions() {
        // 0.5 * 0.5 = 0.25
        let half = OwampNum64(0x8000_0000);
        let quarter = num64_mult(half, half);
        assert_eq!(quarter.0, 0x4000_0000);
    }
}
