//! Slot schedules / Poisson (exponential) distribution scheduling.
//!
//! Port of `schedule.c`: AES-CTR uniform RNG, Knuth Algorithm 3.4.1.S
//! exponential deviate, and cyclic slot schedule generation.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes128, Block};

use crate::arithm64::num64_mult;
use crate::owamp::{
    OwampNum64, OwampSid, OwampSlot, OwampSlotLiteral, OwampSlotRandExp, OwampSlotType,
    OwampTestSpec,
};
use crate::Result;

/// Aliases matching earlier schedule-local names.
pub type Slot = OwampSlot;
pub type SlotType = crate::owamp::OwampSlotType;
pub type TestSpec = OwampTestSpec;

pub use crate::arithm64::{double_to_num64, num64_to_double, ulong_to_num64};

/// Convenience: add two Num64 values.
#[inline]
#[must_use]
pub fn num64_add(x: OwampNum64, y: OwampNum64) -> OwampNum64 {
    x + y
}

// ---------------------------------------------------------------------------
// Exponential deviate context (AES-CTR + Knuth S)
// ---------------------------------------------------------------------------

/// Precomputed Q[k] = sum_{i=1..k} (ln2)^i / i! as 32.32 Num64
/// (values already × 2^32, stored in the fractional half).
const Q: [u64; 12] = [
    0,           // placeholder
    0xb172_17f8, // ln2
    0xeef1_93f7,
    0xfd27_1862,
    0xff9d_6dd0,
    0xfff4_cfd0,
    0xfffe_e819,
    0xffff_e7ff,
    0xffff_fe2b,
    0xffff_ffe0,
    0xffff_fffe,
    0xffff_ffff,
];

const MASK32: u64 = 0xffff_ffff;
const BIT31: u64 = 0x8000_0000;
const LN2: u64 = Q[1];

/// AES-CTR seeded exponential RNG (`OWPExpContextRec`).
pub struct ExpContext {
    cipher: Aes128,
    counter: [u8; 16],
    out: [u8; 16],
    alive: bool,
}

impl ExpContext {
    /// Seed with a 16-byte key (`OWPExpContextCreate` / `bytes2Key` + zero counter/out).
    #[must_use]
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant from the C port is violated.
    pub fn create(seed: &[u8; 16]) -> Self {
        Self {
            cipher: Aes128::new_from_slice(seed).expect("AES-128 key length"),
            counter: [0u8; 16],
            out: [0u8; 16],
            alive: true,
        }
    }

    fn reset_key(&mut self, seed: &[u8; 16]) {
        self.cipher = Aes128::new_from_slice(seed).expect("AES-128 key length");
        self.counter = [0u8; 16];
        self.out = [0u8; 16];
        self.alive = true;
    }

    const fn reset_state(&mut self) {
        self.counter = [0u8; 16];
        self.out = [0u8; 16];
    }

    /// `OWPExpContextFree` — mark released (Drop frees memory).
    pub fn free(mut self) {
        self.alive = false;
        self.counter = [0u8; 16];
        self.out = [0u8; 16];
    }

    /// 32-bit uniform fraction in the low half of Num64 (`OWPUnifRand64`).
    fn unif_rand64(&mut self) -> OwampNum64 {
        let forth = self.counter[15] & 3;

        if forth == 0 {
            let mut block = Block::clone_from_slice(&self.counter);
            self.cipher.encrypt_block(&mut block);
            self.out.copy_from_slice(&block);
        }

        // Increment 128-bit counter in network byte order.
        for j in (0..16).rev() {
            self.counter[j] = self.counter[j].wrapping_add(1);
            if self.counter[j] != 0 {
                break;
            }
        }

        let start = 4 * forth as usize;
        let mut ret: u64 = 0;
        for b in &self.out[start..start + 4] {
            ret = (ret << 8) | u64::from(*b);
        }
        OwampNum64(ret)
    }

    /// Exponential deviate with mean 1.0 (`OWPExpContextNext`, Knuth Algorithm S).
    pub fn next(&mut self) -> OwampNum64 {
        let mut j: u32 = 0;
        let mut u = self.unif_rand64().0;

        while (u & BIT31) != 0 && j < 32 {
            u <<= 1;
            j += 1;
        }
        u <<= 1;
        u &= MASK32;

        if u < LN2 {
            return num64_add(
                num64_mult(ulong_to_num64(j), OwampNum64(LN2)),
                OwampNum64(u),
            );
        }

        let mut k = 2usize;
        while k < Q.len() {
            if u < Q[k] {
                break;
            }
            k += 1;
        }

        let mut v = self.unif_rand64().0;
        for _ in 2..=k {
            let tmp = self.unif_rand64().0;
            if tmp < v {
                v = tmp;
            }
        }

        num64_mult(num64_add(ulong_to_num64(j), OwampNum64(v)), OwampNum64(LN2))
    }
}

/// `OWPExpContextCreate`
#[must_use]
pub fn exp_context_create(seed: &[u8; 16]) -> ExpContext {
    ExpContext::create(seed)
}

/// `OWPExpContextFree`
pub fn exp_context_free(ectx: ExpContext) {
    ectx.free();
}

/// `OWPExpContextNext`
pub fn exp_context_next(ectx: &mut ExpContext) -> OwampNum64 {
    ectx.next()
}

// ---------------------------------------------------------------------------
// Schedule context
// ---------------------------------------------------------------------------

/// Validate slot types for create/reset (`CheckSlots`).
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn check_slots(tspec: &OwampTestSpec) -> Result<()> {
    if tspec.slots.is_empty() {
        return Err(crate::OwampError::Message(
            "OWPScheduleContextGenerateNextDelta: Invalid slot".into(),
        ));
    }
    for slot in &tspec.slots {
        match slot.slot_type() {
            OwampSlotType::RandExp | OwampSlotType::Literal => {},
            OwampSlotType::Unspecified => {
                return Err(crate::OwampError::Message(
                    "OWPScheduleContextGenerateNextDelta: Invalid slot".into(),
                ));
            },
        }
    }
    Ok(())
}

/// Stateful schedule generator (`OWPScheduleContextRec`).
pub struct ScheduleContext {
    exp: ExpContext,
    i: u64,
    maxi: u64,
    nslots: u32,
    slots: Vec<OwampSlot>,
    alive: bool,
}

impl ScheduleContext {
    /// `OWPScheduleContextCreate`
    ///
    /// TWAMP `TestRequest` carries `npackets=0`/`nslots=0` on the wire; the
    /// reflector still allocates an endpoint schedule handle (C keeps
    /// `tsession->sctx` nullable/unused for reflect). Allow an inert context.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn create(sid: &OwampSid, tspec: &OwampTestSpec) -> Result<Self> {
        if tspec.npackets == 0 {
            return Ok(Self {
                exp: ExpContext::create(sid),
                i: 0,
                maxi: 0,
                nslots: 0,
                slots: Vec::new(),
                alive: true,
            });
        }
        check_slots(tspec)?;

        let nslots = (tspec.slots.len() as u32).min(tspec.npackets);
        Ok(Self {
            exp: ExpContext::create(sid),
            i: 0,
            maxi: u64::from(tspec.npackets),
            nslots,
            slots: tspec.slots.clone(),
            alive: true,
        })
    }

    /// `OWPScheduleContextFree` — release schedule buffers (Drop frees memory).
    pub fn free(mut self) {
        self.alive = false;
        self.i = 0;
        self.maxi = 0;
        self.nslots = 0;
        self.slots.clear();
        self.exp.reset_state();
    }

    /// Reset generation; optionally re-seed from a new SID / `TestSpec`
    /// (`OWPScheduleContextReset`).
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn reset(&mut self, sid: Option<&OwampSid>, tspec: Option<&OwampTestSpec>) -> Result<()> {
        if !self.alive {
            return Err(crate::OwampError::Message(
                "OWPScheduleContextReset: context freed".into(),
            ));
        }
        self.exp.reset_state();
        self.i = 0;

        if let (Some(sid), Some(tspec)) = (sid, tspec) {
            check_slots(tspec)?;
            self.exp.reset_key(sid);
            self.maxi = u64::from(tspec.npackets);
            self.nslots = (tspec.slots.len() as u32).min(tspec.npackets);
            self.slots.clone_from(&tspec.slots);
        }
        Ok(())
    }

    /// Next inter-packet delta (`OWPScheduleContextGenerateNextDelta`).
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn generate_next_delta(&mut self) -> Result<OwampNum64> {
        if !self.alive {
            return Err(crate::OwampError::Message(
                "OWPScheduleContextGenerateNextDelta: context freed".into(),
            ));
        }
        if self.i >= self.maxi {
            return Err(crate::OwampError::Message(
                "OWPScheduleContextGenerateNextDelta: Schedule complete".into(),
            ));
        }
        if self.nslots == 0 || self.slots.is_empty() {
            return Err(crate::OwampError::Message(
                "OWPScheduleContextGenerateNextDelta: Invalid slot".into(),
            ));
        }
        let slot = self.slots[(self.i % u64::from(self.nslots)) as usize];
        self.i += 1;

        match slot {
            OwampSlot::RandExp(OwampSlotRandExp { mean }) => Ok(num64_mult(self.exp.next(), mean)),
            OwampSlot::Literal(OwampSlotLiteral { offset }) => Ok(offset),
        }
    }

    /// Absolute send times for all packets starting at `start_time`.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn generate_send_times(&mut self, start_time: OwampNum64) -> Result<Vec<OwampNum64>> {
        self.reset(None, None)?;
        let mut times = Vec::with_capacity(self.maxi as usize);
        let mut offset = OwampNum64::ZERO;
        for _ in 0..self.maxi {
            offset = num64_add(offset, self.generate_next_delta()?);
            times.push(num64_add(start_time, offset));
        }
        Ok(times)
    }

    #[must_use]
    pub const fn index(&self) -> u64 {
        self.i
    }

    #[must_use]
    pub const fn max_packets(&self) -> u64 {
        self.maxi
    }

    #[must_use]
    pub const fn is_alive(&self) -> bool {
        self.alive
    }
}

/// `OWPScheduleContextFree`
pub fn schedule_context_free(sctx: ScheduleContext) {
    sctx.free();
}

/// Average packets/second from slot means (`OWPTestPacketRate`).
#[must_use]
pub fn test_packet_rate(tspec: &OwampTestSpec) -> f64 {
    if tspec.slots.is_empty() {
        return 0.0;
    }
    let mut duration = OwampNum64::ZERO;
    for s in &tspec.slots {
        duration = num64_add(duration, s.mean_delay());
    }
    if duration.0 == 0 {
        return 0.0;
    }
    tspec.slots.len() as f64 / num64_to_double(duration)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lit(seconds: u32) -> OwampSlot {
        OwampSlot::Literal(OwampSlotLiteral {
            offset: ulong_to_num64(seconds),
        })
    }

    #[test]
    fn literal_slot_deltas() {
        let sid = [0u8; 16];
        let tspec = OwampTestSpec {
            npackets: 4,
            slots: vec![lit(1), lit(2)],
            ..Default::default()
        };
        let mut sctx = ScheduleContext::create(&sid, &tspec).unwrap();
        assert_eq!(sctx.generate_next_delta().unwrap(), ulong_to_num64(1));
        assert_eq!(sctx.generate_next_delta().unwrap(), ulong_to_num64(2));
        assert_eq!(sctx.generate_next_delta().unwrap(), ulong_to_num64(1));
        assert_eq!(sctx.generate_next_delta().unwrap(), ulong_to_num64(2));
        assert!(sctx.generate_next_delta().is_err());
    }

    #[test]
    fn send_times_accumulate() {
        let sid = [1u8; 16];
        let tspec = OwampTestSpec {
            start_time: ulong_to_num64(100),
            npackets: 3,
            slots: vec![lit(1)],
            ..Default::default()
        };
        let mut sctx = ScheduleContext::create(&sid, &tspec).unwrap();
        let times = sctx.generate_send_times(tspec.start_time).unwrap();
        assert_eq!(
            times,
            vec![
                ulong_to_num64(101),
                ulong_to_num64(102),
                ulong_to_num64(103),
            ]
        );
    }

    #[test]
    fn exponential_slots_deterministic() {
        let sid = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let mean = ulong_to_num64(1);
        let tspec = OwampTestSpec {
            npackets: 8,
            slots: vec![OwampSlot::RandExp(OwampSlotRandExp { mean })],
            ..Default::default()
        };
        let mut a = ScheduleContext::create(&sid, &tspec).unwrap();
        let mut b = ScheduleContext::create(&sid, &tspec).unwrap();
        let da: Vec<_> = (0..8).map(|_| a.generate_next_delta().unwrap()).collect();
        let db: Vec<_> = (0..8).map(|_| b.generate_next_delta().unwrap()).collect();
        assert_eq!(da, db);
        assert!(da.iter().all(|d| d.0 > 0));
    }

    #[test]
    fn reset_restarts_sequence() {
        let sid = [0x42u8; 16];
        let tspec = OwampTestSpec {
            npackets: 3,
            slots: vec![OwampSlot::RandExp(OwampSlotRandExp {
                mean: double_to_num64(0.1),
            })],
            ..Default::default()
        };
        let mut sctx = ScheduleContext::create(&sid, &tspec).unwrap();
        let first: Vec<_> = (0..3)
            .map(|_| sctx.generate_next_delta().unwrap())
            .collect();
        sctx.reset(None, None).unwrap();
        let second: Vec<_> = (0..3)
            .map(|_| sctx.generate_next_delta().unwrap())
            .collect();
        assert_eq!(first, second);
    }

    #[test]
    fn reset_with_new_sid_and_slots() {
        let sid_a = [0x11u8; 16];
        let sid_b = [0x22u8; 16];
        let tspec_a = OwampTestSpec {
            npackets: 2,
            slots: vec![lit(1)],
            ..Default::default()
        };
        let tspec_b = OwampTestSpec {
            npackets: 3,
            slots: vec![lit(5), lit(7)],
            ..Default::default()
        };
        let mut sctx = ScheduleContext::create(&sid_a, &tspec_a).unwrap();
        assert_eq!(sctx.generate_next_delta().unwrap(), ulong_to_num64(1));
        sctx.reset(Some(&sid_b), Some(&tspec_b)).unwrap();
        assert_eq!(sctx.max_packets(), 3);
        assert_eq!(sctx.generate_next_delta().unwrap(), ulong_to_num64(5));
        assert_eq!(sctx.generate_next_delta().unwrap(), ulong_to_num64(7));
        assert_eq!(sctx.generate_next_delta().unwrap(), ulong_to_num64(5));
        assert!(sctx.generate_next_delta().is_err());
    }

    #[test]
    fn check_slots_rejects_empty() {
        let tspec = OwampTestSpec {
            npackets: 1,
            slots: vec![],
            ..Default::default()
        };
        assert!(check_slots(&tspec).is_err());
        assert!(ScheduleContext::create(&[0u8; 16], &tspec).is_err());
    }

    #[test]
    fn exp_context_create_free_and_next() {
        let seed = [7u8; 16];
        let mut ectx = exp_context_create(&seed);
        let a = exp_context_next(&mut ectx);
        let b = exp_context_next(&mut ectx);
        assert_ne!(a, b);
        exp_context_free(ectx);
    }

    #[test]
    fn schedule_context_free_clears() {
        let sid = [3u8; 16];
        let tspec = OwampTestSpec {
            npackets: 2,
            slots: vec![lit(1)],
            ..Default::default()
        };
        let sctx = ScheduleContext::create(&sid, &tspec).unwrap();
        assert!(sctx.is_alive());
        schedule_context_free(sctx);
    }

    #[test]
    fn packet_rate_from_literal_slots() {
        let tspec = OwampTestSpec {
            npackets: 10,
            slots: vec![lit(1), lit(1)],
            ..Default::default()
        };
        assert!((test_packet_rate(&tspec) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn num64_mult_identity() {
        let one = ulong_to_num64(1);
        let half = OwampNum64(0x8000_0000);
        assert_eq!(num64_mult(one, half), half);
        assert_eq!(num64_mult(ulong_to_num64(2), half), one);
    }
}
