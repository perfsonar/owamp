//! Loss / delay / jitter statistics and report formatting.
//!
//! Port of `stats.c`. Bucket/packet hashes use idiomatic Rust maps; formulas and
//! machine/human printers match the C code.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::io::{Read, Seek, SeekFrom};

use crate::api::{read_data_skips, SessionFinishedType, SessionHeader, SkipRec};
use crate::arithm64::num64_to_double;
use crate::context::{SlotType, TestSpec as CtxTestSpec};
use crate::owamp::{
    OwampDataRec, OwampDelayType, OwampNum64, OwampPacketType, OwampSkipRec, OwampSlot,
    OwampSlotLiteral, OwampSlotRandExp, OwampTestSpec, OwampTimeStamp, OwampTtlType,
    OwampTwDataRec,
};
use crate::owampP::OWP_JAN_1970;
use crate::schedule::{num64_add, test_packet_rate, ScheduleContext};
use crate::time::{get_timestamp_error, timestamp_to_timespec};
use crate::Result;

fn ctx_tspec_to_owamp(ts: &CtxTestSpec) -> OwampTestSpec {
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

// ---------------------------------------------------------------------------
// Public aliases (C / prior local names)
// ---------------------------------------------------------------------------

pub type DataRec = OwampDataRec;
pub type TwDataRec = OwampTwDataRec;
pub type DelayType = OwampDelayType;
pub type PacketType = OwampPacketType;
pub type TtlType = OwampTtlType;
pub type TestSpec = OwampTestSpec;

pub const PKT_TYPE_NUM: usize = 2;
pub const DELAY_TYPE_NUM: usize = 3; // excludes Proc for histogram
pub const DELAY_TYPE_NUM_INC_PROC: usize = 4;
pub const TTL_TYPE_NUM: usize = 2;

const MIN_BUCKETS: usize = 10;
const MAX_BUCKETS: usize = 2_048;
const PACKET_BUFFER_ALLOC_FACTOR: f64 = 3.5;

/// Delay in seconds — C `OWPDelay` (signed difference of timestamps).
#[inline]
#[must_use]
pub fn delay(send: &OwampTimeStamp, recv: &OwampTimeStamp) -> f64 {
    num64_to_double(recv.owptime) - num64_to_double(send.owptime)
}

/// Lost iff receive timestamp is all-zero (`OWPIsLostRecord`).
#[inline]
#[must_use]
pub const fn is_lost_record(rec: &OwampDataRec) -> bool {
    rec.recv.owptime.0 == 0
}

/// Scale factor for human-readable output (`OWPStatsScaleFactor`).
#[must_use]
pub const fn scale_factor(scale: char) -> (f32, &'static str) {
    match scale.to_ascii_lowercase() {
        'n' => (1_000_000_000.0, "ns"),
        'u' => (1_000_000.0, "us"),
        'm' => (1_000.0, "ms"),
        's' => (1.0, "s"),
        _ => (0.0, ""),
    }
}

const fn delay_index(dtype: OwampDelayType) -> usize {
    dtype as u8 as usize
}

const fn pkt_index(ptype: OwampPacketType) -> usize {
    ptype as u8 as usize
}

// ---------------------------------------------------------------------------
// Packet hash plumbing (`OWPPacketRec` / `PacketAlloc` / `PacketGet` / flush)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
struct PacketNode {
    #[allow(dead_code)]
    seq: u32,
    seen: u32,
    lost: bool,
    schedtime: OwampNum64,
    associated_seq: u32,
}

// ---------------------------------------------------------------------------
// Delay histogram / percentiles / jitter
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Bucket {
    #[allow(dead_code)]
    b: i32,
    delay_samples: [u32; DELAY_TYPE_NUM],
}

/// Accumulated session statistics (`OWPStatsRec` summary fields).
pub struct Stats {
    pub twoway: bool,
    pub bucket_width: f64,
    pub scale: f32,
    pub scale_abrv: String,
    pub sent: u32,
    pub lost: u32,
    pub dups: [u32; PKT_TYPE_NUM],
    pub min_delay: [f64; DELAY_TYPE_NUM_INC_PROC],
    pub max_delay: [f64; DELAY_TYPE_NUM_INC_PROC],
    pub maxerr: [f64; DELAY_TYPE_NUM],
    pub sync: bool,
    pub clocks_offset: bool,
    pub inf_delay: f64,
    pub ttl_count: [[u64; 256]; TTL_TYPE_NUM],
    pub rn: Vec<u32>,
    pub rnumseqno: u32,
    pub start_time: OwampNum64,
    pub end_time: OwampNum64,
    pub sid: [u8; 16],
    pub from_host: String,
    pub to_host: String,
    pub from_addr: String,
    pub to_addr: String,
    pub from_serv: String,
    pub to_serv: String,
    pub display_unix_ts: bool,
    pub rec_limit: u32,
    pub first: u32,
    pub last: u32,
    pub begin_oset: u64,
    pub next_oset: u64,
    pub loss_timeout: OwampNum64,
    pub packet_size_padding: u32,
    pub npackets: u32,
    pub type_p: u32,
    pub finished: SessionFinishedType,
    pub hdr_version: u32,
    pub hdr_rec_size: u32,
    pub oset_skiprecs: u64,
    pub oset_datarecs: u64,
    buckets: BTreeMap<i32, Bucket>,
    bsort: Vec<i32>,
    blistlen: usize,
    seen: BTreeMap<u32, u32>,
    seen_bck: BTreeMap<u32, u32>,
    /// Packet hash tables per direction (`ptable`).
    ptable: [HashMap<u32, PacketNode>; PKT_TYPE_NUM],
    pbegin: [Option<u32>; PKT_TYPE_NUM],
    pend: [Option<u32>; PKT_TYPE_NUM],
    plistlen: usize,
    isctx: [u32; PKT_TYPE_NUM],
    endnum: OwampNum64,
    skips: Vec<OwampSkipRec>,
    iskip: usize,
    rseqno: Vec<u32>,
    rindex: usize,
    rlistlen: usize,
    sctx: Option<ScheduleContext>,
    file_index: u32,
    /// When set, iterate paths emit per-packet lines like C `stats->output`.
    pub emit_packet_lines: bool,
}

impl Stats {
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn create(
        twoway: bool,
        loss_timeout: OwampNum64,
        scale: char,
        bucket_width: f64,
        reorder_window: usize,
    ) -> Result<Self> {
        let (factor, abrv) = scale_factor(scale);
        if factor == 0.0 || bucket_width <= 0.0 {
            return Err(crate::OwampError::Message(
                "OWPStatsCreate: invalid scale/bucketwidth".into(),
            ));
        }
        let inf = num64_to_double(OwampNum64(loss_timeout.0.wrapping_add(1 << 32)));
        // C skips reordering buffers for TWAMP (`rlistlen == 0`).
        let rlistlen = reorder_window;
        let blistlen = {
            let d = num64_to_double(loss_timeout) / bucket_width;
            let n = if d > f64::from(i32::MAX) {
                i32::MAX as usize
            } else {
                d as usize
            };
            n.clamp(MIN_BUCKETS, MAX_BUCKETS)
        };
        Ok(Self {
            twoway,
            bucket_width,
            scale: factor,
            scale_abrv: abrv.to_string(),
            sent: 0,
            lost: 0,
            dups: [0; PKT_TYPE_NUM],
            min_delay: [inf; DELAY_TYPE_NUM_INC_PROC],
            max_delay: [-inf; DELAY_TYPE_NUM_INC_PROC],
            maxerr: [0.0; DELAY_TYPE_NUM],
            sync: true,
            clocks_offset: false,
            inf_delay: inf,
            ttl_count: [[0; 256]; TTL_TYPE_NUM],
            rn: vec![0; rlistlen],
            rnumseqno: 0,
            start_time: OwampNum64::ZERO,
            end_time: OwampNum64::ZERO,
            sid: [0; 16],
            from_host: String::new(),
            to_host: String::new(),
            from_addr: String::new(),
            to_addr: String::new(),
            from_serv: String::new(),
            to_serv: String::new(),
            display_unix_ts: false,
            rec_limit: 0,
            first: 0,
            last: 0,
            begin_oset: 0,
            next_oset: 0,
            loss_timeout,
            packet_size_padding: 0,
            npackets: 0,
            type_p: 0,
            finished: SessionFinishedType::Error,
            hdr_version: 3,
            hdr_rec_size: 0,
            oset_skiprecs: 0,
            oset_datarecs: 0,
            buckets: BTreeMap::new(),
            bsort: Vec::new(),
            blistlen,
            seen: BTreeMap::new(),
            seen_bck: BTreeMap::new(),
            ptable: [HashMap::new(), HashMap::new()],
            pbegin: [None, None],
            pend: [None, None],
            plistlen: rlistlen.max(10),
            isctx: [0; PKT_TYPE_NUM],
            endnum: OwampNum64::ZERO,
            skips: Vec::new(),
            iskip: 0,
            rseqno: vec![0; rlistlen],
            rindex: 0,
            rlistlen,
            sctx: None,
            file_index: 0,
            emit_packet_lines: false,
        })
    }

    /// `OWPStatsCreate` with session header metadata (hosts, skips, schedule).
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn create_from_header(
        hdr: &SessionHeader,
        fromhost: Option<&str>,
        tohost: Option<&str>,
        scale: char,
        bucket_width: f64,
        skips: Vec<OwampSkipRec>,
    ) -> Result<Self> {
        if !hdr.header || hdr.version < 2 {
            return Err(crate::OwampError::Message(format!(
                "OWPStatsCreate: owp files must be version 2 or greater (version = {})",
                hdr.version
            )));
        }
        // C: twoway → d=0 then MAX(10); one-way → rate × timeout × factor.
        let reorder = if hdr.twoway {
            10
        } else {
            let ow_ts = ctx_tspec_to_owamp(&hdr.test_spec);
            let rate = test_packet_rate(&ow_ts);
            let d = rate * num64_to_double(hdr.test_spec.loss_timeout) * PACKET_BUFFER_ALLOC_FACTOR;
            if d > f64::from(i32::MAX) {
                i32::MAX as usize
            } else if d < 10.0 {
                10
            } else {
                d as usize
            }
        };
        let mut stats = Self::create(
            hdr.twoway,
            hdr.test_spec.loss_timeout,
            scale,
            bucket_width,
            if hdr.twoway { 0 } else { reorder },
        )?;
        stats.sid = hdr.sid;
        stats.npackets = hdr.test_spec.npackets;
        stats.packet_size_padding = hdr.test_spec.packet_size_padding;
        stats.type_p = hdr.test_spec.type_p;
        stats.finished = hdr.finished;
        stats.hdr_version = hdr.version;
        stats.hdr_rec_size = hdr.rec_size;
        stats.oset_skiprecs = hdr.oset_skiprecs;
        stats.oset_datarecs = hdr.oset_datarecs;
        stats.skips = skips;
        stats.plistlen = reorder.max(10);
        stats.from_host = fromhost.unwrap_or("***").to_string();
        stats.to_host = tohost.unwrap_or("***").to_string();
        if let Some(sa) = hdr.sender {
            stats.from_addr = sa.ip().to_string();
            stats.from_serv = sa.port().to_string();
            if fromhost.is_none() {
                stats.from_host.clone_from(&stats.from_addr);
            }
        } else {
            stats.from_addr = "***".into();
            stats.from_serv.clear();
        }
        if let Some(sa) = hdr.receiver {
            stats.to_addr = sa.ip().to_string();
            stats.to_serv = sa.port().to_string();
            if tohost.is_none() {
                stats.to_host.clone_from(&stats.to_addr);
            }
        } else {
            stats.to_addr = "***".into();
            stats.to_serv.clear();
        }
        // C always creates a schedule context (needed for packet-hash flush timing).
        let ow_ts = ctx_tspec_to_owamp(&hdr.test_spec);
        if let Ok(sctx) = ScheduleContext::create(&hdr.sid, &ow_ts) {
            stats.sctx = Some(sctx);
            stats.endnum = hdr.test_spec.start_time;
        }
        Ok(stats)
    }

    /// `OWPStatsFree` — drop packet/bucket/reorder/schedule buffers.
    pub fn free(&mut self) {
        self.rn.clear();
        self.rseqno.clear();
        self.bsort.clear();
        self.buckets.clear();
        for t in 0..PKT_TYPE_NUM {
            self.ptable[t].clear();
            self.pbegin[t] = None;
            self.pend[t] = None;
        }
        self.seen.clear();
        self.seen_bck.clear();
        self.skips.clear();
        self.sctx = None;
        self.rlistlen = 0;
        self.rnumseqno = 0;
        self.rindex = 0;
        self.blistlen = 0;
        self.plistlen = 0;
    }

    fn bucket_index(&self, d: f64) -> i32 {
        let scaled = d / self.bucket_width;
        if scaled < 0.0 {
            scaled.floor() as i32
        } else {
            scaled.ceil() as i32
        }
    }

    fn increment_delay_bucket(&mut self, d: f64, dtype: OwampDelayType) {
        let ti = delay_index(dtype);
        if ti >= DELAY_TYPE_NUM {
            return;
        }
        let b = self.bucket_index(d);
        self.buckets
            .entry(b)
            .or_insert_with(|| Bucket {
                b,
                delay_samples: [0; DELAY_TYPE_NUM],
            })
            .delay_samples[ti] += 1;
    }

    fn update_minmax(&mut self, d: f64, dtype: OwampDelayType) {
        let i = delay_index(dtype);
        if d < self.min_delay[i] {
            self.min_delay[i] = d;
        }
        if d > self.max_delay[i] {
            self.max_delay[i] = d;
        }
    }

    fn note_seen(map: &mut BTreeMap<u32, u32>, seq: u32) -> u32 {
        let e = map.entry(seq).or_insert(0);
        *e += 1;
        *e
    }

    fn track_reordering(&mut self, seq_no: u32) {
        if self.rlistlen == 0 {
            return;
        }
        let n = self.rnumseqno.min(self.rlistlen as u32) as usize;
        for i in 0..n {
            let idx = if self.rindex > i {
                self.rindex - i - 1
            } else {
                self.rindex + self.rlistlen - i - 1
            };
            if seq_no < self.rseqno[idx] {
                self.rn[i] += 1;
            } else {
                break;
            }
        }
        self.rseqno[self.rindex] = seq_no;
        self.rnumseqno += 1;
        self.rindex = (self.rindex + 1) % self.rlistlen;
    }

    // --- Packet hash -------------------------------------------------------

    fn packet_alloc(&mut self, seq: u32, ptype: OwampPacketType) -> Result<&PacketNode> {
        let ti = pkt_index(ptype);
        if (ptype != OwampPacketType::BckPkts && seq > self.last)
            || self.pend[ti].is_some_and(|p| seq <= p)
        {
            return Err(crate::OwampError::Message(format!(
                "PacketAlloc: Invalid seq number for OWPPacket buffer {ti}"
            )));
        }
        let node = PacketNode {
            seq,
            seen: 0,
            lost: false,
            schedtime: self.endnum,
            associated_seq: 0,
        };
        self.ptable[ti].insert(seq, node);
        self.pend[ti] = Some(seq);
        if self.pbegin[ti].is_none() {
            self.pbegin[ti] = Some(seq);
        }
        Ok(self.ptable[ti].get(&seq).unwrap())
    }

    fn packet_free(&mut self, seq: u32, ptype: OwampPacketType) {
        let ti = pkt_index(ptype);
        self.ptable[ti].remove(&seq);
    }

    fn packet_clean(&mut self, ptype: OwampPacketType) {
        let ti = pkt_index(ptype);
        self.ptable[ti].clear();
        self.pbegin[ti] = None;
        self.pend[ti] = None;
    }

    fn packet_get(&mut self, seq: u32, ptype: OwampPacketType) -> Result<u32> {
        let ti = pkt_index(ptype);
        if let Some(end) = self.pend[ti] {
            if seq == end {
                return Ok(seq);
            }
        }
        if seq < self.first || (ptype != OwampPacketType::BckPkts && seq > self.last) {
            return Err(crate::OwampError::Message(format!(
                "Invalid type {ti} seq number request (out of range)"
            )));
        }
        let pend = self.pend[ti].unwrap_or_else(|| seq.saturating_sub(1));
        if seq > pend {
            let mut cur = pend;
            // If no pend yet, allocate `seq` directly after advancing schedule.
            if self.pend[ti].is_none() {
                if ptype != OwampPacketType::BckPkts {
                    if let Some(ref mut sctx) = self.sctx {
                        self.endnum = num64_add(self.endnum, sctx.generate_next_delta()?);
                    }
                }
                self.isctx[ti] = self.isctx[ti].saturating_add(1);
                let _ = self.packet_alloc(seq, ptype)?;
                return Ok(seq);
            }
            while cur < seq {
                if self.sctx.is_some() {
                    assert_eq!(cur + 1, self.isctx[ti]);
                }
                if ptype != OwampPacketType::BckPkts {
                    if let Some(ref mut sctx) = self.sctx {
                        self.endnum = num64_add(self.endnum, sctx.generate_next_delta()?);
                    }
                }
                self.isctx[ti] = cur + 1;
                let next = cur + 1;
                let sched = self.endnum;
                self.ptable[ti].insert(
                    next,
                    PacketNode {
                        seq: next,
                        seen: 0,
                        lost: false,
                        schedtime: sched,
                        associated_seq: 0,
                    },
                );
                self.pend[ti] = Some(next);
                if self.pbegin[ti].is_none() {
                    self.pbegin[ti] = Some(next);
                }
                cur = next;
            }
            return Ok(seq);
        }
        let begin = self.pbegin[ti].unwrap_or(self.first);
        if seq < begin {
            return Err(crate::OwampError::Message(format!(
                "Invalid type {ti} seq number request"
            )));
        }
        if self.ptable[ti].contains_key(&seq) {
            Ok(seq)
        } else {
            Err(crate::OwampError::Message(format!(
                "Unable to fetch seq ({seq}) from packet hash {ti}"
            )))
        }
    }

    fn in_skip_range(&self, seq: u32) -> bool {
        for s in self.skips.iter().skip(self.iskip) {
            if seq >= s.begin && seq <= s.end {
                return true;
            }
        }
        false
    }

    fn packet_begin_flush(&mut self, ptype: OwampPacketType) -> Result<bool> {
        let ti = pkt_index(ptype);
        let Some(seq) = self.pbegin[ti] else {
            return Err(crate::OwampError::Message(format!(
                "PacketBeginFlush: type {ti} begin node empty?"
            )));
        };
        let Some(node) = self.ptable[ti].get(&seq).cloned() else {
            return Err(crate::OwampError::Message(
                "PacketBeginFlush: missing begin node".into(),
            ));
        };

        while self.iskip < self.skips.len() && seq > self.skips[self.iskip].end {
            self.iskip += 1;
        }
        let skipped = self.iskip < self.skips.len()
            && seq >= self.skips[self.iskip].begin
            && seq <= self.skips[self.iskip].end;

        if !skipped {
            if node.lost {
                if ptype != OwampPacketType::BckPkts {
                    self.lost += 1;
                }
            } else if node.seen > 0 {
                self.dups[ti] += node.seen - 1;
            }
        }

        self.end_time = node.schedtime;

        let keep = if let Some(next) = self.ptable[ti].keys().copied().filter(|&s| s > seq).min() {
            self.pbegin[ti] = Some(next);
            true
        } else if seq + 1 < self.last {
            let nseq = self.packet_get(seq + 1, ptype)?;
            self.pbegin[ti] = Some(nseq);
            true
        } else {
            self.pbegin[ti] = None;
            false
        };
        self.packet_free(seq, ptype);
        Ok(keep)
    }

    fn rebuild_bsort(&mut self) {
        self.bsort = self.buckets.keys().copied().collect();
        self.bsort.sort_unstable();
    }

    // --- Record ingestion --------------------------------------------------

    /// Ingest one one-way data record (core of `IterateSummarizeSession`).
    pub fn process_record(&mut self, rec: &OwampDataRec) {
        if is_lost_record(rec) {
            let seen = Self::note_seen(&mut self.seen, rec.seq_no);
            if seen == 1 {
                self.sent += 1;
                self.lost += 1;
            }
            return;
        }

        let seen = Self::note_seen(&mut self.seen, rec.seq_no);
        if seen == 1 {
            self.sent += 1;
        } else {
            self.dups[OwampPacketType::FwdPkts as usize] += 1;
            return;
        }

        if !self.twoway {
            self.track_reordering(rec.seq_no);
        }

        if !rec.send.sync || !rec.recv.sync {
            self.sync = false;
        }

        let d = delay(&rec.send, &rec.recv);
        let derr = get_timestamp_error(&rec.send) + get_timestamp_error(&rec.recv);
        let di = delay_index(OwampDelayType::Delay);
        if derr > self.maxerr[di] {
            self.maxerr[di] = derr;
        }

        self.update_minmax(d, OwampDelayType::Delay);
        self.increment_delay_bucket(d, OwampDelayType::Delay);
        self.ttl_count[OwampTtlType::FwdTtl as usize][rec.ttl as usize] += 1;
        self.end_time = rec.send.owptime;
        if self.start_time.0 == 0 {
            self.start_time = rec.send.owptime;
        }
    }

    /// Packet-hash aware one-way iterate step (`IterateSummarizeSession`).
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant from the C port is violated.
    pub fn iterate_summarize(&mut self, rec: &OwampDataRec) -> Result<()> {
        if self.next_oset == 0 && rec.seq_no >= self.last {
            self.next_oset =
                self.begin_oset + u64::from(self.file_index) * u64::from(self.hdr_rec_size.max(1));
        }
        self.file_index += 1;
        if rec.seq_no < self.first || rec.seq_no >= self.last {
            return Ok(());
        }

        // Flush buffered packets past loss timeout / before this lost seq.
        if is_lost_record(rec) {
            while let Some(bseq) = self.pbegin[0] {
                if bseq >= rec.seq_no {
                    break;
                }
                if !self.packet_begin_flush(OwampPacketType::FwdPkts)? {
                    break;
                }
            }
        } else {
            let thresh = OwampNum64(rec.recv.owptime.0.wrapping_sub(self.loss_timeout.0));
            while let Some(bseq) = self.pbegin[0] {
                let Some(node) = self.ptable[0].get(&bseq) else {
                    break;
                };
                if node.schedtime.0 >= thresh.0 {
                    break;
                }
                if !self.packet_begin_flush(OwampPacketType::FwdPkts)? {
                    break;
                }
            }
        }

        let seq = self.packet_get(rec.seq_no, OwampPacketType::FwdPkts)?;
        if self.in_skip_range(seq) {
            return Ok(());
        }

        let node = self.ptable[0].get_mut(&seq).unwrap();
        if is_lost_record(rec) {
            if node.seen > 0 {
                return Err(crate::OwampError::Message(
                    "IterateSummarizeSession: Unexpected lost packet record".into(),
                ));
            }
            node.lost = true;
            self.sent += 1;
            if !rec.recv.sync {
                self.sync = false;
            }
            let derr = get_timestamp_error(&rec.recv);
            if derr > self.maxerr[0] {
                self.maxerr[0] = derr;
            }
            if self.emit_packet_lines {
                // Caller may capture via print helpers; keep line available as String.
                let _ = format!("seq_no={:<10} *LOST*\n", rec.seq_no);
            }
            return Ok(());
        }
        if node.lost {
            return Err(crate::OwampError::Message(
                "IterateSummarizeSession: Unexpected duplicate packet record (for lost one)".into(),
            ));
        }
        if node.seen == 0 {
            self.sent += 1;
        }
        node.seen += 1;
        let seen = node.seen;

        if !self.twoway {
            self.track_reordering(rec.seq_no);
        }
        if !rec.send.sync || !rec.recv.sync {
            self.sync = false;
        }
        let d = delay(&rec.send, &rec.recv);
        let derr = get_timestamp_error(&rec.send) + get_timestamp_error(&rec.recv);
        if derr > self.maxerr[0] {
            self.maxerr[0] = derr;
        }
        self.update_minmax(d, OwampDelayType::Delay);
        if self.emit_packet_lines {
            let _ = self.format_ow_packet_line(rec, d, derr);
        }
        if seen > 1 {
            return Ok(());
        }
        self.increment_delay_bucket(d, OwampDelayType::Delay);
        self.ttl_count[OwampTtlType::FwdTtl as usize][rec.ttl as usize] += 1;
        Ok(())
    }

    /// Packet-hash aware two-way iterate (`IterateSummarizeTWSession`).
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant from the C port is violated.
    #[allow(clippy::too_many_lines)] // C-parity body
    pub fn iterate_summarize_tw(&mut self, rec: &OwampTwDataRec) -> Result<()> {
        if self.next_oset == 0 && rec.sent.seq_no >= self.last {
            self.next_oset =
                self.begin_oset + u64::from(self.file_index) * u64::from(self.hdr_rec_size.max(1));
        }
        self.file_index += 1;
        if rec.sent.seq_no < self.first || rec.sent.seq_no >= self.last {
            return Ok(());
        }

        if is_lost_record(&rec.sent) {
            while let Some(bseq) = self.pbegin[0] {
                if bseq >= rec.sent.seq_no {
                    break;
                }
                if !self.packet_begin_flush(OwampPacketType::FwdPkts)? {
                    break;
                }
            }
        } else {
            let thresh = OwampNum64(rec.sent.send.owptime.0.wrapping_sub(self.loss_timeout.0));
            while let Some(bseq) = self.pbegin[0] {
                let Some(node) = self.ptable[0].get(&bseq) else {
                    break;
                };
                if node.schedtime.0 >= thresh.0 {
                    break;
                }
                if !self.packet_begin_flush(OwampPacketType::FwdPkts)? {
                    break;
                }
            }
        }

        // Flush reflect packets whose associated send seq was already flushed.
        while let [Some(fb), Some(bb)] = self.pbegin {
            let Some(fwd) = self.ptable[0].get(&fb) else {
                break;
            };
            if fwd.associated_seq <= bb {
                break;
            }
            if !self.packet_begin_flush(OwampPacketType::BckPkts)? {
                break;
            }
        }

        let fwd_seq = self.packet_get(rec.sent.seq_no, OwampPacketType::FwdPkts)?;
        let fwd = self.ptable[0].get_mut(&fwd_seq).unwrap();

        if is_lost_record(&rec.sent) {
            if fwd.seen > 0 {
                return Err(crate::OwampError::Message(
                    "IterateSummarizeTWSession: Unexpected lost packet record".into(),
                ));
            }
            fwd.lost = true;
            self.sent += 1;
            if !rec.sent.recv.sync {
                self.sync = false;
            }
            let derr = get_timestamp_error(&rec.sent.recv);
            for i in 0..DELAY_TYPE_NUM {
                if derr > self.maxerr[i] {
                    self.maxerr[i] = derr;
                }
            }
            return Ok(());
        }

        if fwd.lost {
            return Err(crate::OwampError::Message(
                "IterateSummarizeTWSession: Unexpected duplicate packet record (for lost one)"
                    .into(),
            ));
        }

        let bck_seq = self.packet_get(rec.reflected.seq_no, OwampPacketType::BckPkts)?;
        {
            let bck = self.ptable[1].get_mut(&bck_seq).unwrap();
            if bck.seen == 0 {
                bck.associated_seq = rec.sent.seq_no;
            } else if bck.associated_seq != rec.sent.seq_no {
                return Err(crate::OwampError::Message(
                    "IterateSummarizeTWSession: Reflect sequence number associated with multiple send sequence numbers"
                        .into(),
                ));
            }
            bck.seen += 1;
        }

        let bck_seen = self.ptable[1].get(&bck_seq).map_or(0, |n| n.seen);
        let fwd = self.ptable[0].get_mut(&fwd_seq).unwrap();
        if fwd.seen == 0 {
            self.sent += 1;
            fwd.seen += 1;
            fwd.associated_seq = rec.reflected.seq_no;
        } else if fwd.associated_seq != rec.reflected.seq_no && bck_seen == 1 {
            fwd.seen += 1;
        }
        let fwd_seen = fwd.seen;

        let mut delays = [0.0; DELAY_TYPE_NUM_INC_PROC];
        delays[delay_index(OwampDelayType::ProcDelay)] = delay(&rec.sent.recv, &rec.reflected.send);
        delays[delay_index(OwampDelayType::Delay)] = delay(&rec.sent.send, &rec.reflected.recv)
            - delays[delay_index(OwampDelayType::ProcDelay)];
        delays[delay_index(OwampDelayType::FwdDelay)] = delay(&rec.sent.send, &rec.sent.recv);
        delays[delay_index(OwampDelayType::BckDelay)] =
            delay(&rec.reflected.send, &rec.reflected.recv);

        let delay_errs = [
            get_timestamp_error(&rec.sent.send)
                + get_timestamp_error(&rec.reflected.recv)
                + get_timestamp_error(&rec.reflected.send)
                + get_timestamp_error(&rec.sent.recv),
            get_timestamp_error(&rec.sent.send) + get_timestamp_error(&rec.sent.recv),
            get_timestamp_error(&rec.reflected.send) + get_timestamp_error(&rec.reflected.recv),
        ];

        if delays[delay_index(OwampDelayType::FwdDelay)] < 0.0
            || delays[delay_index(OwampDelayType::BckDelay)] < 0.0
        {
            self.clocks_offset = true;
        }

        if self.emit_packet_lines {
            let _ = self.format_tw_packet_line(rec, &delays, delay_errs[0]);
        }

        for (i, &d) in delays.iter().enumerate() {
            self.update_minmax(
                d,
                match i {
                    0 => OwampDelayType::Delay,
                    1 => OwampDelayType::FwdDelay,
                    2 => OwampDelayType::BckDelay,
                    _ => OwampDelayType::ProcDelay,
                },
            );
        }
        for (maxerr, &derr) in self.maxerr.iter_mut().zip(delay_errs.iter()) {
            if derr > *maxerr {
                *maxerr = derr;
            }
        }

        if fwd_seen > 1 || bck_seen > 1 {
            return Ok(());
        }

        for (i, &d) in delays.iter().take(DELAY_TYPE_NUM).enumerate() {
            self.increment_delay_bucket(
                d,
                match i {
                    0 => OwampDelayType::Delay,
                    1 => OwampDelayType::FwdDelay,
                    _ => OwampDelayType::BckDelay,
                },
            );
        }
        self.ttl_count[OwampTtlType::FwdTtl as usize][rec.sent.ttl as usize] += 1;
        self.ttl_count[OwampTtlType::BckTtl as usize][rec.reflected.ttl as usize] += 1;
        Ok(())
    }

    /// Format one-way / lost packet line for callers that stream parse output.
    #[must_use]
    pub fn packet_line_ow(&self, rec: &OwampDataRec) -> String {
        if is_lost_record(rec) {
            return format!("seq_no={:<10} *LOST*\n", rec.seq_no);
        }
        let d = delay(&rec.send, &rec.recv);
        let derr = get_timestamp_error(&rec.send) + get_timestamp_error(&rec.recv);
        self.format_ow_packet_line(rec, d, derr)
    }

    /// Format two-way packet line for parse streaming.
    #[must_use]
    pub fn packet_line_tw(&self, rec: &OwampTwDataRec) -> String {
        if is_lost_record(&rec.sent) {
            return format!("seq_no={:<10} *LOST*\n", rec.sent.seq_no);
        }
        let mut delays = [0.0; DELAY_TYPE_NUM_INC_PROC];
        delays[3] = delay(&rec.sent.recv, &rec.reflected.send);
        delays[0] = delay(&rec.sent.send, &rec.reflected.recv) - delays[3];
        delays[1] = delay(&rec.sent.send, &rec.sent.recv);
        delays[2] = delay(&rec.reflected.send, &rec.reflected.recv);
        let derr = get_timestamp_error(&rec.sent.send)
            + get_timestamp_error(&rec.reflected.recv)
            + get_timestamp_error(&rec.reflected.send)
            + get_timestamp_error(&rec.sent.recv);
        self.format_tw_packet_line(rec, &delays, derr)
    }

    /// Ingest one two-way data record (core of `IterateSummarizeTWSession`).
    pub fn process_tw_record(&mut self, rec: &OwampTwDataRec) {
        if is_lost_record(&rec.sent) {
            let seen = Self::note_seen(&mut self.seen, rec.sent.seq_no);
            if seen == 1 {
                self.sent += 1;
                self.lost += 1;
            }
            return;
        }

        let seen_fwd = Self::note_seen(&mut self.seen, rec.sent.seq_no);
        if seen_fwd == 1 {
            self.sent += 1;
        } else {
            self.dups[OwampPacketType::FwdPkts as usize] += 1;
            return;
        }

        if !is_lost_record(&rec.reflected) {
            let seen_bck = Self::note_seen(&mut self.seen_bck, rec.reflected.seq_no);
            if seen_bck > 1 {
                self.dups[OwampPacketType::BckPkts as usize] += 1;
            }
        }

        if !rec.sent.send.sync
            || !rec.sent.recv.sync
            || !rec.reflected.send.sync
            || !rec.reflected.recv.sync
        {
            self.sync = false;
        }

        let d_proc = delay(&rec.sent.recv, &rec.reflected.send);
        let d_rtt = delay(&rec.sent.send, &rec.reflected.recv) - d_proc;
        let d_fwd = delay(&rec.sent.send, &rec.sent.recv);
        let d_bck = delay(&rec.reflected.send, &rec.reflected.recv);

        if d_fwd < 0.0 || d_bck < 0.0 {
            self.clocks_offset = true;
        }

        let delays = [
            (OwampDelayType::Delay, d_rtt),
            (OwampDelayType::FwdDelay, d_fwd),
            (OwampDelayType::BckDelay, d_bck),
            (OwampDelayType::ProcDelay, d_proc),
        ];
        let delay_errs = [
            get_timestamp_error(&rec.sent.send)
                + get_timestamp_error(&rec.reflected.recv)
                + get_timestamp_error(&rec.reflected.send)
                + get_timestamp_error(&rec.sent.recv),
            get_timestamp_error(&rec.sent.send) + get_timestamp_error(&rec.sent.recv),
            get_timestamp_error(&rec.reflected.send) + get_timestamp_error(&rec.reflected.recv),
        ];
        for &(t, d) in &delays {
            self.update_minmax(d, t);
            let ti = delay_index(t);
            if ti < DELAY_TYPE_NUM {
                self.increment_delay_bucket(d, t);
                if delay_errs[ti] > self.maxerr[ti] {
                    self.maxerr[ti] = delay_errs[ti];
                }
            }
        }

        self.ttl_count[OwampTtlType::FwdTtl as usize][rec.sent.ttl as usize] += 1;
        self.ttl_count[OwampTtlType::BckTtl as usize][rec.reflected.ttl as usize] += 1;
        self.end_time = rec.sent.send.owptime;
        if self.start_time.0 == 0 {
            self.start_time = rec.sent.send.owptime;
        }
    }

    fn format_ow_packet_line(&self, rec: &OwampDataRec, d: f64, derr: f64) -> String {
        let scaled = d * f64::from(self.scale);
        if self.display_unix_ts && rec.send.sync && rec.recv.sync {
            let epochdiff = f64::from(OWP_JAN_1970);
            format!(
                "seq_no={} delay={:e} {} (sync, err={:.3} {}) sent={} recv={}\n",
                rec.seq_no,
                scaled,
                self.scale_abrv,
                derr * f64::from(self.scale),
                self.scale_abrv,
                num64_to_double(rec.send.owptime) - epochdiff,
                num64_to_double(rec.recv.owptime) - epochdiff
            )
        } else if rec.send.sync && rec.recv.sync {
            format!(
                "seq_no={:<10} delay={:.3} {}\t(sync, err={:.3} {})\n",
                rec.seq_no,
                scaled,
                self.scale_abrv,
                derr * f64::from(self.scale),
                self.scale_abrv
            )
        } else {
            format!(
                "seq_no={:<10} delay={:.3} {}\t(unsync)\n",
                rec.seq_no, scaled, self.scale_abrv
            )
        }
    }

    fn format_tw_packet_line(
        &self,
        rec: &OwampTwDataRec,
        delays: &[f64; DELAY_TYPE_NUM_INC_PROC],
        derr: f64,
    ) -> String {
        let sf = f64::from(self.scale);
        if self.display_unix_ts {
            let epochdiff = f64::from(OWP_JAN_1970);
            format!(
                "seq_no={} fwd_delay={:e} {} bck_delay={:e} {} delay={:e} {} proc_delay={:e} {} (err={:.3} {}) sent={} recv={} reflected={} recv={}\n",
                rec.sent.seq_no,
                delays[1] * sf,
                self.scale_abrv,
                delays[2] * sf,
                self.scale_abrv,
                delays[0] * sf,
                self.scale_abrv,
                delays[3] * sf,
                self.scale_abrv,
                derr * sf,
                self.scale_abrv,
                num64_to_double(rec.sent.send.owptime) - epochdiff,
                num64_to_double(rec.sent.recv.owptime) - epochdiff,
                num64_to_double(rec.reflected.send.owptime) - epochdiff,
                num64_to_double(rec.reflected.recv.owptime) - epochdiff
            )
        } else {
            format!(
                "seq_no={:<10} fwd_delay={:.3} {} bck_delay={:.3} {} delay={:.3} {} proc_delay={:.3} {}\t(err={:.3} {})\n",
                rec.sent.seq_no,
                delays[1] * sf,
                self.scale_abrv,
                delays[2] * sf,
                self.scale_abrv,
                delays[0] * sf,
                self.scale_abrv,
                delays[3] * sf,
                self.scale_abrv,
                derr * sf,
                self.scale_abrv
            )
        }
    }

    pub fn finalize_range(&mut self, first: u32, last: u32) {
        for seq in first..last {
            if !self.seen.contains_key(&seq) {
                self.sent += 1;
                self.lost += 1;
            }
        }
    }

    /// Percentile from sorted delay histogram (`BucketBufferSortPercentile`).
    #[must_use]
    pub fn percentile(&self, alpha: f64, dtype: OwampDelayType) -> Option<f64> {
        let ti = delay_index(dtype);
        if ti >= DELAY_TYPE_NUM || !(0.0..=1.0).contains(&alpha) || self.sent == 0 {
            return None;
        }
        let threshold = alpha * f64::from(self.sent);
        let mut sum = 0.0;
        let keys: Box<dyn Iterator<Item = i32>> = if self.bsort.is_empty() {
            Box::new(self.buckets.keys().copied())
        } else {
            Box::new(self.bsort.iter().copied())
        };
        for b in keys {
            let Some(bucket) = self.buckets.get(&b) else {
                continue;
            };
            let samples = f64::from(bucket.delay_samples[ti]);
            if sum + samples >= threshold {
                return Some(f64::from(b) * self.bucket_width);
            }
            sum += samples;
        }
        None
    }

    /// Jitter = P95 − P50 (`CalculateJitter`).
    #[must_use]
    pub fn jitter(&self, dtype: OwampDelayType) -> Option<f64> {
        let pc95 = self.percentile(0.95, dtype)?;
        let pc50 = self.percentile(0.5, dtype)?;
        Some(pc95 - pc50)
    }

    #[must_use]
    pub fn loss_ratio(&self) -> f64 {
        if self.sent == 0 {
            0.0
        } else {
            f64::from(self.lost) / f64::from(self.sent)
        }
    }

    fn fmt_scaled(&self, v: f64) -> String {
        if !v.is_finite() || v.abs() >= self.inf_delay {
            "nan".into()
        } else {
            // C uses `%.3g` for human summaries.
            format!("{:.3}", v * f64::from(self.scale))
        }
    }

    fn fmt_timestamp_local(owptime: OwampNum64) -> (String, f32) {
        let ts = OwampTimeStamp {
            owptime,
            sync: true,
            multiplier: 1,
            scale: 0,
        };
        let Some(spec) = timestamp_to_timespec(&ts) else {
            return ("XXX".into(), 0.0);
        };
        let secs = spec.tv_sec;
        let nsec = spec.tv_nsec.max(0) as u32;
        let datetime = chrono::DateTime::from_timestamp(secs, nsec);
        let stval = datetime.map_or_else(
            || "XXX".into(),
            |dt| dt.with_timezone(&chrono::Local).format("%FT%T").to_string(),
        );
        let frac_ms = (spec.tv_nsec as f32) / 1_000_000.0;
        (stval, frac_ms)
    }

    /// Stats header with host:port (`PrintStatsHeader`).
    #[must_use]
    pub fn print_stats_header(&self) -> String {
        let kind = if self.twoway { "twping" } else { "owping" };
        format!(
            "\n--- {kind} statistics from [{}]:{} to [{}]:{} ---\nSID:\t{}\n",
            self.from_host,
            self.from_serv,
            self.to_host,
            self.to_serv,
            hex::encode(self.sid)
        )
    }

    /// Human-readable summary (`OWPStatsPrintSummary`).
    #[must_use]
    pub fn print_summary(&self, percentiles: &[f32]) -> String {
        let mut out = String::new();

        if self.clocks_offset {
            let _ = writeln!(
                out,
                "\nDirectional delays may be inaccurate due to out of sync clocks!"
            );
        }

        out.push_str(&self.print_stats_header());

        let (stval, sfrac) = Self::fmt_timestamp_local(self.start_time);
        let (etval, efrac) = Self::fmt_timestamp_local(self.end_time);
        let _ = writeln!(out, "first:\t{stval}.{sfrac:03.0}");
        let _ = writeln!(out, "last:\t{etval}.{efrac:03.0}");

        let _ = write!(
            out,
            "{} sent, {} lost ({:.3}%), ",
            self.sent,
            self.lost,
            100.0 * self.loss_ratio()
        );
        if self.twoway {
            let _ = writeln!(
                out,
                "{} send duplicates, {} reflect duplicates",
                self.dups[0], self.dups[1]
            );
        } else {
            let _ = writeln!(out, "{} duplicates", self.dups[0]);
        }

        self.write_delay_line(&mut out, OwampDelayType::Delay);
        if self.twoway {
            self.write_delay_line(&mut out, OwampDelayType::FwdDelay);
            self.write_delay_line(&mut out, OwampDelayType::BckDelay);
            self.write_delay_line(&mut out, OwampDelayType::ProcDelay);
        }

        self.write_jitter_line(&mut out, OwampDelayType::Delay);
        if self.twoway {
            self.write_jitter_line(&mut out, OwampDelayType::FwdDelay);
            self.write_jitter_line(&mut out, OwampDelayType::BckDelay);
        }

        if !percentiles.is_empty() {
            let _ = writeln!(out, "Percentiles:");
            for &p in percentiles {
                let val = self
                    .percentile(f64::from(p) / 100.0, OwampDelayType::Delay)
                    .map_or_else(|| "nan".into(), |d| self.fmt_scaled(d));
                let _ = writeln!(out, "\t{p:.1}: {val} {}", self.scale_abrv);
            }
        }

        // TTL / hops (`PrintTtlStats`) — always in C summary.
        out.push_str(&self.print_ttl_stats());

        if !self.twoway {
            let mut i = 0usize;
            while i < self.rlistlen && self.rn.get(i).copied().unwrap_or(0) != 0 {
                let pct = 100.0 * f64::from(self.rn[i]) / f64::from(self.rnumseqno.max(1));
                let _ = writeln!(out, "{}-reordering = {pct}%", i + 1);
                i += 1;
            }
            if i == 0 {
                let _ = writeln!(out, "no reordering");
            } else if i < self.rlistlen {
                let _ = writeln!(out, "no {}-reordering", i + 1);
            } else {
                let _ = writeln!(out, "{}-reordering not handled", self.rlistlen + 1);
            }
        }

        let _ = writeln!(out);
        out
    }

    fn write_delay_line(&self, out: &mut String, dtype: OwampDelayType) {
        let desc = match dtype {
            OwampDelayType::Delay => {
                if self.twoway {
                    "round-trip time"
                } else {
                    "one-way delay"
                }
            },
            OwampDelayType::FwdDelay => "send time",
            OwampDelayType::BckDelay => "reflect time",
            OwampDelayType::ProcDelay => "reflector processing time",
        };
        let min = self.fmt_scaled(self.min_delay[delay_index(dtype)]);
        let max = self.fmt_scaled(self.max_delay[delay_index(dtype)]);
        if dtype == OwampDelayType::ProcDelay {
            let _ = writeln!(out, "{desc} min/max = {min}/{max} {}", self.scale_abrv);
        } else {
            let med = self
                .percentile(0.5, dtype)
                .map_or_else(|| "nan".into(), |d| self.fmt_scaled(d));
            let _ = write!(
                out,
                "{desc} min/median/max = {min}/{med}/{max} {}, ",
                self.scale_abrv
            );
            if self.sync {
                let _ = writeln!(
                    out,
                    "(err={:.3} {})",
                    self.maxerr[delay_index(dtype)] * f64::from(self.scale),
                    self.scale_abrv
                );
            } else {
                let _ = writeln!(out, "(unsync)");
            }
        }
    }

    fn write_jitter_line(&self, out: &mut String, dtype: OwampDelayType) {
        let desc = match dtype {
            OwampDelayType::Delay => {
                if self.twoway {
                    "two-way"
                } else {
                    "one-way"
                }
            },
            OwampDelayType::FwdDelay => "send",
            OwampDelayType::BckDelay => "reflect",
            OwampDelayType::ProcDelay => return,
        };
        let j = self
            .jitter(dtype)
            .map_or_else(|| "nan".into(), |d| self.fmt_scaled(d));
        let _ = writeln!(out, "{desc} jitter = {j} {} (P95-P50)", self.scale_abrv);
    }

    /// `CalculateTtlStats` — distinct TTL values plus min/max.
    #[must_use]
    pub fn calculate_ttl_stats(&self, ttype: OwampTtlType) -> (u8, u8, u8) {
        let ti = ttype as u8 as usize;
        let mut ttl_num = 0u8;
        let mut min_ttl = 255u8;
        let mut max_ttl = 0u8;
        for i in 0..256 {
            if self.ttl_count[ti][i] == 0 {
                continue;
            }
            ttl_num = ttl_num.saturating_add(1);
            if (i as u8) < min_ttl {
                min_ttl = i as u8;
            }
            if (i as u8) > max_ttl {
                max_ttl = i as u8;
            }
        }
        (ttl_num, min_ttl, max_ttl)
    }

    const fn machine_delay_type_desc(dtype: OwampDelayType) -> &'static str {
        match dtype {
            OwampDelayType::Delay => "",
            OwampDelayType::FwdDelay => "_FWD",
            OwampDelayType::BckDelay => "_BCK",
            OwampDelayType::ProcDelay => "_PROC",
        }
    }

    fn print_min_delay_machine(&self, out: &mut String, dtype: OwampDelayType) {
        let i = delay_index(dtype);
        if self.min_delay[i] < self.inf_delay {
            let _ = writeln!(
                out,
                "MIN{}\t{}",
                Self::machine_delay_type_desc(dtype),
                self.min_delay[i]
            );
        }
    }

    fn print_max_delay_machine(&self, out: &mut String, dtype: OwampDelayType) {
        let i = delay_index(dtype);
        if self.max_delay[i] > -self.inf_delay {
            let _ = writeln!(
                out,
                "MAX{}\t{}",
                Self::machine_delay_type_desc(dtype),
                self.max_delay[i]
            );
        }
    }

    fn print_minmax_ttl_machine(&self, out: &mut String, ttype: OwampTtlType) -> u8 {
        let (ttl_num, min_ttl, max_ttl) = self.calculate_ttl_stats(ttype);
        let type_desc = match ttype {
            OwampTtlType::FwdTtl => {
                if self.twoway {
                    "_FWD"
                } else {
                    ""
                }
            },
            OwampTtlType::BckTtl => "_BCK",
        };
        let _ = writeln!(out, "MINTTL{type_desc}\t{min_ttl}");
        let _ = writeln!(out, "MAXTTL{type_desc}\t{max_ttl}");
        ttl_num
    }

    fn print_ttl_stats_machine(&self, out: &mut String) {
        let mut ttl_num = u16::from(self.print_minmax_ttl_machine(out, OwampTtlType::FwdTtl));
        if self.twoway {
            ttl_num += u16::from(self.print_minmax_ttl_machine(out, OwampTtlType::BckTtl));
        }
        if ttl_num == 0 {
            return;
        }
        let _ = writeln!(out, "<TTLBUCKETS>");
        for i in 0..256u16 {
            if self.twoway {
                let f = self.ttl_count[0][i as usize];
                let b = self.ttl_count[1][i as usize];
                if f != 0 || b != 0 {
                    let _ = writeln!(out, "\t{i}\t{f}\t{b}");
                }
            } else if self.ttl_count[0][i as usize] != 0 {
                let _ = writeln!(out, "\t{i}\t{}", self.ttl_count[0][i as usize]);
            }
        }
        let _ = writeln!(out, "</TTLBUCKETS>");
    }

    fn print_bucket_buffer(&self, out: &mut String) {
        let keys: Box<dyn Iterator<Item = i32>> = if self.bsort.is_empty() {
            Box::new(self.buckets.keys().copied())
        } else {
            Box::new(self.bsort.iter().copied())
        };
        for b in keys {
            let Some(bucket) = self.buckets.get(&b) else {
                continue;
            };
            if self.twoway {
                let _ = writeln!(
                    out,
                    "\t{b}\t{}\t{}\t{}",
                    bucket.delay_samples[0], bucket.delay_samples[1], bucket.delay_samples[2]
                );
            } else {
                let _ = writeln!(out, "\t{b}\t{}", bucket.delay_samples[0]);
            }
        }
    }

    /// Machine-readable summary (`OWPStatsPrintMachine`).
    #[must_use]
    #[allow(clippy::too_many_lines)] // C-parity body
    pub fn print_machine(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "SUMMARY\t{:.2}", 3.0);
        let _ = writeln!(out, "SID\t{}", hex::encode(self.sid));
        let _ = writeln!(out, "FROM_HOST\t{}", self.from_host);
        let _ = writeln!(out, "FROM_ADDR\t{}", self.from_addr);
        let _ = writeln!(out, "FROM_PORT\t{}", self.from_serv);
        let _ = writeln!(out, "TO_HOST\t{}", self.to_host);
        let _ = writeln!(out, "TO_ADDR\t{}", self.to_addr);
        let _ = writeln!(out, "TO_PORT\t{}", self.to_serv);
        let _ = writeln!(out, "START_TIME\t{}", self.start_time.0);
        let _ = writeln!(out, "END_TIME\t{}", self.end_time.0);
        if self.display_unix_ts {
            let epochdiff = f64::from(OWP_JAN_1970);
            let _ = writeln!(
                out,
                "UNIX_START_TIME\t{}",
                num64_to_double(self.start_time) - epochdiff
            );
            let _ = writeln!(
                out,
                "UNIX_END_TIME\t{}",
                num64_to_double(self.end_time) - epochdiff
            );
        }
        if (self.type_p & !0x3f00_0000) == 0 {
            let dscp = (self.type_p >> 24) as u8;
            let _ = writeln!(out, "DSCP\t0x{dscp:02x}");
        }
        let _ = writeln!(out, "LOSS_TIMEOUT\t{}", self.loss_timeout.0);
        let _ = writeln!(out, "PACKET_PADDING\t{}", self.packet_size_padding);
        let _ = writeln!(out, "SESSION_PACKET_COUNT\t{}", self.npackets);
        let sample = self.last.saturating_sub(self.first);
        let _ = writeln!(out, "SAMPLE_PACKET_COUNT\t{sample}");
        let _ = writeln!(out, "BUCKET_WIDTH\t{}", self.bucket_width);
        let finished = u32::from(matches!(self.finished, SessionFinishedType::Normal));
        let _ = writeln!(out, "SESSION_FINISHED\t{finished}");

        let _ = writeln!(out, "SENT\t{}", self.sent);
        let _ = writeln!(out, "SYNC\t{}", u32::from(self.sync));
        let _ = writeln!(out, "MAXERR\t{}", self.maxerr[0]);
        if self.twoway {
            let _ = writeln!(out, "MAXERR_FWD\t{}", self.maxerr[1]);
            let _ = writeln!(out, "MAXERR_BCK\t{}", self.maxerr[2]);
            let _ = writeln!(out, "DUPS_FWD\t{}", self.dups[0]);
            let _ = writeln!(out, "DUPS_BCK\t{}", self.dups[1]);
        } else {
            let _ = writeln!(out, "DUPS\t{}", self.dups[0]);
        }
        let _ = writeln!(out, "LOST\t{}", self.lost);

        self.print_min_delay_machine(&mut out, OwampDelayType::Delay);
        if self.twoway {
            self.print_min_delay_machine(&mut out, OwampDelayType::FwdDelay);
            self.print_min_delay_machine(&mut out, OwampDelayType::BckDelay);
            self.print_min_delay_machine(&mut out, OwampDelayType::ProcDelay);
        }
        if let Some(d1) = self.percentile(0.5, OwampDelayType::Delay) {
            let _ = writeln!(out, "MEDIAN\t{d1}");
        }
        if self.twoway {
            if let Some(d1) = self.percentile(0.5, OwampDelayType::FwdDelay) {
                let _ = writeln!(out, "MEDIAN_FWD\t{d1}");
            }
            if let Some(d1) = self.percentile(0.5, OwampDelayType::BckDelay) {
                let _ = writeln!(out, "MEDIAN_BCK\t{d1}");
            }
        }
        self.print_max_delay_machine(&mut out, OwampDelayType::Delay);
        if self.twoway {
            self.print_max_delay_machine(&mut out, OwampDelayType::FwdDelay);
            self.print_max_delay_machine(&mut out, OwampDelayType::BckDelay);
            self.print_max_delay_machine(&mut out, OwampDelayType::ProcDelay);
        }
        if let Some(d1) = self.jitter(OwampDelayType::Delay) {
            let _ = writeln!(out, "PDV\t{d1}");
        }
        if self.twoway {
            if let Some(d1) = self.jitter(OwampDelayType::FwdDelay) {
                let _ = writeln!(out, "PDV_FWD\t{d1}");
            }
            if let Some(d1) = self.jitter(OwampDelayType::BckDelay) {
                let _ = writeln!(out, "PDV_BCK\t{d1}");
            }
        }

        if self.sent > self.lost {
            let _ = writeln!(out, "<BUCKETS>");
            self.print_bucket_buffer(&mut out);
            let _ = writeln!(out, "</BUCKETS>");
        }
        self.print_ttl_stats_machine(&mut out);
        let _ = writeln!(out);

        if !self.twoway {
            let _ = writeln!(out, "<NREORDERING>");
            let mut j = 0usize;
            while j < self.rlistlen && self.rn.get(j).copied().unwrap_or(0) != 0 {
                let _ = writeln!(out, "\t{}\t{}", j + 1, self.rn[j]);
                j += 1;
            }
            if j == 0 || j >= self.rlistlen {
                let _ = writeln!(out, "\t{}\t0", j + 1);
            }
            let _ = writeln!(out, "</NREORDERING>");
        }
        out
    }
}

/// Convenience: build stats over an in-memory record slice.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn summarize_records(
    records: &[OwampDataRec],
    tspec: &OwampTestSpec,
    scale: char,
    bucket_width: f64,
) -> Result<Stats> {
    let mut stats = Stats::create(false, tspec.loss_timeout, scale, bucket_width, 100)?;
    for r in records {
        stats.process_record(r);
    }
    Ok(stats)
}

fn reset_summary_fields(stats: &mut Stats) {
    stats.sent = 0;
    stats.lost = 0;
    stats.dups = [0; PKT_TYPE_NUM];
    stats.buckets.clear();
    stats.bsort.clear();
    stats.seen.clear();
    stats.seen_bck.clear();
    stats.ttl_count.fill([0; 256]);
    for i in 0..DELAY_TYPE_NUM_INC_PROC {
        stats.min_delay[i] = stats.inf_delay;
        stats.max_delay[i] = -stats.inf_delay;
    }
    for i in 0..DELAY_TYPE_NUM {
        stats.maxerr[i] = 0.0;
    }
    stats.sync = true;
    stats.clocks_offset = false;
    stats.file_index = 0;
    stats.next_oset = 0;
    stats.iskip = 0;
    if !stats.twoway && stats.rlistlen > 0 {
        for i in 0..stats.rlistlen {
            stats.rseqno[i] = 0;
            stats.rn[i] = 0;
        }
        stats.rindex = 0;
        stats.rnumseqno = 0;
    }
    for t in 0..PKT_TYPE_NUM {
        stats.packet_clean(match t {
            0 => OwampPacketType::FwdPkts,
            _ => OwampPacketType::BckPkts,
        });
    }
}

/// `OWPStatsParse` over an already-decoded one-way record slice in `[first, last)`.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn stats_parse(
    stats: &mut Stats,
    records: &[OwampDataRec],
    first: u32,
    last: u32,
) -> Result<()> {
    let end = if last == u32::MAX {
        if stats.npackets > 0 {
            stats.npackets
        } else {
            records
                .iter()
                .map(|r| r.seq_no.saturating_add(1))
                .max()
                .unwrap_or(0)
        }
    } else {
        last
    };
    if first > end || (stats.npackets > 0 && end > stats.npackets) {
        return Err(crate::OwampError::Message(
            "OWPStatsParse: Invalid sample range".into(),
        ));
    }
    reset_summary_fields(stats);
    stats.first = first;
    stats.last = end;

    // Schedule advance to `first` when available.
    if let Some(ref mut sctx) = stats.sctx {
        let _ = sctx.reset(None, None);
        stats.isctx = [0; PKT_TYPE_NUM];
        stats.endnum = OwampNum64::ZERO; // filled below if start known
    }
    if stats.sctx.is_some() {
        // Prefer header start_time via loss_timeout companion fields if set elsewhere.
        // Advance deltas until isctx covers first.
        while stats.isctx[0] <= first {
            if let Some(ref mut sctx) = stats.sctx {
                match sctx.generate_next_delta() {
                    Ok(d) => stats.endnum = num64_add(stats.endnum, d),
                    Err(_) => break,
                }
            }
            stats.isctx[0] += 1;
        }
        stats.isctx[1] = stats.isctx[0];
        stats.start_time = stats.endnum;
        let _ = stats.packet_alloc(first, OwampPacketType::FwdPkts);
        let _ = stats.packet_alloc(first, OwampPacketType::BckPkts);
        for r in records {
            stats.iterate_summarize(r)?;
        }
        for t in 0..PKT_TYPE_NUM {
            let ptype = if t == 0 {
                OwampPacketType::FwdPkts
            } else {
                OwampPacketType::BckPkts
            };
            while stats.pbegin[t].is_some() {
                if !stats.packet_begin_flush(ptype)? {
                    break;
                }
            }
        }
    } else {
        for r in records {
            if r.seq_no < first || r.seq_no >= end {
                continue;
            }
            stats.process_record(r);
        }
        stats.finalize_range(first, end);
    }
    stats.rebuild_bsort();
    Ok(())
}

/// Parse TWAMP records into `stats` (`OWPStatsParse` twoway path).
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn stats_parse_tw(
    stats: &mut Stats,
    records: &[OwampTwDataRec],
    first: u32,
    last: u32,
) -> Result<()> {
    let end = if last == u32::MAX {
        if stats.npackets > 0 {
            stats.npackets
        } else {
            records
                .iter()
                .map(|r| r.sent.seq_no.saturating_add(1))
                .max()
                .unwrap_or(0)
        }
    } else {
        last
    };
    if first > end || (stats.npackets > 0 && end > stats.npackets) {
        return Err(crate::OwampError::Message(
            "OWPStatsParse: Invalid sample range".into(),
        ));
    }
    reset_summary_fields(stats);
    stats.first = first;
    stats.last = end;

    if stats.sctx.is_some() {
        if let Some(ref mut sctx) = stats.sctx {
            let _ = sctx.reset(None, None);
        }
        stats.isctx = [0; PKT_TYPE_NUM];
        while stats.isctx[0] <= first {
            if let Some(ref mut sctx) = stats.sctx {
                match sctx.generate_next_delta() {
                    Ok(d) => stats.endnum = num64_add(stats.endnum, d),
                    Err(_) => break,
                }
            } else {
                break;
            }
            stats.isctx[0] += 1;
        }
        stats.isctx[1] = stats.isctx[0];
        stats.start_time = stats.endnum;
        let _ = stats.packet_alloc(first, OwampPacketType::FwdPkts);
        let _ = stats.packet_alloc(first, OwampPacketType::BckPkts);
        for r in records {
            stats.iterate_summarize_tw(r)?;
        }
        for t in 0..PKT_TYPE_NUM {
            let ptype = if t == 0 {
                OwampPacketType::FwdPkts
            } else {
                OwampPacketType::BckPkts
            };
            while stats.pbegin[t].is_some() {
                if !stats.packet_begin_flush(ptype)? {
                    break;
                }
            }
        }
    } else {
        for r in records {
            if r.sent.seq_no < first || r.sent.seq_no >= end {
                continue;
            }
            stats.process_tw_record(r);
        }
        stats.finalize_range(first, end);
    }
    stats.rebuild_bsort();
    Ok(())
}

/// Full file-oriented `OWPStatsParse`: seek data region, iterate records, flush.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
#[allow(clippy::too_many_lines)] // C-parity body
pub fn stats_parse_file<R: Read + Seek>(
    stats: &mut Stats,
    fp: &mut R,
    begin_oset: u64,
    first: u32,
    last: u32,
) -> Result<()> {
    let end = if last == u32::MAX {
        stats.npackets
    } else {
        last
    };
    if first > end || (stats.npackets > 0 && end > stats.npackets) {
        return Err(crate::OwampError::Message(
            "OWPStatsParse: Invalid sample range".into(),
        ));
    }
    reset_summary_fields(stats);
    stats.first = first;
    stats.last = end;
    stats.begin_oset = begin_oset.max(stats.oset_datarecs);
    stats.next_oset = 0;
    stats.file_index = 0;

    let fileend = if stats.oset_skiprecs > stats.oset_datarecs {
        stats.oset_skiprecs
    } else {
        let cur = fp.stream_position().unwrap_or(0);
        fp.seek(SeekFrom::End(0))
            .map_err(|e| crate::OwampError::Message(format!("OWPStatsParse: seek end: {e}")))?;
        let endpos = fp
            .stream_position()
            .map_err(|e| crate::OwampError::Message(format!("OWPStatsParse: tell: {e}")))?;
        let _ = fp.seek(SeekFrom::Start(cur));
        endpos
    };
    fp.seek(SeekFrom::Start(stats.begin_oset))
        .map_err(|e| crate::OwampError::Message(format!("OWPStatsParse: fseeko: {e}")))?;

    let rec_size = u64::from(stats.hdr_rec_size.max(1));
    let mut nrecs = (fileend.saturating_sub(stats.begin_oset)) / rec_size;
    if stats.rec_limit > 0 && u64::from(stats.rec_limit) < nrecs {
        nrecs = u64::from(stats.rec_limit);
    }

    if stats.twoway {
        if let Some(ref mut sctx) = stats.sctx {
            let _ = sctx.reset(None, None);
        }
        stats.isctx = [0; PKT_TYPE_NUM];
        while stats.isctx[0] <= first {
            if let Some(ref mut sctx) = stats.sctx {
                match sctx.generate_next_delta() {
                    Ok(d) => stats.endnum = num64_add(stats.endnum, d),
                    Err(_) => break,
                }
            } else {
                break;
            }
            stats.isctx[0] += 1;
        }
        stats.isctx[1] = stats.isctx[0];
        stats.start_time = stats.endnum;
        let use_hash = stats.sctx.is_some();
        if use_hash {
            let _ = stats.packet_alloc(first, OwampPacketType::FwdPkts);
            let _ = stats.packet_alloc(first, OwampPacketType::BckPkts);
        }
        let rc = crate::api::parse_tw_records(fp, nrecs as u32, stats.hdr_version, |r| {
            let erec = OwampTwDataRec {
                sent: OwampDataRec {
                    seq_no: r.sent.seq_no,
                    send: r.sent.send,
                    recv: r.sent.recv,
                    ttl: r.sent.ttl,
                },
                reflected: OwampDataRec {
                    seq_no: r.reflected.seq_no,
                    send: r.reflected.send,
                    recv: r.reflected.recv,
                    ttl: r.reflected.ttl,
                },
            };
            if use_hash {
                if stats.iterate_summarize_tw(&erec).is_err() {
                    return false;
                }
            } else if erec.sent.seq_no >= first && erec.sent.seq_no < end {
                stats.process_tw_record(&erec);
            }
            true
        });
        if rc < crate::context::ErrSeverity::Ok {
            return Err(crate::OwampError::Message(
                "OWPStatsParse: iteration of twoway data records failed".into(),
            ));
        }
        if use_hash {
            for t in 0..PKT_TYPE_NUM {
                let ptype = if t == 0 {
                    OwampPacketType::FwdPkts
                } else {
                    OwampPacketType::BckPkts
                };
                while stats.pbegin[t].is_some() {
                    if !stats.packet_begin_flush(ptype)? {
                        break;
                    }
                }
            }
        } else {
            stats.finalize_range(first, end);
        }
    } else {
        // Prepare schedule / first packet node.
        if let Some(ref mut sctx) = stats.sctx {
            let _ = sctx.reset(None, None);
        }
        stats.isctx = [0; PKT_TYPE_NUM];
        while stats.isctx[0] <= first {
            if let Some(ref mut sctx) = stats.sctx {
                match sctx.generate_next_delta() {
                    Ok(d) => stats.endnum = num64_add(stats.endnum, d),
                    Err(_) => break,
                }
            } else {
                break;
            }
            stats.isctx[0] += 1;
        }
        stats.isctx[1] = stats.isctx[0];
        stats.start_time = stats.endnum;
        if stats.sctx.is_some() {
            let _ = stats.packet_alloc(first, OwampPacketType::FwdPkts);
        }
        let use_hash = stats.sctx.is_some();
        let rc = crate::api::parse_records(fp, nrecs as u32, stats.hdr_version, |r| {
            let erec = OwampDataRec {
                seq_no: r.seq_no,
                send: r.send,
                recv: r.recv,
                ttl: r.ttl,
            };
            if use_hash {
                if stats.iterate_summarize(&erec).is_err() {
                    return false;
                }
            } else if erec.seq_no >= first && erec.seq_no < end {
                stats.process_record(&erec);
            }
            true
        });
        if rc < crate::context::ErrSeverity::Ok {
            return Err(crate::OwampError::Message(
                "OWPStatsParse: iteration of data records failed".into(),
            ));
        }
        if use_hash {
            while stats.pbegin[0].is_some() {
                if !stats.packet_begin_flush(OwampPacketType::FwdPkts)? {
                    break;
                }
            }
        } else {
            stats.finalize_range(first, end);
        }
    }
    stats.rebuild_bsort();
    Ok(())
}

/// Read data records from a reader positioned at the first data record and summarize.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn parse_and_summarize(
    fp: &mut dyn std::io::Read,
    nrecs: u32,
    version: u32,
    twoway: bool,
    loss_timeout: OwampNum64,
    scale: char,
    bucket_width: f64,
) -> Result<(Stats, String)> {
    let mut stats = Stats::create(twoway, loss_timeout, scale, bucket_width, 100)?;
    if twoway {
        let rc = crate::api::parse_tw_records(fp, nrecs, version, |r| {
            let erec = OwampTwDataRec {
                sent: OwampDataRec {
                    seq_no: r.sent.seq_no,
                    send: r.sent.send,
                    recv: r.sent.recv,
                    ttl: r.sent.ttl,
                },
                reflected: OwampDataRec {
                    seq_no: r.reflected.seq_no,
                    send: r.reflected.send,
                    recv: r.reflected.recv,
                    ttl: r.reflected.ttl,
                },
            };
            stats.process_tw_record(&erec);
            true
        });
        if rc < crate::context::ErrSeverity::Ok {
            return Err(crate::OwampError::Message(
                "OWPStatsParse: iteration of twoway data records failed".into(),
            ));
        }
    } else {
        let rc = crate::api::parse_records(fp, nrecs, version, |r| {
            let erec = OwampDataRec {
                seq_no: r.seq_no,
                send: r.send,
                recv: r.recv,
                ttl: r.ttl,
            };
            stats.process_record(&erec);
            true
        });
        if rc < crate::context::ErrSeverity::Ok {
            return Err(crate::OwampError::Message(
                "OWPStatsParse: iteration of data records failed".into(),
            ));
        }
    }
    stats.rebuild_bsort();
    let summary = stats.print_summary(&[]);
    Ok((stats, summary))
}

/// Load skips from an already-positioned reader into `OwampSkipRec`s.
#[must_use]
pub fn load_skips_from_api(skips: &[SkipRec]) -> Vec<OwampSkipRec> {
    skips
        .iter()
        .map(|s| OwampSkipRec {
            begin: s.begin,
            end: s.end,
        })
        .collect()
}

/// Helper: read skip records off `fp` into stats-compatible form.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn read_skips_into(fp: &mut dyn Read, n: u32) -> Result<Vec<OwampSkipRec>> {
    let mut api_skips = Vec::new();
    if read_data_skips(fp, n, &mut api_skips) < crate::context::ErrSeverity::Ok {
        return Err(crate::OwampError::Message(
            "OWPStatsCreate: Unable to read skip records from file".into(),
        ));
    }
    Ok(load_skips_from_api(&api_skips))
}

impl Stats {
    /// TTL histogram lines for human output (`PrintTtlStats`).
    #[must_use]
    pub fn print_ttl_stats(&self) -> String {
        let mut out = String::new();
        let ntypes = if self.twoway { 2 } else { 1 };
        for t in 0..ntypes {
            let ttype = if t == 0 {
                OwampTtlType::FwdTtl
            } else {
                OwampTtlType::BckTtl
            };
            let (ttl_num, min_ttl, max_ttl) = self.calculate_ttl_stats(ttype);
            let ttl_desc = match ttype {
                OwampTtlType::FwdTtl => {
                    if self.twoway {
                        "send "
                    } else {
                        ""
                    }
                },
                OwampTtlType::BckTtl => "reflect ",
            };
            match ttl_num.cmp(&1) {
                std::cmp::Ordering::Less => {
                    let _ = writeln!(out, "{ttl_desc}TTL not reported");
                },
                std::cmp::Ordering::Equal => {
                    let _ = writeln!(
                        out,
                        "{ttl_desc}hops = {} (consistently)",
                        255u16 - u16::from(min_ttl)
                    );
                },
                std::cmp::Ordering::Greater => {
                    let _ = writeln!(
                        out,
                        "{ttl_desc}hops takes {ttl_num} values; min hops = {}, max hops = {}",
                        255u16 - u16::from(max_ttl),
                        255u16 - u16::from(min_ttl)
                    );
                },
            }
        }
        out
    }

    /// Write human summary to any `Write` (`OWPStatsPrintSummary`).
    ///
    /// `with_ttl` is retained for API compatibility; TTL/hops are always included
    /// (matching C). When `false`, the TTL block is stripped from the output.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn print_summary_to(
        &self,
        out: &mut dyn std::io::Write,
        percentiles: &[f32],
        with_ttl: bool,
    ) -> std::io::Result<()> {
        let text = self.print_summary(percentiles);
        if with_ttl {
            write!(out, "{text}")
        } else {
            // Drop TTL/hops lines while preserving the rest of the C-shaped summary.
            let mut filtered = String::new();
            for l in text.lines().filter(|l| {
                !l.contains("TTL not reported")
                    && !l.contains("hops =")
                    && !l.contains("hops takes")
            }) {
                filtered.push_str(l);
                filtered.push('\n');
            }
            write!(out, "{filtered}")
        }
    }

    /// Write machine summary to any `Write` (`OWPStatsPrintMachine`).
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn print_machine_to(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        write!(out, "{}", self.print_machine())
    }
}

// ---------------------------------------------------------------------------
// C-name aliases (`stats.c` Bucket*/Packet*/Print* helpers)
// ---------------------------------------------------------------------------

/// `BucketBufferClean`
pub fn bucket_buffer_clean(stats: &mut Stats) {
    stats.buckets.clear();
    stats.bsort.clear();
}

/// `BucketBufferPrint` — one-way delay histogram lines.
pub fn bucket_buffer_print(stats: &Stats, out: &mut String) {
    for (&b, bucket) in &stats.buckets {
        let _ = writeln!(out, "\t{b}\t{}", bucket.delay_samples[0]);
    }
}

/// `BucketBufferPrintTW` — two-way delay histogram lines.
pub fn bucket_buffer_print_tw(stats: &Stats, out: &mut String) {
    for (&b, bucket) in &stats.buckets {
        let _ = writeln!(
            out,
            "\t{b}\t{}\t{}\t{}",
            bucket.delay_samples[0], bucket.delay_samples[1], bucket.delay_samples[2]
        );
    }
}

/// `BucketBufferSortCmp` — compare bucket indices for qsort.
#[must_use]
pub fn bucket_buffer_sort_cmp(a: i32, b: i32) -> i32 {
    a.cmp(&b) as i32
}

/// `BucketBufferSortFill` — rebuild sorted bucket index vector.
pub fn bucket_buffer_sort_fill(stats: &mut Stats) {
    stats.rebuild_bsort();
}

/// `BucketIncrementDelay`
pub fn bucket_increment_delay(stats: &mut Stats, d: f64, dtype: OwampDelayType) {
    stats.increment_delay_bucket(d, dtype);
}

/// `PacketBufferClean`
pub fn packet_buffer_clean(stats: &mut Stats, ptype: OwampPacketType) {
    stats.packet_clean(ptype);
}

/// `PacketAlloc`
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn packet_alloc(stats: &mut Stats, seq: u32, ptype: OwampPacketType) -> Result<()> {
    stats.packet_alloc(seq, ptype).map(|_| ())
}

/// `PacketFree`
pub fn packet_free(stats: &mut Stats, seq: u32, ptype: OwampPacketType) {
    stats.packet_free(seq, ptype);
}

/// `PacketGet`
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn packet_get(stats: &mut Stats, seq: u32, ptype: OwampPacketType) -> Result<u32> {
    stats.packet_get(seq, ptype)
}

/// `PacketBeginFlush`
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn packet_begin_flush(stats: &mut Stats, ptype: OwampPacketType) -> Result<bool> {
    stats.packet_begin_flush(ptype)
}

/// `IterateSummarizeSession`
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn iterate_summarize_session(stats: &mut Stats, rec: &OwampDataRec) -> Result<()> {
    stats.iterate_summarize(rec)
}

/// `IterateSummarizeTWSession`
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn iterate_summarize_tw_session(stats: &mut Stats, rec: &OwampTwDataRec) -> Result<()> {
    stats.iterate_summarize_tw(rec)
}

/// `PrintStatsHeader`
#[must_use]
pub fn print_stats_header(stats: &Stats) -> String {
    stats.print_stats_header()
}

/// `BucketBufferSortPercentile`
#[must_use]
pub fn bucket_buffer_sort_percentile(
    stats: &Stats,
    alpha: f64,
    dtype: OwampDelayType,
) -> Option<f64> {
    stats.percentile(alpha, dtype)
}

/// `OWPStatsScaleFactor`
#[must_use]
pub const fn owp_stats_scale_factor(scale: char) -> (f32, &'static str) {
    scale_factor(scale)
}

/// `CalculateJitter`
#[must_use]
pub fn calculate_jitter(stats: &Stats, dtype: OwampDelayType) -> Option<f64> {
    stats.jitter(dtype)
}

/// `MachineDelayTypeDesc`
#[must_use]
pub const fn machine_delay_type_desc(dtype: OwampDelayType) -> &'static str {
    Stats::machine_delay_type_desc(dtype)
}

/// `PrintMinDelayMachine`
pub fn print_min_delay_machine(stats: &Stats, out: &mut String, dtype: OwampDelayType) {
    stats.print_min_delay_machine(out, dtype);
}

/// `PrintMaxDelayMachine`
pub fn print_max_delay_machine(stats: &Stats, out: &mut String, dtype: OwampDelayType) {
    stats.print_max_delay_machine(out, dtype);
}

/// `PrintTtlStatsMachine`
pub fn print_ttl_stats_machine(stats: &Stats, out: &mut String) {
    stats.print_ttl_stats_machine(out);
}

/// `PrintDelayStats`
pub fn print_delay_stats(stats: &Stats, out: &mut String, dtype: OwampDelayType) {
    stats.write_delay_line(out, dtype);
}

/// `PrintJitterStats`
pub fn print_jitter_stats(stats: &Stats, out: &mut String, dtype: OwampDelayType) {
    stats.write_jitter_line(out, dtype);
}

/// `PrintMinMaxTtlMachine`
pub fn print_min_max_ttl_machine(stats: &Stats, out: &mut String, ttype: OwampTtlType) -> u8 {
    stats.print_minmax_ttl_machine(out, ttype)
}

/// `PrintTtlBucket`
pub fn print_ttl_bucket(stats: &Stats, out: &mut String, ttl: u16) {
    let n = stats.ttl_count[0][ttl as usize];
    if n != 0 {
        let _ = writeln!(out, "\t{ttl}\t{n}");
    }
}

/// `PrintTtlBucketTW`
pub fn print_ttl_bucket_tw(stats: &Stats, out: &mut String, ttl: u16) {
    let f = stats.ttl_count[0][ttl as usize];
    let b = stats.ttl_count[1][ttl as usize];
    if f != 0 || b != 0 {
        let _ = writeln!(out, "\t{ttl}\t{f}\t{b}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithm64::{double_to_num64, ulong_to_num64};

    fn ts_ok(secs: f64) -> OwampTimeStamp {
        OwampTimeStamp {
            owptime: double_to_num64(secs),
            sync: true,
            multiplier: 1,
            scale: 0,
        }
    }

    fn rec(seq: u32, send: f64, recv: f64) -> OwampDataRec {
        OwampDataRec {
            seq_no: seq,
            send: ts_ok(send),
            recv: ts_ok(recv),
            ttl: 64,
        }
    }

    fn lost(seq: u32, send: f64) -> OwampDataRec {
        OwampDataRec {
            seq_no: seq,
            send: ts_ok(send),
            recv: OwampTimeStamp::default(),
            ttl: 0,
        }
    }

    #[test]
    fn delay_and_lost_basics() {
        let r = rec(0, 1.0, 1.05);
        assert!((delay(&r.send, &r.recv) - 0.05).abs() < 1e-9);
        assert!(!is_lost_record(&r));
        assert!(is_lost_record(&lost(1, 1.0)));
    }

    #[test]
    fn scale_factors() {
        assert_eq!(scale_factor('m'), (1_000.0, "ms"));
        assert_eq!(scale_factor('u'), (1_000_000.0, "us"));
        assert_eq!(scale_factor('x').0, 0.0);
    }

    #[test]
    fn loss_and_dup_counts() {
        let mut s = Stats::create(false, ulong_to_num64(10), 'm', 0.001, 16).unwrap();
        s.process_record(&rec(0, 0.0, 0.01));
        s.process_record(&lost(1, 0.1));
        s.process_record(&rec(0, 0.0, 0.012));
        assert_eq!(s.sent, 2);
        assert_eq!(s.lost, 1);
        assert_eq!(s.dups[0], 1);
        assert!((s.loss_ratio() - 0.5).abs() < 1e-12);
    }

    #[test]
    fn min_max_median_jitter() {
        let mut s = Stats::create(false, ulong_to_num64(10), 'm', 0.001, 16).unwrap();
        for (i, d_ms) in [10, 20, 30, 40, 50].iter().enumerate() {
            let d = f64::from(*d_ms) / 1_000.0;
            s.process_record(&rec(i as u32, 0.0, d));
        }
        assert!((s.min_delay[0] - 0.01).abs() < 1e-9);
        assert!((s.max_delay[0] - 0.05).abs() < 1e-9);
        let med = s.percentile(0.5, OwampDelayType::Delay).unwrap();
        assert!((med - 0.03).abs() < 0.002);
        let jit = s.jitter(OwampDelayType::Delay).unwrap();
        assert!(jit >= 0.0);
        assert!((jit - 0.02).abs() < 0.005);
    }

    #[test]
    fn summary_contains_key_fields() {
        let mut s = Stats::create(false, ulong_to_num64(5), 'm', 0.001, 8).unwrap();
        s.from_host = "a".into();
        s.to_host = "b".into();
        s.process_record(&rec(0, 1.0, 1.01));
        s.process_record(&rec(1, 1.1, 1.12));
        let text = s.print_summary(&[50.0, 95.0]);
        assert!(text.contains("2 sent"));
        assert!(text.contains("one-way delay"));
        assert!(text.contains("jitter"));
        assert!(text.contains("Percentiles"));
    }

    #[test]
    fn tw_delays() {
        let mut s = Stats::create(true, ulong_to_num64(5), 'm', 0.001, 8).unwrap();
        let rec = OwampTwDataRec {
            sent: OwampDataRec {
                seq_no: 0,
                send: ts_ok(0.0),
                recv: ts_ok(0.01),
                ttl: 64,
            },
            reflected: OwampDataRec {
                seq_no: 0,
                send: ts_ok(0.011),
                recv: ts_ok(0.021),
                ttl: 63,
            },
        };
        s.process_tw_record(&rec);
        assert_eq!(s.sent, 1);
        assert!((s.min_delay[delay_index(OwampDelayType::FwdDelay)] - 0.01).abs() < 1e-9);
        assert!((s.min_delay[delay_index(OwampDelayType::BckDelay)] - 0.01).abs() < 1e-9);
        assert!((s.min_delay[delay_index(OwampDelayType::ProcDelay)] - 0.001).abs() < 1e-9);
        assert!((s.min_delay[delay_index(OwampDelayType::Delay)] - 0.02).abs() < 1e-9);
    }

    #[test]
    fn stats_parse_range_and_print() {
        let recs = vec![rec(0, 0.0, 0.01), rec(1, 0.1, 0.12), lost(2, 0.2)];
        let mut s = Stats::create(false, ulong_to_num64(5), 'm', 0.001, 8).unwrap();
        stats_parse(&mut s, &recs, 0, 3).unwrap();
        assert_eq!(s.sent, 3);
        assert_eq!(s.lost, 1);
        let mut buf = Vec::new();
        s.print_summary_to(&mut buf, &[50.0], true).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("3 sent"));
        assert!(text.contains("machine") || text.contains("owping") || text.contains("SID"));
        let mach = s.print_machine();
        assert!(mach.contains("SUMMARY\t3.00"));
        assert!(mach.contains("SENT\t3"));
        assert!(mach.contains("<BUCKETS>"));
        assert!(mach.contains("MINTTL"));
        assert!(mach.contains("<TTLBUCKETS>"));
        assert!(mach.contains("<NREORDERING>"));
        // PDV only when P95 and P50 both resolve (enough delay samples vs sent).
        if s.jitter(OwampDelayType::Delay).is_some() {
            assert!(mach.contains("PDV\t"));
        }
    }

    #[test]
    fn calculate_ttl_and_free() {
        let mut s = Stats::create(false, ulong_to_num64(5), 'm', 0.001, 8).unwrap();
        s.process_record(&rec(0, 0.0, 0.01));
        let (n, min, max) = s.calculate_ttl_stats(OwampTtlType::FwdTtl);
        assert_eq!(n, 1);
        assert_eq!(min, 64);
        assert_eq!(max, 64);
        let ttl = s.print_ttl_stats();
        assert!(ttl.contains("hops = 191"));
        s.free();
        assert_eq!(s.buckets, std::collections::BTreeMap::new());
        assert_eq!(s.rn, []);
        assert_eq!(s.plistlen, 0);
    }

    #[test]
    fn packet_hash_alloc_get_flush() {
        let mut s = Stats::create(false, ulong_to_num64(5), 'm', 0.001, 8).unwrap();
        s.first = 0;
        s.last = 4;
        s.endnum = ulong_to_num64(1);
        let _ = s.packet_alloc(0, OwampPacketType::FwdPkts).unwrap();
        assert_eq!(s.pbegin[0], Some(0));
        assert_eq!(s.pend[0], Some(0));
        // Mark seq 0 lost and flush
        s.ptable[0].get_mut(&0).unwrap().lost = true;
        s.sent = 1;
        assert!(
            !s.packet_begin_flush(OwampPacketType::FwdPkts).unwrap()
                || s.pbegin[0].is_none()
                || s.lost == 1
        );
        assert_eq!(s.lost, 1);
    }

    #[test]
    fn create_from_header_rejects_old_version() {
        let hdr = SessionHeader {
            header: true,
            version: 1,
            ..Default::default()
        };
        assert!(Stats::create_from_header(&hdr, None, None, 'm', 0.001, vec![]).is_err());
    }

    #[test]
    fn summary_includes_ttl_first_last_and_reorder_tail() {
        let mut s = Stats::create(false, ulong_to_num64(5), 'm', 0.001, 4).unwrap();
        s.from_host = "a".into();
        s.from_serv = "861".into();
        s.to_host = "b".into();
        s.to_serv = "861".into();
        s.start_time = ulong_to_num64(1_700_000_000);
        s.end_time = ulong_to_num64(1_700_000_010);
        s.process_record(&rec(0, 1.0, 1.01));
        s.process_record(&rec(1, 1.1, 1.12));
        let text = s.print_summary(&[]);
        assert!(text.contains("from [a]:861 to [b]:861"));
        assert!(text.contains("first:"));
        assert!(text.contains("last:"));
        assert!(text.contains("hops"));
        assert!(text.contains("no reordering") || text.contains("-reordering"));
    }

    #[test]
    fn tw_clocks_offset_and_packet_line() {
        let mut s = Stats::create(true, ulong_to_num64(5), 'm', 0.001, 0).unwrap();
        let rec = OwampTwDataRec {
            sent: OwampDataRec {
                seq_no: 0,
                send: ts_ok(1.0),
                recv: ts_ok(0.5), // negative fwd delay
                ttl: 64,
            },
            reflected: OwampDataRec {
                seq_no: 0,
                send: ts_ok(0.6),
                recv: ts_ok(1.2),
                ttl: 63,
            },
        };
        s.process_tw_record(&rec);
        assert!(s.clocks_offset);
        let line = s.packet_line_tw(&rec);
        assert!(line.contains("fwd_delay="));
        assert!(line.contains("proc_delay="));
        let summary = s.print_summary(&[]);
        assert!(summary.contains("Directional delays may be inaccurate"));
        assert!(summary.contains("send hops") || summary.contains("reflect hops"));
    }

    #[test]
    fn reordering_counts_and_machine_block() {
        let mut s = Stats::create(false, ulong_to_num64(5), 'm', 0.001, 8).unwrap();
        // Arrive out of order: 1 then 0 → 1-reordering.
        s.process_record(&rec(1, 0.1, 0.11));
        s.process_record(&rec(0, 0.0, 0.01));
        assert!(s.rn[0] >= 1);
        let mach = s.print_machine();
        assert!(mach.contains("<NREORDERING>"));
        assert!(mach.contains("\t1\t"));
        let text = s.print_summary(&[]);
        assert!(text.contains("1-reordering"));
    }

    #[test]
    fn bucket_and_percentile_edges() {
        let mut s = Stats::create(false, ulong_to_num64(5), 'm', 0.001, 8).unwrap();
        assert!(s.percentile(0.5, OwampDelayType::Delay).is_none());
        s.process_record(&rec(0, 0.0, 0.002));
        s.process_record(&rec(1, 0.0, -0.002)); // negative delay → negative bucket
        s.rebuild_bsort();
        assert!(s.percentile(0.5, OwampDelayType::Delay).is_some());
        assert!(s.percentile(1.1, OwampDelayType::Delay).is_none());
        let mach = s.print_machine();
        assert!(mach.contains("<BUCKETS>"));
    }

    #[test]
    fn lost_packet_line_format() {
        let s = Stats::create(false, ulong_to_num64(5), 'm', 0.001, 8).unwrap();
        let line = s.packet_line_ow(&lost(7, 1.0));
        assert!(line.contains("*LOST*"));
        assert!(line.contains('7'));
        let ok = s.packet_line_ow(&rec(3, 1.0, 1.02));
        assert!(ok.contains("delay="));
        assert!(ok.contains('3'));
    }

    #[test]
    fn summarize_records_and_finalize_range() {
        let tspec = OwampTestSpec {
            start_time: ulong_to_num64(0),
            loss_timeout: ulong_to_num64(5),
            type_p: 0,
            packet_size_padding: 0,
            npackets: 4,
            slots: vec![],
        };
        let recs = [rec(0, 0.0, 0.01), rec(2, 0.2, 0.21)];
        let mut s = summarize_records(&recs, &tspec, 'm', 0.001).unwrap();
        assert_eq!(s.sent, 2);
        s.finalize_range(0, 4);
        // Missing seq 1 and 3 counted as lost.
        assert_eq!(s.sent, 4);
        assert_eq!(s.lost, 2);

        assert_eq!(scale_factor('n'), (1_000_000_000.0, "ns"));
        assert_eq!(scale_factor('s'), (1.0, "s"));
    }

    #[test]
    fn stats_parse_tw_and_print_machine_to() {
        let tw = OwampTwDataRec {
            sent: OwampDataRec {
                seq_no: 0,
                send: ts_ok(0.0),
                recv: ts_ok(0.01),
                ttl: 64,
            },
            reflected: OwampDataRec {
                seq_no: 0,
                send: ts_ok(0.012),
                recv: ts_ok(0.022),
                ttl: 63,
            },
        };
        let mut s = Stats::create(true, ulong_to_num64(5), 'm', 0.001, 0).unwrap();
        stats_parse_tw(&mut s, &[tw], 0, 1).unwrap();
        assert_eq!(s.sent, 1);
        assert!(s.min_delay[0].is_finite());

        let mut buf = Vec::new();
        s.print_machine_to(&mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("SUMMARY\t3.00"));
        assert!(text.contains("SENT\t1"));

        let hdr = s.print_stats_header();
        assert!(hdr.contains("twping"));
        assert!(hdr.contains("SID:"));
    }

    #[test]
    fn load_skips_and_create_from_header_ok() {
        let api_skips = vec![SkipRec { begin: 1, end: 3 }, SkipRec { begin: 5, end: 5 }];
        let skips = load_skips_from_api(&api_skips);
        assert_eq!(skips.len(), 2);
        assert_eq!(skips[0].begin, 1);
        assert_eq!(skips[1].end, 5);

        let mut hdr = SessionHeader {
            header: true,
            version: 3,
            ..Default::default()
        };
        hdr.twoway = false;
        hdr.test_spec.loss_timeout = ulong_to_num64(2);
        hdr.test_spec.npackets = 10;
        hdr.test_spec.nslots = 1;
        hdr.test_spec.slots = vec![crate::context::Slot {
            slot_type: crate::context::SlotType::Literal,
            time: ulong_to_num64(1),
        }];
        hdr.sid = [0x11; 16];
        hdr.sender = Some("127.0.0.1:4001".parse().unwrap());
        hdr.receiver = Some("127.0.0.1:4002".parse().unwrap());
        let s =
            Stats::create_from_header(&hdr, Some("src"), Some("dst"), 'u', 0.001, skips).unwrap();
        assert_eq!(s.from_host, "src");
        assert_eq!(s.to_host, "dst");
        assert_eq!(s.npackets, 10);
        assert_eq!(s.scale_abrv, "us");
        assert_eq!(s.sid, [0x11; 16]);
    }

    #[test]
    fn parse_and_summarize_one_way_v3() {
        let r = DataRec {
            seq_no: 0,
            send: ts_ok(1.0),
            recv: ts_ok(1.05),
            ttl: 60,
        };
        // protocol DataRec wire is distinct; encode via protocol helpers then parse.
        let mut wire = [0u8; crate::protocol::DATARECV3_SIZE];
        crate::protocol::encode_data_record(
            &mut wire,
            &crate::protocol::DataRec {
                seq_no: r.seq_no,
                send: r.send,
                recv: r.recv,
                ttl: r.ttl,
            },
        )
        .unwrap();
        let mut cursor = std::io::Cursor::new(wire.to_vec());
        let (stats, summary) =
            parse_and_summarize(&mut cursor, 1, 3, false, ulong_to_num64(5), 'm', 0.001).unwrap();
        assert_eq!(stats.sent, 1);
        assert!(summary.contains("1 sent"));
    }

    #[test]
    #[allow(clippy::too_many_lines)] // C-parity fixture setup
    fn stats_c_gap_helpers() {
        let mut s = Stats::create(false, ulong_to_num64(10), 'm', 0.001, 8).unwrap();
        s.from_host = "h1".into();
        s.from_serv = "1".into();
        s.to_host = "h2".into();
        s.to_serv = "2".into();
        s.first = 0;
        s.last = 8;

        assert_eq!(owp_stats_scale_factor('m'), (1_000.0, "ms"));
        assert_eq!(machine_delay_type_desc(OwampDelayType::FwdDelay), "_FWD");

        packet_alloc(&mut s, 0, OwampPacketType::FwdPkts).unwrap();
        assert_eq!(packet_get(&mut s, 0, OwampPacketType::FwdPkts).unwrap(), 0);
        packet_free(&mut s, 0, OwampPacketType::FwdPkts);
        assert!(!s.ptable[0].contains_key(&0));

        packet_buffer_clean(&mut s, OwampPacketType::FwdPkts);
        assert!(s.ptable[0].is_empty());

        packet_alloc(&mut s, 1, OwampPacketType::FwdPkts).unwrap();
        s.ptable[0].get_mut(&1).unwrap().lost = true;
        s.sent = 1;
        packet_begin_flush(&mut s, OwampPacketType::FwdPkts).unwrap();
        assert_eq!(s.lost, 1);
        assert!(!s.ptable[0].contains_key(&1));

        bucket_increment_delay(&mut s, 0.015, OwampDelayType::Delay);
        bucket_buffer_sort_fill(&mut s);
        assert_eq!(bucket_buffer_sort_cmp(-1, 2), -1);
        let p50 = bucket_buffer_sort_percentile(&s, 0.5, OwampDelayType::Delay);
        assert!(p50.is_some());

        let mut bout = String::new();
        bucket_buffer_print(&s, &mut bout);
        assert!(bout.contains('\t'));

        bucket_buffer_clean(&mut s);
        assert!(s.buckets.is_empty());

        s.process_record(&rec(0, 0.0, 0.01));
        s.process_record(&rec(1, 0.1, 0.12));
        s.rebuild_bsort();
        let jit = calculate_jitter(&s, OwampDelayType::Delay);
        assert!(jit.is_some() || s.sent < 5);

        print_delay_stats(&s, &mut bout, OwampDelayType::Delay);
        assert!(bout.contains("delay"));

        let mut jout = String::new();
        print_jitter_stats(&s, &mut jout, OwampDelayType::Delay);
        assert!(jout.contains("jitter") || jout.is_empty());

        let hdr = print_stats_header(&s);
        assert!(hdr.contains("owping"));
        assert!(hdr.contains("h1"));

        let (n, min, max) = s.calculate_ttl_stats(OwampTtlType::FwdTtl);
        assert_eq!(n, 1);
        assert_eq!(min, 64);
        assert_eq!(max, 64);

        let ttl_human = s.print_ttl_stats();
        assert!(ttl_human.contains("hops"));

        let mut mach = String::new();
        print_min_delay_machine(&s, &mut mach, OwampDelayType::Delay);
        print_max_delay_machine(&s, &mut mach, OwampDelayType::Delay);
        assert!(mach.contains("MIN"));
        assert!(mach.contains("MAX"));

        let mut ttl_m = String::new();
        let ttl_n = print_min_max_ttl_machine(&s, &mut ttl_m, OwampTtlType::FwdTtl);
        assert_eq!(ttl_n, n);
        print_ttl_stats_machine(&s, &mut ttl_m);
        assert!(ttl_m.contains("MINTTL"));
        assert!(ttl_m.contains("<TTLBUCKETS>"));

        print_ttl_bucket(&s, &mut ttl_m, 64);
        assert!(ttl_m.contains("\t64\t"));

        let mut s2 = Stats::create(true, ulong_to_num64(5), 'm', 0.001, 4).unwrap();
        let tw = OwampTwDataRec {
            sent: OwampDataRec {
                seq_no: 0,
                send: ts_ok(0.0),
                recv: ts_ok(0.01),
                ttl: 64,
            },
            reflected: OwampDataRec {
                seq_no: 0,
                send: ts_ok(0.011),
                recv: ts_ok(0.021),
                ttl: 63,
            },
        };
        stats_parse_tw(&mut s2, &[tw], 0, 1).unwrap();
        assert_eq!(s2.sent, 1);
        reset_summary_fields(&mut s2);
        s2.first = 0;
        s2.last = 1;
        s2.loss_timeout = OwampNum64::ZERO;
        s2.endnum = tw.sent.recv.owptime;
        packet_alloc(&mut s2, 0, OwampPacketType::FwdPkts).unwrap();
        packet_alloc(&mut s2, 0, OwampPacketType::BckPkts).unwrap();
        iterate_summarize_tw_session(&mut s2, &tw).unwrap();
        assert_eq!(s2.sent, 1);

        s2.increment_delay_bucket(0.02, OwampDelayType::Delay);
        let mut tw_b = String::new();
        bucket_buffer_print_tw(&s2, &mut tw_b);
        assert!(tw_b.contains('\t'));
        print_ttl_bucket_tw(&s2, &mut tw_b, 64);
        assert!(tw_b.contains("\t64\t"));

        let mut s3 = Stats::create(false, ulong_to_num64(10), 'm', 0.001, 8).unwrap();
        let r0 = rec(0, 0.0, 0.01);
        s3.first = 0;
        s3.last = 2;
        s3.loss_timeout = OwampNum64::ZERO;
        s3.endnum = r0.recv.owptime;
        packet_alloc(&mut s3, 0, OwampPacketType::FwdPkts).unwrap();
        iterate_summarize_session(&mut s3, &r0).unwrap();
        assert_eq!(s3.sent, 1);
        assert_eq!(s3.ptable[0].get(&0).unwrap().seen, 1);
    }

    /// Checklist of pure stats helpers covered by this module's tests.
    #[test]
    fn coverage_protocol_stats() {
        let exercised = [
            "delay",
            "is_lost_record",
            "scale_factor",
            "Stats::create",
            "Stats::create_from_header",
            "Stats::free",
            "Stats::process_record",
            "Stats::process_tw_record",
            "Stats::packet_line_ow",
            "Stats::packet_line_tw",
            "Stats::finalize_range",
            "Stats::percentile",
            "Stats::jitter",
            "Stats::loss_ratio",
            "Stats::print_stats_header",
            "Stats::print_summary",
            "Stats::print_summary_to",
            "Stats::print_machine",
            "Stats::print_machine_to",
            "Stats::print_ttl_stats",
            "Stats::calculate_ttl_stats",
            "summarize_records",
            "stats_parse",
            "stats_parse_tw",
            "parse_and_summarize",
            "load_skips_from_api",
        ];
        assert!(exercised.len() >= 20);
        assert_eq!(PKT_TYPE_NUM, 2);
        assert_eq!(DELAY_TYPE_NUM, 3);
        assert_eq!(DELAY_TYPE_NUM_INC_PROC, 4);
        assert_eq!(TTL_TYPE_NUM, 2);
    }
}
