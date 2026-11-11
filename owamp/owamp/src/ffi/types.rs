//! `#[repr(C)]` layouts matching `owamp.h` POD types.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use std::os::raw::c_int;

use libc::{off_t, sockaddr_storage, socklen_t, stat};

/// C `uint64_t` / `OWPNum64`.
pub type OWPNum64 = u64;
pub type OWPBoolean = isize;
pub type OWPSessionMode = u32;
pub type OWPPacketSizeT = u32;
pub type OWPAcceptType = c_int;
pub type OWPErrSeverity = c_int;
pub type OWPErrType = c_int;
pub type OWPRequestType = c_int;
pub type OWPSessionFinishedType = c_int;
pub type OWPSID = [u8; 16];
pub type OWPUserID = [u8; 81];

pub const fn owp_true() -> OWPBoolean {
    1
}
pub const fn owp_false() -> OWPBoolean {
    0
}
pub fn owp_bool(v: bool) -> OWPBoolean {
    if v {
        owp_true()
    } else {
        owp_false()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct OWPTimeStamp {
    pub owptime: OWPNum64,
    pub sync: u8,
    pub multiplier: u8,
    pub scale: u8,
}

pub type COwampTimeStamp = OWPTimeStamp;
pub type COwampNum64 = OWPNum64;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OWPSlotRandExp {
    pub slot_type: c_int,
    pub mean: OWPNum64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OWPSlotLiteral {
    pub slot_type: c_int,
    pub offset: OWPNum64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union OWPSlot {
    pub slot_type: c_int,
    pub rand_exp: OWPSlotRandExp,
    pub literal: OWPSlotLiteral,
}

pub type COwampSlot = OWPSlot;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OWPTestSpec {
    pub start_time: OWPNum64,
    pub loss_timeout: OWPNum64,
    pub typeP: u32,
    pub packet_size_padding: u32,
    pub npackets: u32,
    pub nslots: u32,
    pub slots: *mut OWPSlot,
}

pub type COwampTestSpec = OWPTestSpec;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct OWPDataRec {
    pub seq_no: u32,
    pub send: OWPTimeStamp,
    pub recv: OWPTimeStamp,
    pub ttl: u8,
}

pub type COwampDataRec = OWPDataRec;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct OWPTWDataRec {
    pub sent: OWPDataRec,
    pub reflected: OWPDataRec,
}

pub type COwampTwDataRec = OWPTWDataRec;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct OWPSkipRec {
    pub begin: u32,
    pub end: u32,
}

pub type COwampSkipRec = OWPSkipRec;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct OWPPortRangeRec {
    pub low: u16,
    pub high: u16,
}

pub type COwampPortRange = OWPPortRangeRec;

#[repr(C)]
pub struct OWPSessionHeaderRec {
    pub header: OWPBoolean,
    pub version: u32,
    pub rec_size: u32,
    pub twoway: OWPBoolean,
    pub finished: OWPSessionFinishedType,
    pub next_seqno: u32,
    pub num_skiprecs: u32,
    pub num_datarecs: u32,
    pub oset_skiprecs: off_t,
    pub oset_datarecs: off_t,
    pub sbuf: stat,
    pub ipvn: u8,
    pub addr_len: socklen_t,
    pub addr_sender: sockaddr_storage,
    pub addr_receiver: sockaddr_storage,
    pub conf_sender: OWPBoolean,
    pub conf_receiver: OWPBoolean,
    pub sid: OWPSID,
    pub test_spec: OWPTestSpec,
}

pub fn sev_to_i32(s: crate::context::ErrSeverity) -> OWPErrSeverity {
    s as c_int
}

pub fn sev_from_i32(v: OWPErrSeverity) -> crate::context::ErrSeverity {
    match v {
        3 => crate::context::ErrSeverity::Fatal,
        4 => crate::context::ErrSeverity::Warning,
        6 => crate::context::ErrSeverity::Info,
        7 => crate::context::ErrSeverity::Debug,
        _ => crate::context::ErrSeverity::Ok,
    }
}
