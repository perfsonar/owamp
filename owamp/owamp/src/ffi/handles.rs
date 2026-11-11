//! Opaque C handles (`OWPContext*`, `I2Addr`, …).

#![allow(non_camel_case_types)]
#![allow(clippy::missing_safety_doc)]

use std::cell::RefCell;
use std::rc::Rc;

use crate::context::{Addr, Context, Control, ErrHandle};
use crate::schedule::{ExpContext, ScheduleContext};
use crate::stats::Stats;

pub type OWPContext = *mut Context;
pub type OWPControl = *mut Rc<RefCell<Control>>;
pub type OWPScheduleContext = *mut ScheduleContext;
pub type OWPExpContext = *mut ExpContext;
pub type OWPStats = *mut Stats;

/// Opaque I2util stand-in (owned by this library for drop-in package builds).
pub type I2Addr = *mut Addr;
pub type I2ErrHandle = *mut ErrHandle;

#[must_use]
pub fn ctx_into_ptr(ctx: Context) -> OWPContext {
    Box::into_raw(Box::new(ctx))
}

/// # Safety
/// `p` must be a valid pointer from [`ctx_into_ptr`].
#[must_use]
pub unsafe fn ctx_from_ptr<'a>(p: OWPContext) -> Option<&'a Context> {
    if p.is_null() {
        None
    } else {
        Some(unsafe { &*p })
    }
}

/// # Safety
/// `p` must be a valid pointer from [`ctx_into_ptr`].
#[must_use]
pub unsafe fn ctx_clone_from_ptr(p: OWPContext) -> Option<Context> {
    unsafe { ctx_from_ptr(p).cloned() }
}

/// # Safety
/// `p` must be exclusive and from [`ctx_into_ptr`].
pub unsafe fn free_ctx(p: OWPContext) {
    if !p.is_null() {
        drop(unsafe { Box::from_raw(p) });
    }
}

#[must_use]
pub fn control_into_ptr(rc: Rc<RefCell<Control>>) -> OWPControl {
    Box::into_raw(Box::new(rc))
}

/// # Safety
/// `p` must be a valid pointer from [`control_into_ptr`].
#[must_use]
pub unsafe fn control_from_ptr<'a>(p: OWPControl) -> Option<&'a Rc<RefCell<Control>>> {
    if p.is_null() {
        None
    } else {
        Some(unsafe { &*p })
    }
}

/// # Safety
/// `p` must be exclusive and from [`control_into_ptr`].
pub unsafe fn free_control(p: OWPControl) {
    if !p.is_null() {
        drop(unsafe { Box::from_raw(p) });
    }
}

#[must_use]
pub fn addr_into_ptr(addr: Addr) -> I2Addr {
    Box::into_raw(Box::new(addr))
}

/// # Safety
/// `p` must be a valid pointer from [`addr_into_ptr`].
#[must_use]
pub unsafe fn addr_from_ptr<'a>(p: I2Addr) -> Option<&'a Addr> {
    if p.is_null() {
        None
    } else {
        Some(unsafe { &*p })
    }
}

/// # Safety
/// `p` must be exclusive and from [`addr_into_ptr`].
pub unsafe fn free_addr(p: I2Addr) {
    if !p.is_null() {
        drop(unsafe { Box::from_raw(p) });
    }
}

#[must_use]
pub fn sched_into_ptr(s: ScheduleContext) -> OWPScheduleContext {
    Box::into_raw(Box::new(s))
}

/// # Safety
pub unsafe fn sched_from_ptr<'a>(p: OWPScheduleContext) -> Option<&'a mut ScheduleContext> {
    if p.is_null() {
        None
    } else {
        Some(unsafe { &mut *p })
    }
}

/// # Safety
pub unsafe fn free_sched(p: OWPScheduleContext) {
    if !p.is_null() {
        drop(unsafe { Box::from_raw(p) });
    }
}

#[must_use]
pub fn exp_into_ptr(e: ExpContext) -> OWPExpContext {
    Box::into_raw(Box::new(e))
}

/// # Safety
pub unsafe fn exp_from_ptr<'a>(p: OWPExpContext) -> Option<&'a mut ExpContext> {
    if p.is_null() {
        None
    } else {
        Some(unsafe { &mut *p })
    }
}

/// # Safety
pub unsafe fn free_exp(p: OWPExpContext) {
    if !p.is_null() {
        drop(unsafe { Box::from_raw(p) });
    }
}

#[must_use]
pub fn stats_into_ptr(s: Stats) -> OWPStats {
    Box::into_raw(Box::new(s))
}

/// # Safety
pub unsafe fn stats_from_ptr<'a>(p: OWPStats) -> Option<&'a mut Stats> {
    if p.is_null() {
        None
    } else {
        Some(unsafe { &mut *p })
    }
}

/// # Safety
pub unsafe fn free_stats(p: OWPStats) {
    if !p.is_null() {
        drop(unsafe { Box::from_raw(p) });
    }
}
