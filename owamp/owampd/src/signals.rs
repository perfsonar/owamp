//! Signal-Flags analog zu `owpd_exit` / `owpd_int` / `owpd_chld` / `owpd_alrm` in `owampd.c`.
//!
//! SIGHUP/USR1/USR2 setzen wie in C `owpd_exit` (kein Config-Reload — der Daemon
//! beendet sich graceful; ein Supervisor kann neu starten).

use std::ptr::addr_of;
use std::sync::atomic::{AtomicBool, Ordering};

static EXIT: AtomicBool = AtomicBool::new(false);
static INT: AtomicBool = AtomicBool::new(false);
static CHLD: AtomicBool = AtomicBool::new(false);
static ALRM: AtomicBool = AtomicBool::new(false);
static INTR: AtomicBool = AtomicBool::new(false);

/// C `owpd_intr` — mutable int written from the signal handler so API helpers
/// that take `retn_on_intr: Option<&i32>` observe interrupts during `poll`.
static mut OWPD_INTR: i32 = 0;

pub fn should_exit() -> bool {
    EXIT.load(Ordering::SeqCst)
}

pub fn got_int() -> bool {
    INT.load(Ordering::SeqCst)
}

pub fn got_chld() -> bool {
    CHLD.load(Ordering::SeqCst)
}

pub fn got_alarm() -> bool {
    ALRM.load(Ordering::SeqCst)
}

pub fn got_intr() -> bool {
    INTR.load(Ordering::SeqCst)
}

pub fn clear_chld() {
    CHLD.store(false, Ordering::SeqCst);
}

pub fn clear_alarm() {
    ALRM.store(false, Ordering::SeqCst);
}

/// Clear `owpd_intr` (Atomic + C-style int) at the start of a request / wait.
pub fn clear_intr() {
    INTR.store(false, Ordering::SeqCst);
    // SAFETY: only written here and in the signal handler (single int store).
    unsafe {
        OWPD_INTR = 0;
    }
}

/// Force `owpd_intr = 1` (parent/child stop without raising a signal).
pub fn set_intr() {
    INTR.store(true, Ordering::SeqCst);
    unsafe {
        OWPD_INTR = 1;
    }
}

/// C: `owpd_intr = owpd_alrm = owpd_chld = 0` before each control request.
pub fn reset_request_flags() {
    clear_intr();
    clear_alarm();
    clear_chld();
}

/// Borrow of the C-compatible interrupt flag for `retn_on_intr`.
#[must_use]
pub fn intr_i32_ref() -> &'static i32 {
    // SAFETY: object has static lifetime; readers only observe 0/1.
    unsafe { &*addr_of!(OWPD_INTR) }
}

pub fn request_exit() {
    EXIT.store(true, Ordering::SeqCst);
}

extern "C" fn signal_catch(signo: libc::c_int) {
    match signo {
        libc::SIGINT => {
            INT.store(true, Ordering::SeqCst);
            EXIT.store(true, Ordering::SeqCst);
        },
        // C: SIGHUP/USR1/USR2/TERM all set owpd_exit (no in-process reload).
        libc::SIGTERM | libc::SIGHUP | libc::SIGUSR1 | libc::SIGUSR2 => {
            EXIT.store(true, Ordering::SeqCst);
        },
        libc::SIGCHLD => {
            CHLD.store(true, Ordering::SeqCst);
        },
        libc::SIGALRM => {
            ALRM.store(true, Ordering::SeqCst);
        },
        _ => {},
    }
    INTR.store(true, Ordering::SeqCst);
    // SAFETY: async-signal-safe store of a single int (mirrors C owpd_intr=1).
    unsafe {
        OWPD_INTR = 1;
    }
}

/// Installiert SIGPIPE=IGN und Catcher für INT/TERM/HUP/CHLD/ALRM/USR1/USR2.
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn install() -> std::io::Result<()> {
    unsafe {
        let mut ign: libc::sigaction = std::mem::zeroed();
        ign.sa_sigaction = libc::SIG_IGN;
        ign.sa_flags = 0;
        libc::sigemptyset(&mut ign.sa_mask);
        if libc::sigaction(libc::SIGPIPE, &ign, std::ptr::null_mut()) != 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut set: libc::sigaction = std::mem::zeroed();
        set.sa_sigaction = signal_catch as *const () as usize;
        set.sa_flags = 0;
        libc::sigemptyset(&mut set.sa_mask);

        for sig in [
            libc::SIGTERM,
            libc::SIGUSR1,
            libc::SIGUSR2,
            libc::SIGINT,
            libc::SIGHUP,
            libc::SIGCHLD,
            libc::SIGALRM,
        ] {
            if libc::sigaction(sig, &set, std::ptr::null_mut()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_request_flags_clears_intr_i32() {
        unsafe {
            OWPD_INTR = 1;
        }
        INTR.store(true, Ordering::SeqCst);
        ALRM.store(true, Ordering::SeqCst);
        CHLD.store(true, Ordering::SeqCst);
        reset_request_flags();
        assert!(!got_intr());
        assert!(!got_alarm());
        assert!(!got_chld());
        assert_eq!(*intr_i32_ref(), 0);
    }

    #[test]
    fn hup_term_usr_are_exit_not_reload() {
        // Documented C behaviour: these only flip exit; no reload hook exists.
        EXIT.store(false, Ordering::SeqCst);
        signal_catch(libc::SIGHUP);
        assert!(should_exit());
        assert_eq!(*intr_i32_ref(), 1);
        EXIT.store(false, Ordering::SeqCst);
        clear_intr();
    }
}
