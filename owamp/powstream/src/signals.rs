//! Signal handling — port of `sig_catch` / `sig_check` in `powstream.c`.

use std::sync::atomic::{AtomicI32, Ordering};

use tracing::{error, info};

pub static POW_RESET: AtomicI32 = AtomicI32::new(0);
pub static POW_EXIT: AtomicI32 = AtomicI32::new(0);
pub static POW_INTR: AtomicI32 = AtomicI32::new(0);
/// Holds unexpected signal number; `SIGCONT` (19 on many platforms) means "none".
pub static POW_ERROR: AtomicI32 = AtomicI32::new(libc::SIGCONT);

/// Raw pointer to the interrupt flag for `OWPInterruptIO` / `stop_sessions` (C `&pow_intr`).
pub fn intr_ptr() -> *mut i32 {
    POW_INTR.as_ptr()
}

/// Borrow the interrupt flag for library calls that take `Option<&i32>`.
///
/// # Safety
/// Callers must not hold the reference across code that can re-enter signal
/// handling that also mutates `POW_INTR` in a conflicting way; matching C,
/// the library only reads the value.
pub fn intr_ref() -> &'static i32 {
    // SAFETY: AtomicI32 has the same representation as i32; as_ptr is stable.
    unsafe { &*POW_INTR.as_ptr() }
}

extern "C" fn sig_catch(signo: libc::c_int) {
    match signo {
        libc::SIGINT | libc::SIGTERM => {
            POW_EXIT.fetch_add(1, Ordering::SeqCst);
            POW_INTR.fetch_add(1, Ordering::SeqCst);
        },
        libc::SIGHUP => {
            POW_RESET.fetch_add(1, Ordering::SeqCst);
            POW_INTR.fetch_add(1, Ordering::SeqCst);
        },
        _ => {
            POW_ERROR.store(signo, Ordering::SeqCst);
        },
    }
}

pub fn install_handlers() -> std::io::Result<()> {
    unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = libc::SIG_IGN;
        libc::sigemptyset(&mut act.sa_mask);
        act.sa_flags = 0;
        if libc::sigaction(libc::SIGUSR1, &act, std::ptr::null_mut()) != 0
            || libc::sigaction(libc::SIGUSR2, &act, std::ptr::null_mut()) != 0
        {
            return Err(std::io::Error::last_os_error());
        }

        act.sa_sigaction = sig_catch as *const () as usize;
        if libc::sigaction(libc::SIGTERM, &act, std::ptr::null_mut()) != 0
            || libc::sigaction(libc::SIGINT, &act, std::ptr::null_mut()) != 0
            || libc::sigaction(libc::SIGHUP, &act, std::ptr::null_mut()) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Returns `true` when SIGHUP requested a reconnect (after closing sessions).
pub fn sig_check(close_sessions: impl FnOnce()) -> bool {
    let err = POW_ERROR.load(Ordering::SeqCst);
    if err != libc::SIGCONT {
        error!("sig_check({err}): UNEXPECTED SIGNAL NUMBER");
        std::process::exit(1);
    }

    if POW_EXIT.load(Ordering::SeqCst) != 0 || POW_RESET.load(Ordering::SeqCst) != 0 {
        // Allow file I/O to complete; a second signal will interrupt again.
        POW_INTR.store(0, Ordering::SeqCst);
        close_sessions();
    }
    if POW_EXIT.load(Ordering::SeqCst) != 0 {
        info!("SIGTERM/SIGINT Caught: Exiting.");
        std::process::exit(0);
    }
    if POW_RESET.load(Ordering::SeqCst) != 0 {
        POW_RESET.store(0, Ordering::SeqCst);
        POW_INTR.store(0, Ordering::SeqCst);
        info!("SIGHUP: Re-opening connections.");
        return true;
    }
    false
}

pub fn interrupted() -> bool {
    POW_INTR.load(Ordering::SeqCst) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sig_check_idle_is_false() {
        POW_EXIT.store(0, Ordering::SeqCst);
        POW_RESET.store(0, Ordering::SeqCst);
        POW_INTR.store(0, Ordering::SeqCst);
        POW_ERROR.store(libc::SIGCONT, Ordering::SeqCst);
        assert!(!sig_check(|| {}));
    }

    #[test]
    fn sighup_clears_reset_and_returns_true() {
        POW_EXIT.store(0, Ordering::SeqCst);
        POW_RESET.store(1, Ordering::SeqCst);
        POW_INTR.store(1, Ordering::SeqCst);
        POW_ERROR.store(libc::SIGCONT, Ordering::SeqCst);
        let mut closed = false;
        assert!(sig_check(|| {
            closed = true;
        }));
        assert!(closed);
        assert_eq!(POW_RESET.load(Ordering::SeqCst), 0);
        assert_eq!(POW_INTR.load(Ordering::SeqCst), 0);
    }
}
