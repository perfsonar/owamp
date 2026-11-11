//! Port von `bench/timesyscall.c` — misst die Dauer von `10_000_000`
//! `gettimeofday`-Aufrufen (bzw. optional `ntp_gettime` unter `TESTNTP`).

use std::io::{self, Write};
use std::mem::MaybeUninit;
use std::process::ExitCode;

fn gettimeofday() -> libc::timeval {
    let mut tv = MaybeUninit::<libc::timeval>::uninit();
    let rc = unsafe { libc::gettimeofday(tv.as_mut_ptr(), std::ptr::null_mut()) };
    assert_eq!(rc, 0, "gettimeofday failed");
    unsafe { tv.assume_init() }
}

fn main() -> ExitCode {
    // C: `#ifndef STA_NANO` → `!NANO`, sonst `NANO`.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // Linux headers expose STA_NANO when sys/timex.h is present.
        let _ = writeln!(io::stderr(), "NANO");
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        // macOS / BSD: STA_NANO typically absent in the same form as Linux.
        let _ = writeln!(io::stderr(), "!NANO");
    }

    let begin = gettimeofday();
    let mut i = 0i32;
    while i < 10_000_000 {
        // C default path: gettimeofday (TESTNTP would call ntp_gettime).
        let _val = gettimeofday();
        i += 1;
    }
    let mut end = gettimeofday();

    end.tv_sec -= begin.tv_sec;
    if begin.tv_usec > end.tv_usec {
        end.tv_sec -= 1;
        end.tv_usec += 1_000_000;
    }
    end.tv_usec -= begin.tv_usec;

    // C: `fprintf(stdout,"loop took:%u.%u\n",end.tv_sec,end.tv_usec);`
    println!("loop took:{}.{}", end.tv_sec as u32, end.tv_usec as u32);
    ExitCode::SUCCESS
}
