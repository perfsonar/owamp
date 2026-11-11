//! Port von `bench/timeintervals.c` — Histogramm der Abstände zwischen
//! aufeinanderfolgenden `gettimeofday`-Aufrufen.

#![allow(unused_assignments)] // C überschreibt min/max nach der Schätzung hart.

use std::io::{self, Write};
use std::mem::MaybeUninit;
use std::process::ExitCode;

fn gettimeofday() -> libc::timeval {
    let mut tv = MaybeUninit::<libc::timeval>::uninit();
    let rc = unsafe { libc::gettimeofday(tv.as_mut_ptr(), std::ptr::null_mut()) };
    assert_eq!(rc, 0, "gettimeofday failed");
    unsafe { tv.assume_init() }
}

const fn delta_usec(curr: &libc::timeval, prev: &libc::timeval) -> Option<u32> {
    let mut val = (curr.tv_sec - prev.tv_sec) as u32;
    if val > 1 {
        return None;
    }
    val = val.wrapping_mul(1_000_000);
    val = val.wrapping_add(curr.tv_usec as u32);
    val = val.wrapping_sub(prev.tv_usec as u32);
    Some(val)
}

fn main() -> ExitCode {
    let mut buckets = [0u32; 64];
    let mut ts = [libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    }; 2];
    let mut under_min = 0u32;
    let mut over_max = 0u32;

    /*
     * First do a "short" test that should take ~10 seconds to
     * get an estimate of max/min to determine bucket ranges.
     */
    let mut curr: usize = 0;
    let mut prev: usize = 1;
    let mut min: u32 = !0;
    let mut max: u32 = 0;

    ts[prev] = gettimeofday();
    for _ in 0..2_000_000u32 {
        ts[curr] = gettimeofday();
        let Some(val) = delta_usec(&ts[curr], &ts[prev]) else {
            let _ = writeln!(io::stderr(), "val difference too huge!");
            return ExitCode::from(1);
        };
        if val > max {
            max = val;
        }
        if val < min {
            min = val;
        }
        prev = curr;
        curr = (curr + 1) % 2;
    }

    assert!(max > min);
    let mut tmp = max - min;
    // C: `tmp *= 0.05;` then `max += tmp; min *= 0.9;`
    tmp = (f64::from(tmp) * 0.05) as u32;
    max = max.wrapping_add(tmp);
    min = (f64::from(min) * 0.9) as u32;

    // C hard-codes the bucket range after the estimate:
    min = 0;
    max = 63;

    /*
     * compute range for actual bucketing.
     * nbuckets == 64 == 2^6
     */
    tmp = (max - min) >> 6;
    let mut i = 0u32;
    while tmp != 0 {
        i += 1;
        tmp >>= 1;
    }
    tmp = i;
    max = min.wrapping_add(1u32 << (6 + tmp));

    println!("# min={min} usec, max={max} usec");
    println!("# Loosing {tmp} bits of precision from bucketing");

    /*
     * Now do a real test - about 5 min's or 60000000 samples
     */
    curr = 0;
    prev = 1;
    ts[prev] = gettimeofday();
    for _ in 0..60_000_000u32 {
        ts[curr] = gettimeofday();
        let Some(val) = delta_usec(&ts[curr], &ts[prev]) else {
            let _ = writeln!(io::stderr(), "Real test!: val difference too huge!");
            return ExitCode::from(1);
        };

        if val > max {
            over_max += 1;
        } else if val < min {
            under_min += 1;
        } else {
            buckets[((val - min) >> tmp) as usize] += 1;
        }

        prev = curr;
        curr = (curr + 1) % 2;
    }

    println!("# min_bucket={min}\n# max_bucket={max}");
    println!("# under_min={under_min}\n# over_max={over_max}\n");
    println!("# Distribution follows: bucketn\tbucketc\tdelay(usec)\t");

    println!("<{}\t{}\t<{}", 0, under_min, min);
    for i in 0..64u32 {
        println!("{i}\t{}\t{}", buckets[i as usize], min + (i << tmp));
    }
    println!(">{}\t{}\t>{}", 64, over_max, max);

    ExitCode::SUCCESS
}
