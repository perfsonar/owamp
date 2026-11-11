//! Port von `owtvec.c` — AES-basierte Exponential-Deviates (OWAMP Appendix B).

#![allow(dead_code, unused_imports)]

use owamp::arithm64::{num64_to_double, ulong_to_num64};
use owamp::owamp::OwampNum64;
use owamp::schedule::{exp_context_create, exp_context_free, exp_context_next, num64_add};

#[test]
fn owtvec_appendix_b() {
    let seedvals = [
        "2872979303ab47eeac028dab3829dab2",
        "0102030405060708090a0b0c0d0e0f00",
        "deadbeefdeadbeefdeadbeefdeadbeef",
        "feed0feed1feed2feed3feed4feed5ab",
    ];
    let expected_sums = [
        "000f4479bd317381",
        "000f433686466a62",
        "000f416c8884d2d3",
        "000f3f0b4b416ec8",
    ];
    let nice = [1u32, 10, 100, 1_000, 100_000, 1_000_000];

    for (i, seed_hex) in seedvals.iter().enumerate() {
        let seed_bytes = hex::decode(seed_hex).expect("seed hex");
        let mut seed = [0u8; 16];
        seed.copy_from_slice(&seed_bytes);

        let mut exp = exp_context_create(&seed);
        eprintln!("SEED = 0x{seed_hex}");

        let mut n = 0usize;
        let mut sum = ulong_to_num64(0);
        for j in 1u32..=1_000_000 {
            let eval = exp_context_next(&mut exp);
            sum = num64_add(sum, eval);
            if n < nice.len() && j == nice[n] {
                let ve = format!("{:016x}", eval.0);
                let vs = format!("{:016x}", sum.0);
                eprintln!(
                    "EXP[{j}] = 0x{ve} ({})\tSUM[{j}] = 0x{vs} ({})",
                    num64_to_double(eval),
                    num64_to_double(sum)
                );
                n += 1;
            }
        }
        exp_context_free(exp);

        let sum_hex = format!("{:016x}", sum.0);
        eprintln!(
            "FINAL SUM[{i}]: 0x{sum_hex}, EXPECTED_SUM[{i}]: 0x{}",
            expected_sums[i]
        );
        assert_eq!(
            sum_hex, expected_sums[i],
            "sum validation error for seed {i}"
        );
        let _: OwampNum64 = sum;
        eprintln!();
    }
}
