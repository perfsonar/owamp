//! Port von `exp-vector/vector.c`.
//!
//! Für festen Seed den millionsten Exponential-Zufallswert ausgeben.
//! AES-CTR bevorzugt `owamp::rijndael_alg_fst` (äquivalent zur Ref-AES-128).
//! Erwartungswert: C mit `key.blockLen = 128` → `67CD2024` (Kommentar in
//! `vector.c` ist veraltet).

use owamp_exp_vector::{millionth_via_fst, parse_hex_seed, VECTOR_EXPECTED, VECTOR_SEED_HEX};
use std::process::ExitCode;

fn print64(x: u64) {
    // C: `fprintf(stdout, "%llX \n", x);`
    println!("{x:X} ");
}

fn main() -> ExitCode {
    let seed = parse_hex_seed(VECTOR_SEED_HEX);
    let num = millionth_via_fst(&seed);
    print64(num);

    if num != VECTOR_EXPECTED {
        eprintln!("vector: expected {VECTOR_EXPECTED:X}, got {num:X}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}
