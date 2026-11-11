//! `owamp/exp-vector` — Dateinamen = C-Quellen.
//!
//! | Datei                   | C-Vorbild                    |
//! |-------------------------|------------------------------|
//! | `rijndael-alg-ref.rs`   | `rijndael-alg-ref.c` / `.h`  |
//! | `rijndael-api-ref.rs`   | `rijndael-api-ref.c` / `.h`  |
//! | `vector.rs`             | `vector.c` (Binary)          |

#![allow(non_snake_case)]

#[path = "rijndael-alg-ref.rs"]
pub mod rijndael_alg_ref;
#[path = "rijndael-api-ref.rs"]
pub mod rijndael_api_ref;

use owamp::rijndael_alg_fst::{self, MAXRK};

use rijndael_api_ref::{
    block_encrypt, make_key, CipherInstance, KeyInstance, DIR_ENCRYPT, MODE_ECB,
};

/// Millionster Draw für den Default-Seed (C `vector.c` mit `key.blockLen = 128`).
/// Der Kommentar `7F6EDDE6` in C ist veraltet; ungeinitialisiertes `blockLen`
/// machte das Original nicht-deterministisch.
pub const VECTOR_EXPECTED: u64 = 0x67cd_2024;

const MILLION: u64 = 1_000_000;
pub const NUM_DRAWS: u64 = MILLION;

const K: usize = 12;
const Q: [u64; K] = [
    0,
    0xb172_17f8,
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
const LN2: u64 = Q[1];
const MASK32: u64 = 0xffff_ffff;
const BIT31: u64 = 0x8000_0000;

/// Default seed hex string from `vector.c`.
pub const VECTOR_SEED_HEX: &str = "7a91b6d691c2d36d7a91b6d691c2d36d";

#[must_use]
///
/// # Panics
///
/// Panics if an internal invariant is violated.
pub fn parse_hex_seed(hex: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    assert_eq!(hex.len(), 32, "AES-128 seed must be 32 hex chars");
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex seed");
    }
    out
}

/// AES-128 ECB encrypt of one block via `owamp::rijndael_alg_fst`.
#[must_use]
pub fn aes128_encrypt_fst(key: &[u8; 16], pt: &[u8; 16]) -> [u8; 16] {
    let mut rk = [0u32; MAXRK];
    let nr = rijndael_alg_fst::rijndael_key_setup_enc(&mut rk, key, 128);
    let mut ct = [0u8; 16];
    rijndael_alg_fst::rijndael_encrypt(&rk, nr, pt, &mut ct);
    ct
}

/// `OWPulong2num64` from `vector.c`.
#[inline]
fn ulong2num64(a: u32) -> u64 {
    (1u64 << 32) * u64::from(a)
}

/// `OWPnum64_add` from `vector.c`.
#[inline]
const fn num64_add(x: u64, y: u64) -> u64 {
    x.wrapping_add(y)
}

/// `OWPnum64_mul` from `vector.c` — **intentionally** uses modulus `0xFFFFFFFF`
/// (= 2³²−1), matching the C experiment (not the fixed `arithm64` path).
fn num64_mul_vector_c(x: u64, y: u64) -> u64 {
    // Match historical C on ILP32: `unsigned long w[4]` is 32-bit, and the
    // radix is the buggy `0xFFFFFFFF` (= 2^32-1), not 2^32.
    const RADIX: u64 = 0xffff_ffff;

    let xdec = [x & 0xffff_ffff, x >> 32];
    let ydec = [y & 0xffff_ffff, y >> 32];
    let mut w = [0u32; 4];

    for j in 0..2 {
        let mut k = 0u64;
        let mut i = 0usize;
        loop {
            let t = k + xdec[i] * ydec[j] + u64::from(w[i + j]);
            w[i + j] = (t % RADIX) as u32;
            k = t / RADIX;
            i += 1;
            if i < 2 {
                continue;
            }
            w[j + 2] = k as u32; // truncate like 32-bit unsigned long
            break;
        }
    }

    let mut ret = u64::from(w[2]);
    ret <<= 32;
    u64::from(w[1]).wrapping_add(ret)
}

fn raw2num64(raw: &[u8]) -> u64 {
    (u64::from(raw[0]) << 24)
        + (u64::from(raw[1]) << 16)
        + (u64::from(raw[2]) << 8)
        + u64::from(raw[3])
}

type EncryptFn = Box<dyn FnMut(&[u8; 16], &mut [u8; 16])>;

/// Counter-mode RNG state shared by fst / ref backends.
struct RandCtx64 {
    counter: [u8; 16],
    out: [u8; 16],
    encrypt: EncryptFn,
}

fn unif_rand64(next: &mut RandCtx64) -> u64 {
    let res = next.counter[15] & 3;
    if res == 0 {
        (next.encrypt)(&next.counter, &mut next.out);
    }
    for j in (0..16).rev() {
        next.counter[j] = next.counter[j].wrapping_add(1);
        if next.counter[j] != 0 {
            break;
        }
    }
    raw2num64(&next.out[4 * res as usize..4 * res as usize + 4])
}

fn exp_rand64(next: &mut RandCtx64) -> u64 {
    let mut j = 0u32;
    let mut u = unif_rand64(next);
    while (u & BIT31) != 0 && j < 32 {
        u <<= 1;
        j += 1;
    }
    u <<= 1;
    u &= MASK32;
    let jj = ulong2num64(j);
    if u < LN2 {
        return num64_add(num64_mul_vector_c(jj, LN2), u);
    }
    let mut k = 2usize;
    while k < K {
        if u < Q[k] {
            break;
        }
        k += 1;
    }
    let mut v = unif_rand64(next);
    for _ in 2..=k {
        let tmp = unif_rand64(next);
        if tmp < v {
            v = tmp;
        }
    }
    num64_mul_vector_c(num64_add(jj, v), LN2)
}

fn run_draws(mut ctx: RandCtx64) -> u64 {
    let mut num = 0u64;
    for _ in 0..NUM_DRAWS {
        num = exp_rand64(&mut ctx);
    }
    num
}

/// Millionth draw with AES via `rijndael_alg_fst` (preferred) + C `vector.c` mul.
#[must_use]
pub fn millionth_via_fst(seed: &[u8; 16]) -> u64 {
    let key = *seed;
    let mut rk = [0u32; MAXRK];
    let nr = rijndael_alg_fst::rijndael_key_setup_enc(&mut rk, &key, 128);
    run_draws(RandCtx64 {
        counter: [0u8; 16],
        out: [0u8; 16],
        encrypt: Box::new(move |pt, out| {
            rijndael_alg_fst::rijndael_encrypt(&rk, nr, pt, out);
        }),
    })
}

/// Millionth draw with reference Rijndael API (literal C `vector.c` crypto path).
#[must_use]
///
/// # Panics
///
/// Panics if an internal invariant is violated.
pub fn millionth_via_ref(seed_hex: &str) -> u64 {
    let mut key = KeyInstance {
        block_len: 128,
        ..Default::default()
    };
    assert!(
        make_key(&mut key, DIR_ENCRYPT, 128, Some(seed_hex.as_bytes())) > 0,
        "makeKey failed"
    );
    let cipher = CipherInstance {
        mode: MODE_ECB,
        iv: [0; 16],
        block_len: 128,
    };
    run_draws(RandCtx64 {
        counter: [0u8; 16],
        out: [0u8; 16],
        encrypt: Box::new(move |pt, out| {
            let n = block_encrypt(&cipher, &key, pt, 128, out);
            assert!(n >= 0, "encryption failed");
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn millionth_draw_matches_c_comment() {
        let seed = parse_hex_seed(VECTOR_SEED_HEX);
        let fst = millionth_via_fst(&seed);
        assert_eq!(fst, VECTOR_EXPECTED, "fst path");
        let re = millionth_via_ref(VECTOR_SEED_HEX);
        assert_eq!(re, VECTOR_EXPECTED, "ref path");
        assert_eq!(fst, re);
    }

    #[test]
    fn fst_fips197_block() {
        let key = parse_hex_seed("000102030405060708090a0b0c0d0e0f");
        let pt = parse_hex_seed("00112233445566778899aabbccddeeff");
        let ct = aes128_encrypt_fst(&key, &pt);
        assert_eq!(ct, parse_hex_seed("69c4e0d86a7b0430d8cdb78070b4c55a"));
    }
}
