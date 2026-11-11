//! Port of `rijndael-test-fst.c` (AES Known-Answer / Monte-Carlo driver).
//!
//! C is a standalone program under `#define INTERMEDIATE_VALUE_KAT`. This module
//! exposes the same KAT/MCT logic as callable helpers plus `#[cfg(test)]` unit
//! tests that exercise [`crate::rijndael_alg_fst`] (and AES-128 parity with
//! [`crate::rijndael_api_fst`]) instead of writing NIST text files.
//!
//! Ported suites: Variable-Key KAT, Variable-Text KAT, Tables KAT,
//! Intermediate-Value KAT, FIPS vectors, ECB/CBC Monte Carlo (scaled + full
//! inner consistency checks).

#![allow(dead_code)]

use crate::config::INTERMEDIATE_VALUE_KAT;
use crate::rijndael_alg_fst::{
    rijndael_decrypt, rijndael_decrypt_round, rijndael_encrypt, rijndael_encrypt_round,
    rijndael_key_setup_dec, rijndael_key_setup_enc, MAXKB, MAXRK, RIJNDAEL_BLOCK_SIZE,
};

/// Submitter-String wie in C (`SUBMITTER`).
pub const SUBMITTER: &str = "Joan Daemen";

/// C `DIR_ENCRYPT`.
pub const DIR_ENCRYPT: u8 = 0;
/// C `DIR_DECRYPT`.
pub const DIR_DECRYPT: u8 = 1;

const KEY_SIZES: [i32; 3] = [128, 192, 256];

/// Hex-encode a block like C `blockPrint` (uppercase, no separators).
#[must_use]
pub fn block_hex(block: &[u8; RIJNDAEL_BLOCK_SIZE]) -> String {
    let mut s = String::with_capacity(32);
    for b in block {
        use std::fmt::Write;
        let _ = write!(s, "{b:02X}");
    }
    s
}

fn parse_key_hex(key_material: &str, key_bits: i32) -> [u8; MAXKB] {
    let need = (key_bits as usize) / 8;
    let bytes = hex::decode(key_material)
        .unwrap_or_else(|_| panic!("bad key material hex (keyBits={key_bits}): {key_material:?}"));
    assert_eq!(bytes.len(), need, "key material length");
    let mut out = [0u8; MAXKB];
    out[..need].copy_from_slice(&bytes);
    out
}

fn make_key(direction: u8, key_bits: i32, key_material: &str) -> (i32, [u32; MAXRK]) {
    let cipher_key = parse_key_hex(key_material, key_bits);
    let need = (key_bits as usize) / 8;
    let mut rk = [0u32; MAXRK];
    let nr = if direction == DIR_ENCRYPT {
        rijndael_key_setup_enc(&mut rk, &cipher_key[..need], key_bits)
    } else {
        rijndael_key_setup_dec(&mut rk, &cipher_key[..need], key_bits)
    };
    assert!(nr > 0, "makeKey failed for keyBits={key_bits}");
    (nr, rk)
}

fn ecb_encrypt(rk: &[u32], nr: i32, input: &[u8; 16], output: &mut [u8; 16]) {
    rijndael_encrypt(rk, nr, input, output);
}

fn ecb_decrypt(rk: &[u32], nr: i32, input: &[u8; 16], output: &mut [u8; 16]) {
    rijndael_decrypt(rk, nr, input, output);
}

/// AESAPI-style `cipherUpdateRounds` (ECB, one block).
fn cipher_update_rounds(
    direction: u8,
    rk: &[u32],
    nr: i32,
    input: &[u8; 16],
    output: &mut [u8; 16],
    rounds: i32,
) {
    const {
        assert!(INTERMEDIATE_VALUE_KAT);
    }
    *output = *input;
    if direction == DIR_ENCRYPT {
        rijndael_encrypt_round(rk, nr, output, rounds);
    } else {
        rijndael_decrypt_round(rk, nr, output, rounds);
    }
}

fn sequential_key_hex(key_bits: i32) -> String {
    let nbytes = (key_bits as usize) / 8;
    let mut s = String::with_capacity(nbytes * 2);
    for i in 0..nbytes {
        use std::fmt::Write;
        let _ = write!(s, "{i:02X}");
    }
    s
}

fn bin_key_to_hex(bin: &[u8], key_bits: i32) -> String {
    let nbytes = (key_bits as usize) / 8;
    let mut s = String::with_capacity(nbytes * 2);
    for b in &bin[..nbytes] {
        use std::fmt::Write;
        let _ = write!(s, "{b:02X}");
    }
    s
}

/// Variable-Key KAT (`rijndaelVKKAT`): walking-bit keys, PT=0, decrypt roundtrip.
#[must_use]
///
/// # Panics
///
/// Panics if an internal invariant from the C port is violated.
pub fn rijndael_vk_kat(key_bits: i32) -> Vec<[u8; 16]> {
    let hex_len = (key_bits as usize) / 4;
    let mut key_material = vec![b'0'; hex_len];
    let mut byte_val = b'8';
    let mut ciphertexts = Vec::with_capacity(key_bits as usize);

    for i in 0..key_bits as usize {
        key_material[i / 4] = byte_val;
        let key_str = std::str::from_utf8(&key_material).unwrap();
        let (nr_e, rk_e) = make_key(DIR_ENCRYPT, key_bits, key_str);
        let mut block = [0u8; 16];
        ecb_encrypt(&rk_e, nr_e, &[0u8; 16], &mut block);
        ciphertexts.push(block);

        let (nr_d, rk_d) = make_key(DIR_DECRYPT, key_bits, key_str);
        let mut plain = [0u8; 16];
        ecb_decrypt(&rk_d, nr_d, &block, &mut plain);
        assert_eq!(plain, [0u8; 16], "VKKAT decrypt roundtrip bit {i}");

        key_material[i / 4] = b'0';
        byte_val = match byte_val {
            b'8' => b'4',
            b'4' => b'2',
            b'2' => b'1',
            _ => b'8',
        };
    }
    assert_eq!(byte_val, b'8');
    ciphertexts
}

/// Variable-Text KAT (`rijndaelVTKAT`): walking-bit plaintext, all-zero key.
#[must_use]
///
/// # Panics
///
/// Panics if an internal invariant from the C port is violated.
pub fn rijndael_vt_kat(key_bits: i32) -> Vec<([u8; 16], [u8; 16])> {
    let hex_len = (key_bits as usize) / 4;
    let key_str = "0".repeat(hex_len);
    let (nr_e, rk_e) = make_key(DIR_ENCRYPT, key_bits, &key_str);
    let (nr_d, rk_d) = make_key(DIR_DECRYPT, key_bits, &key_str);
    let mut out = Vec::with_capacity(128);

    for i in 0..128 {
        let mut block = [0u8; 16];
        block[i / 8] |= 1 << (7 - (i % 8));
        let pt = block;
        let mut ct = [0u8; 16];
        ecb_encrypt(&rk_e, nr_e, &pt, &mut ct);

        let mut recovered = [0u8; 16];
        ecb_decrypt(&rk_d, nr_d, &ct, &mut recovered);
        assert_eq!(recovered, pt, "VTKAT roundtrip bit {i}");
        out.push((pt, ct));
    }
    out
}

/// One Tables-KAT vector: key hex + 16-byte block (PT for encrypt half, CT for decrypt).
#[derive(Clone, Debug)]
pub struct TableKatEntry {
    pub key_hex: String,
    pub block: [u8; 16],
}

/// Parse NIST-style `table.{128,192,256}` input used by C `rijndaelTKAT`.
#[must_use]
///
/// # Panics
///
/// Panics if an internal invariant from the C port is violated.
pub fn parse_table_kat(table: &str, key_bits: i32) -> Vec<TableKatEntry> {
    let key_chars = (key_bits as usize) / 4;
    let mut entries = Vec::with_capacity(128);
    for line in table.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        assert!(
            line.len() >= key_chars + 1 + 16 * 3 - 1,
            "table line too short for keyBits={key_bits}: {line:?}"
        );
        let key_hex = line[..key_chars].to_string();
        let rest = line[key_chars..].trim_start();
        let mut block = [0u8; 16];
        let mut parts = rest.split_whitespace();
        for b in &mut block {
            let p = parts.next().expect("table PT/CT byte");
            *b = u8::from_str_radix(p, 16).expect("table hex byte");
        }
        assert!(parts.next().is_none(), "extra bytes on table line");
        entries.push(TableKatEntry { key_hex, block });
    }
    assert_eq!(entries.len(), 128, "expected 128 table vectors");
    entries
}

/// Tables KAT (`rijndaelTKAT`): first 64 encrypt, next 64 decrypt; verify roundtrips.
#[must_use]
///
/// # Panics
///
/// Panics if an internal invariant from the C port is violated.
pub fn rijndael_t_kat(entries: &[TableKatEntry], key_bits: i32) -> Vec<[u8; 16]> {
    assert_eq!(entries.len(), 128);
    let mut results = Vec::with_capacity(128);

    for (i, e) in entries.iter().enumerate().take(64) {
        let (nr_e, rk_e) = make_key(DIR_ENCRYPT, key_bits, &e.key_hex);
        let (nr_d, rk_d) = make_key(DIR_DECRYPT, key_bits, &e.key_hex);
        let mut ct = [0u8; 16];
        ecb_encrypt(&rk_e, nr_e, &e.block, &mut ct);
        let mut pt = [0u8; 16];
        ecb_decrypt(&rk_d, nr_d, &ct, &mut pt);
        assert_eq!(pt, e.block, "TKAT encrypt roundtrip I={}", i + 1);
        results.push(ct);
    }

    for (i, e) in entries.iter().enumerate().skip(64) {
        let (nr_d, rk_d) = make_key(DIR_DECRYPT, key_bits, &e.key_hex);
        let (nr_e, rk_e) = make_key(DIR_ENCRYPT, key_bits, &e.key_hex);
        let mut pt = [0u8; 16];
        ecb_decrypt(&rk_d, nr_d, &e.block, &mut pt);
        let mut ct = [0u8; 16];
        ecb_encrypt(&rk_e, nr_e, &pt, &mut ct);
        assert_eq!(ct, e.block, "TKAT decrypt roundtrip I={}", i + 1);
        results.push(pt);
    }
    results
}

/// Intermediate-value record for one key size.
#[derive(Clone, Debug)]
pub struct IvKatResult {
    pub key_bits: i32,
    pub key_hex: String,
    pub pt: [u8; 16],
    pub ct: [u8; 16],
    pub enc_intermediate: Vec<[u8; 16]>,
    pub dec_intermediate: Vec<[u8; 16]>,
}

/// Intermediate Value KAT (`rijndaelIVKAT`).
#[must_use]
///
/// # Panics
///
/// Panics if an internal invariant from the C port is violated.
pub fn rijndael_iv_kat(key_bits: i32) -> IvKatResult {
    const {
        assert!(INTERMEDIATE_VALUE_KAT);
    }
    let key_hex = sequential_key_hex(key_bits);
    let mut pt = [0u8; 16];
    for (i, b) in pt.iter_mut().enumerate() {
        *b = i as u8;
    }

    let (nr_e, rk_e) = make_key(DIR_ENCRYPT, key_bits, &key_hex);
    let mut enc_intermediate = Vec::new();
    for i in 1..nr_e {
        let mut ct = [0u8; 16];
        cipher_update_rounds(DIR_ENCRYPT, &rk_e, nr_e, &pt, &mut ct, i);
        enc_intermediate.push(ct);
    }
    let mut ct = [0u8; 16];
    cipher_update_rounds(DIR_ENCRYPT, &rk_e, nr_e, &pt, &mut ct, nr_e);

    // Full encrypt must match Nr-round update.
    let mut ct_full = [0u8; 16];
    ecb_encrypt(&rk_e, nr_e, &pt, &mut ct_full);
    assert_eq!(ct, ct_full, "IVKAT final CT vs full encrypt");

    let (nr_d, rk_d) = make_key(DIR_DECRYPT, key_bits, &key_hex);
    let mut dec_intermediate = Vec::new();
    for i in 1..nr_d {
        let mut out = [0u8; 16];
        cipher_update_rounds(DIR_DECRYPT, &rk_d, nr_d, &ct, &mut out, i);
        dec_intermediate.push(out);
    }
    let mut pt_out = [0u8; 16];
    cipher_update_rounds(DIR_DECRYPT, &rk_d, nr_d, &ct, &mut pt_out, nr_d);
    assert_eq!(pt_out, pt, "IVKAT final PT recovery");

    IvKatResult {
        key_bits,
        key_hex,
        pt,
        ct,
        enc_intermediate,
        dec_intermediate,
    }
}

/// FIPS-style vectors as in C `makeFIPSTestVectors` (key 00.., PT 001122..eeff).
#[derive(Clone, Debug)]
pub struct FipsKatResult {
    pub key_bits: i32,
    pub key_hex: String,
    pub pt: [u8; 16],
    pub ct: [u8; 16],
    pub enc_round_keys: Vec<[u8; 16]>,
    pub dec_round_keys: Vec<[u8; 16]>,
    pub enc_intermediate: Vec<[u8; 16]>,
    pub dec_intermediate: Vec<[u8; 16]>,
}

fn round_key_bytes(rk: &[u32], r: usize) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..4 {
        let w = rk[4 * r + i];
        out[4 * i] = (w >> 24) as u8;
        out[4 * i + 1] = (w >> 16) as u8;
        out[4 * i + 2] = (w >> 8) as u8;
        out[4 * i + 3] = w as u8;
    }
    out
}

/// Build FIPS test vectors for one key size (`makeFIPSTestVectors` body).
#[must_use]
///
/// # Panics
///
/// Panics if an internal invariant from the C port is violated.
pub fn make_fips_test_vectors(key_bits: i32) -> FipsKatResult {
    const {
        assert!(INTERMEDIATE_VALUE_KAT);
    }
    let key_hex = sequential_key_hex(key_bits);
    let mut pt = [0u8; 16];
    for (i, b) in pt.iter_mut().enumerate() {
        *b = ((i as u8) << 4) | (i as u8);
    }

    let (nr_e, rk_e) = make_key(DIR_ENCRYPT, key_bits, &key_hex);
    let enc_round_keys: Vec<_> = (0..=nr_e as usize)
        .map(|r| round_key_bytes(&rk_e, r))
        .collect();
    let mut enc_intermediate = Vec::new();
    for i in 1..nr_e {
        let mut ct = [0u8; 16];
        cipher_update_rounds(DIR_ENCRYPT, &rk_e, nr_e, &pt, &mut ct, i);
        enc_intermediate.push(ct);
    }
    let mut ct = [0u8; 16];
    cipher_update_rounds(DIR_ENCRYPT, &rk_e, nr_e, &pt, &mut ct, nr_e);

    let (nr_d, rk_d) = make_key(DIR_DECRYPT, key_bits, &key_hex);
    let dec_round_keys: Vec<_> = (0..=nr_d as usize)
        .map(|r| round_key_bytes(&rk_d, r))
        .collect();
    let mut dec_intermediate = Vec::new();
    for i in 1..nr_d {
        let mut out = [0u8; 16];
        cipher_update_rounds(DIR_DECRYPT, &rk_d, nr_d, &ct, &mut out, i);
        dec_intermediate.push(out);
    }
    let mut pt_out = [0u8; 16];
    cipher_update_rounds(DIR_DECRYPT, &rk_d, nr_d, &ct, &mut pt_out, nr_d);
    assert_eq!(pt_out, pt);

    FipsKatResult {
        key_bits,
        key_hex,
        pt,
        ct,
        enc_round_keys,
        dec_round_keys,
        enc_intermediate,
        dec_intermediate,
    }
}

fn mct_update_key(bin_key: &mut [u8], key_bits: i32, in_block: &[u8; 16], out_block: &[u8; 16]) {
    match key_bits {
        128 => {
            for j in 0..16 {
                bin_key[j] ^= out_block[j];
            }
        },
        192 => {
            for j in 0..8 {
                bin_key[j] ^= in_block[j + 8];
            }
            for j in 0..16 {
                bin_key[j + 8] ^= out_block[j];
            }
        },
        256 => {
            for j in 0..16 {
                bin_key[j] ^= in_block[j];
            }
            for j in 0..16 {
                bin_key[j + 16] ^= out_block[j];
            }
        },
        _ => panic!("bad keyBits"),
    }
}

fn mct_update_key_cbc(
    bin_key: &mut [u8],
    key_bits: i32,
    direction: u8,
    in_block: &[u8; 16],
    out_block: &[u8; 16],
    cv: &[u8; 16],
) {
    match key_bits {
        128 => {
            for j in 0..16 {
                bin_key[j] ^= out_block[j];
            }
        },
        192 => {
            for j in 0..8 {
                if direction == DIR_ENCRYPT {
                    bin_key[j] ^= in_block[j + 8];
                } else {
                    bin_key[j] ^= cv[j + 8];
                }
            }
            for j in 0..16 {
                bin_key[j + 8] ^= out_block[j];
            }
        },
        256 => {
            for j in 0..16 {
                if direction == DIR_ENCRYPT {
                    bin_key[j] ^= in_block[j];
                } else {
                    bin_key[j] ^= cv[j];
                }
            }
            for j in 0..16 {
                bin_key[j + 16] ^= out_block[j];
            }
        },
        _ => panic!("bad keyBits"),
    }
}

/// One ECB-MCT outer iteration result (KEY / PT-or-CT / CT-or-PT).
#[derive(Clone, Debug)]
pub struct MctRecord {
    pub key_hex: String,
    pub input: [u8; 16],
    pub output: [u8; 16],
}

/// ECB Monte Carlo (`rijndaelECB_MCT`). C uses 400×10000; tests may scale down.
#[must_use]
pub fn rijndael_ecb_mct(
    key_bits: i32,
    direction: u8,
    outer: usize,
    inner: usize,
) -> Vec<MctRecord> {
    let mut out_block = [0u8; 16];
    let mut bin_key = [0u8; MAXKB];
    let mut records = Vec::with_capacity(outer);

    for _ in 0..outer {
        let key_hex = bin_key_to_hex(&bin_key, key_bits);
        let (nr, rk) = make_key(direction, key_bits, &key_hex);
        let input = out_block;
        let mut in_block = [0u8; 16];
        if direction == DIR_ENCRYPT {
            for _ in 0..inner {
                in_block = out_block;
                ecb_encrypt(&rk, nr, &in_block, &mut out_block);
            }
        } else {
            for _ in 0..inner {
                in_block = out_block;
                ecb_decrypt(&rk, nr, &in_block, &mut out_block);
            }
        }
        records.push(MctRecord {
            key_hex,
            input,
            output: out_block,
        });
        mct_update_key(&mut bin_key, key_bits, &in_block, &out_block);
    }
    records
}

/// CBC Monte Carlo (`rijndaelCBC_MCT`). Note: C still calls `cipherInit(MODE_ECB)`
/// and manually XORs the chaining value — same algorithm here.
#[must_use]
pub fn rijndael_cbc_mct(
    key_bits: i32,
    direction: u8,
    outer: usize,
    inner: usize,
) -> Vec<MctRecord> {
    let mut cv = [0u8; 16];
    let mut in_block = [0u8; 16];
    let mut out_block = [0u8; 16];
    let mut bin_key = [0u8; MAXKB];
    let mut records = Vec::with_capacity(outer);

    for _ in 0..outer {
        let key_hex = bin_key_to_hex(&bin_key, key_bits);
        let (nr, rk) = make_key(direction, key_bits, &key_hex);
        // C prints IV=cv and PT/CT=inBlock before the loop (both directions).
        let printed_in = in_block;

        if direction == DIR_ENCRYPT {
            for _ in 0..inner {
                for t in 0..16 {
                    in_block[t] ^= cv[t];
                }
                ecb_encrypt(&rk, nr, &in_block, &mut out_block);
                in_block = cv;
                cv = out_block;
            }
        } else {
            for _ in 0..inner {
                ecb_decrypt(&rk, nr, &in_block, &mut out_block);
                for t in 0..16 {
                    out_block[t] ^= cv[t];
                }
                cv = in_block;
                in_block = out_block;
            }
        }

        records.push(MctRecord {
            key_hex,
            input: printed_in,
            output: out_block,
        });
        mct_update_key_cbc(
            &mut bin_key,
            key_bits,
            direction,
            &in_block,
            &out_block,
            &cv,
        );
    }
    records
}

/// Run all KATs that do not need external table files.
pub fn make_kats_without_tables() {
    for &bits in &KEY_SIZES {
        let _ = rijndael_vk_kat(bits);
        let _ = rijndael_vt_kat(bits);
        let _ = rijndael_iv_kat(bits);
        let _ = make_fips_test_vectors(bits);
    }
}

/// `makeKATs` — C writes NIST text files; Rust runs in-memory KATs.
pub fn make_kats(_vk_file: &str, _vt_file: &str, _tbl_file: &str, _iv_file: &str) {
    make_kats_without_tables();
}

/// `makeMCTs` — scaled Monte-Carlo for all key sizes (in-memory).
pub fn make_mcts(
    _ecb_enc_file: &str,
    _ecb_dec_file: &str,
    _cbc_enc_file: &str,
    _cbc_dec_file: &str,
) {
    for &bits in &KEY_SIZES {
        let _ = rijndael_ecb_mct(bits, DIR_ENCRYPT, 2, 32);
        let _ = rijndael_ecb_mct(bits, DIR_DECRYPT, 2, 32);
        let _ = rijndael_cbc_mct(bits, DIR_ENCRYPT, 2, 32);
        let _ = rijndael_cbc_mct(bits, DIR_DECRYPT, 2, 32);
    }
}

/// `rijndaelSpeed` — micro-timing of key setup + encrypt/decrypt (no printf).
#[must_use]
pub fn rijndael_speed(key_bits: i32) -> (u64, u64, u64, u64) {
    use std::time::Instant;
    const ITERATIONS: u32 = 10_000;
    let cipher_key = [0u8; 32];
    let mut pt = [0u8; 16];
    let mut ct = [0u8; 16];
    let mut rk = [0u32; MAXRK];

    let t0 = Instant::now();
    let mut nr = 0i32;
    for _ in 0..ITERATIONS {
        nr = rijndael_key_setup_enc(&mut rk, &cipher_key, key_bits);
    }
    let enc_sched = t0.elapsed().as_nanos() as u64;

    let t1 = Instant::now();
    for _ in 0..ITERATIONS {
        rijndael_encrypt(&rk, nr, &pt, &mut ct);
    }
    let enc = t1.elapsed().as_nanos() as u64;

    let t2 = Instant::now();
    for _ in 0..ITERATIONS {
        nr = rijndael_key_setup_dec(&mut rk, &cipher_key, key_bits);
    }
    let dec_sched = t2.elapsed().as_nanos() as u64;

    let t3 = Instant::now();
    for _ in 0..ITERATIONS {
        rijndael_decrypt(&rk, nr, &ct, &mut pt);
    }
    let dec = t3.elapsed().as_nanos() as u64;

    (enc_sched, enc, dec_sched, dec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rijndael_api_fst::AesKey;

    const TABLE_128: &str = include_str!("../testdata/table.128");
    const TABLE_192: &str = include_str!("../testdata/table.192");
    const TABLE_256: &str = include_str!("../testdata/table.256");

    #[test]
    fn intermediate_value_kat_flag_enabled() {
        const {
            assert!(INTERMEDIATE_VALUE_KAT);
        }
    }

    #[test]
    fn variable_key_kat_all_sizes() {
        for &bits in &KEY_SIZES {
            let cts = rijndael_vk_kat(bits);
            assert_eq!(cts.len(), bits as usize);
            // Distinct walking-bit keys should not all collapse to one CT.
            assert!(cts.iter().any(|c| *c != cts[0]) || bits == 0);
        }
    }

    #[test]
    fn variable_text_kat_all_sizes() {
        for &bits in &KEY_SIZES {
            let pairs = rijndael_vt_kat(bits);
            assert_eq!(pairs.len(), 128);
        }
    }

    #[test]
    fn tables_kat_all_sizes() {
        let cases = [(128, TABLE_128), (192, TABLE_192), (256, TABLE_256)];
        for (bits, table) in cases {
            let entries = parse_table_kat(table, bits);
            let results = rijndael_t_kat(&entries, bits);
            assert_eq!(results.len(), 128);
        }
    }

    #[test]
    fn intermediate_value_kat_all_sizes() {
        for &bits in &KEY_SIZES {
            let iv = rijndael_iv_kat(bits);
            // Nr is 10/12/14 → intermediates 9/11/13
            let nr = match bits {
                128 => 10,
                192 => 12,
                256 => 14,
                _ => unreachable!(),
            };
            assert_eq!(iv.enc_intermediate.len(), (nr - 1) as usize);
            assert_eq!(iv.dec_intermediate.len(), (nr - 1) as usize);
        }
    }

    #[test]
    fn fips_test_vectors_match_known_aes() {
        // FIPS-197 Appendix C ciphertext for sequential key / 001122..eeff PT.
        let expect = [
            (128, "69C4E0D86A7B0430D8CDB78070B4C55A"),
            (192, "DDA97CA4864CDFE06EAF70A0EC0D7191"),
            (256, "8EA2B7CA516745BFEAFC49904B496089"),
        ];
        for &(bits, ct_hex) in &expect {
            let f = make_fips_test_vectors(bits);
            assert_eq!(block_hex(&f.ct), ct_hex);
            assert_eq!(block_hex(&f.pt), "00112233445566778899AABBCCDDEEFF");
        }
    }

    #[test]
    fn ecb_mct_scaled_encrypt_decrypt_consistency() {
        // Scaled Monte Carlo: chained encrypts then matching decrypts recover PT.
        for &bits in &KEY_SIZES {
            let outer = 3usize;
            let inner = 50usize;
            let mut block = [0u8; 16];
            let key_hex = sequential_key_hex(bits);
            let (nr_e, rk_e) = make_key(DIR_ENCRYPT, bits, &key_hex);
            let (nr_d, rk_d) = make_key(DIR_DECRYPT, bits, &key_hex);
            let start = block;
            for _ in 0..outer {
                for _ in 0..inner {
                    let inp = block;
                    ecb_encrypt(&rk_e, nr_e, &inp, &mut block);
                }
            }
            for _ in 0..outer {
                for _ in 0..inner {
                    let inp = block;
                    ecb_decrypt(&rk_d, nr_d, &inp, &mut block);
                }
            }
            assert_eq!(block, start, "ECB MCT-style chain AES-{bits}");
        }

        // Also exercise the MCT key-update driver briefly.
        for &bits in &KEY_SIZES {
            let enc = rijndael_ecb_mct(bits, DIR_ENCRYPT, 2, 32);
            assert_eq!(enc.len(), 2);
            let dec = rijndael_ecb_mct(bits, DIR_DECRYPT, 2, 32);
            assert_eq!(dec.len(), 2);
        }
    }

    #[test]
    fn cbc_mct_scaled_runs() {
        for &bits in &KEY_SIZES {
            let enc = rijndael_cbc_mct(bits, DIR_ENCRYPT, 2, 32);
            assert_eq!(enc.len(), 2);
            let dec = rijndael_cbc_mct(bits, DIR_DECRYPT, 2, 32);
            assert_eq!(dec.len(), 2);
        }
    }

    #[test]
    fn api_fst_aes128_matches_alg_vk_sample() {
        // OWAMP `rijndael_api_fst` is AES-128-only; spot-check against alg-fst.
        let cts = rijndael_vk_kat(128);
        let mut key_material = vec![b'0'; 32];
        key_material[0] = b'8'; // first VKKAT key
        let key_str = std::str::from_utf8(&key_material).unwrap();
        let api = AesKey::from_hex(key_str).expect("api makeKey");
        let mut ct = [0u8; 16];
        api.encrypt_ecb_block(&[0u8; 16], &mut ct);
        assert_eq!(ct, cts[0]);
    }

    #[test]
    fn make_kats_smoke() {
        make_kats_without_tables();
    }
}
