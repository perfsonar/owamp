//! Port von `exp-vector/rijndael-alg-ref.c` / `.h` (Reference ANSI C, v2.2).
//!
//! Public-domain reference implementation by Paulo Barreto / Vincent Rijmen.
//! Tables from `boxes-ref.dat`.

#![allow(clippy::needless_range_loop)]
#![allow(clippy::identity_op)]
#![allow(dead_code)]

/// `MAXBC` = 256/32
pub const MAXBC: usize = 8;
/// `MAXKC` = 256/32
pub const MAXKC: usize = 8;
/// `MAXROUNDS`
pub const MAXROUNDS: usize = 14;

pub type Word8 = u8;
pub type Word16 = u16;
pub type Word32 = u32;

static LOGTABLE: [u8; 256] = [
    0, 0, 25, 1, 50, 2, 26, 198, 75, 199, 27, 104, 51, 238, 223, 3, 100, 4, 224, 14, 52, 141, 129,
    239, 76, 113, 8, 200, 248, 105, 28, 193, 125, 194, 29, 181, 249, 185, 39, 106, 77, 228, 166,
    114, 154, 201, 9, 120, 101, 47, 138, 5, 33, 15, 225, 36, 18, 240, 130, 69, 53, 147, 218, 142,
    150, 143, 219, 189, 54, 208, 206, 148, 19, 92, 210, 241, 64, 70, 131, 56, 102, 221, 253, 48,
    191, 6, 139, 98, 179, 37, 226, 152, 34, 136, 145, 16, 126, 110, 72, 195, 163, 182, 30, 66, 58,
    107, 40, 84, 250, 133, 61, 186, 43, 121, 10, 21, 155, 159, 94, 202, 78, 212, 172, 229, 243,
    115, 167, 87, 175, 88, 168, 80, 244, 234, 214, 116, 79, 174, 233, 213, 231, 230, 173, 232, 44,
    215, 117, 122, 235, 22, 11, 245, 89, 203, 95, 176, 156, 169, 81, 160, 127, 12, 246, 111, 23,
    196, 73, 236, 216, 67, 31, 45, 164, 118, 123, 183, 204, 187, 62, 90, 251, 96, 177, 134, 59, 82,
    161, 108, 170, 85, 41, 157, 151, 178, 135, 144, 97, 190, 220, 252, 188, 149, 207, 205, 55, 63,
    91, 209, 83, 57, 132, 60, 65, 162, 109, 71, 20, 42, 158, 93, 86, 242, 211, 171, 68, 17, 146,
    217, 35, 32, 46, 137, 180, 124, 184, 38, 119, 153, 227, 165, 103, 74, 237, 222, 197, 49, 254,
    24, 13, 99, 140, 128, 192, 247, 112, 7,
];

static ALOGTABLE: [u8; 256] = [
    1, 3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19, 53, 95, 225, 56, 72, 216, 115,
    149, 164, 247, 2, 6, 10, 30, 34, 102, 170, 229, 52, 92, 228, 55, 89, 235, 38, 106, 190, 217,
    112, 144, 171, 230, 49, 83, 245, 4, 12, 20, 60, 68, 204, 79, 209, 104, 184, 211, 110, 178, 205,
    76, 212, 103, 169, 224, 59, 77, 215, 98, 166, 241, 8, 24, 40, 120, 136, 131, 158, 185, 208,
    107, 189, 220, 127, 129, 152, 179, 206, 73, 219, 118, 154, 181, 196, 87, 249, 16, 48, 80, 240,
    11, 29, 39, 105, 187, 214, 97, 163, 254, 25, 43, 125, 135, 146, 173, 236, 47, 113, 147, 174,
    233, 32, 96, 160, 251, 22, 58, 78, 210, 109, 183, 194, 93, 231, 50, 86, 250, 21, 63, 65, 195,
    94, 226, 61, 71, 201, 64, 192, 91, 237, 44, 116, 156, 191, 218, 117, 159, 186, 213, 100, 172,
    239, 42, 126, 130, 157, 188, 223, 122, 142, 137, 128, 155, 182, 193, 88, 232, 35, 101, 175,
    234, 37, 111, 177, 200, 67, 197, 84, 252, 31, 33, 99, 165, 244, 7, 9, 27, 45, 119, 153, 176,
    203, 70, 202, 69, 207, 74, 222, 121, 139, 134, 145, 168, 227, 62, 66, 198, 81, 243, 14, 18, 54,
    90, 238, 41, 123, 141, 140, 143, 138, 133, 148, 167, 242, 13, 23, 57, 75, 221, 124, 132, 151,
    162, 253, 28, 36, 108, 180, 199, 82, 246, 1,
];

static S: [u8; 256] = [
    99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125,
    250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204,
    52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235,
    39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0,
    237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133,
    69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16,
    255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129,
    79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92,
    194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234,
    101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138,
    112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105,
    217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65,
    153, 45, 15, 176, 84, 187, 22,
];

static SI: [u8; 256] = [
    82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251, 124, 227, 57, 130,
    155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203, 84, 123, 148, 50, 166, 194, 35, 61,
    238, 76, 149, 11, 66, 250, 195, 78, 8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109,
    139, 209, 37, 114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146, 108,
    112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132, 144, 216, 171, 0, 140,
    188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6, 208, 44, 30, 143, 202, 63, 15, 2, 193, 175,
    189, 3, 1, 19, 138, 107, 58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230,
    115, 150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110, 71, 241, 26,
    113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27, 252, 86, 62, 75, 198, 210, 121, 32,
    154, 219, 192, 254, 120, 205, 90, 244, 31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39,
    128, 236, 95, 96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239, 160,
    224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97, 23, 43, 4, 126, 186, 119,
    214, 38, 225, 105, 20, 99, 85, 33, 12, 125,
];

static RCON: [u8; 30] = [
    1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53,
    106, 212, 179, 125, 250, 239, 197, 145,
];

/// `shifts[SC][row][direction]` — SC = ((BC-4)>>1)
static SHIFTS: [[[u8; 2]; 4]; 3] = [
    [[0, 0], [1, 3], [2, 2], [3, 1]],
    [[0, 0], [1, 5], [2, 4], [3, 3]],
    [[0, 0], [1, 7], [3, 5], [4, 4]],
];

#[inline]
fn mul(a: u8, b: u8) -> u8 {
    if a != 0 && b != 0 {
        ALOGTABLE
            [((u16::from(LOGTABLE[a as usize]) + u16::from(LOGTABLE[b as usize])) % 255) as usize]
    } else {
        0
    }
}

fn add_round_key(a: &mut [[u8; MAXBC]; 4], rk: &[[u8; MAXBC]; 4], bc: usize) {
    for i in 0..4 {
        for j in 0..bc {
            a[i][j] ^= rk[i][j];
        }
    }
}

fn shift_rows(a: &mut [[u8; MAXBC]; 4], d: usize, bc: usize) {
    let sc = (bc - 4) >> 1;
    for i in 1..4 {
        let mut tmp = [0u8; MAXBC];
        for j in 0..bc {
            tmp[j] = a[i][(j + SHIFTS[sc][i][d] as usize) % bc];
        }
        a[i][..bc].copy_from_slice(&tmp[..bc]);
    }
}

fn substitution(a: &mut [[u8; MAXBC]; 4], box_: &[u8; 256], bc: usize) {
    for i in 0..4 {
        for j in 0..bc {
            a[i][j] = box_[a[i][j] as usize];
        }
    }
}

fn mix_columns(a: &mut [[u8; MAXBC]; 4], bc: usize) {
    let mut b = [[0u8; MAXBC]; 4];
    for j in 0..bc {
        for i in 0..4 {
            b[i][j] =
                mul(2, a[i][j]) ^ mul(3, a[(i + 1) % 4][j]) ^ a[(i + 2) % 4][j] ^ a[(i + 3) % 4][j];
        }
    }
    for i in 0..4 {
        for j in 0..bc {
            a[i][j] = b[i][j];
        }
    }
}

fn inv_mix_columns(a: &mut [[u8; MAXBC]; 4], bc: usize) {
    let mut b = [[0u8; MAXBC]; 4];
    for j in 0..bc {
        for i in 0..4 {
            b[i][j] = mul(0x0e, a[i][j])
                ^ mul(0x0b, a[(i + 1) % 4][j])
                ^ mul(0x0d, a[(i + 2) % 4][j])
                ^ mul(0x09, a[(i + 3) % 4][j]);
        }
    }
    for i in 0..4 {
        for j in 0..bc {
            a[i][j] = b[i][j];
        }
    }
}

const fn kc_bc_rounds(key_bits: i32, block_bits: i32) -> Result<(usize, usize, usize), i32> {
    let kc = match key_bits {
        128 => 4,
        192 => 6,
        256 => 8,
        _ => return Err(-1),
    };
    let bc = match block_bits {
        128 => 4,
        192 => 6,
        256 => 8,
        _ => return Err(-2),
    };
    let rounds = match if key_bits >= block_bits {
        key_bits
    } else {
        block_bits
    } {
        128 => 10,
        192 => 12,
        256 => 14,
        _ => return Err(-3),
    };
    Ok((kc, bc, rounds))
}

/// `rijndaelKeySched`
pub fn rijndael_key_sched(
    k: &[[u8; MAXKC]; 4],
    key_bits: i32,
    block_bits: i32,
    w: &mut [[[u8; MAXBC]; 4]; MAXROUNDS + 1],
) -> i32 {
    let (kc, bc, rounds) = match kc_bc_rounds(key_bits, block_bits) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let mut tk = [[0u8; MAXKC]; 4];
    for j in 0..kc {
        for i in 0..4 {
            tk[i][j] = k[i][j];
        }
    }

    let mut t = 0usize;
    let mut rconpointer = 0usize;
    let mut j = 0usize;
    while j < kc && t < (rounds + 1) * bc {
        for i in 0..4 {
            w[t / bc][i][t % bc] = tk[i][j];
        }
        j += 1;
        t += 1;
    }

    while t < (rounds + 1) * bc {
        for i in 0..4 {
            tk[i][0] ^= S[tk[(i + 1) % 4][kc - 1] as usize];
        }
        tk[0][0] ^= RCON[rconpointer];
        rconpointer += 1;

        if kc == 8 {
            for j in 1..(kc / 2) {
                for i in 0..4 {
                    tk[i][j] ^= tk[i][j - 1];
                }
            }
            for i in 0..4 {
                tk[i][kc / 2] ^= S[tk[i][kc / 2 - 1] as usize];
            }
            for j in (kc / 2 + 1)..kc {
                for i in 0..4 {
                    tk[i][j] ^= tk[i][j - 1];
                }
            }
        } else {
            for j in 1..kc {
                for i in 0..4 {
                    tk[i][j] ^= tk[i][j - 1];
                }
            }
        }

        j = 0;
        while j < kc && t < (rounds + 1) * bc {
            for i in 0..4 {
                w[t / bc][i][t % bc] = tk[i][j];
            }
            j += 1;
            t += 1;
        }
    }

    0
}

/// `rijndaelEncrypt`
pub fn rijndael_encrypt(
    a: &mut [[u8; MAXBC]; 4],
    key_bits: i32,
    block_bits: i32,
    rk: &[[[u8; MAXBC]; 4]; MAXROUNDS + 1],
) -> i32 {
    let (_kc, bc, rounds) = match kc_bc_rounds(key_bits, block_bits) {
        Ok(v) => v,
        Err(e) => return e,
    };

    add_round_key(a, &rk[0], bc);
    for r in 1..rounds {
        substitution(a, &S, bc);
        shift_rows(a, 0, bc);
        mix_columns(a, bc);
        add_round_key(a, &rk[r], bc);
    }
    substitution(a, &S, bc);
    shift_rows(a, 0, bc);
    add_round_key(a, &rk[rounds], bc);
    0
}

/// `rijndaelEncryptRound`
pub fn rijndael_encrypt_round(
    a: &mut [[u8; MAXBC]; 4],
    key_bits: i32,
    block_bits: i32,
    rk: &[[[u8; MAXBC]; 4]; MAXROUNDS + 1],
    mut rounds_req: i32,
) -> i32 {
    let (_kc, bc, rounds) = match kc_bc_rounds(key_bits, block_bits) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if rounds_req as usize > rounds {
        rounds_req = rounds as i32;
    }
    let rounds_req = rounds_req as usize;

    add_round_key(a, &rk[0], bc);
    let mut r = 1usize;
    while r <= rounds_req && r < rounds {
        substitution(a, &S, bc);
        shift_rows(a, 0, bc);
        mix_columns(a, bc);
        add_round_key(a, &rk[r], bc);
        r += 1;
    }
    if rounds_req == rounds {
        substitution(a, &S, bc);
        shift_rows(a, 0, bc);
        add_round_key(a, &rk[rounds], bc);
    }
    0
}

/// `rijndaelDecrypt`
pub fn rijndael_decrypt(
    a: &mut [[u8; MAXBC]; 4],
    key_bits: i32,
    block_bits: i32,
    rk: &[[[u8; MAXBC]; 4]; MAXROUNDS + 1],
) -> i32 {
    let (_kc, bc, rounds) = match kc_bc_rounds(key_bits, block_bits) {
        Ok(v) => v,
        Err(e) => return e,
    };

    add_round_key(a, &rk[rounds], bc);
    substitution(a, &SI, bc);
    shift_rows(a, 1, bc);

    for r in (1..rounds).rev() {
        add_round_key(a, &rk[r], bc);
        inv_mix_columns(a, bc);
        substitution(a, &SI, bc);
        shift_rows(a, 1, bc);
    }
    add_round_key(a, &rk[0], bc);
    0
}

/// `rijndaelDecryptRound`
pub fn rijndael_decrypt_round(
    a: &mut [[u8; MAXBC]; 4],
    key_bits: i32,
    block_bits: i32,
    rk: &[[[u8; MAXBC]; 4]; MAXROUNDS + 1],
    mut rounds_req: i32,
) -> i32 {
    let (_kc, bc, rounds) = match kc_bc_rounds(key_bits, block_bits) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if rounds_req as usize > rounds {
        rounds_req = rounds as i32;
    }
    let rounds_req = rounds_req as usize;

    add_round_key(a, &rk[rounds], bc);
    substitution(a, &SI, bc);
    shift_rows(a, 1, bc);

    for r in ((rounds_req + 1)..rounds).rev() {
        add_round_key(a, &rk[r], bc);
        inv_mix_columns(a, bc);
        substitution(a, &SI, bc);
        shift_rows(a, 1, bc);
    }
    if rounds_req == 0 {
        add_round_key(a, &rk[0], bc);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use owamp::rijndael_alg_fst;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn aes128_ecb_matches_fst_fips197() {
        // FIPS-197 Appendix B / C.1
        let key = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        let pt = hex_to_bytes("00112233445566778899aabbccddeeff");

        let mut k = [[0u8; MAXKC]; 4];
        for (i, &b) in key.iter().enumerate() {
            k[i % 4][i / 4] = b;
        }
        let mut rk = [[[0u8; MAXBC]; 4]; MAXROUNDS + 1];
        assert_eq!(rijndael_key_sched(&k, 128, 128, &mut rk), 0);

        let mut a = [[0u8; MAXBC]; 4];
        for (i, &b) in pt.iter().enumerate() {
            a[i % 4][i / 4] = b;
        }
        assert_eq!(rijndael_encrypt(&mut a, 128, 128, &rk), 0);
        let mut ct_ref = [0u8; 16];
        for i in 0..16 {
            ct_ref[i] = a[i % 4][i / 4];
        }

        let mut rk_fst = [0u32; rijndael_alg_fst::MAXRK];
        let nr = rijndael_alg_fst::rijndael_key_setup_enc(&mut rk_fst, &key, 128);
        let mut ct_fst = [0u8; 16];
        let mut pt_arr = [0u8; 16];
        pt_arr.copy_from_slice(&pt);
        rijndael_alg_fst::rijndael_encrypt(&rk_fst, nr, &pt_arr, &mut ct_fst);

        assert_eq!(ct_ref, ct_fst);
        let expected = hex_to_bytes("69c4e0d86a7b0430d8cdb78070b4c55a");
        assert_eq!(ct_ref.as_slice(), expected.as_slice());
    }
}
