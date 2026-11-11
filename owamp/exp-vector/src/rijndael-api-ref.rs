//! Port von `exp-vector/rijndael-api-ref.c` / `.h` (Reference ANSI C API, v2.1).

#![allow(clippy::needless_range_loop)]
#![allow(dead_code)]

use crate::rijndael_alg_ref::{
    rijndael_decrypt, rijndael_decrypt_round, rijndael_encrypt, rijndael_encrypt_round,
    rijndael_key_sched, Word8, MAXBC, MAXKC, MAXROUNDS,
};

pub const DIR_ENCRYPT: u8 = 0;
pub const DIR_DECRYPT: u8 = 1;
pub const MODE_ECB: u8 = 1;
pub const MODE_CBC: u8 = 2;
pub const MODE_CFB1: u8 = 3;

pub const TRUE: i32 = 1;
pub const FALSE: i32 = 0;

pub const BITSPERBLOCK: i32 = 128;

pub const BAD_KEY_DIR: i32 = -1;
pub const BAD_KEY_MAT: i32 = -2;
pub const BAD_KEY_INSTANCE: i32 = -3;
pub const BAD_CIPHER_MODE: i32 = -4;
pub const BAD_CIPHER_STATE: i32 = -5;
pub const BAD_CIPHER_INSTANCE: i32 = -7;

pub const MAX_KEY_SIZE: usize = 64;
pub const MAX_IV_SIZE: usize = (BITSPERBLOCK as usize) / 8;

pub type Byte = u8;

/// `keyInstance`
#[derive(Clone)]
pub struct KeyInstance {
    pub direction: Byte,
    pub key_len: i32,
    pub key_material: [u8; MAX_KEY_SIZE + 1],
    pub block_len: i32,
    pub key_sched: [[[Word8; MAXBC]; 4]; MAXROUNDS + 1],
}

impl Default for KeyInstance {
    fn default() -> Self {
        Self {
            direction: 0,
            key_len: 0,
            key_material: [0; MAX_KEY_SIZE + 1],
            block_len: BITSPERBLOCK,
            key_sched: [[[0; MAXBC]; 4]; MAXROUNDS + 1],
        }
    }
}

/// `cipherInstance`
#[derive(Clone)]
pub struct CipherInstance {
    pub mode: Byte,
    pub iv: [Byte; MAX_IV_SIZE],
    pub block_len: i32,
}

impl Default for CipherInstance {
    fn default() -> Self {
        Self {
            mode: 0,
            iv: [0; MAX_IV_SIZE],
            block_len: BITSPERBLOCK,
        }
    }
}

const fn parse_hex_nibble(t: u8) -> Option<u8> {
    match t {
        b'0'..=b'9' => Some(t - b'0'),
        b'a'..=b'f' => Some(t - b'a' + 10),
        b'A'..=b'F' => Some(t - b'A' + 10),
        _ => None,
    }
}

/// `makeKey`
pub fn make_key(
    key: &mut KeyInstance,
    direction: Byte,
    key_len: i32,
    key_material: Option<&[u8]>,
) -> i32 {
    if !(direction == DIR_ENCRYPT || direction == DIR_DECRYPT) {
        return BAD_KEY_DIR;
    }
    key.direction = direction;

    if !(key_len == 128 || key_len == 192 || key_len == 256) {
        return BAD_KEY_MAT;
    }
    key.key_len = key_len;

    if let Some(mat) = key_material {
        let n = (key_len / 4) as usize;
        let copy_len = n.min(mat.len()).min(MAX_KEY_SIZE);
        key.key_material[..copy_len].copy_from_slice(&mat[..copy_len]);
        if copy_len < MAX_KEY_SIZE + 1 {
            // C strncpy does not guarantee NUL if n chars copied without NUL;
            // leave remaining as-is / zero-init already.
        }
    }

    let mut k = [[0u8; MAXKC]; 4];
    for i in 0..(key.key_len / 8) as usize {
        let t0 = key.key_material[2 * i];
        let Some(hi) = parse_hex_nibble(t0) else {
            return BAD_KEY_MAT;
        };
        let mut j = i32::from(hi) << 4;

        let t1 = key.key_material[2 * i + 1];
        let Some(lo) = parse_hex_nibble(t1) else {
            return BAD_KEY_MAT;
        };
        j ^= i32::from(lo);

        k[i % 4][i / 4] = j as Word8;
    }

    rijndael_key_sched(&k, key.key_len, key.block_len, &mut key.key_sched);
    TRUE
}

/// `cipherInit`
pub fn cipher_init(cipher: &mut CipherInstance, mode: Byte, iv: Option<&[u8]>) -> i32 {
    if !(mode == MODE_ECB || mode == MODE_CBC || mode == MODE_CFB1) {
        return BAD_CIPHER_MODE;
    }
    cipher.mode = mode;

    if let Some(iv_hex) = iv {
        for i in 0..(cipher.block_len / 8) as usize {
            let t0 = iv_hex.get(2 * i).copied().unwrap_or(0);
            let Some(hi) = parse_hex_nibble(t0) else {
                return BAD_CIPHER_INSTANCE;
            };
            let mut j = i32::from(hi) << 4;

            let t1 = iv_hex.get(2 * i + 1).copied().unwrap_or(0);
            let Some(lo) = parse_hex_nibble(t1) else {
                return BAD_CIPHER_INSTANCE;
            };
            j ^= i32::from(lo);
            cipher.iv[i] = j as Byte;
        }
    }

    TRUE
}

/// `blockEncrypt`
pub fn block_encrypt(
    cipher: &CipherInstance,
    key: &KeyInstance,
    input: &[u8],
    input_len: i32,
    out_buffer: &mut [u8],
) -> i32 {
    if key.direction != DIR_ENCRYPT
        || !(key.key_len == 128 || key.key_len == 192 || key.key_len == 256)
    {
        return BAD_KEY_MAT;
    }
    if !(cipher.mode == MODE_ECB || cipher.mode == MODE_CBC || cipher.mode == MODE_CFB1)
        || !(cipher.block_len == 128 || cipher.block_len == 192 || cipher.block_len == 256)
    {
        return BAD_CIPHER_STATE;
    }

    let num_blocks = input_len / cipher.block_len;
    let block_bytes = (cipher.block_len / 8) as usize;
    let cols = (cipher.block_len / 32) as usize;

    match cipher.mode {
        MODE_ECB => {
            for i in 0..num_blocks as usize {
                let mut block = [[0u8; MAXBC]; 4];
                for j in 0..cols {
                    for t in 0..4 {
                        block[t][j] = input[block_bytes * i + 4 * j + t];
                    }
                }
                rijndael_encrypt(&mut block, key.key_len, cipher.block_len, &key.key_sched);
                for j in 0..cols {
                    for t in 0..4 {
                        out_buffer[block_bytes * i + 4 * j + t] = block[t][j];
                    }
                }
            }
        },
        MODE_CBC => {
            let mut block = [[0u8; MAXBC]; 4];
            for j in 0..cols {
                for t in 0..4 {
                    block[t][j] = cipher.iv[t + 4 * j];
                }
            }
            for i in 0..num_blocks as usize {
                for j in 0..cols {
                    for t in 0..4 {
                        block[t][j] ^= input[block_bytes * i + 4 * j + t];
                    }
                }
                rijndael_encrypt(&mut block, key.key_len, cipher.block_len, &key.key_sched);
                for j in 0..cols {
                    for t in 0..4 {
                        out_buffer[block_bytes * i + 4 * j + t] = block[t][j];
                    }
                }
            }
        },
        _ => return BAD_CIPHER_STATE,
    }

    num_blocks * cipher.block_len
}

/// `blockDecrypt`
pub fn block_decrypt(
    cipher: &CipherInstance,
    key: &KeyInstance,
    input: &[u8],
    input_len: i32,
    out_buffer: &mut [u8],
) -> i32 {
    if key.direction == DIR_ENCRYPT || cipher.block_len != key.block_len {
        return BAD_CIPHER_STATE;
    }
    if key.direction != DIR_DECRYPT
        || !(key.key_len == 128 || key.key_len == 192 || key.key_len == 256)
    {
        return BAD_KEY_MAT;
    }
    if !(cipher.mode == MODE_ECB || cipher.mode == MODE_CBC || cipher.mode == MODE_CFB1)
        || !(cipher.block_len == 128 || cipher.block_len == 192 || cipher.block_len == 256)
    {
        return BAD_CIPHER_STATE;
    }

    let num_blocks = input_len / cipher.block_len;
    let block_bytes = (cipher.block_len / 8) as usize;
    let cols = (cipher.block_len / 32) as usize;

    match cipher.mode {
        MODE_ECB => {
            for i in 0..num_blocks as usize {
                let mut block = [[0u8; MAXBC]; 4];
                for j in 0..cols {
                    for t in 0..4 {
                        block[t][j] = input[block_bytes * i + 4 * j + t];
                    }
                }
                rijndael_decrypt(&mut block, key.key_len, cipher.block_len, &key.key_sched);
                for j in 0..cols {
                    for t in 0..4 {
                        out_buffer[block_bytes * i + 4 * j + t] = block[t][j];
                    }
                }
            }
        },
        MODE_CBC => {
            let mut block = [[0u8; MAXBC]; 4];
            for j in 0..cols {
                for t in 0..4 {
                    block[t][j] = input[4 * j + t];
                }
            }
            rijndael_decrypt(&mut block, key.key_len, cipher.block_len, &key.key_sched);
            for j in 0..cols {
                for t in 0..4 {
                    out_buffer[4 * j + t] = block[t][j] ^ cipher.iv[t + 4 * j];
                }
            }
            for i in 1..num_blocks as usize {
                for j in 0..cols {
                    for t in 0..4 {
                        block[t][j] = input[block_bytes * i + 4 * j + t];
                    }
                }
                rijndael_decrypt(&mut block, key.key_len, cipher.block_len, &key.key_sched);
                for j in 0..cols {
                    for t in 0..4 {
                        out_buffer[block_bytes * i + 4 * j + t] =
                            block[t][j] ^ input[block_bytes * i + 4 * j + t - 4 * cols];
                    }
                }
            }
        },
        _ => return BAD_CIPHER_STATE,
    }

    num_blocks * cipher.block_len
}

/// `cipherUpdateRounds`
pub fn cipher_update_rounds(
    cipher: &CipherInstance,
    key: &KeyInstance,
    input: &[u8],
    _input_len: i32,
    out_buffer: &mut [u8],
    rounds: i32,
) -> i32 {
    if cipher.block_len != key.block_len {
        return BAD_CIPHER_STATE;
    }

    let cols = (cipher.block_len / 32) as usize;
    let mut block = [[0u8; MAXBC]; 4];
    for j in 0..cols {
        for t in 0..4 {
            block[t][j] = input[4 * j + t];
        }
    }

    match key.direction {
        DIR_ENCRYPT => {
            rijndael_encrypt_round(
                &mut block,
                key.key_len,
                cipher.block_len,
                &key.key_sched,
                rounds,
            );
        },
        DIR_DECRYPT => {
            rijndael_decrypt_round(
                &mut block,
                key.key_len,
                cipher.block_len,
                &key.key_sched,
                rounds,
            );
        },
        _ => return BAD_KEY_DIR,
    }

    for j in 0..cols {
        for t in 0..4 {
            out_buffer[4 * j + t] = block[t][j];
        }
    }
    TRUE
}
