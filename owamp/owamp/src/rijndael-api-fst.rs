//! OWAMP crypto — Rust replacement for `rijndael-api-fst` / `rijndael-alg-fst`.
//!
//! Adds HMAC-SHA1 and PBKDF2-HMAC-SHA1 as used by the control/test protocol
//! (`io.c`, `capi.c`, `sapi.c`, `endpoint.c`, `protocol.c`).
//!
//! OWAMP uses AES-128 in CBC mode with a mutable IV (updated after each call),
//! 16-byte blocks, and truncates HMAC-SHA1 digests to 16 bytes on the wire.
//!
//! Block cipher primitives with C round-key layout live in
//! [`crate::rijndael_alg_fst`]. This API module keeps using the `aes` crate for
//! CBC/HMAC helpers (same results); call alg-fst directly for KeySetup/Encrypt/
//! Decrypt parity with `rijndael-alg-fst.c`.

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::error::{OwampError, Result};
use crate::owampP::{
    OWP_DEFAULT_PBKDF2_COUNT, OWP_MODE_AUTHENTICATED, OWP_MODE_ENCRYPTED, OWP_RIJNDAEL_BLOCK_SIZE,
    OWP_SALT_SIZE, OWP_TOKEN_SIZE, TWP_MODE_MIXED,
};

type HmacSha1 = Hmac<Sha1>;

/// AES-128 block size (= `_OWP_RIJNDAEL_BLOCK_SIZE`).
pub const BLOCK_SIZE: usize = OWP_RIJNDAEL_BLOCK_SIZE;
/// `SetupResponse` token size (= `_OWP_TOKEN_SIZE`).
pub const TOKEN_SIZE: usize = OWP_TOKEN_SIZE;
/// PBKDF2 salt size (= `_OWP_SALT_SIZE`).
pub const SALT_SIZE: usize = OWP_SALT_SIZE;
/// Default PBKDF2 iteration count (= `_OWP_DEFAULT_PBKDF2_COUNT`).
pub const DEFAULT_PBKDF2_COUNT: u32 = OWP_DEFAULT_PBKDF2_COUNT;

/// AES session key length (128-bit).
pub const AES_KEY_SIZE: usize = 16;
/// Control/test HMAC key length (as stored on `OWPControl` / endpoint).
pub const HMAC_KEY_SIZE: usize = 32;
/// Full HMAC-SHA1 digest length.
pub const HMAC_SHA1_DIGEST_SIZE: usize = 20;
/// Truncated digest length used on the wire (one AES block).
pub const HMAC_TRUNC_SIZE: usize = BLOCK_SIZE;

/// Modes that authenticate/encrypt test packets (`OWP_MODE_DOCIPHER_TEST`).
pub const MODE_DOCIPHER_TEST: u32 = OWP_MODE_AUTHENTICATED | OWP_MODE_ENCRYPTED;
/// Modes that authenticate/encrypt control messages (`OWP_MODE_DOCIPHER_CNTRL`).
pub const MODE_DOCIPHER_CNTRL: u32 = MODE_DOCIPHER_TEST | TWP_MODE_MIXED;

#[inline]
#[must_use]
pub const fn mode_docipher_test(mode: u32) -> bool {
    (mode & MODE_DOCIPHER_TEST) != 0
}

#[inline]
#[must_use]
pub const fn mode_docipher_cntrl(mode: u32) -> bool {
    (mode & MODE_DOCIPHER_CNTRL) != 0
}

/// AES-128 key schedule wrapper (C `keyInstance`).
///
/// One instance supports both encrypt and decrypt (CBC helpers choose the
/// direction). Matches OWAMP usage where encrypt/decrypt keyInstances are
/// derived from the same 16-byte session key.
#[derive(Clone)]
pub struct AesKey {
    cipher: Aes128,
}

impl AesKey {
    /// Create a key from 16 raw bytes (`bytes2Key` / `_OWPMakeKey` / SID setup).
    #[must_use]
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant from the C port is violated.
    pub fn from_bytes(key: &[u8; AES_KEY_SIZE]) -> Self {
        Self {
            cipher: Aes128::new_from_slice(key).expect("AES-128 key length is fixed at 16"),
        }
    }

    /// Parse a 32-character hex string into an AES-128 key (`makeKey`).
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn from_hex(key_material: &str) -> Result<Self> {
        let bytes = parse_hex_exact(key_material, AES_KEY_SIZE)?;
        let mut key = [0u8; AES_KEY_SIZE];
        key.copy_from_slice(&bytes);
        Ok(Self::from_bytes(&key))
    }

    /// Single-block AES-128 ECB encrypt (used for test-session key derivation).
    pub fn encrypt_ecb_block(&self, input: &[u8; BLOCK_SIZE], output: &mut [u8; BLOCK_SIZE]) {
        let mut block = *aes::Block::from_slice(input);
        self.cipher.encrypt_block(&mut block);
        output.copy_from_slice(&block);
    }

    /// Single-block AES-128 ECB decrypt.
    pub fn decrypt_ecb_block(&self, input: &[u8; BLOCK_SIZE], output: &mut [u8; BLOCK_SIZE]) {
        let mut block = *aes::Block::from_slice(input);
        self.cipher.decrypt_block(&mut block);
        output.copy_from_slice(&block);
    }
}

/// Zero IV (OWAMP token encryption and authenticated-mode first block).
#[inline]
#[must_use]
pub const fn zero_iv() -> [u8; BLOCK_SIZE] {
    [0u8; BLOCK_SIZE]
}

/// Initialize a binary IV from optional hex (`cipherInit`).
///
/// `None` / empty clears the IV to zeros.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn cipher_init(hex_iv: Option<&str>) -> Result<[u8; BLOCK_SIZE]> {
    match hex_iv {
        None | Some("") => Ok(zero_iv()),
        Some(hex) => {
            let bytes = parse_hex_exact(hex, BLOCK_SIZE)?;
            let mut iv = [0u8; BLOCK_SIZE];
            iv.copy_from_slice(&bytes);
            Ok(iv)
        },
    }
}

/// AES-128 CBC encrypt of whole blocks; updates `iv` to the last ciphertext
/// block (C `blockEncrypt`). `input` length must be a multiple of 16.
///
/// Supports in-place encryption when `input` and `output` alias the same buffer.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn block_encrypt(
    iv: &mut [u8; BLOCK_SIZE],
    key: &AesKey,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize> {
    let n_bits = cbc_crypt(iv, key, input, output, true)?;
    Ok(n_bits)
}

/// AES-128 CBC decrypt of whole blocks; updates `iv` to the last ciphertext
/// block (C `blockDecrypt`). `input` length must be a multiple of 16.
///
/// Supports in-place decryption when `input` and `output` alias the same buffer.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn block_decrypt(
    iv: &mut [u8; BLOCK_SIZE],
    key: &AesKey,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize> {
    let n_bits = cbc_crypt(iv, key, input, output, false)?;
    Ok(n_bits)
}

/// Encrypt `num_blocks` AES blocks in CBC mode (`_OWPEncryptBlocks`).
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn encrypt_blocks(
    iv: &mut [u8; BLOCK_SIZE],
    key: &AesKey,
    input: &[u8],
    output: &mut [u8],
    num_blocks: usize,
) -> Result<()> {
    let need = num_blocks
        .checked_mul(BLOCK_SIZE)
        .ok_or_else(|| OwampError::Message("block count overflow".into()))?;
    if input.len() < need || output.len() < need {
        return Err(OwampError::Message(
            "encrypt_blocks: buffer shorter than num_blocks".into(),
        ));
    }
    let bits = block_encrypt(iv, key, &input[..need], &mut output[..need])?;
    if bits != need * 8 {
        return Err(OwampError::Message(
            "encrypt_blocks: unexpected bit length".into(),
        ));
    }
    Ok(())
}

/// Decrypt `num_blocks` AES blocks in CBC mode (`_OWPDecryptBlocks`).
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn decrypt_blocks(
    iv: &mut [u8; BLOCK_SIZE],
    key: &AesKey,
    input: &[u8],
    output: &mut [u8],
    num_blocks: usize,
) -> Result<()> {
    let need = num_blocks
        .checked_mul(BLOCK_SIZE)
        .ok_or_else(|| OwampError::Message("block count overflow".into()))?;
    if input.len() < need || output.len() < need {
        return Err(OwampError::Message(
            "decrypt_blocks: buffer shorter than num_blocks".into(),
        ));
    }
    let bits = block_decrypt(iv, key, &input[..need], &mut output[..need])?;
    if bits != need * 8 {
        return Err(OwampError::Message(
            "decrypt_blocks: unexpected bit length".into(),
        ));
    }
    Ok(())
}

/// PBKDF2-HMAC-SHA1 → 16-byte AES key (as in `OWPEncryptToken` / `OWPDecryptToken`).
#[must_use]
pub fn derive_aes_key_pbkdf2(
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    count: u32,
) -> [u8; AES_KEY_SIZE] {
    let rounds = if count == 0 {
        DEFAULT_PBKDF2_COUNT
    } else {
        count
    };
    let mut dk = [0u8; AES_KEY_SIZE];
    pbkdf2::pbkdf2_hmac::<Sha1>(password, salt, rounds, &mut dk);
    dk
}

/// Encrypt the 64-byte `SetupResponse` token
/// (`AES-CBC, IV=0, key=PBKDF2-HMAC-SHA1(pf, salt, count)`).
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn encrypt_token(
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    count: u32,
    token_in: &[u8; TOKEN_SIZE],
    token_out: &mut [u8; TOKEN_SIZE],
) -> Result<()> {
    let dk = derive_aes_key_pbkdf2(password, salt, count);
    let key = AesKey::from_bytes(&dk);
    let mut iv = zero_iv();
    let bits = block_encrypt(&mut iv, &key, token_in, token_out)?;
    if bits != TOKEN_SIZE * 8 {
        return Err(OwampError::Message("encrypt_token failed".into()));
    }
    Ok(())
}

/// Decrypt the 64-byte `SetupResponse` token.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn decrypt_token(
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    count: u32,
    token_in: &[u8; TOKEN_SIZE],
    token_out: &mut [u8; TOKEN_SIZE],
) -> Result<()> {
    let dk = derive_aes_key_pbkdf2(password, salt, count);
    let key = AesKey::from_bytes(&dk);
    let mut iv = zero_iv();
    let bits = block_decrypt(&mut iv, &key, token_in, token_out)?;
    if bits != TOKEN_SIZE * 8 {
        return Err(OwampError::Message("decrypt_token failed".into()));
    }
    Ok(())
}

/// Build plaintext token layout: `challenge(16) || aes_session_key(16) || hmac_key(32)`.
#[must_use]
pub fn build_token_plaintext(
    challenge: &[u8; BLOCK_SIZE],
    aes_session_key: &[u8; AES_KEY_SIZE],
    hmac_key: &[u8; HMAC_KEY_SIZE],
) -> [u8; TOKEN_SIZE] {
    let mut token = [0u8; TOKEN_SIZE];
    token[..16].copy_from_slice(challenge);
    token[16..32].copy_from_slice(aes_session_key);
    token[32..64].copy_from_slice(hmac_key);
    token
}

/// Split a decrypted token into challenge / AES session key / HMAC key.
#[must_use]
pub fn split_token_plaintext(
    token: &[u8; TOKEN_SIZE],
) -> ([u8; BLOCK_SIZE], [u8; AES_KEY_SIZE], [u8; HMAC_KEY_SIZE]) {
    let mut challenge = [0u8; BLOCK_SIZE];
    let mut aes_session_key = [0u8; AES_KEY_SIZE];
    let mut hmac_key = [0u8; HMAC_KEY_SIZE];
    challenge.copy_from_slice(&token[..16]);
    aes_session_key.copy_from_slice(&token[16..32]);
    hmac_key.copy_from_slice(&token[32..64]);
    (challenge, aes_session_key, hmac_key)
}

/// Derive test-session AES key bytes: `AES-ECB(SID, control_aes_session_key)`
/// (RFC 4656 §4.1 / `endpoint.c`).
#[must_use]
pub fn derive_test_aes_key_bytes(
    sid: &[u8; AES_KEY_SIZE],
    control_aes_session_key: &[u8; AES_KEY_SIZE],
) -> [u8; AES_KEY_SIZE] {
    let sid_key = AesKey::from_bytes(sid);
    let mut out = [0u8; AES_KEY_SIZE];
    sid_key.encrypt_ecb_block(control_aes_session_key, &mut out);
    out
}

/// Derive test-session HMAC key: `AES-CBC(IV=0, key=SID, control_hmac_key)`.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn derive_test_hmac_key(
    sid: &[u8; AES_KEY_SIZE],
    control_hmac_key: &[u8; HMAC_KEY_SIZE],
) -> Result<[u8; HMAC_KEY_SIZE]> {
    let sid_key = AesKey::from_bytes(sid);
    let mut iv = zero_iv();
    let mut out = [0u8; HMAC_KEY_SIZE];
    let bits = block_encrypt(&mut iv, &sid_key, control_hmac_key, &mut out)?;
    if bits != HMAC_KEY_SIZE * 8 {
        return Err(OwampError::Message(
            "derive_test_hmac_key: blockEncrypt failed".into(),
        ));
    }
    Ok(out)
}

/// Incremental HMAC-SHA1 context (C `I2HMACSha1Context`).
///
/// After [`finish_truncated_clear`] / [`check_truncated_clear`] the context is
/// re-initialized with the same key, matching `_OWPSendHMACDigestClear` /
/// `_OWPRecvHMACCheckClear`.
pub struct HmacSha1Ctx {
    key: Vec<u8>,
    mac: HmacSha1,
}

impl HmacSha1Ctx {
    fn mac_from_key(key: &[u8]) -> Result<HmacSha1> {
        <HmacSha1 as Mac>::new_from_slice(key)
            .map_err(|_| OwampError::Message("invalid HMAC key length".into()))
    }

    /// Allocate and initialize with `key` (`I2HMACSha1Init`).
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn new(key: &[u8]) -> Result<Self> {
        Ok(Self {
            key: key.to_vec(),
            mac: Self::mac_from_key(key)?,
        })
    }

    /// Re-initialize with the stored key.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant from the C port is violated.
    pub fn reset(&mut self) {
        self.mac = Self::mac_from_key(&self.key).expect("HMAC key was already validated");
    }

    /// Replace the key and re-initialize.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn reinit(&mut self, key: &[u8]) -> Result<()> {
        self.mac = Self::mac_from_key(key)?;
        self.key = key.to_vec();
        Ok(())
    }

    /// Append raw bytes (`I2HMACSha1Append`).
    pub fn update(&mut self, data: &[u8]) {
        self.mac.update(data);
    }

    /// Append `num_blocks` AES blocks (`_OWPSendHMACAdd` / `_OWPRecvHMACAdd`).
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn add_blocks(&mut self, data: &[u8], num_blocks: usize) -> Result<()> {
        let need = num_blocks
            .checked_mul(BLOCK_SIZE)
            .ok_or_else(|| OwampError::Message("HMAC block count overflow".into()))?;
        if data.len() < need {
            return Err(OwampError::Message(
                "HMAC add_blocks: buffer shorter than num_blocks".into(),
            ));
        }
        self.update(&data[..need]);
        Ok(())
    }

    /// Finish into a full 20-byte digest and re-init for the next message.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant from the C port is violated.
    pub fn finish_full(&mut self) -> [u8; HMAC_SHA1_DIGEST_SIZE] {
        let mac = std::mem::replace(
            &mut self.mac,
            Self::mac_from_key(&self.key).expect("HMAC key was already validated"),
        );
        let result = mac.finalize().into_bytes();
        let mut out = [0u8; HMAC_SHA1_DIGEST_SIZE];
        out.copy_from_slice(&result);
        out
    }

    /// Finish, copy the first 16 bytes into `digest`, then clear/re-init
    /// (`_OWPSendHMACDigestClear`).
    pub fn finish_truncated_clear(&mut self, digest: &mut [u8; HMAC_TRUNC_SIZE]) {
        digest.fill(0);
        let full = self.finish_full();
        digest.copy_from_slice(&full[..HMAC_TRUNC_SIZE]);
        // finish_full already re-inited via replace
    }

    /// Compare the first 16 bytes of the digest to `check`, then clear/re-init
    /// (`_OWPRecvHMACCheckClear`). Returns `true` on match.
    pub fn check_truncated_clear(&mut self, check: &[u8; HMAC_TRUNC_SIZE]) -> bool {
        let full = self.finish_full();
        check[..] == full[..HMAC_TRUNC_SIZE]
    }
}

/// Control-session crypto state mirroring the encryption fields on `OWPControl`.
pub struct ControlCrypto {
    pub aes_session_key: [u8; AES_KEY_SIZE],
    pub encrypt_key: AesKey,
    pub decrypt_key: AesKey,
    pub write_iv: [u8; BLOCK_SIZE],
    pub read_iv: [u8; BLOCK_SIZE],
    pub hmac_key: [u8; HMAC_KEY_SIZE],
    pub send_hmac: HmacSha1Ctx,
    pub recv_hmac: HmacSha1Ctx,
}

impl ControlCrypto {
    /// Install the AES session key (`_OWPMakeKey`) and prepare HMAC contexts.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn from_session_keys(
        aes_session_key: [u8; AES_KEY_SIZE],
        hmac_key: [u8; HMAC_KEY_SIZE],
        write_iv: [u8; BLOCK_SIZE],
        read_iv: [u8; BLOCK_SIZE],
    ) -> Result<Self> {
        let encrypt_key = AesKey::from_bytes(&aes_session_key);
        let decrypt_key = AesKey::from_bytes(&aes_session_key);
        let send_hmac = HmacSha1Ctx::new(&hmac_key)?;
        let recv_hmac = HmacSha1Ctx::new(&hmac_key)?;
        Ok(Self {
            aes_session_key,
            encrypt_key,
            decrypt_key,
            write_iv,
            read_iv,
            hmac_key,
            send_hmac,
            recv_hmac,
        })
    }

    /// Generate random session material and encrypt the setup token (client side).
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn client_setup(
        password: &[u8],
        salt: &[u8; SALT_SIZE],
        count: u32,
        challenge: &[u8; BLOCK_SIZE],
    ) -> Result<(Self, [u8; TOKEN_SIZE])> {
        let mut aes_session_key = [0u8; AES_KEY_SIZE];
        let mut hmac_key = [0u8; HMAC_KEY_SIZE];
        let mut write_iv = [0u8; BLOCK_SIZE];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut aes_session_key);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut hmac_key);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut write_iv);

        let plaintext = build_token_plaintext(challenge, &aes_session_key, &hmac_key);
        let mut token = [0u8; TOKEN_SIZE];
        encrypt_token(password, salt, count, &plaintext, &mut token)?;

        let crypto = Self::from_session_keys(aes_session_key, hmac_key, write_iv, zero_iv())?;
        Ok((crypto, token))
    }

    /// Decrypt the setup token and install keys (server side).
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn server_setup(
        password: &[u8],
        salt: &[u8; SALT_SIZE],
        count: u32,
        expected_challenge: &[u8; BLOCK_SIZE],
        token_in: &[u8; TOKEN_SIZE],
        client_write_iv: [u8; BLOCK_SIZE],
    ) -> Result<Self> {
        let mut plaintext = [0u8; TOKEN_SIZE];
        decrypt_token(password, salt, count, token_in, &mut plaintext)?;
        let (challenge, aes_session_key, hmac_key) = split_token_plaintext(&plaintext);
        if &challenge != expected_challenge {
            return Err(OwampError::Message("Invalid challenge encryption".into()));
        }
        // Server readIV = client's writeIV; server writeIV starts at zero until
        // the first encrypted control write (callers may overwrite write_iv).
        Self::from_session_keys(aes_session_key, hmac_key, zero_iv(), client_write_iv)
    }

    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn encrypt_blocks(&mut self, buf: &mut [u8], num_blocks: usize) -> Result<()> {
        let need = num_blocks * BLOCK_SIZE;
        let tmp = buf[..need].to_vec();
        encrypt_blocks(
            &mut self.write_iv,
            &self.encrypt_key,
            &tmp,
            &mut buf[..need],
            num_blocks,
        )
    }

    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn decrypt_blocks(&mut self, buf: &mut [u8], num_blocks: usize) -> Result<()> {
        let need = num_blocks * BLOCK_SIZE;
        let tmp = buf[..need].to_vec();
        decrypt_blocks(
            &mut self.read_iv,
            &self.decrypt_key,
            &tmp,
            &mut buf[..need],
            num_blocks,
        )
    }

    /// Append plaintext/ciphertext blocks to the send HMAC when mode requires it.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn send_hmac_add(&mut self, mode: u32, data: &[u8], num_blocks: usize) -> Result<()> {
        if !mode_docipher_cntrl(mode) {
            return Ok(());
        }
        self.send_hmac.add_blocks(data, num_blocks)
    }

    pub fn send_hmac_digest_clear(&mut self, mode: u32, digest: &mut [u8; HMAC_TRUNC_SIZE]) {
        digest.fill(0);
        if !mode_docipher_cntrl(mode) {
            return;
        }
        self.send_hmac.finish_truncated_clear(digest);
    }

    ///
    /// # Errors
    ///
    /// Returns an error when the underlying IO or protocol operation fails.
    pub fn recv_hmac_add(&mut self, mode: u32, data: &[u8], num_blocks: usize) -> Result<()> {
        if !mode_docipher_cntrl(mode) {
            return Ok(());
        }
        self.recv_hmac.add_blocks(data, num_blocks)
    }

    pub fn recv_hmac_check_clear(&mut self, mode: u32, check: &[u8; HMAC_TRUNC_SIZE]) -> bool {
        if !mode_docipher_cntrl(mode) {
            return true;
        }
        self.recv_hmac.check_truncated_clear(check)
    }
}

fn parse_hex_exact(hex_str: &str, nbytes: usize) -> Result<Vec<u8>> {
    let hex_str = hex_str.trim();
    if hex_str.len() != nbytes * 2 {
        return Err(OwampError::Message(format!(
            "hex length {}: expected {}",
            hex_str.len(),
            nbytes * 2
        )));
    }
    hex::decode(hex_str).map_err(|e| OwampError::Message(format!("bad hex: {e}")))
}

fn cbc_crypt(
    iv: &mut [u8; BLOCK_SIZE],
    key: &AesKey,
    input: &[u8],
    output: &mut [u8],
    encrypt: bool,
) -> Result<usize> {
    if input.is_empty() {
        return Ok(0);
    }
    if !input.len().is_multiple_of(BLOCK_SIZE) {
        return Err(OwampError::Message(
            "CBC input length must be a multiple of 16".into(),
        ));
    }
    if output.len() < input.len() {
        return Err(OwampError::Message("CBC output buffer too small".into()));
    }

    let num_blocks = input.len() / BLOCK_SIZE;
    let mut prev = *iv;

    for i in 0..num_blocks {
        let off = i * BLOCK_SIZE;
        let in_block: [u8; BLOCK_SIZE] =
            input[off..off + BLOCK_SIZE].try_into().expect("block size");

        if encrypt {
            let mut block = [0u8; BLOCK_SIZE];
            for j in 0..BLOCK_SIZE {
                block[j] = in_block[j] ^ prev[j];
            }
            let mut aes_block = *aes::Block::from_slice(&block);
            key.cipher.encrypt_block(&mut aes_block);
            output[off..off + BLOCK_SIZE].copy_from_slice(&aes_block);
            prev.copy_from_slice(&aes_block);
        } else {
            let mut aes_block = *aes::Block::from_slice(&in_block);
            key.cipher.decrypt_block(&mut aes_block);
            for j in 0..BLOCK_SIZE {
                output[off + j] = aes_block[j] ^ prev[j];
            }
            prev = in_block;
        }
    }

    *iv = prev;
    Ok(num_blocks * BLOCK_SIZE * 8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owampP::OWP_MODE_OPEN;

    #[test]
    fn aes_cbc_roundtrip_single_block() {
        let key = AesKey::from_bytes(b"0123456789abcdef");
        let mut iv_enc = zero_iv();
        let mut iv_dec = zero_iv();
        let plain = *b"hello OWAMP blk!";
        let mut cipher = [0u8; BLOCK_SIZE];
        let mut out = [0u8; BLOCK_SIZE];

        block_encrypt(&mut iv_enc, &key, &plain, &mut cipher).unwrap();
        assert_ne!(cipher, plain);
        block_decrypt(&mut iv_dec, &key, &cipher, &mut out).unwrap();
        assert_eq!(out, plain);
        assert_eq!(iv_enc, cipher);
        assert_eq!(iv_dec, cipher);
    }

    #[test]
    fn aes_cbc_roundtrip_multi_block_inplace() {
        let key = AesKey::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        let mut buf = [0u8; 48];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = i as u8;
        }
        let original = buf;
        let mut iv = [1u8; BLOCK_SIZE];
        let mut iv2 = iv;

        encrypt_blocks(&mut iv, &key, &buf.clone(), &mut buf, 3).unwrap();
        assert_ne!(buf, original);
        decrypt_blocks(&mut iv2, &key, &buf.clone(), &mut buf, 3).unwrap();
        assert_eq!(buf, original);
    }

    #[test]
    fn pbkdf2_key_length_is_16() {
        let salt = [0x5au8; SALT_SIZE];
        let key = derive_aes_key_pbkdf2(b"shared-secret", &salt, DEFAULT_PBKDF2_COUNT);
        assert_eq!(key.len(), AES_KEY_SIZE);
        // Deterministic: same inputs → same key
        let key2 = derive_aes_key_pbkdf2(b"shared-secret", &salt, DEFAULT_PBKDF2_COUNT);
        assert_eq!(key, key2);
        let key3 = derive_aes_key_pbkdf2(b"other-secret", &salt, DEFAULT_PBKDF2_COUNT);
        assert_ne!(key, key3);
    }

    #[test]
    fn token_encrypt_decrypt_roundtrip() {
        let salt = *b"0123456789abcdef";
        let challenge = *b"challenge-block!";
        let aes_key = *b"aes-session-key!";
        let hmac_key = *b"hmac-key-32-bytes-..............";
        assert_eq!(hmac_key.len(), HMAC_KEY_SIZE);

        let plain = build_token_plaintext(&challenge, &aes_key, &hmac_key);
        let mut enc = [0u8; TOKEN_SIZE];
        let mut dec = [0u8; TOKEN_SIZE];
        encrypt_token(b"passphrase", &salt, DEFAULT_PBKDF2_COUNT, &plain, &mut enc).unwrap();
        assert_ne!(enc, plain);
        decrypt_token(b"passphrase", &salt, DEFAULT_PBKDF2_COUNT, &enc, &mut dec).unwrap();
        assert_eq!(dec, plain);

        let (c, a, h) = split_token_plaintext(&dec);
        assert_eq!(c, challenge);
        assert_eq!(a, aes_key);
        assert_eq!(h, hmac_key);
    }

    #[test]
    fn hmac_truncate_and_check() {
        let mut ctx = HmacSha1Ctx::new(b"0123456789abcdef0123456789abcdef").unwrap();
        ctx.add_blocks(&[0u8; 32], 2).unwrap();
        let mut digest = [0u8; HMAC_TRUNC_SIZE];
        ctx.finish_truncated_clear(&mut digest);
        assert!(digest.iter().any(|&b| b != 0));

        // After clear, context is ready for next message
        ctx.add_blocks(&[0u8; 32], 2).unwrap();
        assert!(ctx.check_truncated_clear(&digest));
    }

    #[test]
    fn test_session_key_derivation_lengths() {
        let sid = *b"session-id-16byt";
        let aes = *b"control-aes-key!";
        let hmac = *b"control-hmac-key-32-bytes.......";
        let test_aes = derive_test_aes_key_bytes(&sid, &aes);
        assert_eq!(test_aes.len(), AES_KEY_SIZE);
        assert_ne!(test_aes, aes);
        let test_hmac = derive_test_hmac_key(&sid, &hmac).unwrap();
        assert_eq!(test_hmac.len(), HMAC_KEY_SIZE);
        assert_ne!(test_hmac, hmac);
    }

    #[test]
    fn mode_helpers() {
        assert!(!mode_docipher_test(OWP_MODE_OPEN));
        assert!(mode_docipher_test(OWP_MODE_AUTHENTICATED));
        assert!(mode_docipher_test(OWP_MODE_ENCRYPTED));
        assert!(mode_docipher_cntrl(TWP_MODE_MIXED));
        assert!(!mode_docipher_cntrl(OWP_MODE_OPEN));
    }
}
