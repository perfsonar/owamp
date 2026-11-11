//! Control-channel block I/O — port of `io.c`.
//!
//! Provides AES-block send/receive (optionally CBC-encrypted), token
//! encrypt/decrypt via PBKDF2+AES-CBC, and send/recv HMAC helpers.
//! Low-level interruptible read/write mirrors I2util `I2Readni`/`I2Writeni`.

use std::io::{ErrorKind, Read, Write};
use std::os::fd::{FromRawFd, IntoRawFd, RawFd};

use crate::context::Control;
use crate::error::{OwampError, Result};
use crate::owampP::{
    OWP_MODE_DOCIPHER_CNTRL, OWP_RIJNDAEL_BLOCK_SIZE, OWP_SALT_SIZE, OWP_TOKEN_SIZE,
};
use crate::rijndael_api_fst::{self as rijndael, AesKey, HMAC_TRUNC_SIZE};

/// Whether `*retn_on_intr != 0` (C convention: non-zero → return on EINTR).
#[inline]
fn should_return_on_intr(retn_on_intr: Option<&i32>) -> bool {
    retn_on_intr.is_some_and(|v| *v != 0)
}

/// Read exactly `buf.len()` bytes from raw `fd`, honouring interrupt policy.
///
/// Returns bytes read on success; on EOF after a partial read returns the
/// short count; on error returns `-1` (errno preserved via `io::Error` lastos).
pub fn read_ni(fd: RawFd, buf: &mut [u8], retn_on_intr: Option<&i32>) -> isize {
    if buf.is_empty() {
        return 0;
    }
    // Safety: caller owns a valid socket/file descriptor for the duration.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let result = read_ni_reader(&mut file, buf, retn_on_intr);
    let _ = file.into_raw_fd(); // don't close — Control still owns fd
    result
}

fn read_ni_reader<R: Read>(r: &mut R, buf: &mut [u8], retn_on_intr: Option<&i32>) -> isize {
    let mut off = 0usize;
    while off < buf.len() {
        match r.read(&mut buf[off..]) {
            Ok(0) => return off as isize, // EOF / short read
            Ok(n) => off += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {
                if should_return_on_intr(retn_on_intr) {
                    return -1;
                }
                // else retry
            },
            Err(_) => return -1,
        }
    }
    off as isize
}

/// Write exactly `buf.len()` bytes to raw `fd`, honouring interrupt policy.
#[must_use]
pub fn write_ni(fd: RawFd, buf: &[u8], retn_on_intr: Option<&i32>) -> isize {
    if buf.is_empty() {
        return 0;
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let result = write_ni_writer(&mut file, buf, retn_on_intr);
    let _ = file.into_raw_fd();
    result
}

fn write_ni_writer<W: Write>(w: &mut W, buf: &[u8], retn_on_intr: Option<&i32>) -> isize {
    let mut off = 0usize;
    while off < buf.len() {
        match w.write(&buf[off..]) {
            Ok(0) => return if off == 0 { -1 } else { off as isize },
            Ok(n) => off += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {
                if should_return_on_intr(retn_on_intr) {
                    return -1;
                }
            },
            Err(_) => return -1,
        }
    }
    off as isize
}

/// Convenience wrappers used by higher layers (ignore interrupt policy).
pub fn read_fully(fd: RawFd, buf: &mut [u8]) -> isize {
    read_ni(fd, buf, None)
}

#[must_use]
pub fn write_fully(fd: RawFd, buf: &[u8]) -> isize {
    write_ni(fd, buf, None)
}

const fn resolve_intr<'a>(cntrl: &'a Control, retn_on_intr: Option<&'a i32>) -> Option<&'a i32> {
    if retn_on_intr.is_some() {
        retn_on_intr
    } else {
        cntrl.retn_on_intr.as_ref()
    }
}

/// `_OWPEncryptBlocks` — CBC encrypt in-place using the control write IV.
pub fn encrypt_blocks(cntrl: &mut Control, buf: &mut [u8], num_blocks: usize) -> i32 {
    let need = num_blocks.saturating_mul(OWP_RIJNDAEL_BLOCK_SIZE);
    if buf.len() < need || !cntrl.aes_ready {
        return -1;
    }
    let key = AesKey::from_bytes(&cntrl.aessession_key);
    let tmp = buf[..need].to_vec();
    match rijndael::encrypt_blocks(
        &mut cntrl.write_iv,
        &key,
        &tmp,
        &mut buf[..need],
        num_blocks,
    ) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// `_OWPDecryptBlocks` — CBC decrypt in-place using the control read IV.
pub fn decrypt_blocks(cntrl: &mut Control, buf: &mut [u8], num_blocks: usize) -> i32 {
    let need = num_blocks.saturating_mul(OWP_RIJNDAEL_BLOCK_SIZE);
    if buf.len() < need || !cntrl.aes_ready {
        return -1;
    }
    let key = AesKey::from_bytes(&cntrl.aessession_key);
    let tmp = buf[..need].to_vec();
    match rijndael::decrypt_blocks(&mut cntrl.read_iv, &key, &tmp, &mut buf[..need], num_blocks) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// `_OWPMakeKey` — install AES-128 session key + expanded round keys.
pub fn make_key(cntrl: &mut Control, bin_key: &[u8; OWP_RIJNDAEL_BLOCK_SIZE]) {
    crate::context::make_key(cntrl, bin_key);
}

/// `_OWPSendBlocksIntr`
pub fn send_blocks_intr(
    cntrl: &mut Control,
    buf: &mut [u8],
    num_blocks: i32,
    retn_on_intr: Option<&i32>,
) -> i32 {
    if num_blocks < 0 {
        return -1;
    }
    let nblocks = num_blocks as usize;
    let need = nblocks.saturating_mul(OWP_RIJNDAEL_BLOCK_SIZE);
    if buf.len() < need {
        return -1;
    }

    if (cntrl.mode & OWP_MODE_DOCIPHER_CNTRL) != 0
        && encrypt_blocks(cntrl, &mut buf[..need], nblocks) != 0
    {
        return -1;
    }

    let intr = resolve_intr(cntrl, retn_on_intr);
    let wr = write_ni(cntrl.sockfd, &buf[..need], intr);
    if wr < 0 {
        return -1;
    }
    num_blocks
}

/// `_OWPReceiveBlocksIntr`
///
/// Returns `num_blocks` on success, `0` on short read (peer closed), `-1` on error.
pub fn receive_blocks_intr(
    cntrl: &mut Control,
    buf: &mut [u8],
    num_blocks: i32,
    retn_on_intr: Option<&i32>,
) -> i32 {
    if num_blocks < 0 {
        return -1;
    }
    let nblocks = num_blocks as usize;
    let need = nblocks.saturating_mul(OWP_RIJNDAEL_BLOCK_SIZE);
    if buf.len() < need {
        return -1;
    }

    let intr = resolve_intr(cntrl, retn_on_intr);
    let rd = read_ni(cntrl.sockfd, &mut buf[..need], intr);
    if rd < 0 {
        return -1;
    }
    if rd as usize != need {
        return 0;
    }

    if (cntrl.mode & OWP_MODE_DOCIPHER_CNTRL) != 0
        && decrypt_blocks(cntrl, &mut buf[..need], nblocks) != 0
    {
        return -1;
    }
    num_blocks
}

/// `_OWPSendBlocks` — uses `cntrl.retn_on_intr` or defaults to return-on-intr (=1).
pub fn send_blocks(cntrl: &mut Control, buf: &mut [u8], num_blocks: i32) -> i32 {
    let flag = cntrl.retn_on_intr.unwrap_or(1);
    send_blocks_intr(cntrl, buf, num_blocks, Some(&flag))
}

/// `_OWPReceiveBlocks`
pub fn receive_blocks(cntrl: &mut Control, buf: &mut [u8], num_blocks: i32) -> i32 {
    let flag = cntrl.retn_on_intr.unwrap_or(1);
    receive_blocks_intr(cntrl, buf, num_blocks, Some(&flag))
}

/// `OWPEncryptToken` — returns `0` on success, `-1` on failure (C ABI).
pub fn encrypt_token(
    pf: &[u8],
    salt: &[u8; OWP_SALT_SIZE],
    count: u32,
    token_in: &[u8; OWP_TOKEN_SIZE],
    token_out: &mut [u8; OWP_TOKEN_SIZE],
) -> i32 {
    match rijndael::encrypt_token(pf, salt, count, token_in, token_out) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// `OWPDecryptToken` — returns `0` on success, `-1` on failure (C ABI).
pub fn decrypt_token(
    pf: &[u8],
    salt: &[u8; OWP_SALT_SIZE],
    count: u32,
    token_in: &[u8; OWP_TOKEN_SIZE],
    token_out: &mut [u8; OWP_TOKEN_SIZE],
) -> i32 {
    match rijndael::decrypt_token(pf, salt, count, token_in, token_out) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Idiomatic Result wrappers for token crypto.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn encrypt_token_result(
    pf: &[u8],
    salt: &[u8; OWP_SALT_SIZE],
    count: u32,
    token_in: &[u8; OWP_TOKEN_SIZE],
    token_out: &mut [u8; OWP_TOKEN_SIZE],
) -> Result<()> {
    rijndael::encrypt_token(pf, salt, count, token_in, token_out)
}

///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn decrypt_token_result(
    pf: &[u8],
    salt: &[u8; OWP_SALT_SIZE],
    count: u32,
    token_in: &[u8; OWP_TOKEN_SIZE],
    token_out: &mut [u8; OWP_TOKEN_SIZE],
) -> Result<()> {
    rijndael::decrypt_token(pf, salt, count, token_in, token_out)
}

/// `_OWPSendHMACAdd` — append ciphertext/plaintext blocks to send HMAC when ciphered.
pub fn send_hmac_add(cntrl: &mut Control, txt: &[u8], num_blocks: u32) {
    if (cntrl.mode & OWP_MODE_DOCIPHER_CNTRL) == 0 {
        return;
    }
    let n = (num_blocks as usize).saturating_mul(OWP_RIJNDAEL_BLOCK_SIZE);
    cntrl.send_hmac.add(&txt[..n.min(txt.len())]);
}

/// `_OWPSendHMACDigestClear` — finish send HMAC into a 16-byte digest and re-init.
pub fn send_hmac_digest_clear(cntrl: &mut Control, digest: &mut [u8; OWP_RIJNDAEL_BLOCK_SIZE]) {
    digest.fill(0);
    if (cntrl.mode & OWP_MODE_DOCIPHER_CNTRL) == 0 {
        return;
    }
    let full = cntrl.send_hmac.digest_clear();
    let n = HMAC_TRUNC_SIZE.min(full.len());
    digest[..n].copy_from_slice(&full[..n]);
    // Re-init with the session HMAC key (C: I2HMACSha1Init after Finish).
    let key = cntrl.hmac_key;
    cntrl.send_hmac.init(&key);
}

/// `_OWPRecvHMACAdd`
pub fn recv_hmac_add(cntrl: &mut Control, txt: &[u8], num_blocks: u32) {
    if (cntrl.mode & OWP_MODE_DOCIPHER_CNTRL) == 0 {
        return;
    }
    let n = (num_blocks as usize).saturating_mul(OWP_RIJNDAEL_BLOCK_SIZE);
    cntrl.recv_hmac.add(&txt[..n.min(txt.len())]);
}

/// `_OWPRecvHMACCheckClear` — compare peer digest, then re-init recv HMAC.
pub fn recv_hmac_check_clear(cntrl: &mut Control, check: &[u8; OWP_RIJNDAEL_BLOCK_SIZE]) -> bool {
    if (cntrl.mode & OWP_MODE_DOCIPHER_CNTRL) == 0 {
        return true;
    }
    let full = cntrl.recv_hmac.digest_clear();
    let n = HMAC_TRUNC_SIZE.min(full.len());
    let ok = check[..n] == full[..n];
    let key = cntrl.hmac_key;
    cntrl.recv_hmac.init(&key);
    ok
}

/// Encrypt blocks using explicit key/IV (no Control) — thin crypto wrapper.
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn encrypt_blocks_raw(
    iv: &mut [u8; OWP_RIJNDAEL_BLOCK_SIZE],
    key: &[u8; OWP_RIJNDAEL_BLOCK_SIZE],
    buf: &mut [u8],
    num_blocks: usize,
) -> Result<()> {
    let aes = AesKey::from_bytes(key);
    let need = num_blocks * OWP_RIJNDAEL_BLOCK_SIZE;
    if buf.len() < need {
        return Err(OwampError::Message(
            "encrypt_blocks_raw: buffer too short".into(),
        ));
    }
    let tmp = buf[..need].to_vec();
    rijndael::encrypt_blocks(iv, &aes, &tmp, &mut buf[..need], num_blocks)
}

/// Decrypt blocks using explicit key/IV (no Control).
///
/// # Errors
///
/// Returns an error when the underlying IO or protocol operation fails.
pub fn decrypt_blocks_raw(
    iv: &mut [u8; OWP_RIJNDAEL_BLOCK_SIZE],
    key: &[u8; OWP_RIJNDAEL_BLOCK_SIZE],
    buf: &mut [u8],
    num_blocks: usize,
) -> Result<()> {
    let aes = AesKey::from_bytes(key);
    let need = num_blocks * OWP_RIJNDAEL_BLOCK_SIZE;
    if buf.len() < need {
        return Err(OwampError::Message(
            "decrypt_blocks_raw: buffer too short".into(),
        ));
    }
    let tmp = buf[..need].to_vec();
    rijndael::decrypt_blocks(iv, &aes, &tmp, &mut buf[..need], num_blocks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::Context;
    use crate::owampP::OWP_DEFAULT_PBKDF2_COUNT;
    use std::rc::Rc;

    #[test]
    fn token_roundtrip_via_io() {
        let pf = b"passphrase";
        let salt = [9u8; OWP_SALT_SIZE];
        let mut plain = [0u8; OWP_TOKEN_SIZE];
        plain[0] = 0x11;
        plain[32] = 0x22;
        plain[63] = 0x33;
        let mut enc = [0u8; OWP_TOKEN_SIZE];
        let mut dec = [0u8; OWP_TOKEN_SIZE];
        assert_eq!(
            encrypt_token(pf, &salt, OWP_DEFAULT_PBKDF2_COUNT, &plain, &mut enc),
            0
        );
        assert_ne!(enc, plain);
        assert_eq!(
            decrypt_token(pf, &salt, OWP_DEFAULT_PBKDF2_COUNT, &enc, &mut dec),
            0
        );
        assert_eq!(dec, plain);
    }

    #[test]
    fn cbc_raw_roundtrip() {
        let key = [0x42u8; 16];
        let mut iv_e = [0u8; 16];
        let mut iv_d = [0u8; 16];
        let mut buf = [0u8; 32];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = i as u8;
        }
        let original = buf;
        encrypt_blocks_raw(&mut iv_e, &key, &mut buf, 2).unwrap();
        assert_ne!(buf, original);
        decrypt_blocks_raw(&mut iv_d, &key, &mut buf, 2).unwrap();
        assert_eq!(buf, original);
        // IV must advance to last ciphertext block
        assert_eq!(iv_e, iv_d);
    }

    #[test]
    fn hmac_skipped_in_open_mode() {
        let ctx = Context::create().expect("ctx");
        let rc = Control::alloc(&ctx, false).expect("ctrl");
        let mut cntrl = rc.borrow_mut();
        cntrl.mode = crate::owampP::OWP_MODE_OPEN;
        let mut digest = [0xaau8; 16];
        send_hmac_add(&mut cntrl, &[1u8; 16], 1);
        send_hmac_digest_clear(&mut cntrl, &mut digest);
        assert_eq!(digest, [0u8; 16]);
        assert!(recv_hmac_check_clear(&mut cntrl, &[0u8; 16]));
        drop(cntrl);
        let _ = Control::close_rc(rc);
        ctx.free();
    }

    #[test]
    fn read_write_ni_memory() {
        let data = b"abcdefghijklmnopqrstuvwxyz";
        let mut cursor = std::io::Cursor::new(data.to_vec());
        let mut out = [0u8; 26];
        assert_eq!(read_ni_reader(&mut cursor, &mut out, None), 26);
        assert_eq!(&out, data);

        let mut sink = Vec::new();
        assert_eq!(write_ni_writer(&mut sink, data, Some(&1)), 26);
        assert_eq!(sink, data);
    }

    fn unix_socket_pair() -> [i32; 2] {
        let mut fds = [0i32; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
            0
        );
        fds
    }

    #[test]
    fn send_receive_blocks_open_socketpair() {
        let fds = unix_socket_pair();
        let ctx = Context::create().expect("ctx");
        let a_rc = Control::alloc(&ctx, false).expect("a");
        let b_rc = Control::alloc(&ctx, false).expect("b");
        {
            let mut a = a_rc.borrow_mut();
            let mut b = b_rc.borrow_mut();
            a.sockfd = fds[0];
            b.sockfd = fds[1];
            a.mode = crate::owampP::OWP_MODE_OPEN;
            b.mode = crate::owampP::OWP_MODE_OPEN;
            let mut payload = *b"0123456789abcdef0123456789abcdef";
            assert_eq!(send_blocks(&mut a, &mut payload, 2), 2);
            let mut got = [0u8; 32];
            assert_eq!(receive_blocks(&mut b, &mut got, 2), 2);
            assert_eq!(got, payload);
            a.sockfd = -1;
            b.sockfd = -1;
        }
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        let _ = Control::close_rc(a_rc);
        let _ = Control::close_rc(b_rc);
        ctx.free();
    }

    #[test]
    fn send_receive_blocks_encrypted_socketpair() {
        use crate::context::make_key;
        use crate::owampP::{OWP_MODE_DOCIPHER_CNTRL, OWP_MODE_ENCRYPTED};

        let fds = unix_socket_pair();
        let ctx = Context::create().expect("ctx");
        let key = [0x5au8; 16];
        let iv = [0x7bu8; 16];
        let plain = *b"0123456789abcdef0123456789abcdef";

        let a_rc = Control::alloc(&ctx, false).expect("a");
        let b_rc = Control::alloc(&ctx, false).expect("b");
        for rc in [&a_rc, &b_rc] {
            let mut c = rc.borrow_mut();
            c.sockfd = if Rc::ptr_eq(rc, &a_rc) {
                fds[0]
            } else {
                fds[1]
            };
            c.mode = OWP_MODE_ENCRYPTED | OWP_MODE_DOCIPHER_CNTRL;
            c.aessession_key = key;
            make_key(&mut c, &key);
            c.aes_ready = true;
            if Rc::ptr_eq(rc, &a_rc) {
                c.write_iv = iv;
            } else {
                c.read_iv = iv;
            }
        }
        {
            let mut a = a_rc.borrow_mut();
            let mut wire = plain;
            assert_eq!(send_blocks_intr(&mut a, &mut wire, 2, None), 2);
            assert_ne!(wire, plain);
            let mut b = b_rc.borrow_mut();
            let mut got = [0u8; 32];
            assert_eq!(receive_blocks_intr(&mut b, &mut got, 2, None), 2);
            assert_eq!(got, plain);
            a.sockfd = -1;
            b.sockfd = -1;
        }
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        let _ = Control::close_rc(a_rc);
        let _ = Control::close_rc(b_rc);
        ctx.free();
    }
}
