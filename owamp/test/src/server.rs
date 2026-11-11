//! Port von `server.c` / `server.h` — TWAMP/OWAMP Control-Server-Emulation.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use owamp::owampP::{
    OWP_MODE_AUTHENTICATED, OWP_MODE_ENCRYPTED, OWP_MODE_OPEN, OWP_RIJNDAEL_BLOCK_SIZE,
};
use owamp::rijndael_api_fst::{
    block_decrypt, block_encrypt, derive_aes_key_pbkdf2, AesKey, HMAC_KEY_SIZE, HMAC_TRUNC_SIZE,
};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

pub const SESSION_USERID: &str = "bogus userid";
pub const SESSION_PASSPHRASE: &str = "this is the passphrase";

const SESSION_PORT: u16 = 0xabcd;
const GREETING_COUNT: u32 = 1_024;
const GREETING_CHALLENGE: &[u8; 16] = b"just a challenge";
const GREETING_SALT: &[u8; 16] = b"some funny saltT";
const SERVER_TEST_IV: &[u8; 16] = b"this is the IV!!";

/// `struct _server_test_params`
#[derive(Clone, Debug, Default)]
pub struct ServerTestParams {
    pub input: ServerTestInput,
    pub output: ServerTestOutput,
}

#[derive(Clone, Debug, Default)]
pub struct ServerTestInput {
    pub expected_modes: u32,
    pub expected_num_test_slots: u32,
    pub expected_num_test_packets: u32,
    pub sid: [u8; 16],
}

#[derive(Clone, Debug, Default)]
pub struct ServerTestOutput {
    pub sent_greeting: bool,
    pub setup_response_ok: bool,
    pub sent_server_start: bool,
    pub sent_accept_session: bool,
    pub test_complete: bool,
}

fn read_exact_stream(s: &mut TcpStream, buf: &mut [u8]) -> bool {
    s.read_exact(buf).is_ok()
}

fn write_all_stream(s: &mut TcpStream, buf: &[u8]) -> bool {
    s.write_all(buf).is_ok()
}

fn set_stream_timeouts(s: &TcpStream) {
    let t = std::time::Duration::from_secs(5);
    let _ = s.set_read_timeout(Some(t));
    let _ = s.set_write_timeout(Some(t));
}

fn with_output(ctx: &Arc<Mutex<ServerTestParams>>, f: impl FnOnce(&mut ServerTestOutput)) {
    if let Ok(mut params) = ctx.lock() {
        f(&mut params.output);
    }
}

fn encrypt_outgoing(clear: &[u8], cipher: &mut [u8], key_bytes: &[u8; 16], iv: &mut [u8; 16]) {
    assert_eq!(clear.len() % 16, 0);
    assert_eq!(clear.len(), cipher.len());
    if clear.is_empty() {
        return;
    }
    let key = AesKey::from_bytes(key_bytes);
    let mut tmp = clear.to_vec();
    block_encrypt(iv, &key, clear, &mut tmp).expect("encrypt");
    cipher.copy_from_slice(&tmp);
    let n = cipher.len();
    iv.copy_from_slice(&cipher[n - 16..]);
}

fn decrypt_incoming(cipher: &[u8], clear: &mut [u8], key_bytes: &[u8; 16], iv: &mut [u8; 16]) {
    assert_eq!(cipher.len() % 16, 0);
    assert_eq!(cipher.len(), clear.len());
    if cipher.is_empty() {
        return;
    }
    let mut next_iv = [0u8; 16];
    next_iv.copy_from_slice(&cipher[cipher.len() - 16..]);
    let key = AesKey::from_bytes(key_bytes);
    let mut tmp = vec![0u8; cipher.len()];
    let mut iv_work = *iv;
    block_decrypt(&mut iv_work, &key, cipher, &mut tmp).expect("decrypt");
    clear.copy_from_slice(&tmp);
    *iv = next_iv;
}

fn hmac_init(key: &[u8]) -> HmacSha1 {
    <HmacSha1 as Mac>::new_from_slice(key).expect("hmac key")
}

fn hmac_update(mac: &mut HmacSha1, data: &[u8]) {
    mac.update(data);
}

fn hmac_final(mac: HmacSha1) -> [u8; 20] {
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 20];
    out.copy_from_slice(&result);
    out
}

/// `do_control_setup_server` — Server-Seite des Control-Protokolls.
///
/// Gibt `false` zurück (= Test fertig, keine weiteren Clients), wie C `return 0`.
///
/// # Panics
///
/// Panics if an internal invariant is violated.
pub fn do_control_setup_server(mut s: TcpStream, ctx: Arc<Mutex<ServerTestParams>>) -> bool {
    // Never hold `ctx` across blocking I/O — the client polls the same mutex.
    set_stream_timeouts(&s);
    let input = {
        let mut params = ctx.lock().expect("lock");
        params.output = ServerTestOutput::default();
        params.input.clone()
    };

    // Greeting (64 bytes)
    let mut greeting = [0u8; 64];
    let modes = OWP_MODE_ENCRYPTED | OWP_MODE_AUTHENTICATED | OWP_MODE_OPEN;
    greeting[12..16].copy_from_slice(&modes.to_be_bytes());
    greeting[16..32].copy_from_slice(GREETING_CHALLENGE);
    greeting[32..48].copy_from_slice(GREETING_SALT);
    greeting[48..52].copy_from_slice(&GREETING_COUNT.to_be_bytes());
    let sent_greeting = write_all_stream(&mut s, &greeting);
    with_output(&ctx, |o| o.sent_greeting = sent_greeting);
    if !sent_greeting {
        with_output(&ctx, |o| o.test_complete = true);
        return false;
    }

    // Setup-Response (164 bytes)
    let mut setup_response = [0u8; 164];
    if !read_exact_stream(&mut s, &mut setup_response) {
        eprintln!("error reading setup response");
        with_output(&ctx, |o| o.test_complete = true);
        return false;
    }

    let mut mb = [0u8; 4];
    mb.copy_from_slice(&setup_response[0..4]);
    let mode = u32::from_be_bytes(mb);
    if mode != input.expected_modes {
        eprintln!(
            "expected setup response mode == 0x{:08x}, got: 0x{:08x}",
            input.expected_modes, mode
        );
        with_output(&ctx, |o| o.test_complete = true);
        return false;
    }

    if mode & (OWP_MODE_ENCRYPTED | OWP_MODE_AUTHENTICATED) != 0 {
        let key_end = setup_response[4..84]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(80);
        let key_id = std::str::from_utf8(&setup_response[4..4 + key_end]).unwrap_or("");
        if key_id != SESSION_USERID {
            eprintln!("expected key id '{SESSION_USERID}', got '{key_id}'");
            with_output(&ctx, |o| o.test_complete = true);
            return false;
        }
    }

    let dk = derive_aes_key_pbkdf2(SESSION_PASSPHRASE.as_bytes(), GREETING_SALT, GREETING_COUNT);

    let mut clear_token = [0u8; 64];
    let mut aes_session_key = [0u8; 16];
    let mut hmac_session_key = [0u8; HMAC_KEY_SIZE];

    if mode & (OWP_MODE_ENCRYPTED | OWP_MODE_AUTHENTICATED) != 0 {
        let token_key = AesKey::from_bytes(&dk);
        let mut iv0 = [0u8; 16];
        let token_in: [u8; 64] = setup_response[84..148].try_into().unwrap();
        block_decrypt(&mut iv0, &token_key, &token_in, &mut clear_token).expect("token decrypt");
        if clear_token[..16] != GREETING_CHALLENGE[..] {
            eprintln!("failed to validate challenge in decrypted token");
            with_output(&ctx, |o| o.test_complete = true);
            return false;
        }
        aes_session_key.copy_from_slice(&clear_token[16..32]);
        hmac_session_key.copy_from_slice(&clear_token[32..64]);
    }

    with_output(&ctx, |o| o.setup_response_ok = true);

    let mut enc_session_iv = *SERVER_TEST_IV;
    let mut dec_session_iv = [0u8; 16];
    dec_session_iv.copy_from_slice(&setup_response[148..164]);

    let mut send_hmac = hmac_init(&hmac_session_key);
    let mut recv_hmac = hmac_init(&hmac_session_key);

    // Server-Start (48 bytes)
    let mut server_start = [0u8; 48];
    // Accept = 0
    let unix_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    server_start[16..32].copy_from_slice(SERVER_TEST_IV);
    server_start[32..40].copy_from_slice(&unix_now.to_be_bytes());

    hmac_update(&mut send_hmac, &server_start[32..48]);
    if mode & OWP_MODE_ENCRYPTED != 0 {
        let mut block = [0u8; 16];
        block.copy_from_slice(&server_start[32..48]);
        encrypt_outgoing(
            &block.clone(),
            &mut block,
            &aes_session_key,
            &mut enc_session_iv,
        );
        server_start[32..48].copy_from_slice(&block);
    }

    let sent_server_start = write_all_stream(&mut s, &server_start);
    with_output(&ctx, |o| o.sent_server_start = sent_server_start);
    if !sent_server_start {
        eprintln!("error sending server start response");
        with_output(&ctx, |o| o.test_complete = true);
        return false;
    }

    // Request-Session (112 bytes)
    let mut request_session = [0u8; 112];
    if !read_exact_stream(&mut s, &mut request_session) {
        eprintln!("error reading request session message");
        with_output(&ctx, |o| o.test_complete = true);
        return false;
    }

    if mode & OWP_MODE_ENCRYPTED != 0 {
        let cipher = request_session;
        decrypt_incoming(
            &cipher,
            &mut request_session,
            &aes_session_key,
            &mut dec_session_iv,
        );
    }

    hmac_update(&mut recv_hmac, &request_session[..96]);
    let expected_hmac = hmac_final(std::mem::replace(
        &mut recv_hmac,
        hmac_init(&hmac_session_key),
    ));
    recv_hmac = hmac_init(&hmac_session_key);

    if mode & (OWP_MODE_ENCRYPTED | OWP_MODE_AUTHENTICATED) != 0
        && request_session[96..112] != expected_hmac[..HMAC_TRUNC_SIZE]
    {
        eprintln!("hmac verification error in Request-Session");
        with_output(&ctx, |o| o.test_complete = true);
        return false;
    }

    let mut nb = [0u8; 4];
    nb.copy_from_slice(&request_session[4..8]);
    let num_slots = u32::from_be_bytes(nb);
    if num_slots != input.expected_num_test_slots {
        eprintln!(
            "expected {} test slots, got {num_slots}",
            input.expected_num_test_slots
        );
        with_output(&ctx, |o| o.test_complete = true);
        return false;
    }

    nb.copy_from_slice(&request_session[8..12]);
    let num_packets = u32::from_be_bytes(nb);
    if num_packets != input.expected_num_test_packets {
        eprintln!(
            "expected {} test packets, got {num_packets}",
            input.expected_num_test_packets
        );
        with_output(&ctx, |o| o.test_complete = true);
        return false;
    }

    if num_slots > 0 {
        let slots_len = num_slots as usize * OWP_RIJNDAEL_BLOCK_SIZE;
        let mut slots = vec![0u8; slots_len];
        if !read_exact_stream(&mut s, &mut slots) {
            eprintln!("error reading slot descriptions");
            with_output(&ctx, |o| o.test_complete = true);
            return false;
        }

        // C: decrypt for AUTH|ENC (test server quirk; production ENC-only for Req).
        if mode & (OWP_MODE_ENCRYPTED | OWP_MODE_AUTHENTICATED) != 0 {
            let cipher = slots.clone();
            decrypt_incoming(&cipher, &mut slots, &aes_session_key, &mut dec_session_iv);
        }

        hmac_update(&mut recv_hmac, &slots);
        let expected = hmac_final(recv_hmac);

        let mut hmac_msg = [0u8; 16];
        if !read_exact_stream(&mut s, &mut hmac_msg) {
            eprintln!("error reading hmac");
            with_output(&ctx, |o| o.test_complete = true);
            return false;
        }

        if mode & OWP_MODE_ENCRYPTED != 0 {
            let cipher = hmac_msg;
            decrypt_incoming(
                &cipher,
                &mut hmac_msg,
                &aes_session_key,
                &mut dec_session_iv,
            );
        }

        if mode & (OWP_MODE_ENCRYPTED | OWP_MODE_AUTHENTICATED) != 0
            && hmac_msg != expected[..HMAC_TRUNC_SIZE]
        {
            eprintln!("hmac verification error for Slot list");
            with_output(&ctx, |o| o.test_complete = true);
            return false;
        }
    } else {
        let _ = recv_hmac;
    }

    // Accept-Session (48 bytes)
    let mut accept_session = [0u8; 48];
    accept_session[2..4].copy_from_slice(&SESSION_PORT.to_be_bytes());
    accept_session[4..20].copy_from_slice(&input.sid);

    hmac_update(&mut send_hmac, &accept_session[..32]);
    let digest = hmac_final(std::mem::replace(
        &mut send_hmac,
        hmac_init(&hmac_session_key),
    ));
    accept_session[32..48].copy_from_slice(&digest[..HMAC_TRUNC_SIZE]);
    let _ = send_hmac; // re-inited above if continued

    if mode & OWP_MODE_ENCRYPTED != 0 {
        let clear = accept_session;
        encrypt_outgoing(
            &clear,
            &mut accept_session,
            &aes_session_key,
            &mut enc_session_iv,
        );
    }

    if !write_all_stream(&mut s, &accept_session) {
        eprintln!("error sending Accept-Session response");
        with_output(&ctx, |o| o.test_complete = true);
        return false;
    }

    with_output(&ctx, |o| {
        o.sent_accept_session = true;
        o.test_complete = true;
    });
    eprintln!("do_server: finished!");
    false // stop serving
}

/// In `server.h` deklariert, in C nicht implementiert — Alias.
pub fn do_control_setup_server_encrypted(s: TcpStream, ctx: Arc<Mutex<ServerTestParams>>) -> bool {
    do_control_setup_server(s, ctx)
}
