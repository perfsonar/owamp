//! Port von `hmac.c` — HMAC-SHA1 Verifikation anhand RFC 2202.

#![allow(dead_code)]

use hmac::{Hmac, Mac};
use owamp::rijndael_api_fst::HmacSha1Ctx;
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

struct TestCase {
    id: u32,
    key: Vec<u8>,
    data: Vec<u8>,
    digest: [u8; 20],
}

/// `init_test_case_defs` — RFC-2202 HMAC-SHA1 Vektoren.
fn init_test_case_defs() -> Vec<TestCase> {
    vec![
        TestCase {
            id: 1,
            key: vec![0x0b; 20],
            data: b"Hi There".to_vec(),
            digest: hex_20("b617318655057264e28bc0b6fb378c8ef146be00"),
        },
        TestCase {
            id: 2,
            key: b"Jefe".to_vec(),
            data: b"what do ya want for nothing?".to_vec(),
            digest: hex_20("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"),
        },
        TestCase {
            id: 3,
            key: vec![0xaa; 20],
            data: vec![0xdd; 50],
            digest: hex_20("125d7342b9ac11cd91a39af48aa17b4f63f175d3"),
        },
        TestCase {
            id: 4,
            key: hex::decode("0102030405060708090a0b0c0d0e0f10111213141516171819").unwrap(),
            data: vec![0xcd; 50],
            digest: hex_20("4c9007f4026250c6bc8414f9bf50c86c2d7235da"),
        },
        TestCase {
            id: 5,
            key: vec![0x0c; 20],
            data: b"Test With Truncation".to_vec(),
            digest: hex_20("4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"),
        },
        TestCase {
            id: 6,
            key: vec![0xaa; 80],
            data: b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
            digest: hex_20("aa4ae5e15272d00e95705637ce8a3b55ed402112"),
        },
        TestCase {
            id: 7,
            key: vec![0xaa; 80],
            data: b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
                .to_vec(),
            digest: hex_20("e8e99d0f45237d786d6bbaa7965c7808bbff1a91"),
        },
    ]
}

fn hex_20(s: &str) -> [u8; 20] {
    let v = hex::decode(s).expect("hex");
    let mut out = [0u8; 20];
    out.copy_from_slice(&v);
    out
}

/// `openssl_api_test` — HMAC via `hmac`/`sha1` Crates (OpenSSL-Ersatz).
fn openssl_api_test(tc: &TestCase) -> bool {
    let mut mac = <HmacSha1 as Mac>::new_from_slice(&tc.key).expect("hmac key");
    mac.update(&tc.data);
    let digest = mac.finalize().into_bytes();
    digest.as_slice() == tc.digest.as_slice()
}

/// `owp_hmac_test` — HMAC via OWAMP `HmacSha1Ctx` (I2Utils-Ersatz).
fn owp_hmac_test(tc: &TestCase) -> bool {
    let mut ctx = HmacSha1Ctx::new(&tc.key).expect("HmacSha1Ctx");
    ctx.update(&tc.data);
    let digest = ctx.finish_full();
    digest == tc.digest
}

#[test]
fn hmac_rfc2202() {
    let mut error_found = false;
    for tc in init_test_case_defs() {
        eprintln!("verifying test data set #{} ...", tc.id);
        if !openssl_api_test(&tc) {
            error_found = true;
            eprintln!("\topenssl hash api error");
        }
        if !owp_hmac_test(&tc) {
            error_found = true;
            eprintln!("\towp hash api error");
        }
    }
    assert!(!error_found, "hmac test failed");
}
