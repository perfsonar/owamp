//! Port von `twping_enc.c` — TWAMP Control-Setup im Encrypted-Mode.

#![allow(dead_code, unused_imports)]

use std::sync::{Arc, Mutex};

use owamp::owampP::OWP_MODE_ENCRYPTED;

use crate::server::ServerTestParams;
use crate::session_setup::{default_passphrase_callback, session_setup_test, ControlOpenKind};

const NUM_TEST_SLOTS: u32 = 15;
const NUM_TEST_PACKETS: u32 = 18;
const SID_VALUE: &[u8; 16] = b"this is the SID!";

#[test]
fn twping_enc() {
    let mut test_params = ServerTestParams::default();
    test_params.input.expected_modes = OWP_MODE_ENCRYPTED;
    test_params.input.expected_num_test_slots = 0;
    test_params.input.expected_num_test_packets = 0;
    test_params.input.sid = *SID_VALUE;
    let test_params = Arc::new(Mutex::new(test_params));

    if session_setup_test(
        OWP_MODE_ENCRYPTED,
        NUM_TEST_PACKETS,
        NUM_TEST_SLOTS,
        Arc::clone(&test_params),
        ControlOpenKind::Twp,
        Some(Box::new(default_passphrase_callback)),
    ) {
        panic!("ping client detected an error");
    }

    let out = &test_params.lock().unwrap().output;
    assert!(out.sent_greeting);
    assert!(out.setup_response_ok);
    assert!(out.sent_server_start);
    assert!(out.sent_accept_session);
    assert!(out.test_complete);
}
