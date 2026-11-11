//! Port von `owping_enc.c` — OWAMP Control-Setup im Encrypted-Mode.

#![allow(dead_code, unused_imports)]

use std::sync::{Arc, Mutex};

use owamp::owampP::OWP_MODE_ENCRYPTED;

use crate::server::ServerTestParams;
use crate::session_setup::{default_passphrase_callback, session_setup_test, ControlOpenKind};

const NUM_TEST_SLOTS: u32 = 44;
const NUM_TEST_PACKETS: u32 = 27;
const SID_VALUE: &[u8; 16] = b"really crazy sid";

#[test]
fn owping_enc() {
    let mut test_params = ServerTestParams::default();
    test_params.input.expected_modes = OWP_MODE_ENCRYPTED;
    test_params.input.expected_num_test_slots = NUM_TEST_SLOTS;
    test_params.input.expected_num_test_packets = NUM_TEST_PACKETS;
    test_params.input.sid = *SID_VALUE;
    let test_params = Arc::new(Mutex::new(test_params));

    if session_setup_test(
        OWP_MODE_ENCRYPTED,
        NUM_TEST_PACKETS,
        NUM_TEST_SLOTS,
        Arc::clone(&test_params),
        ControlOpenKind::Owp,
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
