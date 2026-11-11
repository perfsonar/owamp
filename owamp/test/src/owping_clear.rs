//! Port von `owping_clear.c` — OWAMP Control-Setup im Open-Mode.

#![allow(dead_code, unused_imports)]

use std::sync::{Arc, Mutex};

use owamp::owampP::OWP_MODE_OPEN;

use crate::server::ServerTestParams;
use crate::session_setup::{session_setup_test, ControlOpenKind};

const NUM_TEST_SLOTS: u32 = 19;
const NUM_TEST_PACKETS: u32 = 8;
const SID_VALUE: &[u8; 16] = b"some SID value!!";

#[test]
fn owping_clear() {
    let mut test_params = ServerTestParams::default();
    test_params.input.expected_modes = OWP_MODE_OPEN;
    test_params.input.expected_num_test_slots = NUM_TEST_SLOTS;
    test_params.input.expected_num_test_packets = NUM_TEST_PACKETS;
    test_params.input.sid = *SID_VALUE;
    let test_params = Arc::new(Mutex::new(test_params));

    if session_setup_test(
        OWP_MODE_OPEN,
        NUM_TEST_PACKETS,
        NUM_TEST_SLOTS,
        Arc::clone(&test_params),
        ControlOpenKind::Owp,
        None,
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
