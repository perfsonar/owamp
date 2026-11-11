//! Port von `twping_clear.c` — TWAMP Control-Setup im Open-Mode.

#![allow(dead_code, unused_imports)]

use std::sync::{Arc, Mutex};

use owamp::owampP::OWP_MODE_OPEN;

use crate::server::ServerTestParams;
use crate::session_setup::{session_setup_test, ControlOpenKind};

const NUM_TEST_SLOTS: u32 = 99;
const NUM_TEST_PACKETS: u32 = 41;
const SID_VALUE: &[u8; 16] = b"different SID!!?";

#[test]
fn twping_clear() {
    let mut test_params = ServerTestParams::default();
    test_params.input.expected_modes = OWP_MODE_OPEN;
    // TWAMP wire: nslots/npackets are 0
    test_params.input.expected_num_test_slots = 0;
    test_params.input.expected_num_test_packets = 0;
    test_params.input.sid = *SID_VALUE;
    let test_params = Arc::new(Mutex::new(test_params));

    if session_setup_test(
        OWP_MODE_OPEN,
        NUM_TEST_PACKETS,
        NUM_TEST_SLOTS,
        Arc::clone(&test_params),
        ControlOpenKind::Twp,
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
