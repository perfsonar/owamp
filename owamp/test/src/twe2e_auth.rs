//! Port von `twe2e_auth.c` — E2E TWAMP Authenticated-Mode.

#![allow(unused_imports)]

use crate::e2e_utils::{e2e_test, require_bin, verify_twping_output, Protocol};

#[test]
fn twe2e_auth() {
    let _ = require_bin("twampd");
    let _ = require_bin("twping");
    assert!(
        !e2e_test(Protocol::Twamp, "A", verify_twping_output),
        "twe2e_auth failed"
    );
}
