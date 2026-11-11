//! Port von `owe2e_enc.c` — E2E OWAMP Encrypted-Mode.

#![allow(unused_imports)]

use crate::e2e_utils::{e2e_test, require_bin, verify_owping_output, Protocol};

#[test]
fn owe2e_enc() {
    let _ = require_bin("owampd");
    let _ = require_bin("owping");
    assert!(
        !e2e_test(Protocol::Owamp, "E", verify_owping_output),
        "owe2e_enc failed"
    );
}
