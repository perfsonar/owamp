//! Port von `owe2e_clear.c` — E2E OWAMP Open-Mode (braucht Daemon).

#![allow(unused_imports)]

use crate::e2e_utils::{e2e_test, require_bin, verify_owping_output, Protocol};

#[test]
fn owe2e_clear() {
    let _ = require_bin("owampd");
    let _ = require_bin("owping");
    assert!(
        !e2e_test(Protocol::Owamp, "O", verify_owping_output),
        "owe2e_clear failed"
    );
}
