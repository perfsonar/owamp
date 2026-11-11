//! `twping.c` — in C: `#define TWAMP` + `#include "owping.c"`.

use std::process::ExitCode;

/// Wie C `twping`: gleicher Client-Code wie `owping`, mit `twoway=true`.
#[must_use]
pub fn main_twping() -> ExitCode {
    crate::run(true)
}
