//! `twampd.c` — in C: `#define TWAMP` + `#include "owampd.c"`.

/// Startet denselben Daemon-Pfad wie `owampd`, mit TWAMP-Defaults.
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn main_twamp() -> anyhow::Result<()> {
    crate::run_server(true)
}
