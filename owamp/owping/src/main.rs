//! OWAMP client binary — port of `owping/owping.c`.
//!
//! Dispatches by argv[0] (owping / twping / owstats / owfetch / owup), matching C.

fn main() -> std::process::ExitCode {
    owping::run_by_progname()
}
