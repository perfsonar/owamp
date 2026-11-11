//! Port von `owping/` — Dateinamen wie in C.
//!
//! C embeds owping / twping / owstats / owfetch / owup in one binary selected by
//! argv[0]. Rust keeps the same modes as library entry points (no separate crates
//! unless they already exist — `twping` remains a thin wrapper).

#![allow(non_snake_case)] // Module wie in C (`owpingP`)

mod auth;
mod hex;
mod owfetch;
mod owping;
mod owpingP;
mod owstats;
mod owup;
mod parse;
mod stats_io;
/// `twping.c`
mod twping;

pub use owping::{run, run_by_progname};
pub use owpingP::{
    print_conn_args, print_output_args, print_test_args, usage, usage_for_mode, Args, ProgMode,
};
pub use twping::main_twping;

#[must_use]
pub fn main_owstats() -> std::process::ExitCode {
    owstats::run()
}

#[must_use]
pub fn main_owfetch() -> std::process::ExitCode {
    owfetch::run()
}

#[must_use]
pub fn main_owup() -> std::process::ExitCode {
    owup::run()
}
