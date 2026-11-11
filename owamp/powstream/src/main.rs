//! Binary-Einstieg — Logik in `powstream.rs` (← `powstream.c`).

mod auth;
mod powstream;
#[allow(non_snake_case)] // C-parity module name (`powstreamP.h`)
mod powstreamP;
mod session;
mod signals;

fn main() {
    powstream::run();
}
