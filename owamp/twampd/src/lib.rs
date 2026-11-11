//! Library facade so workspace tests can depend on `twampd` as a crate
//! (Cargo cannot link bin-only packages as `[dev-dependencies]`).
//! The daemon entrypoint remains [`main`] in `src/main.rs`.

pub use owampd::twampd;
