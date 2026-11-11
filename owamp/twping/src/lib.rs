//! Library facade so workspace tests can depend on `twping` as a crate
//! (Cargo cannot link bin-only packages as `[dev-dependencies]`).
//! The client entrypoint remains in `src/main.rs`.

pub use owping::main_twping;
