//! C ABI (`OWP*` / `TWP*` / minimal `I2*`) — drop-in `libowamp` surface.
//!
//! Pedantic/nursery lints are relaxed here: signatures and pointer use follow
//! `owamp.h` / I2util, not idiomatic Rust.

#![allow(clippy::all)]
#![allow(clippy::pedantic)]
#![allow(clippy::nursery)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(missing_docs)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

pub mod cfile;
pub mod exports;
pub mod handles;
pub mod i2;
pub mod types;
