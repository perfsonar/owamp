//! `libowamp` — Dateinamen = C-Quelldateien (nur `.rs` statt `.c`/`.h`).
//!
//! Mapping der Module auf die C-Quellen:
//!
//! | Datei | C-Vorbild |
//! |-------|-----------|
//! | `owamp.rs` | `owamp.h` |
//! | `owampP.rs` | `owampP.h` |
//! | `api.rs` / `capi.rs` / `sapi.rs` | `api.c` / `capi.c` / `sapi.c` |
//! | `context.rs` / `protocol.rs` / `endpoint.rs` | `context.c` / `protocol.c` / `endpoint.c` |
//! | `error.rs` / `io.rs` / `time.rs` | `error.c` / `io.c` / `time.c` |
//! | `arithm64.rs` / `schedule.rs` / `stats.rs` | `arithm64.c` / `schedule.c` / `stats.c` |
//! | `rijndael-*.rs` / `config.rs` | Rijndael-Quellen / `config.h.in` |

#![allow(non_snake_case)] // Module/API wie in C (`owampP`, `OWP…`)

pub mod api;
pub mod arithm64;
/// `owamp.h` 1:1 C-name surface (`OWP*` / `TWP*` / `I2*`).
pub mod c_api;
pub mod capi;
/// `config.h.in`
pub mod config;
pub mod context;
pub mod endpoint;
pub mod error;
/// C ABI (`#[no_mangle]` `OWP*` / `TWP*` / `I2*`).
pub mod ffi;
pub mod io;
/// `owamp.h` types
pub mod owamp;
/// `owampP.h`
pub mod owampP;
pub mod protocol;
/// `rijndael-alg-fst.c` / `.h`
#[path = "rijndael-alg-fst.rs"]
pub mod rijndael_alg_fst;
/// `rijndael-api-fst.c` / `.h`
#[path = "rijndael-api-fst.rs"]
pub mod rijndael_api_fst;
/// `rijndael-test-fst.c`
#[path = "rijndael-test-fst.rs"]
pub mod rijndael_test_fst;
pub mod sapi;
pub mod schedule;
pub mod stats;
/// Syslog helper (`I2ErrLogSyslog` / daemon `-e`/`-g`/`-R`).
pub mod syslog;
pub mod time;

pub use c_api::*;
pub use error::{report_level_by_name, syslog_facility_by_name, OwampError, Result};
pub use owamp::*;
pub use owampP::*;

// Kompatibilität für bestehende `use owamp::…`-Pfade
pub use owamp as types;
pub use owamp as owamp_h;
pub use owampP as constants;
pub use owampP as owamp_p;
pub use rijndael_api_fst as crypto;
pub use rijndael_api_fst as rijndael;
