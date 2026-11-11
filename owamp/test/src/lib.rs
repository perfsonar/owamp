//! `owamp/test` — Dateinamen = C-Testdateien (nur `.rs` statt `.c`/`.h`).
//!
//! | Datei              | C-Vorbild           |
//! |--------------------|---------------------|
//! | `e2e_utils.rs`     | `e2e_utils.c` / `.h`|
//! | `owtest_utils.rs`  | `owtest_utils.c` / `.h` |
//! | `server.rs`        | `server.c` / `.h`   |
//! | `session_setup.rs` | `session_setup.c` / `.h` |
//! | `hmac.rs`          | `hmac.c`            |
//! | `owtvec.rs`        | `owtvec.c`          |
//! | `owstats.rs`       | `owstats.c`         |
//! | `owping_*.rs`      | `owping_*.c`        |
//! | `twping_*.rs`      | `twping_*.c`        |
//! | `owe2e_*.rs`       | `owe2e_*.c`         |
//! | `twe2e_*.rs`       | `twe2e_*.c`         |

#![allow(non_snake_case)]

pub mod e2e_utils;
pub mod hmac;
pub mod owe2e_auth;
pub mod owe2e_clear;
pub mod owe2e_enc;
pub mod owping_clear;
pub mod owping_enc;
pub mod owstats;
pub mod owtest_utils;
pub mod owtvec;
pub mod server;
pub mod session_setup;
pub mod twe2e_auth;
pub mod twe2e_clear;
pub mod twe2e_enc;
pub mod twping_clear;
pub mod twping_enc;
