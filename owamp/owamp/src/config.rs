//! Port of `owamp/config.h.in` — Compile-Time-Feature-Flags wie in Autoconf.
//!
//! In C kommen die Werte aus `./configure`. Hier setzen wir sinnvolle
//! Defaults für den Rust-Port (Unix/macOS/Linux).
//!
//! Zusätzlich: Rijndael-KAT-Flag `INTERMEDIATE_VALUE_KAT` (in C oft per
//! Compiler-`-D`, nicht in `config.h.in`), benötigt von `rijndael-test-fst`.

#![allow(dead_code)]

/// Entspricht `AUTOCONF_SYSCONFDIR` (relativer Sysconf-Pfad unter Prefix).
pub const AUTOCONF_SYSCONFDIR: &str = "etc";

pub const HAVE_BIND: bool = true;
pub const HAVE_CONNECT: bool = true;
pub const HAVE_GETADDRINFO: bool = true;
pub const HAVE_SOCKET: bool = true;
pub const HAVE_ERRNO_H: bool = true;
pub const HAVE_NETDB_H: bool = true;
pub const HAVE_SYS_SOCKET_H: bool = true;
pub const HAVE_SYS_TYPES_H: bool = true;
pub const HAVE_SYS_TIME_H: bool = true;
pub const HAVE_UNISTD_H: bool = true;
pub const HAVE_STDINT_H: bool = true;
pub const HAVE_STDLIB_H: bool = true;
pub const HAVE_STRING_H: bool = true;
pub const STDC_HEADERS: bool = true;
pub const TIME_WITH_SYS_TIME: bool = true;
pub const SIZEOF_UINT64_T: usize = 8;

/// `sys/timex.h` / `ntp_adjtime` — platfromabhängig (siehe `time.rs`).
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
))]
pub const HAVE_SYS_TIMEX_H: bool = true;
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
)))]
pub const HAVE_SYS_TIMEX_H: bool = false;

/// libcap — Rust-Port ohne libcap (wie C ohne `HAVE_LIBCAP`).
pub const HAVE_LIBCAP: bool = false;

/// I2util ist im Rust-Port nicht als C-Library verdrahtet.
pub const HAVE_I2UTIL_UTIL_H: bool = false;
pub const HAVE_I2UTIL_CONF_H: bool = false;

/// Enable Intermediate Value KAT / `rijndaelEncryptRound` /
/// `rijndaelDecryptRound` (C: `#define INTERMEDIATE_VALUE_KAT`).
///
/// Required by `rijndael-test-fst.c`; always on in this port.
pub const INTERMEDIATE_VALUE_KAT: bool = true;
