//! Port von `e2e_utils.c` / `e2e_utils.h` — End-to-End Prozess-Utilities.

use std::fs::{self, File};
use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use crate::owtest_utils::{count_occurrences, rmdir_recursive, tmp_dir};

pub const NUM_TEST_PACKETS: u32 = 10;

const OWAMPD_CONF_FILENAME: &str = "owamp-server.conf";
const OWAMPD_LIMITS_FILENAME: &str = "owamp-server.limits";
const OWAMPD_PFS_FILENAME: &str = "owamp-server.pfs";

const TWAMPD_CONF_FILENAME: &str = "twamp-server.conf";
const TWAMPD_LIMITS_FILENAME: &str = "twamp-server.limits";
const TWAMPD_PFS_FILENAME: &str = "twamp-server.pfs";

pub const USERID: &str = "fake-user";
pub const PASSPHRASE: &str = "super secret passphrase";

/// `PROTOCOL`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Owamp,
    Twamp,
}

pub type OutputVerificationHandler = fn(&str) -> bool;

/// `find_available_port`
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn find_available_port() -> std::io::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

fn bin_candidates(name: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(p) = std::env::var(format!("CARGO_BIN_EXE_{name}")) {
        out.push(PathBuf::from(p));
    }
    // Prefer the workspace cargo target-dir (see .cargo/config.toml).
    if let Ok(dir) = std::env::var("CARGO_TARGET_DIR") {
        for profile in ["debug", "release"] {
            out.push(PathBuf::from(&dir).join(profile).join(name));
        }
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // Workspace root is repo root; configured target-dir is .rust-target/.
    for profile in ["debug", "release"] {
        out.push(manifest.join("../../.rust-target").join(profile).join(name));
        out.push(manifest.join("../../target").join(profile).join(name));
    }
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            out.push(PathBuf::from(dir).join(name));
        }
    }
    out
}

fn resolve_bin(name: &str) -> Option<PathBuf> {
    // Prefer the newest mtime when several candidates exist (avoids stale
    // target/ copies after builds land in CARGO_TARGET_DIR).
    let mut found: Vec<PathBuf> = bin_candidates(name)
        .into_iter()
        .filter(|p| p.is_file())
        .collect();
    found.sort_by_key(|p| {
        std::cmp::Reverse(
            p.metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH),
        )
    });
    found.into_iter().next()
}

/// Resolve a required workspace binary or panic with a build hint.
#[must_use]
///
/// # Panics
///
/// Panics if an internal invariant is violated.
pub fn require_bin(name: &str) -> PathBuf {
    resolve_bin(name).unwrap_or_else(|| {
        panic!(
            "{name} binary not found; build first:\n  cargo build -p owampd -p owping -p twampd -p twping"
        )
    })
}

fn resolve_c_bin(name: &str) -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("OWAMP_C_BIN_DIR") {
        let p = PathBuf::from(dir).join(name);
        if p.is_file() {
            return Some(p);
        }
    }
    // Prefer PATH entries that are NOT the Rust target tree.
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            if dir.contains("/target/") {
                continue;
            }
            let p = PathBuf::from(dir).join(name);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

/// `launch_xwampd`
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn launch_xwampd(protocol: Protocol, config_dir: &Path) -> std::io::Result<Child> {
    let name = match protocol {
        Protocol::Owamp => "owampd",
        Protocol::Twamp => "twampd",
    };
    let bin = resolve_bin(name).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{name} binary not found"),
        )
    })?;
    Command::new(bin)
        .arg("-c")
        .arg(config_dir)
        .arg("-R")
        .arg(config_dir)
        .arg("-v")
        .arg("-Z")
        .arg("-f")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

/// `launch_xwping` — startet owping/twping und liefert Child + stdout-Pipe.
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn launch_xwping(
    protocol: Protocol,
    port: u16,
    authmode: &str,
    config_dir: &Path,
) -> std::io::Result<Child> {
    let name = match protocol {
        Protocol::Owamp => "owping",
        Protocol::Twamp => "twping",
    };
    let bin = resolve_bin(name).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{name} binary not found"),
        )
    })?;
    let address = format!("127.0.0.1:{port}");
    let pfs = config_dir.join(match protocol {
        Protocol::Owamp => OWAMPD_PFS_FILENAME,
        Protocol::Twamp => TWAMPD_PFS_FILENAME,
    });
    let mut cmd = Command::new(bin);
    cmd.arg("-c")
        .arg(NUM_TEST_PACKETS.to_string())
        .arg("-a")
        .arg("25,50,75")
        .arg("-b")
        .arg(".000001")
        .arg("-z")
        .arg("5")
        .arg("-A")
        .arg(authmode);
    if authmode.contains('A') || authmode.contains('E') {
        cmd.arg("-u").arg(USERID).arg("-k").arg(&pfs);
    }
    cmd.arg(address)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
}

/// `create_config_dir`
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn create_config_dir(protocol: Protocol, authmode: &str) -> std::io::Result<(u16, PathBuf)> {
    let port = find_available_port()?;
    eprintln!("available server port: {port}, 0x{port:04x}");
    let config_dir = tmp_dir()?;
    eprintln!("config directory: '{}'", config_dir.display());

    let conf_name = match protocol {
        Protocol::Owamp => OWAMPD_CONF_FILENAME,
        Protocol::Twamp => TWAMPD_CONF_FILENAME,
    };
    let mut f = File::create(config_dir.join(conf_name))?;
    writeln!(f, "srcnode 127.0.0.1:{port}")?;

    let limits_name = match protocol {
        Protocol::Owamp => OWAMPD_LIMITS_FILENAME,
        Protocol::Twamp => TWAMPD_LIMITS_FILENAME,
    };
    let mut f = File::create(config_dir.join(limits_name))?;
    writeln!(f, "limit root with disk=0, bandwidth=0, delete_on_fetch=on")?;
    writeln!(f, "limit regular with parent=root, disk=10G, bandwidth=20M")?;
    writeln!(f, "assign default regular")?;

    if authmode.contains('A') || authmode.contains('E') {
        let pfs_name = match protocol {
            Protocol::Owamp => OWAMPD_PFS_FILENAME,
            Protocol::Twamp => TWAMPD_PFS_FILENAME,
        };
        let hex_pass = hex::encode(PASSPHRASE.as_bytes());
        let mut f = File::create(config_dir.join(pfs_name))?;
        writeln!(f, "{USERID} {hex_pass}")?;
    }

    Ok((port, config_dir))
}

/// `verify_owping_output` — non-zero = Fehler (wie C).
#[must_use]
pub fn verify_owping_output(output: &str) -> bool {
    let status_str = format!("{NUM_TEST_PACKETS} sent, 0 lost");
    count_occurrences(output, &status_str) != 2
}

/// `verify_twping_output`
#[must_use]
pub fn verify_twping_output(output: &str) -> bool {
    let status_str = format!("{NUM_TEST_PACKETS} sent, 0 lost");
    count_occurrences(output, &status_str) != 1
}

fn run_one_e2e(
    protocol: Protocol,
    authmode: &str,
    verify_output: OutputVerificationHandler,
    daemon_bin: &Path,
    ping_bin: &Path,
) -> Result<bool, String> {
    let mut server: Option<Child> = None;
    let mut ping: Option<Child> = None;
    let mut config_dir: Option<PathBuf> = None;

    let run = (|| -> Result<bool, String> {
        let (port, dir) = create_config_dir(protocol, authmode)
            .map_err(|e| format!("error initializing test config: {e}"))?;
        config_dir = Some(dir.clone());

        let child = Command::new(daemon_bin)
            .arg("-c")
            .arg(&dir)
            .arg("-R")
            .arg(&dir)
            .arg("-v")
            .arg("-Z")
            .arg("-f")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?;
        server = Some(child);

        thread::sleep(Duration::from_secs(3));

        // Bind/connect on IPv4 loopback so daemon+client share one family.
        let address = format!("127.0.0.1:{port}");
        let pfs = dir.join(match protocol {
            Protocol::Owamp => OWAMPD_PFS_FILENAME,
            Protocol::Twamp => TWAMPD_PFS_FILENAME,
        });
        let mut cmd = Command::new(ping_bin);
        cmd.arg("-c")
            .arg(NUM_TEST_PACKETS.to_string())
            .arg("-a")
            .arg("25,50,75")
            .arg("-b")
            .arg(".000001")
            // Extra start delay vs C's 1s floor: Rust debug AES handshake for
            // two OWAMP sessions can otherwise start sending past loss_timeout.
            .arg("-z")
            .arg("5")
            .arg("-A")
            .arg(authmode);
        if authmode.contains('A') || authmode.contains('E') {
            cmd.arg("-u").arg(USERID).arg("-k").arg(&pfs);
        }
        let mut child = cmd
            .arg(address)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        ping = Some(child);

        let status = ping
            .as_mut()
            .unwrap()
            .wait()
            .map_err(|e| format!("waitpid failed: {e}"))?;
        let _ = ping.take();

        let mut output = String::new();
        if let Some(mut out) = stdout {
            use std::io::Read;
            let _ = out.read_to_string(&mut output);
        }
        let mut err_out = String::new();
        if let Some(mut err) = stderr {
            use std::io::Read;
            let _ = err.read_to_string(&mut err_out);
        }
        let label = match protocol {
            Protocol::Owamp => "owping",
            Protocol::Twamp => "twping",
        };
        println!("{label} OUTPUT:\n{output}");
        if !err_out.is_empty() {
            println!("{label} STDERR:\n{err_out}");
        }
        if status.success() {
            Ok(verify_output(&output))
        } else {
            Ok(true)
        }
    })();

    let exit_code = match run {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{e}");
            true
        },
    };

    if let Some(mut p) = ping.take() {
        let _ = p.kill();
        let _ = p.wait();
    }
    if let Some(mut s) = server.take() {
        let _ = s.kill();
        let _ = s.wait();
    }
    if let Some(dir) = config_dir.take() {
        rmdir_recursive(&dir);
        let _ = fs::remove_dir_all(&dir);
    }

    Ok(exit_code)
}

/// `e2e_test` — startet Daemon + Ping, prüft Output. `true` = Fehler.
///
/// Requires Rust binaries under `target/` (see [`require_bin`]). When
/// `OWAMP_C_BIN_DIR` (or PATH) provides C `owampd`/`owping`/`twampd`/`twping`,
/// the same scenario is also run against C and must agree on pass/fail.
pub fn e2e_test(
    protocol: Protocol,
    authmode: &str,
    verify_output: OutputVerificationHandler,
) -> bool {
    let (dname, pname) = match protocol {
        Protocol::Owamp => ("owampd", "owping"),
        Protocol::Twamp => ("twampd", "twping"),
    };
    let daemon = require_bin(dname);
    let ping = require_bin(pname);

    let rust_fail = match run_one_e2e(protocol, authmode, verify_output, &daemon, &ping) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("rust e2e error: {e}");
            true
        },
    };

    if let (Some(c_daemon), Some(c_ping)) = (resolve_c_bin(dname), resolve_c_bin(pname)) {
        eprintln!(
            "OWAMP_C_BIN_DIR/PATH: also comparing against C {} + {}",
            c_daemon.display(),
            c_ping.display()
        );
        let c_fail = match run_one_e2e(protocol, authmode, verify_output, &c_daemon, &c_ping) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("C e2e error: {e}");
                true
            },
        };
        if rust_fail != c_fail {
            eprintln!(
                "C↔Rust e2e mismatch: rust_fail={rust_fail} c_fail={c_fail} authmode={authmode:?}"
            );
            return true;
        }
    } else {
        eprintln!("note: C binaries not found (set OWAMP_C_BIN_DIR to enable C↔Rust e2e diff)");
    }

    rust_fail
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_helpers_count_status() {
        let ow = "10 sent, 0 lost\nfoo\n10 sent, 0 lost\n";
        assert!(!verify_owping_output(ow));
        assert!(verify_owping_output("10 sent, 0 lost\n"));

        let tw = "10 sent, 0 lost\n";
        assert!(!verify_twping_output(tw));
        assert!(verify_twping_output("nothing"));
    }

    #[test]
    fn find_port_ok() {
        assert!(find_available_port().unwrap() > 0);
    }
}
