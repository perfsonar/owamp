//! Port von `owtest_utils.c` / `owtest_utils.h`.

use std::fs::{self, File};
use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use owamp::context::Context;

pub const TMPNAME_FMT: &str = "owtest.XXXXXX";

/// `tmpFile` — anonymes Tempfile (wird nach dem Öffnen entlinkt).
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn tmpFile() -> io::Result<File> {
    let dir = std::env::temp_dir();
    let mut path = dir.join(format!("owtest.{}.{}", std::process::id(), rand_suffix()));
    let file = File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)?;
    let _ = fs::remove_file(&path);
    // Keep `path` out of scope intentionally; file stays open via fd.
    let _ = &mut path;
    Ok(file)
}

/// `tmpSessionDataFile` — Tempfile mit aus Hex dekodierten Bytes.
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn tmpSessionDataFile(hex: &str) -> io::Result<File> {
    use std::io::{Seek, SeekFrom};
    let bytes = hex::decode(hex.replace([' ', '\n', '\t'], ""))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let mut fp = tmpFile()?;
    fp.write_all(&bytes)?;
    fp.sync_all()?;
    fp.seek(SeekFrom::Start(0))?;
    Ok(fp)
}

/// `rmdir_recursive` — einfaches `rm -r`.
pub fn rmdir_recursive(dir_name: &Path) {
    let Ok(entries) = fs::read_dir(dir_name) else {
        eprintln!("can't open directory: {}", dir_name.display());
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if name == "." || name == ".." {
            continue;
        }
        if path.is_dir() {
            rmdir_recursive(&path);
        } else if let Err(e) = fs::remove_file(&path) {
            eprintln!("couldn't unlink file: {}: {e}", path.display());
        }
    }
    if let Err(e) = fs::remove_dir(dir_name) {
        eprintln!("couldn't rmdir: {}: {e}", dir_name.display());
    }
}

/// `tmpContext` — frischer `OWPContext` für Tests.
#[must_use]
///
/// # Panics
///
/// Panics if an internal invariant is violated.
pub fn tmpContext() -> Context {
    Context::create().expect("OWPContextCreate returned NULL")
}

/// Parameter für den Test-TCP-Server (`struct _server_params`).
pub struct ServerParams {
    pub listener: Option<TcpListener>,
    pub client_proc: Arc<dyn Fn(TcpStream, Arc<Mutex<()>>) -> bool + Send + Sync>,
    pub test_context: Arc<Mutex<()>>,
}

/// Generischer Server-Lauf mit Client-Handler und geteiltem Kontext.
pub type ClientProc<T> = Arc<dyn Fn(TcpStream, Arc<Mutex<T>>) -> bool + Send + Sync>;

/// `run_server` — akzeptiert Verbindungen und ruft `client_proc` auf.
/// Rückgabe `false` von `client_proc` beendet die Schleife (wie C).
pub fn run_server<T: Send + 'static>(
    listener: TcpListener,
    client_proc: ClientProc<T>,
    test_context: Arc<Mutex<T>>,
) {
    loop {
        let Ok((stream, _)) = listener.accept() else {
            break;
        };
        let keep = (client_proc)(stream, Arc::clone(&test_context));
        if !keep {
            break;
        }
    }
}

/// Startet `run_server` in einem Hintergrundthread.
pub fn spawn_server<T: Send + 'static>(
    listener: TcpListener,
    client_proc: ClientProc<T>,
    test_context: Arc<Mutex<T>>,
) -> JoinHandle<()> {
    thread::spawn(move || run_server(listener, client_proc, test_context))
}

/// Bindet `127.0.0.1:0` und liefert Listener + Port.
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn bind_ephemeral() -> io::Result<(TcpListener, u16)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    Ok((listener, port))
}

/// `count_occurrences` — Anzahl der Vorkommen von `needle` in `haystack`.
#[must_use]
pub fn count_occurrences(haystack: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let mut num = 0;
    let mut rest = haystack;
    while let Some(idx) = rest.find(needle) {
        num += 1;
        rest = &rest[idx + needle.len()..];
    }
    num
}

/// Temporäres Verzeichnis mit `mkdtemp`-ähnlichem Namen.
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn tmp_dir() -> io::Result<PathBuf> {
    let base = std::env::temp_dir();
    for _ in 0..32 {
        let path = base.join(format!(
            "owtest-cfg-{}.{}",
            std::process::id(),
            rand_suffix()
        ));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {},
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "tmp_dir: exhausted retries",
    ))
}

fn rand_suffix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    t ^ u64::from(std::process::id()).wrapping_mul(0x9e37_79b9)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_occurrences_basic() {
        assert_eq!(count_occurrences("ababab", "ab"), 3);
        assert_eq!(count_occurrences("aaa", "aa"), 1);
        assert_eq!(count_occurrences("hello", "xyz"), 0);
    }

    #[test]
    fn tmp_session_roundtrip() {
        use std::io::Read;
        let hex = "4f7741"; // "OwA"
        let mut f = tmpSessionDataFile(hex).unwrap();
        let mut buf = [0u8; 3];
        f.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"OwA");
    }
}
