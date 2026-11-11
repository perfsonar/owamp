//! Authentication mode + passphrase setup — port of `owp_set_auth` / `getclientpf`.

use std::fs;
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};

use owamp::context::Context;
use owamp::owampP::{
    OWP_DEFAULT_OFFERED_MODE, OWP_MODE_AUTHENTICATED, OWP_MODE_ENCRYPTED, OWP_MODE_OPEN,
    TWP_DEFAULT_OFFERED_MODE, TWP_MODE_MIXED,
};

use crate::owpingP::Args;

const MAX_PASSPROMPT: usize = 256;

/// Decode `-A` authmode string into a mode bitmask.
pub fn parse_auth_mode(s: &str, twoway: bool) -> Result<u32, String> {
    let mut mode = 0u32;
    for ch in s.chars() {
        match ch.to_ascii_uppercase() {
            'O' => mode |= OWP_MODE_OPEN,
            'A' => mode |= OWP_MODE_AUTHENTICATED,
            'E' => mode |= OWP_MODE_ENCRYPTED,
            'M' if twoway => mode |= TWP_MODE_MIXED,
            other => {
                return Err(format!("Invalid -authmode '{other}'"));
            },
        }
    }
    Ok(mode)
}

fn read_passphrase_prompt(identity: &str) -> io::Result<Vec<u8>> {
    let prompt = format!("Enter passphrase for identity '{identity}': ");
    if prompt.len() >= MAX_PASSPROMPT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid identity (prompt too long)",
        ));
    }
    eprint!("{prompt}");
    let _ = io::stderr().flush();

    // Best-effort echo-off on the controlling tty.
    let stdin = io::stdin();
    let fd = stdin.as_raw_fd();
    let mut old: libc::termios = unsafe { std::mem::zeroed() };
    let mut echoed = false;
    unsafe {
        if libc::tcgetattr(fd, &mut old) == 0 {
            let mut neu = old;
            neu.c_lflag &= !(libc::ECHO);
            if libc::tcsetattr(fd, libc::TCSANOW, &neu) == 0 {
                echoed = true;
            }
        }
    }

    let mut line = String::new();
    let res = stdin.read_line(&mut line);
    if echoed {
        unsafe {
            libc::tcsetattr(fd, libc::TCSANOW, &old);
        }
        eprintln!();
    }
    res?;
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(line.into_bytes())
}

/// Decode a PFS passphrase token like C `I2ParsePFFile` / daemon `parse_pfs_file`.
///
/// Hex (even length, hex digits only) → binary; otherwise treat as raw bytes
/// (interactive prompt / non-hex fallback).
fn decode_passphrase_token(token: &str) -> Result<Vec<u8>, String> {
    let even_hex = token.len().is_multiple_of(2)
        && !token.is_empty()
        && token.bytes().all(|b| b.is_ascii_hexdigit());
    if even_hex {
        hex::decode(token).map_err(|e| format!("Invalid hex passphrase: {e}"))
    } else {
        Ok(token.as_bytes().to_vec())
    }
}

fn load_passphrase(args: &Args) -> Result<Option<Vec<u8>>, String> {
    let Some(ref identity) = args.identity else {
        return Ok(None);
    };
    if let Some(ref path) = args.pffile {
        // Match I2ParsePFFile: identity + hex passphrase (server parse_pfs_file).
        let data = fs::read_to_string(path).map_err(|e| format!("Unable to open {path}: {e}"))?;
        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            if let (Some(id), Some(pf)) = (parts.next(), parts.next()) {
                if id == identity.as_str() {
                    return Ok(Some(decode_passphrase_token(pf)?));
                }
            } else if line != identity.as_str() {
                // Bare passphrase line (no identity column).
                return Ok(Some(decode_passphrase_token(line)?));
            }
            // Single-token identity with empty pf — skip.
        }
        return Err(format!(
            "Unable to find pass-phrase for id=\"{identity}\" from pffile=\"{path}\""
        ));
    }
    read_passphrase_prompt(identity)
        .map(Some)
        .map_err(|e| e.to_string())
}

type GetPfFn =
    Box<dyn Fn(&Context, &str, &mut Option<Vec<u8>>, &mut owamp::context::ErrSeverity) -> bool>;

/// `getclientpf` — return the loaded passphrase buffer to the library `GetPF` hook.
pub fn getclientpf(pfbuff: Arc<Mutex<Vec<u8>>>) -> GetPfFn {
    Box::new(move |_ctx, _userid, out, _err| {
        pfbuff.lock().is_ok_and(|guard| {
            *out = Some(guard.clone());
            true
        })
    })
}

/// Install `GetPF` callback and compute `auth_mode` (C `owp_set_auth`).
///
/// With `-u` + passphrase (`-k` or prompt), Authenticated/Encrypted(/Mixed) AES
/// modes are offered via the library `GetPF` + `control_open` handshake.
pub fn set_auth(ctx: &Context, args: &Args, twoway: bool) -> Result<(u32, Option<String>), String> {
    let mut identity = args.identity.clone();
    if identity.is_some() {
        match load_passphrase(args)? {
            Some(pf_owned) => {
                let pfbuff = Arc::new(Mutex::new(pf_owned));
                ctx.set_get_pf(getclientpf(pfbuff));
            },
            None => {
                // C clears identity when no passphrase is available.
                identity = None;
            },
        }
    }

    let auth_mode = if let Some(ref mode_s) = args.authmode {
        parse_auth_mode(mode_s, twoway)?
    } else if identity.is_some() {
        if twoway {
            TWP_DEFAULT_OFFERED_MODE
        } else {
            OWP_DEFAULT_OFFERED_MODE
        }
    } else {
        OWP_MODE_OPEN
    };

    Ok((auth_mode, identity))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_mode_open_auth_enc() {
        assert_eq!(
            parse_auth_mode("OAE", false).unwrap(),
            OWP_MODE_OPEN | OWP_MODE_AUTHENTICATED | OWP_MODE_ENCRYPTED
        );
    }

    #[test]
    fn auth_mode_mixed_only_twamp() {
        assert!(parse_auth_mode("M", false).is_err());
        assert_eq!(parse_auth_mode("M", true).unwrap(), TWP_MODE_MIXED);
    }

    #[test]
    fn passphrase_hex_matches_daemon_pfs() {
        let plain = b"super secret passphrase";
        let hex_pf = hex::encode(plain);
        assert_eq!(decode_passphrase_token(&hex_pf).unwrap(), plain);
        // Non-hex prompt text stays raw.
        assert_eq!(decode_passphrase_token("not-hex!!").unwrap(), b"not-hex!!");
    }
}
