//! Authentication / passphrase setup — port of `owp_set_auth` in `powstream.c`.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::Mutex;

use owamp::context::Context;
use tracing::{error, warn};

use crate::powstreamP::{AppCtx, MAX_PASSPROMPT};

/// Passphrase buffer installed into the OWP context via `OWPGetPF`.
static PFBUFF: Mutex<Option<Vec<u8>>> = Mutex::new(None);

fn load_passphrase_from_pffile(pffile: &str, identity: &str) -> Option<Vec<u8>> {
    let file = File::open(pffile)
        .map_err(|e| {
            error!("Unable to open {pffile}: {e}");
            e
        })
        .ok()?;
    let reader = BufReader::new(file);
    for line in reader.lines().map_while(Result::ok) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Accept "identity passphrase" or "identity\tpassphrase"
        let mut parts = line.splitn(2, |c: char| c.is_whitespace());
        let id = parts.next().unwrap_or("");
        let rest = parts.next().unwrap_or("").trim();
        if id == identity && !rest.is_empty() {
            return Some(rest.as_bytes().to_vec());
        }
    }
    warn!("Unable to find pass-phrase for id=\"{identity}\" from pffile=\"{pffile}\"");
    None
}

fn prompt_passphrase(identity: &str) -> Option<Vec<u8>> {
    let prompt = format!("Enter passphrase for identity '{identity}': ");
    if prompt.len() >= MAX_PASSPROMPT {
        error!("owp_set_auth: Invalid identity");
        return None;
    }
    eprint!("{prompt}");
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        error!("I2ReadPassPhraseAlloc(): failed to read passphrase");
        return None;
    }
    let pass = line.trim_end_matches(['\r', '\n']).as_bytes().to_vec();
    if pass.is_empty() {
        None
    } else {
        Some(pass)
    }
}

/// Install passphrase + decode auth mode into `app` / `ctx`.
pub fn owp_set_auth(ctx: &Context, app: &mut AppCtx) {
    if let Some(identity) = app.opt.identity.clone() {
        let passphrase = app.opt.pffile.as_ref().map_or_else(
            || prompt_passphrase(&identity),
            |pffile| load_passphrase_from_pffile(pffile, &identity),
        );

        if let Some(pf) = passphrase {
            {
                let mut guard = PFBUFF.lock().unwrap();
                *guard = Some(pf);
            }
            ctx.set_get_pf(Box::new(
                |_ctx: &Context,
                 _userid: &str,
                 pf_out: &mut Option<Vec<u8>>,
                 _err: &mut owamp::context::ErrSeverity|
                 -> bool {
                    let guard = PFBUFF.lock().unwrap();
                    (*guard).as_ref().is_some_and(|buf| {
                        *pf_out = Some(buf.clone());
                        true
                    })
                },
            ));
        } else {
            app.opt.identity = None;
        }
    }

    match crate::powstreamP::decode_auth_mode(app.opt.authmode.as_deref()) {
        Ok(m) => app.auth_mode = m,
        Err(e) => {
            error!("{e}");
            std::process::exit(1);
        },
    }
}
