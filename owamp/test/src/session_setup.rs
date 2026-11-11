//! Port von `session_setup.c` / `session_setup.h`.

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use owamp::arithm64::double_to_num64;
use owamp::capi::{control_open, session_request, twp_control_open};
use owamp::context::{Addr, Context, Control, ErrSeverity, Slot, SlotType, TestSpec, OWP_GET_PF};
use owamp::owamp::OwampNum64;
use owamp::time::get_time_of_day;

use crate::owtest_utils::{bind_ephemeral, spawn_server, tmpContext, ClientProc};
use crate::server::{
    do_control_setup_server, ServerTestParams, SESSION_PASSPHRASE, SESSION_USERID,
};

/// `OWPGetPFFunc` / default passphrase callback.
pub type GetPfFn =
    Box<dyn Fn(&Context, &str, &mut Option<Vec<u8>>, &mut ErrSeverity) -> bool + Send + Sync>;

/// `default_passphrase_callback`
pub fn default_passphrase_callback(
    _ctx: &Context,
    _userid: &str,
    pf: &mut Option<Vec<u8>>,
    _err_ret: &mut ErrSeverity,
) -> bool {
    *pf = Some(SESSION_PASSPHRASE.as_bytes().to_vec());
    true
}

/// Welche ControlOpen-Variante der Client nutzen soll.
#[derive(Clone, Copy, Debug)]
pub enum ControlOpenKind {
    /// `OWPControlOpen`
    Owp,
    /// `TWPControlOpen`
    Twp,
}

/// `session_setup_test` — startet Server-Emulator und Client-Control-Session.
///
/// Rückgabe: `true` bei Fehler (wie C non-zero), `false` bei Erfolg.
///
/// # Panics
///
/// Panics if an internal invariant is violated.
pub fn session_setup_test(
    client_mode_mask: u32,
    num_test_packets: u32,
    num_test_slots: u32,
    test_params: Arc<Mutex<ServerTestParams>>,
    control_open_kind: ControlOpenKind,
    passphrase_callback: Option<GetPfFn>,
) -> bool {
    let Ok((listener, port)) = bind_ephemeral() else {
        eprintln!("bind error");
        return true;
    };

    let server_ctx = Arc::clone(&test_params);
    let client_proc: ClientProc<ServerTestParams> = Arc::new(do_control_setup_server);
    let server_thread = spawn_server(listener, client_proc, server_ctx);

    // Kurz warten, bis accept bereit ist.
    thread::sleep(Duration::from_millis(50));

    let ctx = tmpContext();
    if let Some(cb) = passphrase_callback {
        ctx.set_get_pf(cb);
        let _ = OWP_GET_PF;
    }

    let server_addr = Addr::by_node("127.0.0.1", Some(&port.to_string()));
    let mut err = ErrSeverity::Ok;
    let cntrl_rc = match control_open_kind {
        ControlOpenKind::Owp => control_open(
            &ctx,
            None,
            server_addr,
            client_mode_mask,
            Some(SESSION_USERID),
            None,
            &mut err,
        ),
        ControlOpenKind::Twp => twp_control_open(
            &ctx,
            None,
            server_addr,
            client_mode_mask,
            Some(SESSION_USERID),
            None,
            &mut err,
        ),
    };

    let Some(cntrl_rc) = cntrl_rc else {
        eprintln!("OWPControlOpen error");
        let _ = server_thread.join();
        return true;
    };

    let mut client_successful = false;
    {
        let mut cntrl = cntrl_rc.borrow_mut();
        let curr = get_time_of_day().unwrap_or(owamp::owamp::OwampTimeStamp {
            owptime: OwampNum64(0),
            sync: false,
            multiplier: 0,
            scale: 0,
        });
        let mut slots = Vec::with_capacity(num_test_slots as usize);
        for i in 0..num_test_slots {
            slots.push(Slot {
                slot_type: SlotType::Literal,
                time: double_to_num64(f64::from(i)),
            });
        }
        let tspec = TestSpec {
            start_time: curr.owptime,
            loss_timeout: OwampNum64(0),
            type_p: 0,
            packet_size_padding: 0,
            npackets: num_test_packets,
            nslots: num_test_slots,
            slots,
        };

        let mut sid_ret = [0u8; 16];
        let mut err_ret = ErrSeverity::Ok;
        let ok = session_request(
            &mut cntrl,
            Some(Addr::by_node("localhost", None)),
            true,
            Some(Addr::by_node("localhost", None)),
            true,
            false,
            &tspec,
            &mut sid_ret,
            &mut err_ret,
        );

        if ok {
            let expected_sid = test_params.lock().unwrap().input.sid;
            if sid_ret == expected_sid {
                client_successful = true;
            } else {
                eprintln!("received incorrect SID");
            }
        } else {
            eprintln!("OWPSessionRequest returned error");
        }
    }

    // Auf Server-Completion warten.
    for _ in 0..50 {
        if test_params.lock().unwrap().output.test_complete {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    if test_params.lock().unwrap().output.test_complete {
        let _ = server_thread.join();
    } else {
        eprintln!("warning: server thread didn't exit");
        // Listener/accept blockiert ggf. — Thread wird beim Prozessende beendet.
    }

    let _ = Control::close_rc(cntrl_rc);
    ctx.free();

    !client_successful
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_passphrase_returns_session_secret() {
        let ctx = tmpContext();
        let mut pf = None;
        let mut err = ErrSeverity::Ok;
        assert!(default_passphrase_callback(&ctx, "x", &mut pf, &mut err));
        assert_eq!(pf.unwrap(), SESSION_PASSPHRASE.as_bytes());
        ctx.free();
    }
}
