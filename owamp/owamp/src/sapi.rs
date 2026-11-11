//! Port of `sapi.c` — server listen socket, control accept, request processing.

use std::cell::RefCell;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::rc::Rc;
use std::thread;
use std::time::Duration;

use crate::api::{
    self, create_sid, endpoint_init, endpoint_init_hook, endpoint_start, fail_control_session,
    is_lost_record, read_setup_response, read_start_sessions, read_test_request,
    test_session_free_unlinked, write_accept_session, write_server_greeting, write_server_start,
    write_start_ack, DataRec,
};
use crate::context::{
    call_check_control_policy, call_check_fetch_policy, call_check_test_policy, call_get_pf,
    decrypt_token, get_time_of_day, make_key, num64_sub, AcceptType, Addr, Context, Control,
    ErrSeverity, ErrType, ScheduleContext, Sid, OWP_MODE_DOCIPHER_CNTRL, STATE_ACCEPT_SESSION,
    STATE_FETCHING, STATE_REQUEST,
};
use crate::io::{send_blocks_intr, send_hmac_add, send_hmac_digest_clear};
use crate::owamp::OwampNum64;
use crate::owampP::{
    OWP_CONTROL_SERVICE_NAME, OWP_FETCH_AES_BLOCKS, OWP_FETCH_DATAREC_BLOCKS, OWP_LISTEN_BACKLOG,
    OWP_MAGIC_FILETYPE, OWP_MODE_AUTHENTICATED, OWP_MODE_ENCRYPTED, OWP_MODE_OPEN,
    OWP_RIJNDAEL_BLOCK_SIZE, OWP_SKIPREC_SIZE, OWP_TESTREC_OFFSET, TWP_CONTROL_SERVICE_NAME,
    TWP_MODE_MIXED,
};
use crate::protocol::{self, encode_data_record};
use crate::rijndael_api_fst as rijndael;

// ---------------------------------------------------------------------------
// LOCAL stand-ins (missing from other modules)
// ---------------------------------------------------------------------------

/// LOCAL — `OWPSessionFinishedType` values used by fetch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
enum SessionFinished {
    Error = 0,
    Normal = 1,
    Incomplete = 2,
}

/// LOCAL — `_OWPSessionHeaderInitialRec`
#[derive(Clone, Debug, Default)]
struct SessionHeaderInitial {
    version: u32,
    rec_size: u32,
    finished: u32,
    next_seqno: u32,
    num_skiprecs: u32,
    num_datarecs: u32,
    oset_skiprecs: u64,
    oset_datarecs: u64,
    file_size: u64,
}

/// `GetSessionFinishedType` for fetch headers (invalid → Error, matches C return).
const fn session_finished_from_u32(v: u32) -> u32 {
    match v {
        1 => SessionFinished::Normal as u32,
        2 => SessionFinished::Incomplete as u32,
        _ => SessionFinished::Error as u32,
    }
}

/// LOCAL — `_OWPReadDataHeaderInitial` (version-3 focused; fetch requires v3).
fn read_data_header_initial(fp: &mut File) -> Option<SessionHeaderInitial> {
    let meta = fp.metadata().ok()?;
    let file_size = meta.len();
    if file_size < 16 {
        return None;
    }
    fp.seek(SeekFrom::Start(0)).ok()?;

    let mut magic = [0u8; 4];
    fp.read_exact(&mut magic).ok()?;
    // C magic is 3 bytes "OwA" + NUL in a 4-byte field
    if &magic[..3] != OWP_MAGIC_FILETYPE && magic != *b"OwA\0" {
        return None;
    }

    let mut u32b = [0u8; 4];
    fp.read_exact(&mut u32b).ok()?;
    let version = u32::from_be_bytes(u32b);

    let mut hdr = SessionHeaderInitial {
        version,
        file_size,
        ..Default::default()
    };

    match version {
        0 | 2 => {
            let mut osetb = [0u8; 8];
            fp.read_exact(&mut osetb).ok()?;
            let oset = u64::from_be_bytes(osetb);
            hdr.rec_size = crate::owampP::OWP_DATARECV2_SIZE as u32;
            hdr.oset_datarecs = oset;
            if version >= 2 {
                fp.read_exact(&mut u32b).ok()?;
                hdr.finished = session_finished_from_u32(u32::from_be_bytes(u32b));
            }
            if hdr.oset_datarecs <= file_size {
                hdr.num_datarecs =
                    ((file_size - hdr.oset_datarecs) / u64::from(hdr.rec_size)) as u32;
            }
            return Some(hdr);
        },
        3 => {
            hdr.rec_size = crate::owampP::OWP_DATARECV3_SIZE as u32;
        },
        v if v == (crate::owampP::OWP_VERSION_TWOWAY | 3) => {
            hdr.rec_size = crate::owampP::OWP_DATAREC_TWV3_SIZE as u32;
        },
        _ => return None,
    }

    // version >= 3 path
    fp.read_exact(&mut u32b).ok()?;
    hdr.finished = session_finished_from_u32(u32::from_be_bytes(u32b));
    fp.read_exact(&mut u32b).ok()?;
    hdr.next_seqno = u32::from_be_bytes(u32b);
    fp.read_exact(&mut u32b).ok()?;
    hdr.num_skiprecs = u32::from_be_bytes(u32b);
    fp.read_exact(&mut u32b).ok()?;
    hdr.num_datarecs = u32::from_be_bytes(u32b);
    let mut osetb = [0u8; 8];
    fp.read_exact(&mut osetb).ok()?;
    hdr.oset_skiprecs = u64::from_be_bytes(osetb);
    fp.read_exact(&mut osetb).ok()?;
    hdr.oset_datarecs = u64::from_be_bytes(osetb);
    Some(hdr)
}

/// `_OWPCallOpenFile` — app hook only; NULL/None when unset (C).
fn call_open_file(
    cntrl: &Control,
    closure: Option<&dyn std::any::Any>,
    sid: &Sid,
    fname_out: &mut PathBuf,
) -> Option<File> {
    crate::context::call_open_file(cntrl, closure, sid, fname_out)
}

/// `_OWPCallCloseFile`
fn call_close_file(
    cntrl: &Control,
    closure: Option<&dyn std::any::Any>,
    fp: File,
    acceptval: AcceptType,
) {
    crate::context::call_close_file(cntrl, closure, fp, acceptval);
}

/// LOCAL — `_OWPReadFetchSession` (first AES block already in `cntrl.msg`).
fn read_fetch_session(cntrl: &mut Control) -> Result<(u32, u32, Sid), ErrSeverity> {
    // Remaining 2 blocks of FetchSession (48 bytes total).
    let mut rest = [0u8; 32];
    if send_blocks_intr_recv(cntrl, &mut rest, 2) != 2 {
        return Err(ErrSeverity::Fatal);
    }
    let mut buf = [0u8; 48];
    buf[..16].copy_from_slice(&cntrl.msg[..16]);
    buf[16..48].copy_from_slice(&rest);
    let fs = protocol::FetchSession::decode(&buf).map_err(|_| ErrSeverity::Fatal)?;
    cntrl.state = (cntrl.state & !crate::context::STATE_READING) | STATE_FETCHING;
    Ok((fs.begin, fs.end, fs.sid))
}

/// LOCAL — receive blocks via context/io receive helper.
fn send_blocks_intr_recv(cntrl: &mut Control, buf: &mut [u8], num_blocks: i32) -> i32 {
    crate::io::receive_blocks_intr(cntrl, buf, num_blocks, None)
}

/// LOCAL — `_OWPWriteFetchAck`
fn write_fetch_ack(
    cntrl: &mut Control,
    acceptval: AcceptType,
    finished: u8,
    next_seqno: u32,
    num_skiprecs: u32,
    num_datarecs: u32,
) -> ErrSeverity {
    let mut hmac = [0u8; 16];
    let mut ack = protocol::FetchAck {
        accept: match acceptval {
            AcceptType::Accept => protocol::AcceptType::Accept,
            AcceptType::Reject => protocol::AcceptType::Reject,
            AcceptType::Failure => protocol::AcceptType::Failure,
            AcceptType::Unsupported => protocol::AcceptType::Unsupported,
            AcceptType::UnavailablePerm => protocol::AcceptType::UnavailablePerm,
            AcceptType::UnavailableTemp => protocol::AcceptType::UnavailableTemp,
            AcceptType::Invalid => protocol::AcceptType::Invalid,
        },
        finished,
        next_seqno,
        num_skiprecs,
        num_datarecs,
        hmac,
    };
    protocol::normalize_fetch_ack(&mut ack);
    let mut buf = [0u8; 32];
    if ack.encode(&mut buf).is_err() {
        return ErrSeverity::Fatal;
    }
    send_hmac_add(cntrl, &buf[..16], 1);
    send_hmac_digest_clear(cntrl, &mut hmac);
    buf[16..32].copy_from_slice(&hmac);
    if send_blocks_intr(cntrl, &mut buf, 2, None) != 2 {
        return ErrSeverity::Fatal;
    }
    ErrSeverity::Ok
}

/// LOCAL — decode one data record from file version into `api::DataRec`.
fn decode_file_data_rec(version: u32, buf: &[u8]) -> Option<DataRec> {
    let rec = protocol::decode_data_record(version, buf).ok()?;
    Some(DataRec {
        seq_no: rec.seq_no,
        send: rec.send,
        recv: rec.recv,
        ttl: rec.ttl,
    })
}

/// LOCAL — `OWPParseRecords` simplified: iterate num records from current seek.
fn parse_records<F>(
    fp: &mut File,
    num_datarecs: u32,
    version: u32,
    rec_size: usize,
    mut cb: F,
) -> ErrSeverity
where
    F: FnMut(&DataRec) -> i32,
{
    let mut buf = vec![0u8; rec_size.max(1)];
    for _ in 0..num_datarecs {
        if fp.read_exact(&mut buf).is_err() {
            return ErrSeverity::Fatal;
        }
        let Some(rec) = decode_file_data_rec(version, &buf) else {
            return ErrSeverity::Fatal;
        };
        let rc = cb(&rec);
        if rc < 0 {
            return ErrSeverity::Fatal;
        }
    }
    ErrSeverity::Ok
}

/// Fetch-session data-record callback state (`struct DoDataState` in C).
pub struct DoDataState {
    pub err: ErrSeverity,
    pub rec_size: u32,
    pub send: bool,
    pub begin: u32,
    pub end: u32,
    pub inbuf: u32,
    pub count: u64,
    pub maxiseen: u32,
}

impl DoDataState {
    fn handle_record(&mut self, cntrl: &mut Control, rec: &DataRec) -> i32 {
        if rec.seq_no > self.maxiseen && !is_lost_record(rec) {
            self.maxiseen = rec.seq_no;
        }
        if rec.seq_no < self.begin || rec.seq_no > self.end {
            return 0;
        }
        self.count += 1;
        if !self.send {
            return 0;
        }
        let offset = (self.inbuf as usize).saturating_mul(self.rec_size as usize);
        let end = offset + self.rec_size as usize;
        if end > cntrl.msg.len() {
            self.err = ErrSeverity::Fatal;
            fail_control_session(cntrl, ErrSeverity::Fatal);
            return -1;
        }
        let mut tmp = [0u8; 64];
        let need = self.rec_size as usize;
        if encode_data_record(
            &mut tmp[..need.max(protocol::DATARECV3_SIZE)],
            &protocol::DataRec {
                seq_no: rec.seq_no,
                send: rec.send,
                recv: rec.recv,
                ttl: rec.ttl,
            },
        )
        .is_err()
        {
            return -1;
        }
        cntrl.msg[offset..end].copy_from_slice(&tmp[..need]);
        self.inbuf += 1;

        if self.inbuf == OWP_FETCH_DATAREC_BLOCKS as u32 {
            let n = OWP_FETCH_AES_BLOCKS;
            let mut block = [0u8; OWP_FETCH_AES_BLOCKS * OWP_RIJNDAEL_BLOCK_SIZE];
            block.copy_from_slice(&cntrl.msg[..n * OWP_RIJNDAEL_BLOCK_SIZE]);
            send_hmac_add(cntrl, &block, n as u32);
            if send_blocks_intr(cntrl, &mut block, n as i32, None) != n as i32 {
                self.err = ErrSeverity::Fatal;
                fail_control_session(cntrl, ErrSeverity::Fatal);
                return -1;
            }
            cntrl.msg[..n * OWP_RIJNDAEL_BLOCK_SIZE].copy_from_slice(&block);
            self.inbuf = 0;
        } else if self.inbuf > OWP_FETCH_DATAREC_BLOCKS as u32 {
            self.err = ErrSeverity::Fatal;
            fail_control_session(cntrl, ErrSeverity::Fatal);
            return -1;
        }
        0
    }
}

/// `DoDataRecords` — fetch-session per-record callback.
pub fn do_data_records(state: &mut DoDataState, cntrl: &mut Control, rec: &DataRec) -> i32 {
    state.handle_record(cntrl, rec)
}

// ---------------------------------------------------------------------------
// OpenSocket / ServerSockCreate
// ---------------------------------------------------------------------------

fn open_socket(ctx: &Context, family: i32, addr: &mut Addr, def_serv: &str) -> i32 {
    let addrs = match addr.addr_info(Some(def_serv)) {
        Some(a) => a.to_vec(),
        None => return -2,
    };

    for ai in addrs {
        let ai_family = match ai {
            SocketAddr::V4(_) => libc::AF_INET,
            SocketAddr::V6(_) => libc::AF_INET6,
        };
        if ai_family != family {
            continue;
        }
        let domain = if family == libc::AF_INET6 {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        };
        let Ok(sock) =
            socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))
        else {
            continue;
        };
        let _ = sock.set_reuse_address(true);
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "freebsd",
            target_os = "macos"
        ))]
        if family == libc::AF_INET6 {
            let _ = sock.set_only_v6(false);
        }
        if sock.bind(&ai.into()).is_err() {
            // Distinguish EADDRINUSE like C (-2)
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EADDRINUSE) {
                return -2;
            }
            continue;
        }
        let fd = sock.as_raw_fd();
        if !addr.set_saddr(ai)
            || !addr.set_protocol(libc::IPPROTO_TCP)
            || !addr.set_socktype(libc::SOCK_STREAM)
            || !addr.set_fd(fd, true)
        {
            ctx.error(
                ErrSeverity::Fatal,
                ErrType::Unknown,
                "OpenSocket: Unable to set saddr in address record",
            );
            return -1;
        }
        // Keep socket alive via Addr.fd ownership
        std::mem::forget(sock);
        return fd;
    }
    -1
}

fn server_sock_create_common(
    ctx: &Context,
    mut addr: Option<Addr>,
    def_serv: &str,
    err_ret: &mut ErrSeverity,
) -> Option<Addr> {
    *err_ret = ErrSeverity::Ok;

    if let Some(ref a) = addr {
        if a.fd().is_some_and(|f| f > -1) {
            ctx.error(
                ErrSeverity::Fatal,
                ErrType::Invalid,
                "Invalid Addr record - fd already specified.",
            );
            *err_ret = ErrSeverity::Fatal;
            return None;
        }
    }

    if addr.is_none() {
        addr = Some(Addr::by_wildcard(libc::SOCK_STREAM, def_serv));
    }
    let mut addr = addr?;
    let _ = addr.set_passive(true);

    // Prefer IPv6 then IPv4 (same as C).
    let mut fd = open_socket(ctx, libc::AF_INET6, &mut addr, def_serv);
    if fd == -1 {
        fd = open_socket(ctx, libc::AF_INET, &mut addr, def_serv);
    }
    if fd < 0 {
        ctx.error(
            ErrSeverity::Fatal,
            ErrType::Unknown,
            "OWPServerSockCreate failed",
        );
        *err_ret = ErrSeverity::Fatal;
        return None;
    }

    if unsafe { libc::listen(fd, OWP_LISTEN_BACKLOG) } < 0 {
        ctx.error(
            ErrSeverity::Fatal,
            ErrType::Unknown,
            &format!("listen({fd},{OWP_LISTEN_BACKLOG}) failed"),
        );
        *err_ret = ErrSeverity::Fatal;
        return None;
    }
    Some(addr)
}

/// `OWPServerSockCreate`
pub fn server_sock_create(
    ctx: &Context,
    addr: Option<Addr>,
    err_ret: &mut ErrSeverity,
) -> Option<Addr> {
    server_sock_create_common(ctx, addr, OWP_CONTROL_SERVICE_NAME, err_ret)
}

/// `TWPServerSockCreate`
pub fn twp_server_sock_create(
    ctx: &Context,
    addr: Option<Addr>,
    err_ret: &mut ErrSeverity,
) -> Option<Addr> {
    server_sock_create_common(ctx, addr, TWP_CONTROL_SERVICE_NAME, err_ret)
}

// ---------------------------------------------------------------------------
// ControlAccept
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)] // C-parity body
fn control_accept_common(
    ctx: &Context,
    connfd: i32,
    connsaddr: Option<SocketAddr>,
    mode_offered: u32,
    uptime: OwampNum64,
    twoway: bool,
    err_ret: &mut ErrSeverity,
) -> Option<Rc<RefCell<Control>>> {
    *err_ret = ErrSeverity::Ok;

    let cntrl_rc = match Control::alloc(ctx, twoway) {
        Ok(c) => c,
        Err(e) => {
            *err_ret = e;
            return None;
        },
    };

    let result = (|| {
        {
            let mut cntrl = cntrl_rc.borrow_mut();
            cntrl.sockfd = connfd;
            cntrl.server = true;

            if let Some(sa) = connsaddr {
                let mut remote = Addr::by_sockaddr(sa, libc::SOCK_STREAM, 0);
                let _ = remote.set_fd(connfd, true);
                cntrl.remote_addr = Some(remote);
            } else {
                cntrl.remote_addr = Addr::by_sockfd(connfd, true);
            }
            cntrl.local_addr = Addr::by_local_sockfd(connfd, false);
            if cntrl.local_addr.is_none() {
                *err_ret = ErrSeverity::Fatal;
                return Err(());
            }

            let local_sa = cntrl.local_addr.as_ref().and_then(Addr::saddr);
            let remote_sa = cntrl.remote_addr.as_ref().and_then(Addr::saddr);
            cntrl.ctx.error(
                ErrSeverity::Debug,
                ErrType::Policy,
                &format!("Connection to ({local_sa:?}) from ({remote_sa:?})"),
            );

            let mut challenge = [0u8; 16];
            let mut salt = [0u8; 16];
            if !ctx.random_bytes(&mut challenge) || !ctx.random_bytes(&mut salt) {
                *err_ret = ErrSeverity::Fatal;
                return Err(());
            }

            let Some(timestart) = get_time_of_day(ctx) else {
                *err_ret = ErrSeverity::Fatal;
                return Err(());
            };

            let rc = write_server_greeting(
                &mut cntrl,
                None,
                mode_offered,
                &challenge,
                &salt,
                ctx.pbkdf2_count(),
            );
            if rc < ErrSeverity::Ok {
                *err_ret = rc;
                return Err(());
            }

            if mode_offered == 0 {
                cntrl.ctx.error(
                    ErrSeverity::Warning,
                    ErrType::Policy,
                    "Control request denied: mode == 0",
                );
                return Err(());
            }

            let mut mode = 0u32;
            let mut rawtoken = [0u8; 64];
            let mut client_iv = [0u8; 16];
            let rc =
                read_setup_response(&mut cntrl, None, &mut mode, &mut rawtoken, &mut client_iv);
            if rc < ErrSeverity::Ok {
                *err_ret = rc;
                return Err(());
            }
            cntrl.mode = mode;
            cntrl.read_iv = client_iv;

            let Some(timeend) = get_time_of_day(ctx) else {
                *err_ret = ErrSeverity::Fatal;
                return Err(());
            };
            cntrl.rtt_bound = num64_sub(timeend.owptime, timestart.owptime);

            // Exactly one mode must be chosen.
            let valid = cntrl.mode == OWP_MODE_OPEN
                || (twoway && cntrl.mode == TWP_MODE_MIXED)
                || cntrl.mode == OWP_MODE_AUTHENTICATED
                || cntrl.mode == OWP_MODE_ENCRYPTED;
            if !valid {
                *err_ret = ErrSeverity::Fatal;
                return Err(());
            }
            if (cntrl.mode & mode_offered) == 0 {
                cntrl.ctx.error(
                    ErrSeverity::Warning,
                    ErrType::Policy,
                    &format!("Control request denied: mode not offered ({})", cntrl.mode),
                );
                let _ = write_server_start(&mut cntrl, None, AcceptType::Reject, OwampNum64(0));
                return Err(());
            }

            if (cntrl.mode & OWP_MODE_DOCIPHER_CNTRL) != 0 {
                let uid_end = cntrl.userid_buffer[..80]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(80);
                let userid = std::str::from_utf8(&cntrl.userid_buffer[..uid_end])
                    .unwrap_or("")
                    .to_string();
                let mut e = ErrSeverity::Ok;
                let getkey_success = call_get_pf(&cntrl.ctx, &userid, &mut e);
                if getkey_success.is_none() && e != ErrSeverity::Ok {
                    let _ =
                        write_server_start(&mut cntrl, None, AcceptType::Failure, OwampNum64(0));
                    return Err(());
                }
                let pf = getkey_success.clone().unwrap_or_default();
                let mut token = [0u8; 64];
                if decrypt_token(&pf, &salt, ctx.pbkdf2_count(), &rawtoken, &mut token) < 0 {
                    let _ =
                        write_server_start(&mut cntrl, None, AcceptType::Failure, OwampNum64(0));
                    *err_ret = ErrSeverity::Fatal;
                    return Err(());
                }
                let (chal, aes_key, hmac_key) = rijndael::split_token_plaintext(&token);
                if chal != challenge || getkey_success.is_none() {
                    let _ = write_server_start(&mut cntrl, None, AcceptType::Reject, OwampNum64(0));
                    return Err(());
                }
                cntrl.userid = Some(userid);
                let mut write_iv = [0u8; 16];
                if !cntrl.ctx.random_bytes(&mut write_iv) {
                    let _ =
                        write_server_start(&mut cntrl, None, AcceptType::Failure, OwampNum64(0));
                    return Err(());
                }
                cntrl.write_iv = write_iv;
                // C: store keys on cntrl, then re-read for make_key / HMAC init.
                #[allow(clippy::almost_swapped)]
                {
                    cntrl.aessession_key = aes_key;
                    let aes_key = cntrl.aessession_key;
                    make_key(&mut cntrl, &aes_key);
                    cntrl.hmac_key = hmac_key;
                    let hmac_key = cntrl.hmac_key;
                    cntrl.send_hmac.init(&hmac_key);
                    cntrl.recv_hmac.init(&hmac_key);
                }
            }

            let local_sa = cntrl.local_addr.as_ref().and_then(Addr::saddr);
            let remote_sa = cntrl.remote_addr.as_ref().and_then(Addr::saddr);
            let uid = cntrl.userid.clone();
            if !call_check_control_policy(
                &cntrl,
                cntrl.mode,
                uid.as_deref(),
                local_sa,
                remote_sa,
                err_ret,
            ) {
                if *err_ret > ErrSeverity::Warning {
                    let _ = write_server_start(&mut cntrl, None, AcceptType::Reject, OwampNum64(0));
                } else {
                    let _ =
                        write_server_start(&mut cntrl, None, AcceptType::Failure, OwampNum64(0));
                }
                return Err(());
            }

            let rc = write_server_start(&mut cntrl, None, AcceptType::Accept, uptime);
            if rc < ErrSeverity::Ok {
                *err_ret = rc;
                return Err(());
            }
            cntrl.ctx.error(
                ErrSeverity::Debug,
                ErrType::Policy,
                &format!(
                    "ControlSession accepted from userid({:?}):({remote_sa:?})",
                    cntrl.userid
                ),
            );
        }
        Ok(())
    })();

    if result == Ok(()) {
        Some(cntrl_rc)
    } else {
        let _ = Control::close_rc(cntrl_rc);
        None
    }
}

/// `OWPControlAccept`
pub fn control_accept(
    ctx: &Context,
    connfd: i32,
    connsaddr: Option<SocketAddr>,
    mode_offered: u32,
    uptime: OwampNum64,
    err_ret: &mut ErrSeverity,
) -> Option<Rc<RefCell<Control>>> {
    control_accept_common(ctx, connfd, connsaddr, mode_offered, uptime, false, err_ret)
}

/// `TWPControlAccept`
pub fn twp_control_accept(
    ctx: &Context,
    connfd: i32,
    connsaddr: Option<SocketAddr>,
    mode_offered: u32,
    uptime: OwampNum64,
    err_ret: &mut ErrSeverity,
) -> Option<Rc<RefCell<Control>>> {
    control_accept_common(ctx, connfd, connsaddr, mode_offered, uptime, true, err_ret)
}

// ---------------------------------------------------------------------------
// ProcessTestRequest / TW / StartSessions
// ---------------------------------------------------------------------------

/// `OWPProcessTestRequest`
///
/// # Panics
///
/// Panics if an internal invariant from the C port is violated.
#[allow(clippy::too_many_lines)] // C-parity body
pub fn process_test_request(cntrl: &mut Control) -> ErrSeverity {
    let mut acceptval = AcceptType::Failure;
    let mut tsession = match read_test_request(cntrl, None, &mut acceptval) {
        Ok(t) => t,
        Err(e) => {
            return if (acceptval as i32) < 0 {
                ErrSeverity::Fatal
            } else {
                e.max_ok_warning()
            };
        },
    };

    let rsaddr = tsession.receiver.as_ref().and_then(Addr::saddr);
    let ssaddr = tsession.sender.as_ref().and_then(Addr::saddr);
    let (Some(rsaddr), Some(ssaddr)) = (rsaddr, ssaddr) else {
        cntrl.ctx.error(
            ErrSeverity::Fatal,
            ErrType::Unknown,
            "Invalid addresses from ReadTestRequest",
        );
        let _ = test_session_free_unlinked(cntrl, tsession, acceptval);
        return ErrSeverity::Fatal;
    };

    let mut err_ret = ErrSeverity::Ok;
    if tsession.conf_receiver && create_sid(cntrl, &mut tsession) != 0 {
        acceptval = AcceptType::Failure;
        let _ = write_accept_session(cntrl, None, acceptval, 0, None);
        let _ = test_session_free_unlinked(cntrl, tsession, acceptval);
        return ErrSeverity::Warning;
    }

    tsession.sctx = ScheduleContext::create(&cntrl.ctx, &tsession.sid, &tsession.test_spec);
    if tsession.sctx.is_none() {
        cntrl.ctx.error(
            ErrSeverity::Fatal,
            ErrType::Unknown,
            "Unable to init schedule generator",
        );
        acceptval = AcceptType::Failure;
        let _ = write_accept_session(cntrl, None, acceptval, 0, None);
        let _ = test_session_free_unlinked(cntrl, tsession, acceptval);
        return ErrSeverity::Warning;
    }

    let mut port = 0u16;

    if tsession.conf_receiver {
        if tsession.conf_sender {
            // This implementation only configures "local" test endpoints.
            acceptval = AcceptType::Unsupported;
            let _ = write_accept_session(cntrl, None, acceptval, 0, None);
            let _ = test_session_free_unlinked(cntrl, tsession, acceptval);
            return ErrSeverity::Warning;
        }
        let spec = tsession.test_spec.clone();
        if !call_check_test_policy(
            cntrl,
            false,
            rsaddr,
            ssaddr,
            &spec,
            &mut tsession.closure,
            &mut err_ret,
        ) {
            if err_ret < ErrSeverity::Ok {
                let _ = test_session_free_unlinked(cntrl, tsession, acceptval);
                return err_ret;
            }
            cntrl
                .ctx
                .error(ErrSeverity::Warning, ErrType::Policy, "Test not allowed");
            acceptval = AcceptType::Reject;
            let _ = write_accept_session(cntrl, None, acceptval, 0, None);
            let _ = test_session_free_unlinked(cntrl, tsession, acceptval);
            return ErrSeverity::Warning;
        }
        let recv = tsession.receiver.clone().unwrap();
        if !endpoint_init(cntrl, &mut tsession, &recv, None, &mut acceptval, false) {
            if err_ret >= ErrSeverity::Warning {
                let _ = write_accept_session(cntrl, None, acceptval, 0, None);
            }
            let _ = test_session_free_unlinked(cntrl, tsession, acceptval);
            return err_ret.max_ok_warning();
        }
    }

    if tsession.conf_sender {
        // Open-mode DoS check: receiver must equal control client.
        if (cntrl.mode & OWP_MODE_DOCIPHER_CNTRL) == 0 {
            let csaddr = cntrl.remote_addr.as_ref().and_then(Addr::saddr);
            if csaddr.is_none_or(|c| !same_ip(c, rsaddr)) {
                cntrl.ctx.error(
                    ErrSeverity::Warning,
                    ErrType::Policy,
                    "Test Denied: OpenMode receive_addr != control_client",
                );
                acceptval = AcceptType::Reject;
                let _ = write_accept_session(cntrl, None, acceptval, 0, None);
                let _ = test_session_free_unlinked(cntrl, tsession, acceptval);
                return ErrSeverity::Warning;
            }
        }
        let spec = tsession.test_spec.clone();
        if !call_check_test_policy(
            cntrl,
            true,
            ssaddr,
            rsaddr,
            &spec,
            &mut tsession.closure,
            &mut err_ret,
        ) {
            if err_ret < ErrSeverity::Ok {
                let _ = test_session_free_unlinked(cntrl, tsession, acceptval);
                return err_ret;
            }
            cntrl
                .ctx
                .error(ErrSeverity::Warning, ErrType::Policy, "Test not allowed");
            acceptval = AcceptType::Reject;
            let _ = write_accept_session(cntrl, None, acceptval, 0, None);
            let _ = test_session_free_unlinked(cntrl, tsession, acceptval);
            return ErrSeverity::Warning;
        }
        let send_addr = tsession.sender.clone().unwrap();
        if !endpoint_init(cntrl, &mut tsession, &send_addr, None, &mut acceptval, true)
            || !endpoint_init_hook(cntrl, &mut tsession, &mut acceptval)
        {
            if err_ret >= ErrSeverity::Warning {
                let _ = write_accept_session(cntrl, None, acceptval, 0, None);
            }
            let _ = test_session_free_unlinked(cntrl, tsession, acceptval);
            return ErrSeverity::Warning;
        }
        port = tsession.sender.as_ref().map_or(0, Addr::port);
    }

    if tsession.conf_receiver {
        if !endpoint_init_hook(cntrl, &mut tsession, &mut acceptval) {
            if err_ret >= ErrSeverity::Warning {
                let _ = write_accept_session(cntrl, None, acceptval, 0, None);
            }
            let _ = test_session_free_unlinked(cntrl, tsession, acceptval);
            return ErrSeverity::Warning;
        }
        port = tsession.receiver.as_ref().map_or(0, Addr::port);
    }

    let sid = tsession.sid;
    let rc = write_accept_session(cntrl, None, AcceptType::Accept, port, Some(&sid));
    if rc < ErrSeverity::Ok {
        let _ = test_session_free_unlinked(cntrl, tsession, acceptval);
        return rc;
    }
    cntrl.tests.push(*tsession);
    ErrSeverity::Ok
}

/// `OWPProcessTestRequestTW`
///
/// # Panics
///
/// Panics if an internal invariant from the C port is violated.
pub fn process_test_request_tw(cntrl: &mut Control) -> ErrSeverity {
    let mut acceptval = AcceptType::Failure;
    let mut tsession = match read_test_request(cntrl, None, &mut acceptval) {
        Ok(t) => t,
        Err(e) => {
            return if (acceptval as i32) < 0 {
                ErrSeverity::Fatal
            } else {
                e
            };
        },
    };

    let rsaddr = tsession.receiver.as_ref().and_then(Addr::saddr);
    let ssaddr = tsession.sender.as_ref().and_then(Addr::saddr);
    let (Some(rsaddr), Some(ssaddr)) = (rsaddr, ssaddr) else {
        cntrl.ctx.error(
            ErrSeverity::Fatal,
            ErrType::Unknown,
            "Invalid addresses from ReadTestRequest",
        );
        let _ = test_session_free_unlinked(cntrl, tsession, acceptval);
        return ErrSeverity::Fatal;
    };

    let mut err_ret = ErrSeverity::Ok;
    if create_sid(cntrl, &mut tsession) != 0 {
        acceptval = AcceptType::Failure;
        let _ = write_accept_session(cntrl, None, acceptval, 0, None);
        let _ = test_session_free_unlinked(cntrl, tsession, acceptval);
        return ErrSeverity::Warning;
    }

    let spec = tsession.test_spec.clone();
    if !call_check_test_policy(
        cntrl,
        true,
        rsaddr,
        ssaddr,
        &spec,
        &mut tsession.closure,
        &mut err_ret,
    ) {
        if err_ret < ErrSeverity::Ok {
            let _ = test_session_free_unlinked(cntrl, tsession, acceptval);
            return err_ret;
        }
        cntrl
            .ctx
            .error(ErrSeverity::Warning, ErrType::Policy, "Test not allowed");
        acceptval = AcceptType::Reject;
        let _ = write_accept_session(cntrl, None, acceptval, 0, None);
        let _ = test_session_free_unlinked(cntrl, tsession, acceptval);
        return ErrSeverity::Warning;
    }

    let recv = tsession.receiver.clone().unwrap();
    if !endpoint_init(cntrl, &mut tsession, &recv, None, &mut acceptval, false)
        || !endpoint_init_hook(cntrl, &mut tsession, &mut acceptval)
    {
        if err_ret >= ErrSeverity::Warning {
            let _ = write_accept_session(cntrl, None, acceptval, 0, None);
        }
        let _ = test_session_free_unlinked(cntrl, tsession, acceptval);
        return ErrSeverity::Warning;
    }

    let port = tsession.receiver.as_ref().map_or(0, Addr::port);
    if port == 0 {
        cntrl.ctx.error(
            ErrSeverity::Fatal,
            ErrType::Unknown,
            "Failed to determine test port for session",
        );
        acceptval = AcceptType::Failure;
        let _ = write_accept_session(cntrl, None, acceptval, 0, None);
        let _ = test_session_free_unlinked(cntrl, tsession, acceptval);
        return ErrSeverity::Warning;
    }

    let sid = tsession.sid;
    let rc = write_accept_session(cntrl, None, AcceptType::Accept, port, Some(&sid));
    if rc < ErrSeverity::Ok {
        let _ = test_session_free_unlinked(cntrl, tsession, acceptval);
        return rc;
    }
    cntrl.tests.push(*tsession);
    ErrSeverity::Ok
}

/// `OWPProcessStartSessions`
pub fn process_start_sessions(cntrl: &mut Control) -> ErrSeverity {
    let mut err2 = ErrSeverity::Ok;
    let rc = read_start_sessions(cntrl, None);
    if rc < ErrSeverity::Ok {
        return fail_control_session(cntrl, rc);
    }
    for t in &mut cntrl.tests {
        if let Some(ref mut ep) = t.endpoint {
            if let Err(e) = endpoint_start(ep) {
                let _ = write_start_ack(cntrl, None, AcceptType::Failure);
                return fail_control_session(cntrl, e);
            }
            err2 = err2.min(ErrSeverity::Ok);
        }
    }
    if write_start_ack(cntrl, None, AcceptType::Accept) < ErrSeverity::Ok {
        return fail_control_session(cntrl, ErrSeverity::Fatal);
    }
    err2
}

// ---------------------------------------------------------------------------
// ProcessFetchSession
// ---------------------------------------------------------------------------

/// `OWPProcessFetchSession`
#[allow(clippy::too_many_lines)] // C-parity body
pub fn process_fetch_session(cntrl: &mut Control) -> ErrSeverity {
    let (begin, end, sid) = match read_fetch_session(cntrl) {
        Ok(v) => v,
        Err(e) => return fail_control_session(cntrl, e),
    };

    let lsaddr = cntrl.local_addr.as_ref().and_then(Addr::saddr);
    let rsaddr = cntrl.remote_addr.as_ref().and_then(Addr::saddr);
    let (Some(lsaddr), Some(rsaddr)) = (lsaddr, rsaddr) else {
        return fail_control_session(cntrl, ErrSeverity::Fatal);
    };

    let mut closure: Option<Box<dyn std::any::Any>> = None;
    let mut err = ErrSeverity::Ok;
    if !call_check_fetch_policy(
        cntrl,
        lsaddr,
        rsaddr,
        begin,
        end,
        &sid,
        &mut closure,
        &mut err,
    ) {
        if err < ErrSeverity::Ok {
            return fail_control_session(cntrl, err);
        }
        cntrl
            .ctx
            .error(ErrSeverity::Warning, ErrType::Policy, "Fetch not allowed");
        return fetch_reject(cntrl, None, closure.as_deref(), AcceptType::Reject);
    }

    let mut fname = PathBuf::new();
    let Some(mut fp) = call_open_file(cntrl, closure.as_deref(), &sid, &mut fname) else {
        return fetch_reject(cntrl, None, closure.as_deref(), AcceptType::Reject);
    };

    let mut lock_tries = 0u32;
    let mut finish_tries = 0u32;

    let fhdr = loop {
        let Some(mut fhdr) = read_data_header_initial(&mut fp) else {
            cntrl.ctx.error(
                ErrSeverity::Fatal,
                ErrType::Unknown,
                &format!("_OWPReadDataHeaderInitial(\"{}\") failed", fname.display()),
            );
            return fetch_failed(cntrl, Some(fp), closure.as_deref());
        };

        if fhdr.version != 3 {
            cntrl.ctx.error(
                ErrSeverity::Fatal,
                ErrType::Invalid,
                &format!(
                    "OWPProcessFetchSession(\"{}\"): Invalid file version: {}",
                    fname.display(),
                    fhdr.version
                ),
            );
            return fetch_failed(cntrl, Some(fp), closure.as_deref());
        }
        if fhdr.finished == SessionFinished::Error as u32 {
            cntrl.ctx.error(
                ErrSeverity::Fatal,
                ErrType::Invalid,
                &format!(
                    "OWPProcessFetchSession(\"{}\"): Invalid file!",
                    fname.display()
                ),
            );
            return fetch_failed(cntrl, Some(fp), closure.as_deref());
        }

        if fhdr.finished != SessionFinished::Normal as u32 {
            // Try advisory read-lock; on contention retry with backoff.
            let locked = try_fcntl_rdlock(&fp);
            if !locked {
                if lock_tries > 4 {
                    return fetch_failed(cntrl, Some(fp), closure.as_deref());
                }
                let _ = fp.flush();
                thread::sleep(Duration::from_secs(1u64 << lock_tries));
                lock_tries += 1;
                continue;
            }
            // Re-read after lock.
            let Some(fhdr2) = read_data_header_initial(&mut fp) else {
                return fetch_failed(cntrl, Some(fp), closure.as_deref());
            };
            fhdr = fhdr2;

            if begin == 0 && end == 0xffff_ffff && fhdr.finished != SessionFinished::Normal as u32 {
                if finish_tries > 4 {
                    let _ = try_fcntl_unlock(&fp);
                    return fetch_reject(cntrl, Some(fp), closure.as_deref(), AcceptType::Reject);
                }
                let _ = fp.flush();
                let _ = try_fcntl_unlock(&fp);
                thread::sleep(Duration::from_secs(1u64 << finish_tries));
                finish_tries += 1;
                continue;
            }

            if fhdr.num_datarecs == 0 && fhdr.oset_datarecs <= fhdr.file_size {
                fhdr.num_datarecs =
                    ((fhdr.file_size - fhdr.oset_datarecs) / u64::from(fhdr.rec_size)) as u32;
            }
        }
        break fhdr;
    };

    let mut dodata = DoDataState {
        err: ErrSeverity::Ok,
        rec_size: fhdr.rec_size,
        send: false,
        begin,
        end,
        inbuf: 0,
        count: 0,
        maxiseen: 0,
    };

    let mut sendrecs: u32;
    if fhdr.finished == SessionFinished::Normal as u32 && begin == 0 && end == 0xffff_ffff {
        sendrecs = fhdr.num_datarecs;
    } else {
        if fp.seek(SeekFrom::Start(fhdr.oset_datarecs)).is_err() {
            return fetch_failed(cntrl, Some(fp), closure.as_deref());
        }
        let rc = parse_records(
            &mut fp,
            fhdr.num_datarecs,
            fhdr.version,
            fhdr.rec_size as usize,
            |rec| dodata.handle_record(cntrl, rec),
        );
        if rc != ErrSeverity::Ok {
            return fetch_failed(cntrl, Some(fp), closure.as_deref());
        }
        sendrecs = dodata.count as u32;
        dodata.count = 0;

        if fhdr.finished != SessionFinished::Normal as u32 && dodata.maxiseen < end {
            dodata.end = dodata.maxiseen;
            if fp.seek(SeekFrom::Start(fhdr.oset_datarecs)).is_err() {
                return fetch_failed(cntrl, Some(fp), closure.as_deref());
            }
            let rc = parse_records(
                &mut fp,
                fhdr.num_datarecs,
                fhdr.version,
                fhdr.rec_size as usize,
                |rec| dodata.handle_record(cntrl, rec),
            );
            if rc != ErrSeverity::Ok {
                return fetch_failed(cntrl, Some(fp), closure.as_deref());
            }
            sendrecs = dodata.count as u32;
            dodata.count = 0;
        }
    }

    let (next_seqno, num_skiprecs) = if fhdr.finished != 0 {
        (fhdr.next_seqno, fhdr.num_skiprecs)
    } else {
        (0, 0)
    };

    if fp.seek(SeekFrom::Start(OWP_TESTREC_OFFSET as u64)).is_err() {
        return fetch_failed(cntrl, Some(fp), closure.as_deref());
    }

    let acceptval = AcceptType::Accept;
    let err = write_fetch_ack(
        cntrl,
        acceptval,
        fhdr.finished as u8,
        next_seqno,
        num_skiprecs,
        sendrecs,
    );
    if err < ErrSeverity::Ok {
        call_close_file(cntrl, closure.as_deref(), fp, AcceptType::Failure);
        return fail_control_session(cntrl, err);
    }

    // Determine TestReq size including slots.
    let mut tr_size = if fhdr.oset_skiprecs != 0 {
        fhdr.oset_skiprecs
    } else {
        fhdr.oset_datarecs
    };
    if fhdr.oset_datarecs != 0 {
        tr_size = tr_size.min(fhdr.oset_datarecs);
    }
    if tr_size < OWP_TESTREC_OFFSET as u64 {
        call_close_file(cntrl, closure.as_deref(), fp, AcceptType::Failure);
        return fail_control_session(cntrl, ErrSeverity::Fatal);
    }
    tr_size -= OWP_TESTREC_OFFSET as u64;
    if tr_size % OWP_RIJNDAEL_BLOCK_SIZE as u64 != 0 {
        cntrl.ctx.error(
            ErrSeverity::Fatal,
            ErrType::Unknown,
            &format!(
                "OWPProcessFetchSession: Invalid TestReq in file \"{}\"",
                fname.display()
            ),
        );
    }

    // TestRequestPreamble: 7 blocks; last is HMAC — recompute.
    {
        let mut buf = [0u8; 7 * OWP_RIJNDAEL_BLOCK_SIZE];
        if fp.read_exact(&mut buf).is_err() {
            call_close_file(cntrl, closure.as_deref(), fp, AcceptType::Failure);
            return fail_control_session(cntrl, ErrSeverity::Fatal);
        }
        send_hmac_add(cntrl, &buf[..96], 6);
        let mut digest = [0u8; 16];
        send_hmac_digest_clear(cntrl, &mut digest);
        buf[96..112].copy_from_slice(&digest);
        if send_blocks_intr(cntrl, &mut buf, 7, None) != 7 {
            call_close_file(cntrl, closure.as_deref(), fp, AcceptType::Failure);
            return fail_control_session(cntrl, ErrSeverity::Fatal);
        }
        tr_size = tr_size.saturating_sub((OWP_RIJNDAEL_BLOCK_SIZE * 7) as u64);
    }

    // Remaining TestReq slots (except last HMAC block).
    while tr_size > OWP_RIJNDAEL_BLOCK_SIZE as u64 {
        let mut buf = [0u8; OWP_RIJNDAEL_BLOCK_SIZE];
        if fp.read_exact(&mut buf).is_err() {
            call_close_file(cntrl, closure.as_deref(), fp, AcceptType::Failure);
            return fail_control_session(cntrl, ErrSeverity::Fatal);
        }
        send_hmac_add(cntrl, &buf, 1);
        if send_blocks_intr(cntrl, &mut buf, 1, None) != 1 {
            call_close_file(cntrl, closure.as_deref(), fp, AcceptType::Failure);
            return fail_control_session(cntrl, ErrSeverity::Fatal);
        }
        tr_size -= OWP_RIJNDAEL_BLOCK_SIZE as u64;
    }
    {
        let mut buf = [0u8; OWP_RIJNDAEL_BLOCK_SIZE];
        send_hmac_digest_clear(cntrl, &mut buf);
        if send_blocks_intr(cntrl, &mut buf, 1, None) != 1 {
            call_close_file(cntrl, closure.as_deref(), fp, AcceptType::Failure);
            return fail_control_session(cntrl, ErrSeverity::Fatal);
        }
    }

    // Skip records (if finished).
    if fhdr.finished != 0 && fhdr.num_skiprecs != 0 {
        if fp.seek(SeekFrom::Start(fhdr.oset_skiprecs)).is_err() {
            call_close_file(cntrl, closure.as_deref(), fp, AcceptType::Failure);
            return fail_control_session(cntrl, ErrSeverity::Fatal);
        }
        let mut skip_bytes = u64::from(fhdr.num_skiprecs) * OWP_SKIPREC_SIZE as u64;
        while skip_bytes > OWP_RIJNDAEL_BLOCK_SIZE as u64 {
            let mut buf = [0u8; OWP_RIJNDAEL_BLOCK_SIZE];
            if fp.read_exact(&mut buf).is_err() {
                call_close_file(cntrl, closure.as_deref(), fp, AcceptType::Failure);
                return fail_control_session(cntrl, ErrSeverity::Fatal);
            }
            send_hmac_add(cntrl, &buf, 1);
            if send_blocks_intr(cntrl, &mut buf, 1, None) != 1 {
                call_close_file(cntrl, closure.as_deref(), fp, AcceptType::Failure);
                return fail_control_session(cntrl, ErrSeverity::Fatal);
            }
            skip_bytes -= OWP_RIJNDAEL_BLOCK_SIZE as u64;
        }
        if skip_bytes > 0 {
            let mut buf = [0u8; OWP_RIJNDAEL_BLOCK_SIZE];
            if fp.read_exact(&mut buf[..skip_bytes as usize]).is_err() {
                call_close_file(cntrl, closure.as_deref(), fp, AcceptType::Failure);
                return fail_control_session(cntrl, ErrSeverity::Fatal);
            }
            send_hmac_add(cntrl, &buf, 1);
            if send_blocks_intr(cntrl, &mut buf, 1, None) != 1 {
                call_close_file(cntrl, closure.as_deref(), fp, AcceptType::Failure);
                return fail_control_session(cntrl, ErrSeverity::Fatal);
            }
        }
    }

    // HMAC between skips & data.
    {
        let mut buf = [0u8; OWP_RIJNDAEL_BLOCK_SIZE];
        send_hmac_digest_clear(cntrl, &mut buf);
        if send_blocks_intr(cntrl, &mut buf, 1, None) != 1 {
            call_close_file(cntrl, closure.as_deref(), fp, AcceptType::Failure);
            return fail_control_session(cntrl, ErrSeverity::Fatal);
        }
    }

    if sendrecs != 0 {
        if fp.seek(SeekFrom::Start(fhdr.oset_datarecs)).is_err() {
            call_close_file(cntrl, closure.as_deref(), fp, AcceptType::Failure);
            return fail_control_session(cntrl, ErrSeverity::Fatal);
        }
        dodata.send = true;
        dodata.count = 0;
        dodata.inbuf = 0;
        let rc = parse_records(
            &mut fp,
            fhdr.num_datarecs,
            fhdr.version,
            fhdr.rec_size as usize,
            |rec| dodata.handle_record(cntrl, rec),
        );
        if rc != ErrSeverity::Ok || dodata.count != u64::from(sendrecs) {
            call_close_file(cntrl, closure.as_deref(), fp, AcceptType::Failure);
            return fail_control_session(cntrl, ErrSeverity::Fatal);
        }
        if dodata.inbuf != 0 {
            let used = dodata.inbuf as usize * fhdr.rec_size as usize;
            let blks = (used / OWP_RIJNDAEL_BLOCK_SIZE) + 1;
            let total = blks * OWP_RIJNDAEL_BLOCK_SIZE;
            if used < total {
                cntrl.msg[used..total].fill(0);
            }
            let mut block = vec![0u8; total];
            block.copy_from_slice(&cntrl.msg[..total]);
            send_hmac_add(cntrl, &block, blks as u32);
            if send_blocks_intr(cntrl, &mut block, blks as i32, None) != blks as i32 {
                call_close_file(cntrl, closure.as_deref(), fp, AcceptType::Failure);
                return fail_control_session(cntrl, ErrSeverity::Fatal);
            }
        }
    }

    call_close_file(cntrl, closure.as_deref(), fp, AcceptType::Accept);

    {
        let mut buf = [0u8; OWP_RIJNDAEL_BLOCK_SIZE];
        send_hmac_digest_clear(cntrl, &mut buf);
        if send_blocks_intr(cntrl, &mut buf, 1, None) != 1 {
            return fail_control_session(cntrl, ErrSeverity::Fatal);
        }
    }

    cntrl.state &= !STATE_FETCHING;
    cntrl.state |= STATE_REQUEST;
    ErrSeverity::Ok
}

fn fetch_reject(
    cntrl: &mut Control,
    fp: Option<File>,
    closure: Option<&dyn std::any::Any>,
    acceptval: AcceptType,
) -> ErrSeverity {
    if let Some(fp) = fp {
        call_close_file(cntrl, closure, fp, acceptval);
    }
    let err = write_fetch_ack(cntrl, acceptval, 0, 0, 0, 0);
    if err < ErrSeverity::Ok {
        return fail_control_session(cntrl, err);
    }
    ErrSeverity::Warning
}

fn fetch_failed(
    cntrl: &mut Control,
    fp: Option<File>,
    closure: Option<&dyn std::any::Any>,
) -> ErrSeverity {
    fetch_reject(cntrl, fp, closure, AcceptType::Failure)
}

fn try_fcntl_rdlock(fp: &File) -> bool {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let mut flk: libc::flock = unsafe { std::mem::zeroed() };
        flk.l_type = libc::F_RDLCK;
        flk.l_whence = libc::SEEK_SET as i16;
        flk.l_start = 0;
        flk.l_len = 0;
        let rc = unsafe { libc::fcntl(fp.as_raw_fd(), libc::F_SETLK, &flk) };
        rc == 0
    }
    #[cfg(not(unix))]
    {
        let _ = fp;
        true
    }
}

fn try_fcntl_unlock(fp: &File) -> bool {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let mut flk: libc::flock = unsafe { std::mem::zeroed() };
        flk.l_type = libc::F_UNLCK;
        flk.l_whence = libc::SEEK_SET as i16;
        flk.l_start = 0;
        flk.l_len = 0;
        let rc = unsafe { libc::fcntl(fp.as_raw_fd(), libc::F_SETLK, &flk) };
        rc == 0
    }
    #[cfg(not(unix))]
    {
        let _ = fp;
        true
    }
}

// ---------------------------------------------------------------------------
// UnexpectedRequestType
// ---------------------------------------------------------------------------

/// `OWPUnexpectedRequestType`
pub fn unexpected_request_type(cntrl: &mut Control) -> ErrSeverity {
    // OWAMP: close the control session.
    if !cntrl.twoway {
        return ErrSeverity::Fatal;
    }
    // TWAMP: reply Unsupported and stay in request state.
    cntrl.state |= STATE_ACCEPT_SESSION;
    let rc = write_accept_session(cntrl, None, AcceptType::Unsupported, 0, None);
    cntrl.state = STATE_REQUEST;
    rc
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn same_ip(a: SocketAddr, b: SocketAddr) -> bool {
    match (a, b) {
        (SocketAddr::V4(x), SocketAddr::V4(y)) => x.ip() == y.ip(),
        (SocketAddr::V6(x), SocketAddr::V6(y)) => x.ip() == y.ip(),
        _ => false,
    }
}

trait SeverityExt {
    fn max_ok_warning(self) -> Self;
}

impl SeverityExt for ErrSeverity {
    fn max_ok_warning(self) -> Self {
        if self < Self::Warning {
            Self::Warning
        } else {
            self
        }
    }
}

#[allow(dead_code)]
fn _keep_api() {
    let _: fn(&Control, i32, &str) -> bool = api::socket_interface_bind;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_ip_v4() {
        let a: SocketAddr = "1.2.3.4:5".parse().unwrap();
        let b: SocketAddr = "1.2.3.4:9".parse().unwrap();
        assert!(same_ip(a, b));
    }

    #[test]
    fn session_finished_map() {
        assert_eq!(session_finished_from_u32(1), SessionFinished::Normal as u32);
        assert_eq!(session_finished_from_u32(99), SessionFinished::Error as u32);
    }

    #[test]
    fn open_socket_unresolvable_host_returns_negative_two() {
        let ctx = Context::create().expect("ctx");
        let mut addr = Addr::by_node("owamp-invalid-host-xyzzy.invalid.", Some("0"));
        let rc = open_socket(&ctx, libc::AF_INET, &mut addr, "0");
        assert_eq!(rc, -2);
    }

    #[test]
    fn read_fetch_session_and_write_fetch_ack_socketpair() {
        let mut fds = [0i32; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
            0
        );
        let ctx = Context::create().expect("ctx");
        let sid = [0x66u8; 16];

        let client_rc = Control::alloc(&ctx, false).expect("client");
        {
            let mut c = client_rc.borrow_mut();
            c.sockfd = fds[1];
            c.mode = crate::owampP::OWP_MODE_OPEN;
            c.state = STATE_REQUEST;
            assert_eq!(
                api::write_fetch_session(&mut c, None, 3, 17, &sid),
                ErrSeverity::Ok
            );
        }

        let server_rc = Control::alloc(&ctx, false).expect("server");
        let (begin, end, got_sid) = {
            let mut s = server_rc.borrow_mut();
            s.sockfd = fds[0];
            s.mode = crate::owampP::OWP_MODE_OPEN;
            s.state = STATE_REQUEST | crate::context::STATE_FETCH_SESSION;
            assert_eq!(crate::context::read_fully(s.sockfd, &mut s.msg[..16]), 16);
            read_fetch_session(&mut s).expect("read_fetch_session")
        };
        assert_eq!((begin, end, got_sid), (3, 17, sid));

        {
            let mut s = server_rc.borrow_mut();
            assert_eq!(
                write_fetch_ack(&mut s, AcceptType::Accept, 0, 0, 0, 12),
                ErrSeverity::Ok
            );
        }

        let mut accept = AcceptType::Invalid;
        let (mut finished, mut next, mut nskip, mut ndata) = (0u8, 0u32, 0u32, 0u32);
        {
            let mut c = client_rc.borrow_mut();
            assert_eq!(
                api::read_fetch_ack(
                    &mut c,
                    None,
                    &mut accept,
                    &mut finished,
                    &mut next,
                    &mut nskip,
                    &mut ndata
                ),
                ErrSeverity::Ok
            );
            assert_eq!(accept, AcceptType::Accept);
            assert_eq!((finished, next, nskip, ndata), (0, 0, 0, 12));
        }

        server_rc.borrow_mut().sockfd = -1;
        client_rc.borrow_mut().sockfd = -1;
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        let _ = Control::close_rc(client_rc);
        let _ = Control::close_rc(server_rc);
        ctx.free();
    }

    #[test]
    fn do_data_records_range_and_maxiseen() {
        use crate::api::DataRec;
        use crate::owamp::{OwampNum64, OwampTimeStamp};

        let ctx = Context::create().expect("ctx");
        let cntrl_rc = Control::alloc(&ctx, false).expect("cntrl");
        let mut cntrl = cntrl_rc.borrow_mut();
        let mut st = DoDataState {
            err: ErrSeverity::Ok,
            rec_size: crate::protocol::DATARECV3_SIZE as u32,
            send: false,
            begin: 2,
            end: 4,
            inbuf: 0,
            count: 0,
            maxiseen: 0,
        };
        let mk = |seq: u32, lost: bool| DataRec {
            seq_no: seq,
            send: OwampTimeStamp::default(),
            recv: OwampTimeStamp {
                owptime: if lost { OwampNum64(0) } else { OwampNum64(1) },
                sync: false,
                multiplier: 0,
                scale: 0,
            },
            ttl: 64,
        };
        assert_eq!(do_data_records(&mut st, &mut cntrl, &mk(1, false)), 0);
        assert_eq!(st.count, 0);
        assert_eq!(do_data_records(&mut st, &mut cntrl, &mk(3, false)), 0);
        assert_eq!(st.count, 1);
        assert_eq!(st.maxiseen, 3);
        assert_eq!(do_data_records(&mut st, &mut cntrl, &mk(9, false)), 0);
        assert_eq!(st.count, 1);
        assert_eq!(st.maxiseen, 9);
        assert_eq!(do_data_records(&mut st, &mut cntrl, &mk(10, true)), 0);
        assert_eq!(st.maxiseen, 9);
    }
}
