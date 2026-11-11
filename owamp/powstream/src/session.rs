//! Dual-control session lifecycle — port of `Setup/Reset/Fetch/write_session`.

use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::FromRawFd;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::thread;
use std::time::Duration;

use owamp::api::{
    self, parse_port_range, stop_sessions, DataRec, PortRange, SessionFinishedType, SessionHeader,
    SkipRec,
};
use owamp::capi::{control_open_interface, fetch_session, session_request_ex, start_sessions};
use owamp::context::{
    get_time_of_day, ulong_to_num64, AcceptType, Addr, Context, Control, ErrSeverity, Slot,
    SlotType, TestSpec, OWP_DETACH_PROCESSES, OWP_END_DELAY, OWP_INTERRUPT_IO, OWP_IPV4_ONLY,
    OWP_IPV6_ONLY, OWP_TEST_PORT_RANGE,
};
use owamp::schedule::ScheduleContext;
use owamp::stats::Stats;
use owamp::{
    OwampNum64, OwampSid, OwampSlot, OwampSlotRandExp, OwampTestSpec, OwampTimeStamp, OWP_FILE_EXT,
    OWP_NAME_SEP,
};
use tracing::{error, info, warn};

use crate::powstreamP::{
    format_tstamp, AppCtx, Options, POWLOCK, POW_INC_EXT, POW_SUM_EXT, SETUP_ESTIMATE,
};

/// Per-connection state (`pow_cntrl_rec`).
pub struct PowCntrl {
    pub ctx: Context,
    pub cntrl: Option<Rc<RefCell<Control>>>,
    pub fetch: Option<Rc<RefCell<Control>>>,
    pub sctx: Option<ScheduleContext>,
    pub sid: OwampSid,
    pub next_session_start: Option<OwampNum64>,
    pub next_session_start_num: OwampNum64,
    pub next_session_end_num: OwampNum64,
    pub current_session_start_num: OwampNum64,
    pub current_session_end_num: OwampNum64,
    pub prev_runtime: OwampTimeStamp,
    /// Reader side of the dual session file (C `fp`) — independent offset from `testfp`.
    pub fp: Option<File>,
    /// Writer / endpoint / fetch side (C `testfp`) — passed to `session_request_ex`.
    pub testfp: Option<File>,
    pub num_packets: u32,
    pub call_stop: bool,
    pub session_started: bool,
}

impl PowCntrl {
    pub fn new(ctx: Context) -> Self {
        Self {
            ctx,
            cntrl: None,
            fetch: None,
            sctx: None,
            sid: [0u8; 16],
            next_session_start: None,
            next_session_start_num: OwampNum64::ZERO,
            next_session_end_num: OwampNum64::ZERO,
            current_session_start_num: OwampNum64::ZERO,
            current_session_end_num: OwampNum64::ZERO,
            prev_runtime: OwampTimeStamp::default(),
            fp: None,
            testfp: None,
            num_packets: 0,
            call_stop: false,
            session_started: false,
        }
    }

    fn close_cntrl(&mut self) {
        if let Some(rc) = self.cntrl.take() {
            let _ = Control::close_rc(rc);
        }
    }

    fn close_fetch(&mut self) {
        if let Some(rc) = self.fetch.take() {
            let _ = Control::close_rc(rc);
        }
    }

    fn close_data(&mut self) {
        self.fp = None;
        self.testfp = None;
    }
}

/// Shared streaming state used by the main loop.
pub struct StreamState {
    pub app: AppCtx,
    pub ctx: Context,
    pub tspec: OwampTestSpec,
    pub dirpath: PathBuf,
    #[allow(dead_code)]
    pub file_offset: usize,
    #[allow(dead_code)]
    pub ext_offset: usize,
    pub num_summaries: u32,
    pub iotime: u32,
    pub first_time: bool,
}

impl StreamState {
    pub fn ctx_test_spec(&self, start: OwampNum64) -> TestSpec {
        owamp_to_ctx_tspec(&self.tspec, start)
    }
}

pub fn owamp_to_ctx_tspec(ts: &OwampTestSpec, start: OwampNum64) -> TestSpec {
    TestSpec {
        start_time: start,
        loss_timeout: ts.loss_timeout,
        type_p: ts.type_p,
        packet_size_padding: ts.packet_size_padding,
        npackets: ts.npackets,
        nslots: ts.slots.len() as u32,
        slots: ts
            .slots
            .iter()
            .map(|s| Slot {
                slot_type: match s {
                    OwampSlot::RandExp(_) => SlotType::RandExp,
                    OwampSlot::Literal(_) => SlotType::Literal,
                },
                time: s.mean_delay(),
            })
            .collect(),
    }
}

pub fn build_tspec(opt: &Options) -> OwampTestSpec {
    OwampTestSpec {
        start_time: OwampNum64::ZERO,
        loss_timeout: owamp::arithm64::double_to_num64(opt.loss_threshold),
        type_p: 0,
        packet_size_padding: opt.padding.min(crate::powstreamP::MAX_PADDING_SIZE),
        npackets: opt.num_packets,
        slots: vec![OwampSlot::RandExp(OwampSlotRandExp {
            mean: owamp::arithm64::double_to_num64(opt.mean_wait),
        })],
    }
}

/// Acquire exclusive directory lock (`.powlock`).
pub fn lock_savedir(dirpath: &Path) -> Result<File, String> {
    let lockpath = dirpath.join(POWLOCK);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lockpath)
        .map_err(|e| format!("open({}): {e}", lockpath.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        let mut flk: libc::flock = unsafe { std::mem::zeroed() };
        flk.l_type = libc::F_WRLCK;
        flk.l_whence = libc::SEEK_SET as i16;
        let rc = unsafe { libc::fcntl(fd, libc::F_SETLK, &flk) };
        if rc < 0 {
            return Err(format!(
                "Unable to lock file {}: {}",
                lockpath.display(),
                std::io::Error::last_os_error()
            ));
        }
        let pid = std::process::id();
        let bytes = pid.to_ne_bytes();
        // Best-effort write of pid (ignore short writes).
        let _ = unsafe { libc::pwrite(fd, bytes.as_ptr() as *const libc::c_void, bytes.len(), 0) };
    }
    Ok(file)
}

fn sleep_num64(delta: OwampNum64) {
    let ts = owamp::arithm64::num64_to_timespec(delta);
    let mut remaining = Duration::new(ts.tv_sec.max(0) as u64, ts.tv_nsec.max(0) as u32);
    while !remaining.is_zero() {
        if crate::signals::interrupted() {
            return;
        }
        let slice = remaining.min(Duration::from_millis(200));
        thread::sleep(slice);
        remaining = remaining.saturating_sub(slice);
    }
}

/// Thin wrapper around lib `OWPStopSessionsWait` with powstream's interrupt flag.
///
/// Returns: `-1` error, `0` session over (`StopSessions` sent), `1` wake timeout,
/// `2` interrupted. Pass `wake=None` for the no-summaries path (C `NULL`).
pub fn stop_sessions_wait(
    cntrl: &mut Control,
    wake: Option<&OwampNum64>,
    aval: &mut AcceptType,
) -> i32 {
    let mut err = ErrSeverity::Ok;
    api::stop_sessions_wait(
        cntrl,
        wake,
        Some(crate::signals::intr_ref()),
        aval,
        &mut err,
    )
}

/// Wait until `until` wall-clock time (or interrupt). Used when summaries drive cadence.
pub fn wait_until(until: OwampNum64) -> i32 {
    loop {
        if crate::signals::interrupted() {
            return 2;
        }
        let Some(now) = owamp::time::get_time_of_day() else {
            return -1;
        };
        if now.owptime.cmp_num(until) >= 0 {
            return 1;
        }
        let delta = OwampNum64(until.0.wrapping_sub(now.owptime.0));
        sleep_num64(delta.min(OwampNum64((1u64) << 32))); // cap 1s slices via sleep_num64 internals
    }
}

/// Dual session files like C `SetupSession`: `fp` (mkstemp) + `testfp` (fopen same
/// path) then unlink — independent offsets so endpoint/fetch writes on `testfp`
/// do not disturb summary reads on `fp`.
fn ensure_data_files(p: &mut PowCntrl, state: &StreamState) -> bool {
    if p.fp.is_some() && p.testfp.is_some() {
        return true;
    }
    p.close_data();

    let mut path = state.dirpath.join("pow.XXXXXX");
    let template = path.to_string_lossy().into_owned();
    let Ok(ctemplate) = std::ffi::CString::new(template) else {
        error!("mkstemp: invalid path");
        return false;
    };
    let mut bytes = ctemplate.into_bytes_with_nul();
    let fd = unsafe { libc::mkstemp(bytes.as_mut_ptr() as *mut libc::c_char) };
    if fd < 0 {
        error!(
            "mkstemp({}): {}",
            path.display(),
            std::io::Error::last_os_error()
        );
        return false;
    }
    // Actual path after mkstemp filled in the Xs.
    let cpath = unsafe { std::ffi::CStr::from_ptr(bytes.as_ptr() as *const libc::c_char) };
    path = PathBuf::from(cpath.to_string_lossy().as_ref());

    let fp = unsafe { File::from_raw_fd(fd) };
    let testfp = match OpenOptions::new().read(true).write(true).open(&path) {
        Ok(f) => f,
        Err(e) => {
            error!("fopen({}): {e}", path.display());
            drop(fp);
            let _ = fs::remove_file(&path);
            return false;
        },
    };
    if let Err(e) = fs::remove_file(&path) {
        error!("unlink(): {e}");
        drop(fp);
        drop(testfp);
        return false;
    }
    p.fp = Some(fp);
    p.testfp = Some(testfp);
    true
}

/// Port of C `FetchSession` — open a fetch control connection if needed and
/// pull records `[begin, end]` into the session data file.
pub fn fetch_session_range(
    p: &mut PowCntrl,
    state: &StreamState,
    begin: u32,
    end: u32,
    err_ret: &mut ErrSeverity,
) -> u32 {
    let app = &state.app;
    if p.fetch.is_none() {
        let server = Addr::by_node(&app.remote_serv, Some(owamp::OWP_CONTROL_SERVICE_NAME));
        let mut err = ErrSeverity::Ok;
        let opened = control_open_interface(
            &p.ctx,
            app.opt.srcaddr.as_deref(),
            app.opt.interface.as_deref(),
            server,
            app.auth_mode,
            app.opt.identity.as_deref(),
            None,
            &mut err,
        );
        if let Some(rc) = opened {
            p.fetch = Some(rc);
        } else {
            error!(
                "OWPControlOpen({}): Couldn't open 'fetch' connection to server",
                app.remote_serv
            );
            *err_ret = ErrSeverity::Fatal;
            p.close_fetch();
            return 0;
        }
        if crate::signals::sig_check(|| {}) {
            *err_ret = ErrSeverity::Fatal;
            return 0;
        }
    }

    if !ensure_data_files(p, state) {
        *err_ret = ErrSeverity::Fatal;
        p.close_fetch();
        return 0;
    }

    // Truncate testfp before Fetch like C; refresh reader fp afterwards.
    if let Some(ref mut f) = p.testfp {
        let _ = f.seek(SeekFrom::Start(0));
        let _ = f.set_len(0);
    }
    if let Some(ref mut f) = p.fp {
        let _ = f.flush();
        let _ = f.seek(SeekFrom::Start(0));
    }

    let Some(fetch_rc) = p.fetch.clone() else {
        return 0;
    };
    let sid = p.sid;
    let n = {
        let mut fetch = fetch_rc.borrow_mut();
        let Some(ref mut testfp) = p.testfp else {
            return 0;
        };
        fetch_session(&mut fetch, testfp, begin, end, &sid, err_ret)
    };
    if n == 0 {
        p.close_fetch();
        return 0;
    }
    if let Some(ref mut testfp) = p.testfp {
        let _ = testfp.flush();
    }
    if let Some(ref mut fp) = p.fp {
        let _ = fp.seek(SeekFrom::Start(0));
    }
    n
}

/// State for [`get_max_send`] (C `pow_maxsend_rec`).
#[derive(Debug, Default)]
pub struct MaxSendRec {
    pub index: u32,
    pub sendtime: OwampNum64,
    pub skips: Vec<SkipRec>,
    pub npackets: u32,
}

/// Port of C `GetMaxSend` — track the highest usable `seq_no` / send time,
/// ignoring packets that fall inside skip ranges.
pub fn get_max_send(rec: &DataRec, snd: &mut MaxSendRec) -> bool {
    if !snd.skips.is_empty() {
        let mut iskip = 0usize;
        while iskip < snd.skips.len() && rec.seq_no > snd.skips[iskip].end {
            iskip += 1;
        }
        if iskip < snd.skips.len() && rec.seq_no > snd.skips[iskip].begin {
            return true; // keep scanning (C returns 0 = continue)
        }
    }

    if snd.npackets > 0 {
        debug_assert!(rec.seq_no < snd.npackets);
        debug_assert!(snd.index < snd.npackets);
    }
    if rec.seq_no > snd.index {
        snd.index = rec.seq_no;
        snd.sendtime = rec.send.owptime;
    }
    true
}

/// Compute session end Num64 from schedule up through `index` (inclusive),
/// matching C `write_session` newend path.
pub fn endnum_from_schedule(
    sctx: &mut ScheduleContext,
    start: OwampNum64,
    index: u32,
) -> Result<OwampNum64, String> {
    sctx.reset(None, None).map_err(|e| e.to_string())?;
    let mut endnum = start;
    for _ in 0..=index {
        let d = sctx.generate_next_delta().map_err(|e| e.to_string())?;
        endnum = OwampNum64(endnum.0.wrapping_add(d.0));
    }
    Ok(endnum)
}

fn try_rdlock_datafile(f: &File) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let mut flk: libc::flock = unsafe { std::mem::zeroed() };
        flk.l_type = libc::F_RDLCK;
        flk.l_whence = libc::SEEK_SET as i16;
        let rc = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_SETLK, &flk) };
        if rc < 0 {
            error!(
                "Lock failure: fcntl(session data): {}",
                std::io::Error::last_os_error()
            );
            return false;
        }
        true
    }
    #[cfg(not(unix))]
    {
        let _ = f;
        true
    }
}

/// When `newend` is set (early terminate / `ResetSession`), recompute end from
/// the last valid packet via `GetMaxSend` + schedule. Returns `None` to skip
/// writing (no data).
fn compute_new_end(
    p: &mut PowCntrl,
    state: &StreamState,
    hdr: &SessionHeader,
) -> Option<OwampNum64> {
    if hdr.num_datarecs == 0 {
        if state.app.opt.verbose > 1 {
            info!(
                "No data - skip writing session ({}, {})",
                format_tstamp(p.current_session_start_num),
                format_tstamp(p.current_session_end_num)
            );
        }
        return None;
    }

    let fp = p.fp.as_mut()?;

    let mut snd = MaxSendRec {
        npackets: hdr.test_spec.npackets.max(1),
        ..Default::default()
    };
    if hdr.num_skiprecs > 0 {
        if fp.seek(SeekFrom::Start(hdr.oset_skiprecs)).is_err() {
            error!("fseeko(skips): failed");
            return None;
        }
        if api::read_data_skips(fp, hdr.num_skiprecs, &mut snd.skips) != ErrSeverity::Ok {
            error!("OWPReadDataSkips: failed");
            return None;
        }
    }

    if fp.seek(SeekFrom::Start(hdr.oset_datarecs)).is_err() {
        error!("fseeko(datarecs): failed");
        return None;
    }
    if api::parse_records(fp, hdr.num_datarecs, hdr.version, |rec| {
        get_max_send(rec, &mut snd)
    }) != ErrSeverity::Ok
    {
        error!("GetMaxIndex: failed");
        return None;
    }

    let Some(ref mut sctx) = p.sctx else {
        // Fall back to current end if schedule is unavailable.
        return Some(p.current_session_end_num);
    };
    match endnum_from_schedule(sctx, p.current_session_start_num, snd.index) {
        Ok(n) => Some(n),
        Err(e) => {
            error!("schedule endnum: {e}");
            None
        },
    }
}

/// Write completed session artefacts (`.owp` + `.sum`) — port of `write_session`.
///
/// When `newend` is true (early terminate via `ResetSession`), the end timestamp
/// is recomputed from the last valid packet (`GetMaxSend` + schedule).
pub fn write_session(state: &StreamState, p: &mut PowCntrl, aval: AcceptType, newend: bool) {
    // C: if(!p->fp || !p->session_started || aval != ACCEPT) return;
    if p.fp.is_none() || !p.session_started || aval != AcceptType::Accept {
        return;
    }
    if state.app.opt.sender {
        // Sender needs testfp as the FetchSession destination.
        if p.testfp.is_none() {
            return;
        }
        let mut err = ErrSeverity::Ok;
        let n = fetch_session_range(p, state, 0, u32::MAX, &mut err);
        if n == 0 {
            if matches!(
                err,
                ErrSeverity::Ok | ErrSeverity::Info | ErrSeverity::Debug | ErrSeverity::Warning
            ) {
                error!(
                    "write_session(): OWPFetchSession(): Server denied request for full session data"
                );
            }
            return;
        }
    }

    let mut hdr = SessionHeader::default();
    {
        let Some(ref mut fp) = p.fp else {
            return;
        };
        let _ = fp.seek(SeekFrom::Start(0));
        let _ = api::read_data_header(fp, &mut hdr);
    }
    if !hdr.header {
        error!(
            "OWPReadDataHeader(session data [{}, {}])",
            format_tstamp(p.current_session_start_num),
            format_tstamp(p.current_session_end_num)
        );
        return;
    }

    let endnum = if newend {
        // Lock + re-read when session did not finish normally (C write_session).
        if hdr.finished != SessionFinishedType::Normal {
            let Some(ref fp) = p.fp else {
                return;
            };
            if !try_rdlock_datafile(fp) {
                return;
            }
            let Some(ref mut fp) = p.fp else {
                return;
            };
            let _ = fp.seek(SeekFrom::Start(0));
            hdr = SessionHeader::default();
            let _ = api::read_data_header(fp, &mut hdr);
            if !hdr.header {
                error!(
                    "OWPReadDataHeader(session data [{}, {}])",
                    format_tstamp(p.current_session_start_num),
                    format_tstamp(p.current_session_end_num)
                );
                return;
            }
        }
        match compute_new_end(p, state, &hdr) {
            Some(n) => n,
            None => return,
        }
    } else {
        p.current_session_end_num
    };

    let start = format_tstamp(p.current_session_start_num);
    let end = format_tstamp(endnum);
    let base = format!("{start}{OWP_NAME_SEP}{end}");

    let owp_inc = state
        .dirpath
        .join(format!("{base}{OWP_FILE_EXT}{POW_INC_EXT}"));
    let owp = state.dirpath.join(format!("{base}{OWP_FILE_EXT}"));
    let mut ofname = String::new();

    // Persist session body into `.owp` (atomic via `.i` rename / link+unlink).
    if let Some(ref mut src) = p.fp {
        let _ = src.seek(SeekFrom::Start(0));
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&owp_inc)
        {
            Ok(mut dst) => {
                if std::io::copy(src, &mut dst).is_ok() {
                    let _ = dst.flush();
                    if fs::hard_link(&owp_inc, &owp).is_ok()
                        || fs::rename(&owp_inc, &owp).is_ok()
                        || fs::copy(&owp_inc, &owp).is_ok()
                    {
                        ofname = owp.display().to_string();
                    }
                }
                let _ = fs::remove_file(&owp_inc);
            },
            Err(e) => {
                // C: ENOMEM/EMFILE/ENFILE/ENOSPC/EDQUOT → skip; else exit.
                let soft = matches!(
                    e.raw_os_error(),
                    Some(libc::ENOMEM | libc::EMFILE | libc::ENFILE | libc::ENOSPC | libc::EDQUOT)
                ) || e.kind() == std::io::ErrorKind::AlreadyExists;
                if soft {
                    warn!("open({}): {e}", owp_inc.display());
                } else {
                    error!("open({}): {e}", owp_inc.display());
                    std::process::exit(1);
                }
            },
        }
    }

    let mut sfname = String::new();
    let sum_inc = state
        .dirpath
        .join(format!("{base}{POW_SUM_EXT}{POW_INC_EXT}"));
    let sum = state.dirpath.join(format!("{base}{POW_SUM_EXT}"));

    let Ok(mut stats) = Stats::create(
        false,
        state.tspec.loss_timeout,
        'm',
        state.app.opt.bucket_width,
        100,
    ) else {
        error!("OWPStatsCreate failed");
        if state.app.opt.printfiles && !ofname.is_empty() {
            println!("{ofname}");
        }
        return;
    };
    stats.sid = p.sid;
    stats.start_time = p.current_session_start_num;
    stats.end_time = endnum;
    stats.display_unix_ts = state.app.opt.display_unix_ts;

    if let Some(ref mut fp) = p.fp {
        let _ = fp.seek(SeekFrom::Start(0));
        let mut shdr = SessionHeader::default();
        let nrecs = api::read_data_header(fp, &mut shdr);
        if nrecs > 0 || shdr.header {
            if shdr.oset_datarecs > 0 {
                let _ = fp.seek(SeekFrom::Start(shdr.oset_datarecs));
            }
            let mut recs = Vec::new();
            let _ = api::parse_records(fp, nrecs, shdr.version, |r| {
                recs.push(owamp::OwampDataRec {
                    seq_no: r.seq_no,
                    send: r.send,
                    recv: r.recv,
                    ttl: r.ttl,
                });
                true
            });
            let _ = owamp::stats::stats_parse(&mut stats, &recs, 0, u32::MAX);
        }
    }

    match File::create(&sum_inc) {
        Ok(mut f) => {
            if write!(f, "{}", stats.print_machine()).is_ok() {
                let _ = f.flush();
                if fs::hard_link(&sum_inc, &sum).is_ok()
                    || fs::rename(&sum_inc, &sum).is_ok()
                    || fs::copy(&sum_inc, &sum).is_ok()
                {
                    sfname = sum.display().to_string();
                }
            }
            let _ = fs::remove_file(&sum_inc);
        },
        Err(e) => {
            error!("fopen({}): {e}", sum_inc.display());
            let soft = matches!(
                e.raw_os_error(),
                Some(libc::ENOMEM | libc::EMFILE | libc::ENFILE | libc::ENOSPC | libc::EDQUOT)
            );
            if !soft {
                std::process::exit(1);
            }
        },
    }

    if state.app.opt.printfiles {
        if !ofname.is_empty() {
            println!("{ofname}");
        }
        if !sfname.is_empty() {
            println!("{sfname}");
        }
        let _ = std::io::stdout().flush();
    }
}

/// Reset one control connection (`ResetSession`).
pub fn reset_session(p: &mut PowCntrl, q: &mut PowCntrl, state: &StreamState) {
    let mut aval = AcceptType::Accept;
    if p.num_packets != 0 && p.call_stop {
        if let Some(ref rc) = p.cntrl {
            let mut c = rc.borrow_mut();
            let _ = stop_sessions(&mut c, Some(crate::signals::intr_ref()), &mut aval);
        }
    }
    // Early-terminated artefacts must be written before ControlClose so sender
    // sessions can still FetchSession (C ResetSession order).
    write_session(state, p, aval, true);
    p.close_fetch();
    p.close_cntrl();
    p.close_data();
    p.num_packets = 0;
    p.call_stop = false;
    p.session_started = false;
    p.next_session_start = None;
    q.next_session_start = None;
}

pub fn close_sessions(pcntrl: &mut [PowCntrl; 2], state: &StreamState) {
    // Need split borrows — reset 0 then 1 carefully.
    // First pass: stop & write without touching the other next_session_start twice wrongly.
    for i in 0..2 {
        let j = 1 - i;
        // SAFETY of borrow: use raw indices with split_at_mut
        let (left, right) = pcntrl.split_at_mut(1);
        let (a, b) = if i == 0 {
            (&mut left[0], &mut right[0])
        } else {
            (&mut right[0], &mut left[0])
        };
        let _ = (a, b, j);
    }
    // Simpler sequential reset:
    {
        let (p0, rest) = pcntrl.split_at_mut(1);
        reset_session(&mut p0[0], &mut rest[0], state);
    }
    {
        let (p0, rest) = pcntrl.split_at_mut(1);
        reset_session(&mut rest[0], &mut p0[0], state);
    }
}

/// `SetupSession` — returns `0` ok, `1` signal reset, `-1` error.
pub fn setup_session(
    state: &mut StreamState,
    p: &mut PowCntrl,
    q: &mut PowCntrl,
    stop: Option<OwampNum64>,
) -> i32 {
    if p.num_packets != 0 {
        return 0;
    }

    p.close_fetch();
    p.close_cntrl();
    p.close_data();
    p.num_packets = 0;
    p.call_stop = false;
    p.session_started = false;

    // Retry delay between failed / successive opens.
    if state.app.opt.retry_delay > 0 && p.prev_runtime.owptime.0 > 0 {
        if let Some(curr) = get_time_of_day(&state.ctx) {
            let next_runtime = OwampNum64(
                p.prev_runtime
                    .owptime
                    .0
                    .wrapping_add(ulong_to_num64(state.app.opt.retry_delay).0),
            );
            if next_runtime.cmp_num(curr.owptime) > 0 {
                let wait = OwampNum64(next_runtime.0.wrapping_sub(curr.owptime.0));
                let ts = owamp::arithm64::num64_to_timespec(wait);
                info!(
                    "OWPControlOpen({}): Waiting {}.{} seconds before retrying",
                    state.app.remote_serv, ts.tv_sec, ts.tv_nsec
                );
                sleep_num64(wait);
                if crate::signals::sig_check(|| {}) {
                    return 1;
                }
            }
        }
    }

    let Some(currtime) = get_time_of_day(&state.ctx) else {
        error!("OWPGetTimeOfDay failed");
        std::process::exit(1);
    };

    if let Some(stop_t) = stop {
        if currtime.owptime.cmp_num(stop_t) > 0 {
            q.next_session_start = p.next_session_start;
            if let Some(n) = p.next_session_start {
                q.next_session_start_num = n;
            }
            return 0;
        }
    }

    if let Some(rt) = get_time_of_day(&state.ctx) {
        p.prev_runtime = rt;
    }

    if crate::signals::sig_check(|| {}) {
        return 1;
    }

    if p.sctx.is_none() {
        match ScheduleContext::create(&p.sid, &state.tspec) {
            Ok(s) => p.sctx = Some(s),
            Err(e) => {
                error!("OWPScheduleContextCreate: {e}");
                return -1;
            },
        }
    }

    let server = Addr::by_node(
        &state.app.remote_serv,
        Some(owamp::OWP_CONTROL_SERVICE_NAME),
    );
    let mut err = ErrSeverity::Ok;
    let opened = control_open_interface(
        &state.ctx,
        state.app.opt.srcaddr.as_deref(),
        state.app.opt.interface.as_deref(),
        server,
        state.app.auth_mode,
        state.app.opt.identity.as_deref(),
        None,
        &mut err,
    );
    let Some(cntrl_rc) = opened else {
        if crate::signals::sig_check(|| {}) {
            return 1;
        }
        error!(
            "OWPControlOpen({}): Couldn't open 'control' connection to server",
            state.app.remote_serv
        );
        // C: sctx_clean + fetch_clean
        p.sctx = None;
        p.close_fetch();
        return -1;
    };
    p.cntrl = Some(cntrl_rc);

    if crate::signals::sig_check(|| {}) {
        return 1;
    }

    let Some(mut currtime) = get_time_of_day(&state.ctx) else {
        error!("OWPGetTimeOfDay failed");
        p.close_cntrl();
        p.sctx = None;
        p.close_fetch();
        return -1;
    };
    currtime.owptime = OwampNum64(
        currtime
            .owptime
            .0
            .wrapping_add(ulong_to_num64(SETUP_ESTIMATE).0),
    );
    if state.first_time {
        currtime.owptime = OwampNum64(
            currtime
                .owptime
                .0
                .wrapping_add(ulong_to_num64(state.app.opt.delay_start).0),
        );
        state.first_time = false;
    }

    if let Some(ns) = p.next_session_start {
        if currtime.owptime.cmp_num(ns) > 0 {
            p.next_session_start = None;
        }
    }
    if p.next_session_start.is_none() {
        p.next_session_start_num = currtime.owptime;
        p.next_session_start = Some(p.next_session_start_num);
    }

    // Dual temp files (fp + testfp), unlinked after open — C SetupSession.
    if !ensure_data_files(p, state) {
        p.close_cntrl();
        p.sctx = None;
        p.close_fetch();
        return -1;
    }

    if crate::signals::sig_check(|| {}) {
        return 1;
    }

    let start = p.next_session_start.unwrap_or(currtime.owptime);
    let tspec = state.ctx_test_spec(start);
    let mut sid = p.sid;
    let mut err = ErrSeverity::Ok;

    let ok = {
        let Some(ref cntrl_rc) = p.cntrl else {
            return -1;
        };
        let mut cntrl = cntrl_rc.borrow_mut();
        if state.app.opt.sender {
            // Client sends → server receives. C passes NULL fp (fetch later via testfp).
            let recv = Addr::by_node(
                &state.app.remote_test,
                Some(owamp::OWP_CONTROL_SERVICE_NAME),
            );
            session_request_ex(
                &mut cntrl,
                None,
                false,
                Some(recv),
                true,
                false,
                &tspec,
                None,
                &mut sid,
                &mut err,
            )
        } else {
            // Client receives ← server sends (default): attach testfp for live records.
            let send = Addr::by_node(
                &state.app.remote_test,
                Some(owamp::OWP_CONTROL_SERVICE_NAME),
            );
            let testfp = p.testfp.as_ref();
            session_request_ex(
                &mut cntrl,
                Some(send),
                true,
                None,
                false,
                false,
                &tspec,
                testfp,
                &mut sid,
                &mut err,
            )
        }
    };

    if !ok {
        error!("OWPSessionRequest: Failed");
        // C file_clean → cntrl_clean → sctx_clean → fetch_clean
        p.close_data();
        p.close_cntrl();
        p.sctx = None;
        p.close_fetch();
        return -1;
    }
    p.sid = sid;

    if crate::signals::sig_check(|| {}) {
        return 1;
    }

    {
        let Some(ref cntrl_rc) = p.cntrl else {
            return -1;
        };
        let mut cntrl = cntrl_rc.borrow_mut();
        // C: failure when OWPStartSessions < OWPErrINFO (Fatal/Warning).
        let sev = start_sessions(&mut cntrl);
        if (sev as i32) < (ErrSeverity::Info as i32) {
            error!("OWPStartSessions: Failed");
            drop(cntrl);
            p.close_cntrl();
            p.sctx = None;
            p.close_fetch();
            return -1;
        }
    }
    p.call_stop = true;
    p.session_started = false;

    if crate::signals::sig_check(|| {}) {
        return 1;
    }

    if let Some(ref mut sctx) = p.sctx {
        if let Err(e) = sctx.reset(Some(&p.sid), Some(&state.tspec)) {
            error!("Schedule Initialization Failed: {e}");
            p.close_cntrl();
            p.sctx = None;
            p.close_fetch();
            return -1;
        }
    }

    p.num_packets = state.tspec.npackets;
    p.next_session_end_num = p.next_session_start_num;
    if let Some(ref mut sctx) = p.sctx {
        for _ in 0..p.num_packets {
            match sctx.generate_next_delta() {
                Ok(d) => {
                    p.next_session_end_num = OwampNum64(p.next_session_end_num.0.wrapping_add(d.0));
                },
                Err(e) => {
                    error!("schedule delta: {e}");
                    p.close_cntrl();
                    p.sctx = None;
                    p.close_fetch();
                    return -1;
                },
            }
        }
        // Reset index so the continuous summary loop regenerates from the start.
        let _ = sctx.reset(None, None);
    }

    q.next_session_start_num = p.next_session_end_num;
    q.next_session_start = Some(q.next_session_start_num);
    0
}

/// Configure library context flags from CLI options.
pub fn configure_context(state: &mut StreamState) -> Result<(), String> {
    let ctx = &state.ctx;
    if state.app.opt.v4only {
        if state.app.opt.v6only {
            return Err("-4 and -6 flags cannot be set together".into());
        }
        if !ctx.config_set_v(OWP_IPV4_ONLY, 1) {
            return Err("Unable to set OWPIPv4Only".into());
        }
    }
    if state.app.opt.v6only && !ctx.config_set_v(OWP_IPV6_ONLY, 1) {
        return Err("Unable to set OWPIPv6Only".into());
    }

    // Store port range in a leaked box so the pointer remains valid for the process.
    let pr = Box::leak(Box::new(state.app.opt.port_range));
    if !ctx.config_set_v(OWP_TEST_PORT_RANGE, pr as *const PortRange as usize) {
        return Err("Unable to set OWPTestPortRange".into());
    }

    // Wire the same interrupt flag signals mutate (C `&pow_intr`).
    if !ctx.config_set_v(OWP_INTERRUPT_IO, crate::signals::intr_ptr() as usize) {
        return Err("Unable to set OWPInterruptIO".into());
    }

    if state.app.opt.set_end_delay {
        let ed = Box::leak(Box::new(state.app.opt.end_delay));
        if !ctx.config_set_v(OWP_END_DELAY, ed as *const f64 as usize) {
            return Err("Unable to set OWPEndDelay".into());
        }
    }

    if state.app.opt.childwait && !ctx.config_set_v(owamp::owampP::OWP_CHILD_WAIT, 1) {
        return Err("Unable to set Context var: OWPChildWait".into());
    }

    if !ctx.config_set_v(OWP_DETACH_PROCESSES, 1) {
        return Err("Unable to set OWPDetachProcesses".into());
    }
    Ok(())
}

/// Write one sub-session summary file (`.sum`) for the report cadence.
pub fn write_summary(
    state: &StreamState,
    p: &mut PowCntrl,
    startnum: OwampNum64,
    localstop: OwampNum64,
) -> bool {
    let start = format_tstamp(startnum);
    let end = format_tstamp(localstop);
    let base = format!("{start}{OWP_NAME_SEP}{end}");
    let sum_inc = state
        .dirpath
        .join(format!("{base}{POW_SUM_EXT}{POW_INC_EXT}"));
    let sum = state.dirpath.join(format!("{base}{POW_SUM_EXT}"));

    let Ok(mut stats) = Stats::create(
        false,
        state.tspec.loss_timeout,
        'm',
        state.app.opt.bucket_width,
        100,
    ) else {
        error!("OWPStatsCreate failed");
        return false;
    };
    stats.sid = p.sid;
    stats.start_time = startnum;
    stats.end_time = localstop;
    stats.display_unix_ts = state.app.opt.display_unix_ts;

    if let Some(ref mut data) = p.fp {
        let _ = data.seek(SeekFrom::Start(0));
        let mut hdr = api::SessionHeader::default();
        let nrecs = api::read_data_header(data, &mut hdr);
        if nrecs > 0 || hdr.header {
            let mut recs = Vec::new();
            let _ = api::parse_records(data, nrecs, hdr.version, |r| {
                recs.push(owamp::OwampDataRec {
                    seq_no: r.seq_no,
                    send: r.send,
                    recv: r.recv,
                    ttl: r.ttl,
                });
                true
            });
            let _ = owamp::stats::stats_parse(&mut stats, &recs, 0, u32::MAX);
        }
    }

    match File::create(&sum_inc) {
        Ok(mut fp) => {
            if write!(fp, "{}", stats.print_machine()).is_err() {
                let _ = fs::remove_file(&sum_inc);
                return false;
            }
            let _ = fp.flush();
            if fs::rename(&sum_inc, &sum).is_err() {
                let _ = fs::copy(&sum_inc, &sum);
                let _ = fs::remove_file(&sum_inc);
            }
            if state.app.opt.printfiles {
                println!("{}", sum.display());
                let _ = std::io::stdout().flush();
            }
            true
        },
        Err(e) => {
            error!("fopen({}): {e}", sum_inc.display());
            false
        },
    }
}

/// Open/fetch sub-session range when running as sender; then report.
pub fn collect_summary(
    state: &StreamState,
    p: &mut PowCntrl,
    sum: u32,
    startnum: OwampNum64,
    localstop: OwampNum64,
) {
    if state.app.opt.sender {
        let begin = state.app.opt.num_bucket_packets.saturating_mul(sum);
        let end = state
            .app
            .opt
            .num_bucket_packets
            .saturating_mul(sum + 1)
            .saturating_sub(1);
        let mut err = ErrSeverity::Ok;
        let n = fetch_session_range(p, state, begin, end, &mut err);
        if n == 0 {
            if matches!(
                err,
                ErrSeverity::Ok | ErrSeverity::Warning | ErrSeverity::Info | ErrSeverity::Debug
            ) {
                error!(
                    "OWPFetchSession(): Server denied request for session data seq_no[{begin}-{end}]"
                );
            }
            return;
        }
    }
    let _ = write_summary(state, p, startnum, localstop);
}

pub fn parse_port_opt(optarg: &str, port_range: &mut PortRange) -> Result<(), String> {
    if optarg == "0" {
        port_range.low = 0;
        port_range.high = 0;
        return Ok(());
    }
    if !parse_port_range(optarg, port_range) {
        return Err("Invalid test port range specified.".into());
    }
    if port_range.high != 0 && port_range.low != 0 && (port_range.high - port_range.low + 1) < 2 {
        return Err("Invalid test port range specified: must contain at least 2 ports.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use owamp::{OwampSlotLiteral, OwampTimeStamp};

    fn make_rec(seq: u32, send: u64) -> DataRec {
        DataRec {
            seq_no: seq,
            send: OwampTimeStamp {
                owptime: OwampNum64(send),
                sync: true,
                multiplier: 1,
                scale: 0,
            },
            recv: OwampTimeStamp::default(),
            ttl: 64,
        }
    }

    #[test]
    fn get_max_send_tracks_highest_seq() {
        let mut snd = MaxSendRec {
            npackets: 10,
            ..Default::default()
        };
        assert!(get_max_send(&make_rec(1, 100), &mut snd));
        assert!(get_max_send(&make_rec(5, 500), &mut snd));
        assert!(get_max_send(&make_rec(3, 300), &mut snd));
        assert_eq!(snd.index, 5);
        assert_eq!(snd.sendtime.0, 500);
    }

    #[test]
    fn get_max_send_skips_inside_skip_range() {
        let mut snd = MaxSendRec {
            npackets: 20,
            skips: vec![SkipRec { begin: 2, end: 8 }],
            ..Default::default()
        };
        assert!(get_max_send(&make_rec(1, 10), &mut snd));
        assert_eq!(snd.index, 1);
        // seq 5 is inside (begin, end] relative to C: seq_no > begin && before end check
        assert!(get_max_send(&make_rec(5, 50), &mut snd));
        assert_eq!(snd.index, 1); // unchanged
        assert!(get_max_send(&make_rec(9, 90), &mut snd));
        assert_eq!(snd.index, 9);
    }

    #[test]
    fn endnum_from_literal_schedule() {
        let sid = [1u8; 16];
        let tspec = OwampTestSpec {
            start_time: OwampNum64::ZERO,
            loss_timeout: OwampNum64::ZERO,
            type_p: 0,
            packet_size_padding: 0,
            npackets: 4,
            slots: vec![OwampSlot::Literal(OwampSlotLiteral {
                offset: OwampNum64(10),
            })],
        };
        let mut sctx = ScheduleContext::create(&sid, &tspec).unwrap();
        let end = endnum_from_schedule(&mut sctx, OwampNum64(100), 2).unwrap();
        // indices 0,1,2 → three deltas of 10
        assert_eq!(end.0, 130);
    }

    #[test]
    fn parse_port_opt_requires_two_ports() {
        let mut pr = PortRange { low: 0, high: 0 };
        assert!(parse_port_opt("9000-9000", &mut pr).is_err());
        assert!(parse_port_opt("9000-9001", &mut pr).is_ok());
        assert_eq!(pr.low, 9_000);
        assert_eq!(pr.high, 9_001);
    }

    #[test]
    fn build_tspec_defaults() {
        let opt = Options::default();
        let ts = build_tspec(&opt);
        assert_eq!(ts.npackets, 300);
        assert_eq!(ts.slots.len(), 1);
    }
}
