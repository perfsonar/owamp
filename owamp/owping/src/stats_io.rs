//! Fetch + statistics output — port of `owp_fetch_sid` / `do_stats` / `printraw` /
//! `printrawTW` / `tfile` from `owping.c`.
//!
//! Session wait uses lib `api::stop_sessions_wait` (C `OWPStopSessionsWait` with
//! `wake=NULL`) directly from `owping.rs`.

use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use owamp::api::{parse_records, parse_tw_records, read_data_header, SessionHeader};
use owamp::capi::fetch_session;
use owamp::context::{Control, ErrSeverity, TestSpec};
use owamp::owampP::OWP_JAN_1970;
use owamp::stats::Stats;
use owamp::time::get_timestamp_error;
use owamp::{OwampDataRec, OwampNum64, OwampSid, OwampTwDataRec, OWP_NAME_SEP, OWP_TSTAMPCHARS};
use tracing::error;

use crate::hex::sid_hex_encode;
use crate::owpingP::{Args, OWPING_DEF_EXT, OWPING_INC_EXT, OWPING_SUM_EXT};

const DEF_TMPDIR: &str = "/tmp";

/// Unlinked temp file (`mkstemp` + `unlink`), returned open for read/write.
pub fn tfile() -> Option<File> {
    let dir = std::env::var_os("TMPDIR").map_or_else(|| PathBuf::from(DEF_TMPDIR), PathBuf::from);
    let path = dir.join(format!(
        "owamp.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let fp = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .ok()?;
    let _ = fs::remove_file(&path);
    Some(fp)
}

/// `owp_fetch_sid` — `FetchSession` into `savefile` or an unlinked temp file.
pub fn owp_fetch_sid(savefile: Option<&Path>, cntrl: &mut Control, sid: &OwampSid) -> Option<File> {
    let path = savefile.map(std::path::Path::to_path_buf);
    let mut fp = if let Some(ref p) = path {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(p)
        {
            Ok(f) => f,
            Err(e) => {
                error!("owp_fetch_sid:fopen({}): {e}", p.display());
                return None;
            },
        }
    } else {
        tfile()?
    };

    let mut rc = ErrSeverity::Ok;
    let num_rec = fetch_session(cntrl, &mut fp, 0, u32::MAX, sid, &mut rc);
    if num_rec == 0 {
        if let Some(ref p) = path {
            let _ = fs::remove_file(p);
        }
        if (rc as i32) < (ErrSeverity::Warning as i32) {
            return None;
        }
        error!(
            "owp_fetch_sid:Server denied request for to session data - is your clock synchronized via NTP properly?"
        );
        return None;
    }
    let _ = fp.seek(SeekFrom::Start(0));
    Some(fp)
}

fn format_tstamp(n: OwampNum64) -> String {
    format!("{:0width$}", n.0, width = OWP_TSTAMPCHARS)
}

fn printfiles_dir(args: &Args) -> PathBuf {
    args.savedir
        .as_ref()
        .map_or_else(|| PathBuf::from("."), PathBuf::from)
}

/// Format float like C `%g` for RAW / verbose lines.
fn fmt_g(v: f64) -> String {
    // Prefer compact representation similar to printf %g.
    let s = format!("{v}");
    if s.contains('e') || s.contains('E') {
        format!("{v:.6e}")
    } else if s.contains('.') {
        // trim trailing zeros but keep at least one digit after point if needed
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    } else {
        s
    }
}

/// `printraw` — OWAMP RAW ascii line:
/// `SEQ STIME SS SERR RTIME RS RERR TTL`
pub fn printraw(rec: &OwampDataRec, out: &mut dyn Write) -> std::io::Result<()> {
    writeln!(
        out,
        "{} {:020} {} {} {:020} {} {} {}",
        rec.seq_no,
        rec.send.owptime.0,
        u8::from(rec.send.sync),
        fmt_g(get_timestamp_error(&rec.send)),
        rec.recv.owptime.0,
        u8::from(rec.recv.sync),
        fmt_g(get_timestamp_error(&rec.recv)),
        rec.ttl
    )
}

/// `printrawTW` — TWAMP RAW ascii line:
/// `SSEQ STIME SS SERR SRTIME SRS SRERR STTL RSEQ RSTIME RSS RSERR RTIME RS RERR RTTL`
pub fn printraw_tw(rec: &OwampTwDataRec, out: &mut dyn Write) -> std::io::Result<()> {
    writeln!(
        out,
        "{} {:020} {} {} {:020} {} {} {} {} {:020} {} {} {:020} {} {} {}",
        rec.sent.seq_no,
        rec.sent.send.owptime.0,
        u8::from(rec.sent.send.sync),
        fmt_g(get_timestamp_error(&rec.sent.send)),
        rec.sent.recv.owptime.0,
        u8::from(rec.sent.recv.sync),
        fmt_g(get_timestamp_error(&rec.sent.recv)),
        rec.sent.ttl,
        rec.reflected.seq_no,
        rec.reflected.send.owptime.0,
        u8::from(rec.reflected.send.sync),
        fmt_g(get_timestamp_error(&rec.reflected.send)),
        rec.reflected.recv.owptime.0,
        u8::from(rec.reflected.recv.sync),
        fmt_g(get_timestamp_error(&rec.reflected.recv)),
        rec.reflected.ttl
    )
}

fn print_oneway_verbose(
    rec: &OwampDataRec,
    scale: f32,
    scale_abrv: &str,
    display_unix_ts: bool,
    out: &mut dyn Write,
) -> std::io::Result<()> {
    let d = owamp::stats::delay(&rec.send, &rec.recv);
    let derr = get_timestamp_error(&rec.send) + get_timestamp_error(&rec.recv);
    if rec.send.sync && rec.recv.sync {
        if display_unix_ts {
            let epochdiff = f64::from(OWP_JAN_1970);
            writeln!(
                out,
                "seq_no={} delay={:e} {} (sync, err={:.3} {}) sent={} recv={}",
                rec.seq_no,
                d * f64::from(scale),
                scale_abrv,
                derr * f64::from(scale),
                scale_abrv,
                owamp::arithm64::num64_to_double(rec.send.owptime) - epochdiff,
                owamp::arithm64::num64_to_double(rec.recv.owptime) - epochdiff
            )
        } else {
            writeln!(
                out,
                "seq_no={:<10} delay={:.3} {}\t(sync, err={:.3} {})",
                rec.seq_no,
                d * f64::from(scale),
                scale_abrv,
                derr * f64::from(scale),
                scale_abrv
            )
        }
    } else {
        writeln!(
            out,
            "seq_no={:<10} delay={:.3} {}\t(unsync)",
            rec.seq_no,
            d * f64::from(scale),
            scale_abrv
        )
    }
}

fn print_tw_verbose(
    rec: &OwampTwDataRec,
    scale: f32,
    scale_abrv: &str,
    display_unix_ts: bool,
    out: &mut dyn Write,
) -> std::io::Result<()> {
    let proc_d = owamp::stats::delay(&rec.sent.recv, &rec.reflected.send);
    let delay = owamp::stats::delay(&rec.sent.send, &rec.reflected.recv) - proc_d;
    let fwd = owamp::stats::delay(&rec.sent.send, &rec.sent.recv);
    let bck = owamp::stats::delay(&rec.reflected.send, &rec.reflected.recv);
    let derr = get_timestamp_error(&rec.sent.send) + get_timestamp_error(&rec.reflected.recv);
    let sf = f64::from(scale);
    if display_unix_ts {
        let epochdiff = f64::from(OWP_JAN_1970);
        writeln!(
            out,
            "seq_no={} fwd_delay={:e} {} bck_delay={:e} {} delay={:e} {} proc_delay={:e} {} (err={:.3} {}) sent={} recv={} reflected={} recv={}",
            rec.sent.seq_no,
            fwd * sf,
            scale_abrv,
            bck * sf,
            scale_abrv,
            delay * sf,
            scale_abrv,
            proc_d * sf,
            scale_abrv,
            derr * sf,
            scale_abrv,
            owamp::arithm64::num64_to_double(rec.sent.send.owptime) - epochdiff,
            owamp::arithm64::num64_to_double(rec.sent.recv.owptime) - epochdiff,
            owamp::arithm64::num64_to_double(rec.reflected.send.owptime) - epochdiff,
            owamp::arithm64::num64_to_double(rec.reflected.recv.owptime) - epochdiff
        )
    } else {
        writeln!(
            out,
            "seq_no={:<10} fwd_delay={:.3} {} bck_delay={:.3} {} delay={:.3} {} proc_delay={:.3} {}\t(err={:.3} {})",
            rec.sent.seq_no,
            fwd * sf,
            scale_abrv,
            bck * sf,
            scale_abrv,
            delay * sf,
            scale_abrv,
            proc_d * sf,
            scale_abrv,
            derr * sf,
            scale_abrv
        )
    }
}

/// Statistical output (`do_stats` in `owping.c`).
pub fn do_stats(
    fp: &mut File,
    from: Option<&str>,
    to: Option<&str>,
    tspec: Option<&TestSpec>,
    args: &Args,
    twoway: bool,
) -> Result<(), ()> {
    let mut hdr = SessionHeader::default();
    let num_rec = read_data_header(fp, &mut hdr);
    if num_rec == 0 && !hdr.header {
        error!("OWPReadDataHeader: Invalid file?");
        return Err(());
    }

    if args.raw {
        let mut out = std::io::stdout();
        if hdr.twoway || twoway {
            let rc = parse_tw_records(fp, num_rec, hdr.version, |rec| {
                let tw = OwampTwDataRec {
                    sent: OwampDataRec {
                        seq_no: rec.sent.seq_no,
                        send: rec.sent.send,
                        recv: rec.sent.recv,
                        ttl: rec.sent.ttl,
                    },
                    reflected: OwampDataRec {
                        seq_no: rec.reflected.seq_no,
                        send: rec.reflected.send,
                        recv: rec.reflected.recv,
                        ttl: rec.reflected.ttl,
                    },
                };
                printraw_tw(&tw, &mut out).is_ok()
            });
            if (rc as i32) < (ErrSeverity::Warning as i32) {
                error!("OWPParseTWRecords(): failed");
                return Err(());
            }
        } else {
            let rc = parse_records(fp, num_rec, hdr.version, |rec| {
                let one = OwampDataRec {
                    seq_no: rec.seq_no,
                    send: rec.send,
                    recv: rec.recv,
                    ttl: rec.ttl,
                };
                printraw(&one, &mut out).is_ok()
            });
            if (rc as i32) < (ErrSeverity::Warning as i32) {
                error!("OWPParseRecords(): failed");
                return Err(());
            }
        }
        return Ok(());
    }

    // Reload records into memory for ranged summaries.
    let _ = fp.seek(SeekFrom::Start(0));
    let mut hdr2 = SessionHeader::default();
    let n2 = read_data_header(fp, &mut hdr2);
    if n2 == 0 && !hdr2.header {
        error!("OWPReadDataHeader: Invalid file?");
        return Err(());
    }
    hdr = hdr2;

    if twoway {
        if let Some(ts) = tspec {
            // TWAMP preamble often has npackets=0; override for sub-session math.
            hdr.test_spec.npackets = ts.npackets;
        }
    }

    let loss = hdr.test_spec.loss_timeout;
    let Ok(mut stats) = Stats::create(
        hdr.twoway || twoway,
        loss,
        args.units,
        args.bucket_width,
        100,
    ) else {
        error!("OWPStatsCreate: failed");
        return Err(());
    };
    stats.from_host = from.unwrap_or("").to_string();
    stats.to_host = to.unwrap_or("").to_string();
    stats.sid = hdr.sid;
    stats.npackets = hdr.test_spec.npackets;
    stats.packet_size_padding = hdr.test_spec.packet_size_padding;
    stats.type_p = hdr.test_spec.type_p;
    stats.loss_timeout = hdr.test_spec.loss_timeout;
    if let Some(limit) = args.rec_limit() {
        if limit > 0 {
            stats.rec_limit = limit.min(u64::from(u32::MAX)) as u32;
        }
    }
    if args.display_unix_ts {
        stats.display_unix_ts = true;
    }

    // Load all records once (apply rec_limit like C OWPStatsParse).
    let mut oneway = Vec::new();
    let mut twrecs = Vec::new();
    let parse_n = num_rec.max(n2);
    let parse_n = if stats.rec_limit > 0 {
        parse_n.min(stats.rec_limit)
    } else {
        parse_n
    };
    if hdr.twoway || twoway {
        let rc = parse_tw_records(fp, parse_n, hdr.version, |r| {
            twrecs.push(OwampTwDataRec {
                sent: OwampDataRec {
                    seq_no: r.sent.seq_no,
                    send: r.sent.send,
                    recv: r.sent.recv,
                    ttl: r.sent.ttl,
                },
                reflected: OwampDataRec {
                    seq_no: r.reflected.seq_no,
                    send: r.reflected.send,
                    recv: r.reflected.recv,
                    ttl: r.reflected.ttl,
                },
            });
            true
        });
        if (rc as i32) < (ErrSeverity::Warning as i32) {
            error!("OWPStatsParse: failed");
            return Err(());
        }
    } else {
        let rc = parse_records(fp, parse_n, hdr.version, |r| {
            oneway.push(OwampDataRec {
                seq_no: r.seq_no,
                send: r.send,
                recv: r.recv,
                ttl: r.ttl,
            });
            true
        });
        if (rc as i32) < (ErrSeverity::Warning as i32) {
            error!("OWPStatsParse: failed");
            return Err(());
        }
    }

    let percentiles = args
        .percentiles
        .as_ref()
        .and_then(|s| crate::parse::parse_percentiles(s).ok())
        .unwrap_or_default();

    let npackets = hdr.test_spec.npackets;
    let num_sum = if args.num_bucket_packets == 0 || args.num_bucket_packets >= npackets {
        0
    } else {
        let mut n = npackets / args.num_bucket_packets;
        if npackets % args.num_bucket_packets != 0 {
            n += 1;
        }
        n
    };

    let dir = printfiles_dir(args);
    let want_records = args.records.is_some();

    let emit = |stats: &Stats, out: &mut dyn Write| -> Result<(), ()> {
        if args.machine {
            if stats.print_machine_to(out).is_err() {
                return Err(());
            }
        } else if stats.print_summary_to(out, &percentiles, true).is_err() {
            return Err(());
        }
        Ok(())
    };

    let finalize_printfile = |stats: &Stats, tfname: &Path, ext: &str| -> Result<(), ()> {
        let start = format_tstamp(stats.start_time);
        let end = format_tstamp(stats.end_time);
        let sfname = dir.join(format!("{start}{OWP_NAME_SEP}{end}{ext}"));
        if fs::rename(tfname, &sfname).is_err() {
            if fs::copy(tfname, &sfname).is_err() {
                error!(
                    "OWStatsParse: link({},{}): failed",
                    tfname.display(),
                    sfname.display()
                );
                let _ = fs::remove_file(tfname);
                return Err(());
            }
            let _ = fs::remove_file(tfname);
        }
        println!("{}", sfname.display());
        let _ = std::io::stdout().flush();
        Ok(())
    };

    let run_one = |stats: &mut Stats, begin: u32, end: u32| -> Result<(), ()> {
        if hdr.twoway || twoway {
            if owamp::stats::stats_parse_tw(stats, &twrecs, begin, end).is_err() {
                error!("OWPStatsParse: failed");
                return Err(());
            }
        } else if owamp::stats::stats_parse(stats, &oneway, begin, end).is_err() {
            error!("OWPStatsParse: failed");
            return Err(());
        }

        let ext = if args.machine {
            OWPING_SUM_EXT
        } else {
            OWPING_DEF_EXT
        };

        if args.printfiles {
            let startname = format_tstamp(hdr.test_spec.start_time);
            let tfname = dir.join(format!("{startname}{OWPING_INC_EXT}"));
            let mut tfp = match File::create(&tfname) {
                Ok(f) => f,
                Err(e) => {
                    error!("OWStatsParse: fopen({}): {e}", tfname.display());
                    return Err(());
                },
            };
            if want_records {
                if hdr.twoway || twoway {
                    for r in &twrecs {
                        if r.sent.seq_no < begin || (end != u32::MAX && r.sent.seq_no >= end) {
                            continue;
                        }
                        let _ = print_tw_verbose(
                            r,
                            stats.scale,
                            &stats.scale_abrv,
                            args.display_unix_ts,
                            &mut tfp,
                        );
                    }
                } else {
                    for r in &oneway {
                        if r.seq_no < begin || (end != u32::MAX && r.seq_no >= end) {
                            continue;
                        }
                        let _ = print_oneway_verbose(
                            r,
                            stats.scale,
                            &stats.scale_abrv,
                            args.display_unix_ts,
                            &mut tfp,
                        );
                    }
                }
            }
            emit(stats, &mut tfp)?;
            drop(tfp);
            finalize_printfile(stats, &tfname, ext)?;
        } else {
            let mut out = std::io::stdout();
            if want_records {
                if hdr.twoway || twoway {
                    for r in &twrecs {
                        if r.sent.seq_no < begin || (end != u32::MAX && r.sent.seq_no >= end) {
                            continue;
                        }
                        let _ = print_tw_verbose(
                            r,
                            stats.scale,
                            &stats.scale_abrv,
                            args.display_unix_ts,
                            &mut out,
                        );
                    }
                } else {
                    for r in &oneway {
                        if r.seq_no < begin || (end != u32::MAX && r.seq_no >= end) {
                            continue;
                        }
                        let _ = print_oneway_verbose(
                            r,
                            stats.scale,
                            &stats.scale_abrv,
                            args.display_unix_ts,
                            &mut out,
                        );
                    }
                }
            }
            emit(stats, &mut out)?;
        }
        Ok(())
    };

    if num_sum == 0 {
        run_one(&mut stats, 0, u32::MAX)?;
    } else {
        for sum in 0..num_sum {
            let begin = args.num_bucket_packets.saturating_mul(sum);
            let mut end = args.num_bucket_packets.saturating_mul(sum + 1);
            if end > npackets {
                end = u32::MAX;
            }
            run_one(&mut stats, begin, end)?;
        }
    }

    Ok(())
}

/// Open save-from path or unlinked temp for a local receive session.
pub fn open_from_fp(save_from: Option<&str>) -> Option<File> {
    save_from.map_or_else(tfile, |path| {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
        {
            Ok(f) => Some(f),
            Err(e) => {
                error!("fopen({path}): {e}");
                None
            },
        }
    })
}

pub fn report_fetch_fail(sid: &OwampSid) {
    error!("Unable to fetch data for sid({})", sid_hex_encode(sid));
}

#[cfg(test)]
mod tests {
    use super::*;
    use owamp::owamp::{OwampTimeStamp, OwampTwDataRec};

    fn ts(raw: u64, sync: bool) -> OwampTimeStamp {
        OwampTimeStamp {
            owptime: OwampNum64(raw),
            sync,
            multiplier: 1,
            scale: 0,
        }
    }

    #[test]
    fn printraw_oneway_fields() {
        let rec = OwampDataRec {
            seq_no: 7,
            send: ts(100, true),
            recv: ts(200, true),
            ttl: 64,
        };
        let mut buf = Vec::new();
        printraw(&rec, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.starts_with("7 "));
        assert!(s.contains(" 1 "));
        assert!(s.trim_end().ends_with("64"));
    }

    #[test]
    fn printraw_tw_field_count() {
        let rec = OwampTwDataRec {
            sent: OwampDataRec {
                seq_no: 1,
                send: ts(10, true),
                recv: ts(20, true),
                ttl: 255,
            },
            reflected: OwampDataRec {
                seq_no: 1,
                send: ts(30, true),
                recv: ts(40, true),
                ttl: 254,
            },
        };
        let mut buf = Vec::new();
        printraw_tw(&rec, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        // 16 whitespace-separated fields
        assert_eq!(s.split_whitespace().count(), 16);
    }
}
