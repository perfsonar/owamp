//! Port of `owampd/policy.c` + `policy.h` — Limits/PFS-Parsing und Policy-Hooks.

use std::cell::Cell;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::RawFd;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

// Per-control-thread broker fd. C `fork` gives each child its own `policy->fd`;
// threaded Rust approximates that with TLS so concurrent children do not race
// on `Policy::fd`.
thread_local! {
    static BROKER_FD: Cell<i32> = const { Cell::new(-1) };
}

use anyhow::{anyhow, bail, Context as AnyhowContext, Result};
use tracing::{debug, error, warn};

use owamp::api::{test_diskspace, test_packet_bandwidth};
use owamp::owampP::{
    OWP_CLOSE_FILE, OWP_FILE_EXT, OWP_MODE_AUTHENTICATED, OWP_MODE_ENCRYPTED, OWP_MODE_OPEN,
    OWP_OPEN_FILE, TWP_MODE_MIXED,
};

/// Match C `PATH_MAX` checks in `InitializeDiskUsage` / `node_dir` / `OWPDOpenFile`.
const PATH_MAX: usize = libc::PATH_MAX as usize;
use owamp::context::{
    AcceptType, Context, Control, ErrSeverity, SessionMode, Sid, TestSpec, OWP_MODE_DOCIPHER_CNTRL,
};

use crate::fts::{Fts, FTS_D, FTS_DNR, FTS_DP, FTS_ERR, FTS_NOCHDIR, FTS_PHYSICAL};

pub const OWP_PFS_FILE_SUFFIX: &str = ".pfs";
pub const OWP_LIMITS_FILE_SUFFIX: &str = ".limits";
pub const OWP_CATALOG_DIR: &str = "catalog";
pub const OWP_HIER_DIR: &str = "hierarchy";
pub const OWPD_POLICY: &str = "OWPDPOLICY";
pub const OWPD_POLICY_NODE: &str = "OWPDPOLICY_NODE";
pub const OWPD_MAX_CLASS_LEN: usize = 80;

pub const OWPD_LIM_PARENT: u32 = 0;
pub const OWPD_LIM_BANDWIDTH: u32 = 1;
pub const OWPD_LIM_DISK: u32 = 3;
pub const OWPD_LIM_DELETE_ON_FETCH: u32 = 4;
pub const OWPD_LIM_ALLOW_OPEN_MODE: u32 = 5;
pub const OWPD_LIM_TEST_SESSIONS: u32 = 6;

pub const OWPD_MESG_MARK: u32 = 0xfefe_fefe;
pub const OWPD_MESG_CLASS: u32 = 0xcdef;
pub const OWPD_MESG_RESOURCE: u32 = 0xbeef;
pub const OWPD_MESG_REQUEST: u32 = 0xfeed;
pub const OWPD_MESG_RELEASE: u32 = 0xdead;
pub const OWPD_MESG_CLAIM: u32 = 0x001f_eed1;
pub const OWPD_MESG_INVALID: u32 = 0x0;
pub const OWPD_MESG_OK: u32 = 0x1;
pub const OWPD_MESG_DENIED: u32 = 0x2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InfoType {
    Invalid = 0,
    Fetch = 1,
    Test = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LimType {
    Int,
    Bool,
    Not,
}

struct LimDesc {
    limit: u32,
    name: &'static str,
    ltype: LimType,
    def_value: u64,
}

const LIMKEYS: &[LimDesc] = &[
    LimDesc {
        limit: OWPD_LIM_PARENT,
        name: "parent",
        ltype: LimType::Not,
        def_value: 0,
    },
    LimDesc {
        limit: OWPD_LIM_BANDWIDTH,
        name: "bandwidth",
        ltype: LimType::Int,
        def_value: 0,
    },
    LimDesc {
        limit: OWPD_LIM_DISK,
        name: "disk",
        ltype: LimType::Int,
        def_value: 0,
    },
    LimDesc {
        limit: OWPD_LIM_DELETE_ON_FETCH,
        name: "delete_on_fetch",
        ltype: LimType::Bool,
        def_value: 0,
    },
    LimDesc {
        limit: OWPD_LIM_ALLOW_OPEN_MODE,
        name: "allow_open_mode",
        ltype: LimType::Bool,
        def_value: 1,
    },
    LimDesc {
        limit: OWPD_LIM_TEST_SESSIONS,
        name: "test_sessions",
        ltype: LimType::Int,
        def_value: 0,
    },
];

fn def_limit(lim: u32) -> u64 {
    LIMKEYS
        .iter()
        .find(|k| k.limit == lim)
        .map_or(0, |k| k.def_value)
}

fn max_lim_count() -> usize {
    LIMKEYS.iter().filter(|k| k.ltype != LimType::Not).count()
}

#[derive(Clone, Debug)]
pub struct LimRec {
    pub limit: u32,
    pub value: u64,
}

#[derive(Debug)]
pub struct PolicyNode {
    pub nodename: String,
    pub parent: Option<String>,
    pub limits: Vec<LimRec>,
    pub used: Mutex<Vec<LimRec>>,
    pub initdisk: Mutex<u64>,
}

impl PolicyNode {
    pub fn get_limit(&self, lim: u32) -> u64 {
        self.limits
            .iter()
            .find(|l| l.limit == lim)
            .map_or_else(|| def_limit(lim), |l| l.value)
    }

    fn get_used(&self, lim: u32) -> u64 {
        self.used
            .lock()
            .unwrap()
            .iter()
            .find(|l| l.limit == lim)
            .map_or(0, |l| l.value)
    }

    fn adjust_used(&self, lim: u32, delta: i64) {
        let mut used = self.used.lock().unwrap();
        if let Some(u) = used.iter_mut().find(|l| l.limit == lim) {
            if delta >= 0 {
                u.value = u.value.saturating_add(delta as u64);
            } else {
                u.value = u.value.saturating_sub((-delta) as u64);
            }
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
enum PidKey {
    Default,
    User(String),
    Net {
        addr: [u8; 16],
        addrsize: u8,
        mask_len: u8,
    },
}

#[derive(Debug)]
pub struct Policy {
    pub datadir: PathBuf,
    pub diskfudge: f64,
    /// IPC socket to parent resource broker (`OWPDPolicyRec.fd`); `-1` = in-process.
    pub fd: Mutex<i32>,
    pub root: Option<String>,
    pub limits: HashMap<String, Arc<PolicyNode>>,
    idents: HashMap<PidKey, String>,
    pub pfs: HashMap<String, Vec<u8>>,
    /// sockfd → classname for active control sessions
    session_class: Mutex<HashMap<i32, String>>,
}

impl Policy {
    pub fn node(&self, name: &str) -> Option<Arc<PolicyNode>> {
        self.limits.get(name).cloned()
    }

    pub fn root_node(&self) -> Option<Arc<PolicyNode>> {
        self.root.as_ref().and_then(|n| self.node(n))
    }
}

/// Parse SI-ish integer (`I2StrToNum`-ähnlich): plain int oder K/M/G/T Suffix.
fn parse_num_fixed(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        bail!("empty number");
    }
    let last = s.as_bytes()[s.len() - 1];
    let (digits, mult) = match last {
        b'k' | b'K' => (&s[..s.len() - 1], 1_000u64),
        b'm' | b'M' => (&s[..s.len() - 1], 1_000_000),
        b'g' | b'G' => (&s[..s.len() - 1], 1_000_000_000),
        b't' | b'T' => (&s[..s.len() - 1], 1_000_000_000_000),
        _ => (s, 1),
    };
    let n: u64 = digits
        .trim()
        .parse()
        .with_context(|| format!("invalid number {s}"))?;
    Ok(n.saturating_mul(mult))
}

/// `I2ParsePFFile` / `parsepfs` — identity + **hex-encoded** passphrase only.
///
/// Valid line: `<id><ws><hex-pf>` where hex length is even, non-empty, and the
/// last token on the line. Comments (`#` as first non-ws) and blank lines are
/// skipped. Leading spaces on content lines are rejected (C `parsefileline`).
fn parse_pfs_file(path: &Path, pfs: &mut HashMap<String, Vec<u8>>) -> Result<()> {
    let f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let reader = BufReader::new(f);
    for (lineno, raw) in reader.lines().enumerate() {
        let raw = raw?;
        let line_no = lineno + 1;
        // Leading spaces only legal before a full-line comment.
        let trimmed_start = raw.trim_start();
        if trimmed_start.is_empty() {
            continue;
        }
        if trimmed_start.starts_with('#') {
            continue;
        }
        if raw.as_bytes().first().is_some_and(u8::is_ascii_whitespace) {
            bail!("{}:{}: Leading spaces not allowed", path.display(), line_no);
        }
        let line = raw.trim_end();
        // id = first non-ws run; must be followed by whitespace then hex-pf.
        let id_len = line
            .find(|c: char| c.is_ascii_whitespace())
            .ok_or_else(|| anyhow!("{}:{}: missing passphrase", path.display(), line_no))?;
        let user = &line[..id_len];
        if user.is_empty() {
            bail!("{}:{}: empty identity", path.display(), line_no);
        }
        if user.len() > OWPD_MAX_CLASS_LEN {
            bail!(
                "{}:{}: identity \"{user}\" too long",
                path.display(),
                line_no
            );
        }
        let rest = line[id_len..].trim_start();
        if rest.is_empty() {
            bail!("{}:{}: missing passphrase", path.display(), line_no);
        }
        let hex_len = rest
            .find(|c: char| c.is_ascii_whitespace())
            .unwrap_or(rest.len());
        let hex_pf = &rest[..hex_len];
        let after = rest[hex_len..].trim_start();
        // Trailing tokens only allowed if empty (C: must be last on line).
        if !after.is_empty() {
            bail!(
                "{}:{}: Invalid file syntax (trailing data)",
                path.display(),
                line_no
            );
        }
        if hex_pf.is_empty() || hex_pf.len() % 2 != 0 {
            bail!("{}:{}: Invalid key: not hex?", path.display(), line_no);
        }
        if !hex_pf.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("{}:{}: Invalid key: not hex?", path.display(), line_no);
        }
        if pfs.contains_key(user) {
            bail!(
                "{}:{}: username \"{user}\" duplicated",
                path.display(),
                line_no
            );
        }
        let bytes = hex::decode(hex_pf)
            .with_context(|| format!("{}:{}: Invalid key: not hex?", path.display(), line_no))?;
        pfs.insert(user.to_string(), bytes);
    }
    Ok(())
}

/// Limits-file line cleanup: `I2GetConfLine` skips `#` comment / blank lines
/// after trimming leading whitespace (no mid-line `#` strip).
fn strip_conf_line(line: &str) -> String {
    let s = line.trim();
    if s.is_empty() || s.starts_with('#') {
        return String::new();
    }
    s.to_string()
}

fn parse_limit_line(policy: &mut Policy, line: &str, maxlim: usize) -> Result<()> {
    let mut tokens = line.split_whitespace();
    let cname = tokens
        .next()
        .ok_or_else(|| anyhow!("limit: missing classname"))?;
    if cname.len() > OWPD_MAX_CLASS_LEN {
        bail!("classname \"{cname}\" too long");
    }
    if policy.limits.contains_key(cname) {
        bail!("classname \"{cname}\" duplicated");
    }
    let with = tokens
        .next()
        .ok_or_else(|| anyhow!("limit: expected \"with\""))?;
    if !with.eq_ignore_ascii_case("with") {
        bail!("limit: expected \"with\", got {with}");
    }
    let rest: String = tokens.collect::<Vec<_>>().join(" ");

    let mut parent: Option<String> = None;
    let mut limtemp: Vec<LimRec> = Vec::new();

    for part in rest.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if limtemp.len() >= maxlim && !part.to_ascii_lowercase().starts_with("parent") {
            // parent is separate; allow up to maxlim real limits
        }
        let (limname, limval) = part.find('=').map_or_else(
            || {
                let mut ws = part.split_whitespace();
                (ws.next().unwrap_or(""), ws.next().unwrap_or(""))
            },
            |eq| (part[..eq].trim(), part[eq + 1..].trim()),
        );
        if limname.is_empty() {
            continue;
        }

        if limname.eq_ignore_ascii_case("parent") {
            if policy.root.is_none() {
                bail!("\"parent\" specified for root node");
            }
            if parent.is_some() {
                bail!("multiple parents specified");
            }
            if !policy.limits.contains_key(limval) {
                bail!("parent \"{limval}\" undefined");
            }
            parent = Some(limval.to_string());
            continue;
        }

        let desc = LIMKEYS
            .iter()
            .find(|k| k.ltype != LimType::Not && k.name.eq_ignore_ascii_case(limname))
            .ok_or_else(|| anyhow!("Unknown limit name \"{limname}\""))?;

        if limtemp.iter().any(|l| l.limit == desc.limit) {
            bail!("multiple {limname} values specified");
        }
        if limtemp.len() >= maxlim {
            bail!("Too many limit declarations");
        }

        let value = match desc.ltype {
            LimType::Int => parse_num_fixed(limval)?,
            LimType::Bool => {
                if limval.eq_ignore_ascii_case("on") {
                    1
                } else if limval.eq_ignore_ascii_case("off") {
                    0
                } else {
                    bail!("Invalid value for \"{limname}\"");
                }
            },
            LimType::Not => unreachable!(),
        };
        limtemp.push(LimRec {
            limit: desc.limit,
            value,
        });
    }

    // Inherit non-overridden parent limits
    if let Some(ref pname) = parent {
        let pnode = policy.limits.get(pname).unwrap().clone();
        for pl in &pnode.limits {
            if !limtemp.iter().any(|l| l.limit == pl.limit) {
                limtemp.push(pl.clone());
            }
        }
    } else if policy.root.is_some() {
        bail!("\"parent\" must be specified for non-root node");
    }

    let used: Vec<LimRec> = limtemp
        .iter()
        .map(|l| LimRec {
            limit: l.limit,
            value: 0,
        })
        .collect();

    let node = Arc::new(PolicyNode {
        nodename: cname.to_string(),
        parent,
        limits: limtemp,
        used: Mutex::new(used),
        initdisk: Mutex::new(0),
    });
    if policy.root.is_none() {
        policy.root = Some(cname.to_string());
    }
    policy.limits.insert(cname.to_string(), node);
    Ok(())
}

fn apply_netmask_to_addr(addr: &mut [u8], addrsize: usize, mask_len: u8) {
    let nbytes = (mask_len / 8) as usize;
    let nbits = mask_len % 8;
    if nbits == 0 {
        // Full-byte boundary: zero everything past the masked prefix.
        for b in addr.iter_mut().take(addrsize).skip(nbytes) {
            *b = 0;
        }
    } else if nbytes < addrsize {
        addr[nbytes] &= 0xffu8 << (8 - nbits);
        for b in addr.iter_mut().take(addrsize).skip(nbytes + 1) {
            *b = 0;
        }
    }
}

fn parse_assign_line(policy: &mut Policy, line: &str) -> Result<()> {
    let mut tokens = line.split_whitespace();
    let kind = tokens
        .next()
        .ok_or_else(|| anyhow!("assign: missing type"))?;

    let key = if kind.eq_ignore_ascii_case("default") {
        if policy.idents.contains_key(&PidKey::Default) {
            bail!("Invalid multiple \"assign default\" lines");
        }
        PidKey::Default
    } else if kind.eq_ignore_ascii_case("net") {
        let arg = tokens
            .next()
            .ok_or_else(|| anyhow!("Invalid \"assign net\" argument"))?;
        let (addr_s, mask_s) = match arg.split_once('/') {
            Some((a, m)) => (a, Some(m)),
            None => (arg, None),
        };
        let ip: IpAddr = addr_s
            .parse()
            .with_context(|| format!("Invalid address \"{addr_s}\""))?;
        let (mut addrval, addrsize) = match ip {
            IpAddr::V4(v4) => {
                let mut a = [0u8; 16];
                a[..4].copy_from_slice(&v4.octets());
                (a, 4u8)
            },
            IpAddr::V6(v6) => {
                let o = v6.octets();
                // v4-mapped → treat as v4
                if o[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
                    let mut a = [0u8; 16];
                    a[..4].copy_from_slice(&o[12..16]);
                    (a, 4u8)
                } else {
                    (o, 16u8)
                }
            },
        };
        let mask_len = if let Some(m) = mask_s {
            let ml: u8 = m.parse().context("Invalid address mask")?;
            if ml < 1 || ml as usize > addrsize as usize * 8 {
                bail!("Invalid address mask \"{m}\"");
            }
            ml
        } else {
            addrsize * 8
        };
        // Validate host bits clear
        let mut check = addrval;
        apply_netmask_to_addr(&mut check, addrsize as usize, mask_len);
        if check[..addrsize as usize] != addrval[..addrsize as usize] {
            bail!("Invalid address/mask combination");
        }
        apply_netmask_to_addr(&mut addrval, addrsize as usize, mask_len);
        PidKey::Net {
            addr: addrval,
            addrsize,
            mask_len,
        }
    } else if kind.eq_ignore_ascii_case("user") {
        let user = tokens
            .next()
            .ok_or_else(|| anyhow!("assign user: missing"))?;
        // C: key.dsize >= sizeof(OWPUserID) → invalid (OWP_USERID_LEN+1 == 81).
        if user.len() >= 81 || !policy.pfs.contains_key(user) {
            bail!("Invalid user \"{user}\"");
        }
        PidKey::User(user.to_string())
    } else {
        bail!("Unknown \"assign\" specification");
    };

    let classname = tokens
        .next()
        .ok_or_else(|| anyhow!("assign: missing classname"))?;
    if !policy.limits.contains_key(classname) {
        bail!("Unknown limitclass name \"{classname}\"");
    }
    policy.idents.insert(key, classname.to_string());
    Ok(())
}

fn parse_limits_file(policy: &mut Policy, path: &Path) -> Result<()> {
    let maxlim = max_lim_count();
    let f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Default open class
            parse_limit_line(policy, "default with", maxlim)?;
            return Ok(());
        },
        Err(e) => return Err(e.into()),
    };
    let reader = BufReader::new(f);
    let mut any = false;
    for (lineno, line) in reader.lines().enumerate() {
        let line = line?;
        let line = strip_conf_line(&line);
        if line.is_empty() {
            continue;
        }
        any = true;
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("limit") {
            let rest = line[5..].trim_start();
            parse_limit_line(policy, rest, maxlim)
                .with_context(|| format!("{}:{}", path.display(), lineno + 1))?;
        } else if lower.starts_with("assign") {
            let rest = line[6..].trim_start();
            parse_assign_line(policy, rest)
                .with_context(|| format!("{}:{}", path.display(), lineno + 1))?;
        } else {
            bail!("{}:{}: invalid directive", path.display(), lineno + 1);
        }
    }
    if !any || policy.root.is_none() {
        warn!("WARNING: No limits specified — installing default");
        parse_limit_line(policy, "default with", maxlim)?;
    }
    Ok(())
}

fn node_from_userid(policy: &Policy, userid: &str) -> Option<Arc<PolicyNode>> {
    let key = PidKey::User(userid.to_string());
    policy.idents.get(&key).and_then(|n| policy.node(n))
}

fn node_default(policy: &Policy) -> Option<Arc<PolicyNode>> {
    if let Some(n) = policy.idents.get(&PidKey::Default) {
        return policy.node(n);
    }
    policy.root_node()
}

fn node_from_addr(policy: &Policy, remote: SocketAddr) -> Option<Arc<PolicyNode>> {
    let (mut addrval, addrsize) = match remote.ip() {
        IpAddr::V4(v4) => {
            let mut a = [0u8; 16];
            a[..4].copy_from_slice(&v4.octets());
            (a, 4u8)
        },
        IpAddr::V6(v6) => {
            let o = v6.octets();
            if o[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
                let mut a = [0u8; 16];
                a[..4].copy_from_slice(&o[12..16]);
                (a, 4u8)
            } else {
                (o, 16u8)
            }
        },
    };

    for mask_len in (1..=addrsize * 8).rev() {
        let mut masked = addrval;
        apply_netmask_to_addr(&mut masked, addrsize as usize, mask_len);
        let key = PidKey::Net {
            addr: masked,
            addrsize,
            mask_len,
        };
        if let Some(n) = policy.idents.get(&key).and_then(|c| policy.node(c)) {
            return Some(n);
        }
        // clear next bit for next iteration (C does in-place)
        apply_netmask_to_addr(
            &mut addrval,
            addrsize as usize,
            mask_len.saturating_sub(1).max(1),
        );
        if mask_len == 1 {
            break;
        }
    }
    node_default(policy)
}

fn lim_kind(lim: u32) -> Option<LimType> {
    LIMKEYS.iter().find(|k| k.limit == lim).map(|k| k.ltype)
}

fn lim_name(lim: u32) -> &'static str {
    LIMKEYS
        .iter()
        .find(|k| k.limit == lim)
        .map_or("unknown", |k| k.name)
}

/// Single-node integer usage set (`IntegerResourceUsage` / disk init).
fn resource_usage(node: &PolicyNode, lim: LimRec) {
    if lim_kind(lim.limit) != Some(LimType::Int) {
        return;
    }
    let limit = node.get_limit(lim.limit);
    if limit == 0 {
        return;
    }
    {
        let mut used = node.used.lock().unwrap();
        if let Some(u) = used.iter_mut().find(|l| l.limit == lim.limit) {
            u.value = lim.value;
        } else {
            used.push(lim.clone());
        }
    }
    if lim.value > limit {
        warn!(
            "Resource usage exceeds limits {}:{} (used = {}, limit = {})",
            node.nodename,
            lim_name(lim.limit),
            lim.value,
            limit
        );
    }
}

/// `IntegerResourceDemand` — recursive parent walk with CLAIM fudge.
fn integer_resource_demand(
    policy: &Policy,
    node: Option<&Arc<PolicyNode>>,
    query: u32,
    lim: LimRec,
) -> bool {
    let Some(node) = node else {
        return true;
    };
    let limit = node
        .limits
        .iter()
        .find(|l| l.limit == lim.limit)
        .map(|l| l.value);
    let Some(limit) = limit else {
        // No limit record → unlimited (C asserts def==0 and returns True
        // without walking parents; inheritance copies defined limits down).
        let _ = policy;
        let _ = query;
        return true;
    };
    if limit == 0 {
        return integer_resource_demand(
            policy,
            node.parent.as_ref().and_then(|p| policy.node(p)).as_ref(),
            query,
            lim,
        );
    }

    if query == OWPD_MESG_RELEASE {
        let used = node.get_used(lim.limit);
        if lim.value > used {
            error!(
                "Request to release unallocated resources: {}:{} (allocated={}, release={})",
                node.nodename,
                lim_name(lim.limit),
                used,
                lim.value
            );
            return false;
        }
        if !integer_resource_demand(
            policy,
            node.parent.as_ref().and_then(|p| policy.node(p)).as_ref(),
            query,
            lim.clone(),
        ) {
            return false;
        }
        node.adjust_used(lim.limit, -(lim.value as i64));
        return true;
    }

    let mut fudge = 1.0f64;
    if query == OWPD_MESG_CLAIM {
        if lim.limit != OWPD_LIM_DISK {
            error!("Invalid \"CLAIM\" request");
            return false;
        }
        fudge = policy.diskfudge;
    } else if query != OWPD_MESG_REQUEST {
        error!("Unknown resource request type: {query}");
        return false;
    }

    // C: `(lim.value + used) > (limit * fudge)` with floating multiply.
    let used = node.get_used(lim.limit);
    let demand = used as f64 + lim.value as f64;
    let allowed = limit as f64 * fudge;
    if demand > allowed {
        return false;
    }
    if !integer_resource_demand(
        policy,
        node.parent.as_ref().and_then(|p| policy.node(p)).as_ref(),
        query,
        lim.clone(),
    ) {
        return false;
    }
    node.adjust_used(lim.limit, lim.value as i64);
    true
}

/// `OWPDResourceDemand`
pub fn resource_demand(policy: &Policy, node: &Arc<PolicyNode>, query: u32, lim: LimRec) -> bool {
    match lim_kind(lim.limit) {
        None | Some(LimType::Not) => return false,
        Some(LimType::Bool) => {
            if query == OWPD_MESG_RELEASE {
                return true;
            }
            return node.get_limit(lim.limit) == lim.value;
        },
        Some(LimType::Int) => {},
    }

    let ret = integer_resource_demand(policy, Some(node), query, lim.clone());
    let action = if query == OWPD_MESG_RELEASE {
        "release"
    } else {
        "request"
    };
    if ret {
        debug!(
            "ResReq ALLOWED: {}:{}:{} = {} (result = {}, limit = {})",
            node.nodename,
            action,
            lim_name(lim.limit),
            lim.value,
            node.get_used(lim.limit),
            node.get_limit(lim.limit)
        );
    } else {
        error!(
            "ResReq DENIED: {}:{}:{} = {} (result = {}, limit = {})",
            node.nodename,
            action,
            lim_name(lim.limit),
            lim.value,
            node.get_used(lim.limit),
            node.get_limit(lim.limit)
        );
    }
    if !ret {
        let mut cur = node.parent.as_ref().and_then(|p| policy.node(p));
        while let Some(n) = cur {
            error!(
                "ResReq DENIED: {}:{}:{} = {} (result = {}, limit = {})",
                n.nodename,
                if query == OWPD_MESG_RELEASE {
                    "release"
                } else {
                    "request"
                },
                lim_name(lim.limit),
                lim.value,
                n.get_used(lim.limit),
                n.get_limit(lim.limit)
            );
            cur = n.parent.as_ref().and_then(|p| policy.node(p));
        }
    }
    ret
}

#[allow(dead_code)]
fn resource_demand_tree(
    policy: &Policy,
    node: &Arc<PolicyNode>,
    request: bool,
    lim: LimRec,
) -> bool {
    let q = if request {
        OWPD_MESG_REQUEST
    } else {
        OWPD_MESG_RELEASE
    };
    resource_demand(policy, node, q, lim)
}

/// `OWPDAllowOpenMode`
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn allow_open_mode(policy: &Policy, peer: SocketAddr) -> Result<bool, ErrSeverity> {
    let node = node_from_addr(policy, peer).ok_or(ErrSeverity::Fatal)?;
    Ok(node.get_limit(OWPD_LIM_ALLOW_OPEN_MODE) != 0)
}

/// `OWPDPolicyInstall` — lädt `.pfs`/`.limits` und registriert Context-Hooks.
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn policy_install(
    ctx: &Context,
    datadir: &Path,
    confdir: &Path,
    diskfudge: f64,
    fileprefix: &str,
) -> Result<Arc<Policy>> {
    let mut policy = Policy {
        datadir: datadir.to_path_buf(),
        diskfudge,
        fd: Mutex::new(-1),
        root: None,
        limits: HashMap::new(),
        idents: HashMap::new(),
        pfs: HashMap::new(),
        session_class: Mutex::new(HashMap::new()),
    };

    let pfs_path = confdir.join(format!("{fileprefix}{OWP_PFS_FILE_SUFFIX}"));
    let lim_path = confdir.join(format!("{fileprefix}{OWP_LIMITS_FILE_SUFFIX}"));

    parse_pfs_file(&pfs_path, &mut policy.pfs)
        .with_context(|| format!("parse {}", pfs_path.display()))?;
    parse_limits_file(&mut policy, &lim_path)
        .with_context(|| format!("parse {}", lim_path.display()))?;

    let policy = Arc::new(policy);
    attach_policy_hooks(ctx, policy.clone());
    Ok(policy)
}

/// Installiert Policy-Hooks auf einem (ggf. neuen) Context — für threaded
/// Control-Kinder, die einen eigenen `Context` brauchen (`Rc`/`!Send`).
pub fn attach_policy_hooks(ctx: &Context, policy: Arc<Policy>) {
    install_hooks(ctx, policy.clone());
    let _ = ctx.config_set_v(OWPD_POLICY, Arc::as_ptr(&policy) as usize);
    // Open/Close markers are set by `set_open_file` / `set_close_file` in install_hooks.
    let _ = (OWP_OPEN_FILE, OWP_CLOSE_FILE);
}

/// Attach parent-broker IPC fd (`policy->fd` after fork).
///
/// Also sets a thread-local override so threaded control children (fork
/// approximation) each talk on their own socketpair end.
///
/// # Panics
///
/// Panics if an internal invariant is violated.
pub fn policy_set_broker_fd(policy: &Policy, fd: i32) {
    *policy.fd.lock().unwrap() = fd;
    BROKER_FD.with(|c| c.set(fd));
}

/// Clear thread-local broker fd (child teardown).
pub fn policy_clear_broker_fd() {
    BROKER_FD.with(|c| c.set(-1));
}

/// Drop the control→classname binding when a control session ends
/// (C frees `OWPDPOLICY_NODE` with the control).
///
/// # Panics
///
/// Panics if an internal invariant is violated.
pub fn clear_session_class(policy: &Policy, sockfd: i32) {
    policy.session_class.lock().unwrap().remove(&sockfd);
}

fn broker_fd(policy: &Policy) -> i32 {
    let tl = BROKER_FD.with(std::cell::Cell::get);
    if tl >= 0 {
        tl
    } else {
        *policy.fd.lock().unwrap()
    }
}

/// `OWPDPolicyPostInstall`
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn policy_post_install(policy: &Arc<Policy>) -> Result<()> {
    initialize_disk_usage(policy)
}

fn clean_catalog(catalog: &Path) -> Result<()> {
    fs::create_dir_all(catalog)?;
    let mut fts = Fts::open(&[catalog], FTS_PHYSICAL)?;
    while let Some(ent) = fts.read() {
        match ent.info {
            // C clean_tree: FTS_D / FTS_DC ignored
            crate::fts::FTS_D | crate::fts::FTS_DC => {},
            FTS_ERR if ent.errno != libc::ENOENT => {
                bail!("{}: errno {}", ent.path.display(), ent.errno);
            },
            FTS_DNR | FTS_DP => {
                if ent.level < 1 {
                    continue;
                }
                let _ = fs::remove_dir(&ent.path);
            },
            _ => {
                let _ = fs::remove_file(&ent.path);
            },
        }
    }
    fts.close();
    Ok(())
}

fn is_session_filename(name: &str) -> bool {
    let ext = OWP_FILE_EXT;
    if !name.ends_with(ext) {
        return false;
    }
    let stem = &name[..name.len() - ext.len()];
    stem.len() == 32 && stem.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `node_dir` — build/create hierarchy path for a classname chain.
///
/// `add_chars` mirrors C: bytes needed after this path (filename segment).
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn node_dir(policy: &Policy, classname: &str, make: bool) -> Result<PathBuf> {
    node_dir_with_extra(policy, classname, make, 0)
}

fn node_dir_with_extra(
    policy: &Policy,
    classname: &str,
    make: bool,
    add_chars: usize,
) -> Result<PathBuf> {
    let Some(n) = policy.node(classname) else {
        bail!("unknown class {classname}");
    };
    let mut chain = Vec::new();
    let mut cur = Some(n);
    while let Some(c) = cur {
        chain.push(c.nodename.clone());
        cur = c.parent.as_ref().and_then(|p| policy.node(p));
    }
    chain.reverse();
    // C: datadir + / + hierarchy + (/name)* + add_chars  ≤ PATH_MAX
    let mut len = policy.datadir.as_os_str().len() + 1 + OWP_HIER_DIR.len() + add_chars;
    for part in &chain {
        len += 1 + part.len();
    }
    if len > PATH_MAX {
        bail!("Data file path length too long.");
    }
    let mut path = policy.datadir.join(OWP_HIER_DIR);
    if make {
        fs::create_dir_all(&path)
            .with_context(|| format!("Unable to mkdir({})", path.display()))?;
    }
    for part in chain {
        path.push(part);
        if make {
            fs::create_dir_all(&path)
                .with_context(|| format!("Unable to mkdir({})", path.display()))?;
        }
    }
    Ok(path)
}

fn verify_datadir(policy: &Arc<Policy>, catalog: &Path, hier: &Path) -> Result<()> {
    let mut fts = match Fts::open(&[hier], FTS_PHYSICAL | FTS_NOCHDIR) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let mut dir_nodes: HashMap<PathBuf, String> = HashMap::new();
    while let Some(ent) = fts.read() {
        match ent.info {
            FTS_D if ent.level > 0 => {
                if let Some(node) = policy.limits.get(&ent.name) {
                    let ok = if ent.level == 1 {
                        policy.root.as_deref() == Some(node.nodename.as_str())
                    } else if let Some(parent_path) = ent.path.parent() {
                        match (dir_nodes.get(parent_path), &node.parent) {
                            (Some(pn), Some(expected)) => pn == expected,
                            _ => false,
                        }
                    } else {
                        false
                    };
                    if !ok {
                        bail!(
                            "verify_datadir: Directory \"{}\" unexpected for class {}",
                            ent.path.display(),
                            ent.name
                        );
                    }
                    dir_nodes.insert(ent.path.clone(), ent.name.clone());
                } else {
                    warn!(
                        "verify_datadir: Ignoring \"{}\": No associated user class",
                        ent.path.display()
                    );
                    fts.skip(&ent);
                }
            },
            crate::fts::FTS_DC => {},
            FTS_DP => {
                if let Some(name) = dir_nodes.get(&ent.path) {
                    if let Some(node) = policy.limits.get(name) {
                        let init = *node.initdisk.lock().unwrap();
                        resource_usage(
                            node,
                            LimRec {
                                limit: OWPD_LIM_DISK,
                                value: init,
                            },
                        );
                        if let Some(ref p) = node.parent {
                            if let Some(pn) = policy.limits.get(p) {
                                *pn.initdisk.lock().unwrap() += init;
                            }
                        }
                    }
                }
            },
            FTS_ERR | FTS_DNR if ent.errno != libc::ENOENT => {
                bail!("fts error {}", ent.path.display());
            },
            _ if !ent.is_dir => {
                if !is_session_filename(&ent.name) {
                    continue;
                }
                if let Some(parent) = ent.path.parent() {
                    if let Some(pname) = dir_nodes.get(parent) {
                        if let Some(node) = policy.limits.get(pname) {
                            *node.initdisk.lock().unwrap() += ent.size;
                            let link = catalog.join(&ent.name);
                            let _ = fs::remove_file(&link);
                            symlink(&ent.path, &link)?;
                        }
                    }
                }
            },
            _ => {},
        }
    }
    fts.close();
    Ok(())
}

fn initialize_disk_usage(policy: &Arc<Policy>) -> Result<()> {
    // C InitializeDiskUsage path-length guards.
    let len1 =
        policy.datadir.as_os_str().len() + 2 + OWP_CATALOG_DIR.len() + 32 + OWP_FILE_EXT.len();
    let len2 = policy.datadir.as_os_str().len() + 1 + OWP_HIER_DIR.len();
    if len1.max(len2) > PATH_MAX {
        bail!(
            "InitializeDiskUsage: datadir too long ({})",
            policy.datadir.display()
        );
    }
    if !policy.datadir.as_os_str().is_empty() {
        fs::create_dir_all(&policy.datadir)
            .with_context(|| format!("Unable to mkdir({})", policy.datadir.display()))?;
    }
    let catalog = policy.datadir.join(OWP_CATALOG_DIR);
    let hier = policy.datadir.join(OWP_HIER_DIR);
    clean_catalog(&catalog).with_context(|| {
        format!(
            "InitializeDiskUsage: Invalid catalog directory: {}",
            catalog.display()
        )
    })?;
    // hierarchy may be absent — verify_datadir treats ENOENT as ok; still ensure root exists
    // after catalog rebuild like C (mkdir happens lazily via node_dir / open_file).
    verify_datadir(policy, &catalog, &hier).with_context(|| {
        format!(
            "InitializeDiskUsage: Invalid datadir directory: {}",
            policy.datadir.display()
        )
    })
}

// ---------------------------------------------------------------------------
// Resource-broker IPC (`OWPDSend*` / `OWPDRead*`)
// ---------------------------------------------------------------------------

fn write_all_fd(fd: RawFd, buf: &[u8]) -> bool {
    let mut off = 0;
    while off < buf.len() {
        match unsafe {
            libc::write(
                fd,
                buf[off..].as_ptr() as *const libc::c_void,
                buf.len() - off,
            )
        } {
            n if n > 0 => off += n as usize,
            -1 if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted => {},
            _ => return false,
        }
    }
    true
}

fn read_exact_fd(fd: RawFd, buf: &mut [u8]) -> bool {
    let mut off = 0;
    while off < buf.len() {
        match unsafe {
            libc::read(
                fd,
                buf[off..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - off,
            )
        } {
            0 => return false,
            n if n > 0 => off += n as usize,
            -1 if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted => {},
            _ => return false,
        }
    }
    true
}

const fn u32_bytes(v: u32) -> [u8; 4] {
    v.to_ne_bytes()
}

const fn u64_bytes(v: u64) -> [u8; 8] {
    v.to_ne_bytes()
}

const fn read_u32(buf: &[u8]) -> u32 {
    u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]])
}

const fn read_u64(buf: &[u8]) -> u64 {
    u64::from_ne_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ])
}

/// `OWPDSendResponse`
#[must_use]
pub fn send_response(fd: RawFd, mesg: u32) -> i32 {
    let mut buf = [0u8; 12];
    buf[0..4].copy_from_slice(&u32_bytes(OWPD_MESG_MARK));
    buf[4..8].copy_from_slice(&u32_bytes(mesg));
    buf[8..12].copy_from_slice(&u32_bytes(OWPD_MESG_MARK));
    i32::from(!write_all_fd(fd, &buf))
}

/// `OWPDReadResponse`
#[must_use]
pub fn read_response(fd: RawFd) -> u32 {
    let mut buf = [0u8; 12];
    if !read_exact_fd(fd, &mut buf) {
        return OWPD_MESG_INVALID;
    }
    if read_u32(&buf[0..4]) != OWPD_MESG_MARK || read_u32(&buf[8..12]) != OWPD_MESG_MARK {
        return OWPD_MESG_INVALID;
    }
    read_u32(&buf[4..8])
}

/// `OWPDReadClass` — parent perspective.
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn read_class(policy: &Policy, fd: RawFd) -> Result<Option<Arc<PolicyNode>>, i32> {
    let mut hdr = [0u8; 8];
    match unsafe { libc::read(fd, hdr.as_mut_ptr() as *mut libc::c_void, 8) } {
        0 => return Err(0),
        8 => {},
        _ => return Err(1),
    }
    if read_u32(&hdr[0..4]) != OWPD_MESG_MARK || read_u32(&hdr[4..8]) != OWPD_MESG_CLASS {
        return Err(1);
    }
    let mut name = Vec::new();
    loop {
        let mut b = [0u8; 1];
        if !read_exact_fd(fd, &mut b) {
            return Err(1);
        }
        if b[0] == 0 {
            break;
        }
        name.push(b[0]);
        if name.len() > OWPD_MAX_CLASS_LEN {
            return Err(1);
        }
    }
    let mut mark = [0u8; 4];
    if !read_exact_fd(fd, &mut mark) || read_u32(&mark) != OWPD_MESG_MARK {
        return Err(1);
    }
    let cname = String::from_utf8_lossy(&name).into_owned();
    policy.node(&cname).map_or_else(
        || {
            let _ = send_response(fd, OWPD_MESG_DENIED);
            Ok(None)
        },
        |node| {
            let _ = send_response(fd, OWPD_MESG_OK);
            Ok(Some(node))
        },
    )
}

/// `OWPDSendClass` — child → parent.
pub fn send_class(policy: &Policy, node: &PolicyNode) -> u32 {
    let fd = broker_fd(policy);
    if fd < 0 {
        return OWPD_MESG_OK;
    }
    let mut buf = Vec::with_capacity(8 + node.nodename.len() + 1 + 4);
    buf.extend_from_slice(&u32_bytes(OWPD_MESG_MARK));
    buf.extend_from_slice(&u32_bytes(OWPD_MESG_CLASS));
    buf.extend_from_slice(node.nodename.as_bytes());
    buf.push(0);
    buf.extend_from_slice(&u32_bytes(OWPD_MESG_MARK));
    if !write_all_fd(fd, &buf) {
        error!("OWPDCheckControlPolicy: Unable to contact parent");
        return OWPD_MESG_INVALID;
    }
    read_response(fd)
}

/// `OWPDReadQuery` — parent perspective.
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn read_query(fd: RawFd) -> Result<(u32, LimRec), i32> {
    let mut buf = [0u8; 28];
    match unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 28) } {
        0 => return Err(0),
        28 => {},
        _ => return Err(1),
    }
    if read_u32(&buf[0..4]) != OWPD_MESG_MARK
        || read_u32(&buf[24..28]) != OWPD_MESG_MARK
        || read_u32(&buf[4..8]) != OWPD_MESG_RESOURCE
    {
        return Err(1);
    }
    let query = read_u32(&buf[8..12]);
    match query {
        OWPD_MESG_REQUEST | OWPD_MESG_RELEASE | OWPD_MESG_CLAIM => {},
        _ => return Err(1),
    }
    Ok((
        query,
        LimRec {
            limit: read_u32(&buf[12..16]),
            value: read_u64(&buf[16..24]),
        },
    ))
}

/// `OWPDQuery` — child → parent, or local demand when `fd < 0`.
pub fn query(policy: &Policy, node: &Arc<PolicyNode>, mesg: u32, lim: LimRec) -> u32 {
    let fd = broker_fd(policy);
    if fd < 0 {
        return if resource_demand(policy, node, mesg, lim) {
            OWPD_MESG_OK
        } else {
            OWPD_MESG_DENIED
        };
    }
    let mut buf = [0u8; 28];
    buf[0..4].copy_from_slice(&u32_bytes(OWPD_MESG_MARK));
    buf[4..8].copy_from_slice(&u32_bytes(OWPD_MESG_RESOURCE));
    buf[8..12].copy_from_slice(&u32_bytes(mesg));
    buf[12..16].copy_from_slice(&u32_bytes(lim.limit));
    buf[16..24].copy_from_slice(&u64_bytes(lim.value));
    buf[24..28].copy_from_slice(&u32_bytes(OWPD_MESG_MARK));
    if !write_all_fd(fd, &buf) {
        error!("OWPDQuery: Unable to contact parent");
        return OWPD_MESG_INVALID;
    }
    read_response(fd)
}

fn install_hooks(ctx: &Context, policy: Arc<Policy>) {
    let p_pf = policy.clone();
    ctx.set_get_pf(Box::new(move |_ctx, userid, pf_out, err_ret| {
        *err_ret = ErrSeverity::Ok;
        p_pf.pfs.get(userid).map_or_else(
            || {
                error!("userid \"{userid}\" unknown");
                false
            },
            |bytes| {
                *pf_out = Some(bytes.clone());
                true
            },
        )
    }));

    let p_ctrl = policy.clone();
    ctx.set_check_control_policy(Box::new(
        move |cntrl, mode, userid, _local, remote, err_ret| {
            *err_ret = ErrSeverity::Ok;
            let mut node = None;
            // Match C OWPDCheckControlPolicy:
            // 1) assign-user → class; 2) userid as classname in limits; 3) net/default.
            if (mode & OWP_MODE_DOCIPHER_CNTRL) != 0 {
                if let Some(uid) = userid {
                    node = node_from_userid(&p_ctrl, uid);
                    if node.is_none() {
                        debug!("No policy match for userid({uid}) - using netmask match");
                    }
                    // C overwrites with limits[userid] when classname == userid.
                    if let Some(n) = p_ctrl.node(uid) {
                        node = Some(n);
                    }
                }
            }
            if node.is_none() {
                let Some(remote) = remote else {
                    *err_ret = ErrSeverity::Fatal;
                    return false;
                };
                node = node_from_addr(&p_ctrl, remote);
            }
            let Some(node) = node else {
                *err_ret = ErrSeverity::Fatal;
                return false;
            };
            let ret = send_class(&p_ctrl, &node);
            if ret == OWPD_MESG_OK {
                p_ctrl
                    .session_class
                    .lock()
                    .unwrap()
                    .insert(cntrl.sockfd, node.nodename.clone());
                true
            } else {
                if ret != OWPD_MESG_DENIED {
                    *err_ret = ErrSeverity::Fatal;
                }
                false
            }
        },
    ));

    let p_test = policy.clone();
    ctx.set_check_test_policy(Box::new(
        move |cntrl, local_sender, _local, remote, test_spec, closure, err_ret| {
            *err_ret = ErrSeverity::Ok;
            let classname = p_test
                .session_class
                .lock()
                .unwrap()
                .get(&cntrl.sockfd)
                .cloned();
            let Some(classname) = classname else {
                *err_ret = ErrSeverity::Fatal;
                return false;
            };
            let Some(node) = p_test.node(&classname) else {
                *err_ret = ErrSeverity::Fatal;
                return false;
            };

            let one = LimRec {
                limit: OWPD_LIM_TEST_SESSIONS,
                value: 1,
            };
            if !resource_demand(&p_test, &node, OWPD_MESG_REQUEST, one) {
                return false;
            }

            let mut bw = LimRec { limit: 0, value: 0 };
            let mut disk_lim = LimRec { limit: 0, value: 0 };

            if !cntrl.twoway {
                let af = match remote {
                    SocketAddr::V4(_) => libc::AF_INET,
                    SocketAddr::V6(_) => libc::AF_INET6,
                };
                let bits = test_packet_bandwidth(&cntrl.ctx, af, cntrl.mode, test_spec);
                bw = LimRec {
                    limit: OWPD_LIM_BANDWIDTH,
                    value: bits.ceil() as u64,
                };
                let ret = query(&p_test, &node, OWPD_MESG_REQUEST, bw.clone());
                if ret == OWPD_MESG_DENIED {
                    let _ = resource_demand(
                        &p_test,
                        &node,
                        OWPD_MESG_RELEASE,
                        LimRec {
                            limit: OWPD_LIM_TEST_SESSIONS,
                            value: 1,
                        },
                    );
                    return false;
                }
                if ret == OWPD_MESG_INVALID {
                    *err_ret = ErrSeverity::Fatal;
                    return false;
                }
            }

            if !local_sender {
                // C: request OWPTestDiskspace as-is; diskfudge applies only to CLAIM.
                let disk = test_diskspace(test_spec);
                disk_lim = LimRec {
                    limit: OWPD_LIM_DISK,
                    value: disk,
                };
                let ret = query(&p_test, &node, OWPD_MESG_REQUEST, disk_lim.clone());
                if ret == OWPD_MESG_DENIED {
                    let _ = resource_demand(
                        &p_test,
                        &node,
                        OWPD_MESG_RELEASE,
                        LimRec {
                            limit: OWPD_LIM_TEST_SESSIONS,
                            value: 1,
                        },
                    );
                    if bw.limit != 0 {
                        let _ = query(&p_test, &node, OWPD_MESG_RELEASE, bw);
                    }
                    return false;
                }
                if ret == OWPD_MESG_INVALID {
                    *err_ret = ErrSeverity::Fatal;
                    return false;
                }
            }

            *closure = Some(Box::new(TestClosure {
                itype: InfoType::Test,
                classname: node.nodename.clone(),
                bandwidth: bw,
                disk: Mutex::new(disk_lim),
                finfo: Mutex::new(None),
            }));
            true
        },
    ));

    let p_fetch = policy.clone();
    ctx.set_check_fetch_policy(Box::new(
        move |cntrl, _local, _remote, begin, end, _sid, closure, err_ret| {
            *err_ret = ErrSeverity::Ok;
            // C OWPDCheckFetchPolicy: require POLICY_NODE; track begin/end for
            // delete_on_fetch (full-session fetch only).
            let classname = p_fetch
                .session_class
                .lock()
                .unwrap()
                .get(&cntrl.sockfd)
                .cloned();
            let Some(classname) = classname else {
                error!("OWPDCheckFetchPolicy: OWPDPOLICY_NODE not set");
                *err_ret = ErrSeverity::Fatal;
                return false;
            };
            if p_fetch.node(&classname).is_none() {
                error!("OWPDCheckFetchPolicy: OWPDPOLICY_NODE not set");
                *err_ret = ErrSeverity::Fatal;
                return false;
            }
            *closure = Some(Box::new(FetchClosure {
                itype: InfoType::Fetch,
                classname,
                begin,
                end,
                finfo: Mutex::new(None),
            }));
            true
        },
    ));

    let p_done = policy.clone();
    ctx.set_test_complete(Box::new(move |cntrl, closure, _aval| {
        let _ = cntrl;
        if let Some(c) = closure {
            if let Some(tc) = c.downcast_ref::<TestClosure>() {
                if tc.itype != InfoType::Test {
                    error!("OWPDTestComplete: Invalid closure");
                    return;
                }
                if let Some(node) = p_done.node(&tc.classname) {
                    // C OWPDTestComplete: only release bandwidth/disk via Query.
                    // test_sessions is not released on success (matches C).
                    // Session class stays on the control (not cleared here).
                    if tc.bandwidth.limit != 0 {
                        let _ = query(&p_done, &node, OWPD_MESG_RELEASE, tc.bandwidth.clone());
                    }
                    let disk = tc.disk.lock().unwrap().clone();
                    if disk.limit != 0 {
                        let _ = query(&p_done, &node, OWPD_MESG_RELEASE, disk);
                    }
                }
                if tc.finfo.lock().unwrap().is_some() {
                    warn!("OWPDTestComplete: finfo not closed?");
                }
            } else {
                error!("OWPDTestComplete: Invalid closure");
            }
        } else {
            error!("OWPDTestComplete: Invalid closure");
        }
    }));

    // Wire OWPDOpenFile / OWPDCloseFile like C PolicyInstall.
    let p_open = policy.clone();
    ctx.set_open_file(Box::new(move |_cntrl, closure, sid, fname_ret| {
        let Some(c) = closure else {
            error!("OWPDOpenFile: closure not set");
            return None;
        };
        match open_file_any(&p_open, c, sid) {
            Ok((fp, path)) => {
                *fname_ret = path;
                Some(fp)
            },
            Err(e) => {
                error!("OWPDOpenFile: {e:#}");
                None
            },
        }
    }));
    let p_close = policy;
    ctx.set_close_file(Box::new(move |_cntrl, closure, fp, aval| {
        let Some(c) = closure else {
            error!("OWPDCloseFile: closure not set");
            drop(fp);
            return;
        };
        if let Err(e) = close_file_any(&p_close, c, fp, aval) {
            error!("OWPDCloseFile: {e:#}");
        }
    }));
}

#[derive(Debug)]
struct FileInformation {
    node_classname: String,
    filepath: PathBuf,
    linkpath: PathBuf,
}

#[derive(Debug)]
struct TestClosure {
    itype: InfoType,
    classname: String,
    bandwidth: LimRec,
    /// Cleared by `CloseFile` after adjusting to reality (C `tinfo->res[1]=0`).
    disk: Mutex<LimRec>,
    /// Interior mutability so Open/Close hooks can update via `&dyn Any`.
    finfo: Mutex<Option<FileInformation>>,
}

#[derive(Debug)]
struct FetchClosure {
    itype: InfoType,
    #[allow(dead_code)]
    classname: String,
    begin: u32,
    end: u32,
    finfo: Mutex<Option<FileInformation>>,
}

/// Bytes after the classname dirname in a hierarchy session path:
/// `/` + 32 hex SID + `.owp`.
const fn session_path_tail_len() -> usize {
    1 + 32 + OWP_FILE_EXT.len()
}

/// Extract creating classname from a hierarchy filepath (C `OWPDOpenFile` fetch).
fn classname_from_hier_filepath(filepath: &Path) -> Result<String> {
    let s = filepath
        .to_str()
        .ok_or_else(|| anyhow!("Invalid link path encoding"))?;
    let tail = session_path_tail_len();
    if s.len() < tail {
        bail!("readlink: Invalid link");
    }
    // Temporarily treat path as truncated just after last nodename.
    let prefix = &s[..s.len() - tail];
    let dname = prefix
        .rsplit('/')
        .next()
        .filter(|d| !d.is_empty())
        .ok_or_else(|| anyhow!("Unable to determine policy for {}", filepath.display()))?;
    Ok(dname.to_string())
}

/// `OWPDOpenFile` — create/open session file under hierarchy + catalog symlink.
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn open_file(
    policy: &Policy,
    closure: &mut dyn std::any::Any,
    sid: &Sid,
) -> Result<(File, PathBuf)> {
    open_file_any(policy, closure, sid)
}

fn open_file_any(
    policy: &Policy,
    closure: &dyn std::any::Any,
    sid: &Sid,
) -> Result<(File, PathBuf)> {
    let sid_name = hex::encode(sid);
    if let Some(tinfo) = closure.downcast_ref::<TestClosure>() {
        if tinfo.itype != InfoType::Test {
            bail!("OWPDOpenFile: invalid closure");
        }
        let add = session_path_tail_len();
        let dir = node_dir_with_extra(policy, &tinfo.classname, true, add)?;
        let filepath = dir.join(format!("{sid_name}{OWP_FILE_EXT}"));
        if filepath.as_os_str().len() > PATH_MAX {
            bail!("Data file path length too long.");
        }
        let catalog = policy.datadir.join(OWP_CATALOG_DIR);
        fs::create_dir_all(&catalog)
            .with_context(|| format!("Unable to mkdir({})", catalog.display()))?;
        let linkpath = catalog.join(format!("{sid_name}{OWP_FILE_EXT}"));
        let fp = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&filepath)
            .with_context(|| format!("fopen({})", filepath.display()))?;
        let _ = fs::remove_file(&linkpath);
        if let Err(e) = symlink(&filepath, &linkpath) {
            let _ = fs::remove_file(&filepath);
            return Err(e).with_context(|| {
                format!("symlink({}, {})", filepath.display(), linkpath.display())
            });
        }
        *tinfo.finfo.lock().unwrap() = Some(FileInformation {
            node_classname: tinfo.classname.clone(),
            filepath: filepath.clone(),
            linkpath,
        });
        return Ok((fp, filepath));
    }
    if let Some(xinfo) = closure.downcast_ref::<FetchClosure>() {
        if xinfo.itype != InfoType::Fetch {
            bail!("OWPDOpenFile: invalid closure");
        }
        let linkpath = policy
            .datadir
            .join(OWP_CATALOG_DIR)
            .join(format!("{sid_name}{OWP_FILE_EXT}"));
        let filepath = fs::read_link(&linkpath)
            .with_context(|| format!("readlink({})", linkpath.display()))?;
        let fp_os = filepath.as_os_str().len();
        if fp_os >= PATH_MAX || fp_os < session_path_tail_len() {
            bail!("readlink({}): Invalid link", linkpath.display());
        }
        let class_from_path = classname_from_hier_filepath(&filepath)?;
        if !policy.limits.contains_key(&class_from_path) {
            warn!(
                "Unable to determine policy for {}: class {}",
                linkpath.display(),
                class_from_path
            );
        }
        let fp = OpenOptions::new()
            .read(true)
            .open(&linkpath)
            .with_context(|| format!("fopen({})", linkpath.display()))?;
        *xinfo.finfo.lock().unwrap() = Some(FileInformation {
            node_classname: class_from_path,
            filepath,
            linkpath: linkpath.clone(),
        });
        return Ok((fp, linkpath));
    }
    bail!("OWPDOpenFile: closure not set");
}

/// `OWPDCloseFile` — adjust disk claim / `delete_on_fetch`.
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn close_file(
    policy: &Policy,
    closure: &mut dyn std::any::Any,
    fp: File,
    aval: AcceptType,
) -> Result<()> {
    close_file_any(policy, closure, fp, aval)
}

fn close_file_any(
    policy: &Policy,
    closure: &dyn std::any::Any,
    fp: File,
    aval: AcceptType,
) -> Result<()> {
    let size = fp.metadata().map_or(0, |m| m.len());
    drop(fp);

    if let Some(tinfo) = closure.downcast_ref::<TestClosure>() {
        if tinfo.itype != InfoType::Test {
            bail!("OWPDCloseFile: closure not set");
        }
        let Some(finfo) = tinfo.finfo.lock().unwrap().take() else {
            return Ok(());
        };
        let Some(node) = policy.node(&finfo.node_classname) else {
            return Ok(());
        };
        let mut disk = tinfo.disk.lock().unwrap();
        if aval != AcceptType::Accept {
            let _ = fs::remove_file(&finfo.linkpath);
            let _ = fs::remove_file(&finfo.filepath);
            if disk.limit == OWPD_LIM_DISK {
                let _ = query(policy, &node, OWPD_MESG_RELEASE, disk.clone());
            }
        } else if disk.limit == OWPD_LIM_DISK {
            if size < disk.value {
                let lim = LimRec {
                    limit: OWPD_LIM_DISK,
                    value: disk.value - size,
                };
                let _ = query(policy, &node, OWPD_MESG_RELEASE, lim);
            } else if size > disk.value {
                // CLAIM applies diskfudge in IntegerResourceDemand.
                let lim = LimRec {
                    limit: OWPD_LIM_DISK,
                    value: size - disk.value,
                };
                let ret = query(policy, &node, OWPD_MESG_CLAIM, lim);
                if ret == OWPD_MESG_DENIED {
                    warn!(
                        "{} Too large! Deleting... (See diskfudge)",
                        finfo.filepath.display()
                    );
                    let _ = fs::remove_file(&finfo.linkpath);
                    let _ = fs::remove_file(&finfo.filepath);
                    let _ = query(policy, &node, OWPD_MESG_RELEASE, disk.clone());
                }
            }
            // size == reserved → skip resource broker (C exact match).
        }
        // Clear so TestComplete does not double-release (C `tinfo->res[1]=0`).
        *disk = LimRec { limit: 0, value: 0 };
        drop(disk);
        return Ok(());
    }

    if let Some(xinfo) = closure.downcast_ref::<FetchClosure>() {
        if xinfo.itype != InfoType::Fetch {
            bail!("OWPDCloseFile: closure not set");
        }
        let Some(finfo) = xinfo.finfo.lock().unwrap().take() else {
            return Ok(());
        };
        // Full-session fetch + delete_on_fetch on the *file's* class.
        if xinfo.begin == 0 && xinfo.end == 0xffff_ffff && aval == AcceptType::Accept {
            if let Some(node) = policy.node(&finfo.node_classname) {
                if node.get_limit(OWPD_LIM_DELETE_ON_FETCH) != 0 {
                    let _ = fs::remove_file(&finfo.linkpath);
                    let _ = fs::remove_file(&finfo.filepath);
                    if size > 0 {
                        let _ = query(
                            policy,
                            &node,
                            OWPD_MESG_RELEASE,
                            LimRec {
                                limit: OWPD_LIM_DISK,
                                value: size,
                            },
                        );
                    }
                }
            }
        }
        return Ok(());
    }
    bail!("OWPDCloseFile: closure not set")
}

/// Authmode-String → Bitmaske (`O`/`A`/`E`/`M`).
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn parse_authmode(s: &str, twamp: bool) -> Result<u32> {
    let mut mode = 0u32;
    for c in s.chars() {
        match c.to_ascii_uppercase() {
            'O' => mode |= OWP_MODE_OPEN,
            'A' => mode |= OWP_MODE_AUTHENTICATED,
            'E' => mode |= OWP_MODE_ENCRYPTED,
            'M' if twamp => mode |= TWP_MODE_MIXED,
            other => bail!("Invalid -authmode {other}"),
        }
    }
    Ok(mode)
}

#[must_use]
pub const fn default_offered_mode(twamp: bool) -> u32 {
    let m = OWP_MODE_OPEN | OWP_MODE_AUTHENTICATED | OWP_MODE_ENCRYPTED;
    if twamp {
        m | TWP_MODE_MIXED
    } else {
        m
    }
}

#[allow(dead_code)]
const fn _policy_api_surface(_: SessionMode, _: Sid, _: AcceptType, _: &Control, _: &TestSpec) {}

// ---------------------------------------------------------------------------
// C-name aliases (`policy.c`)
// ---------------------------------------------------------------------------

/// `GetDefLimit`
#[must_use]
pub fn get_def_limit(lim: u32) -> u64 {
    def_limit(lim)
}

/// `GetLimName`
#[must_use]
pub fn get_lim_name(lim: u32) -> &'static str {
    lim_name(lim)
}

/// `GetNodeDefault`
pub fn get_node_default(policy: &Policy) -> Option<Arc<PolicyNode>> {
    node_default(policy)
}

/// `GetNodeFromAddr`
pub fn get_node_from_addr(policy: &Policy, remote: SocketAddr) -> Option<Arc<PolicyNode>> {
    node_from_addr(policy, remote)
}

/// `GetNodeFromUserID`
pub fn get_node_from_user_id(policy: &Policy, userid: &str) -> Option<Arc<PolicyNode>> {
    node_from_userid(policy, userid)
}

/// `parseassignline`
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn parseassignline(policy: &mut Policy, line: &str) -> Result<()> {
    parse_assign_line(policy, line)
}

/// `parselimitline`
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn parselimitline(policy: &mut Policy, line: &str, maxlim: usize) -> Result<()> {
    parse_limit_line(policy, line, maxlim)
}

/// `parselimits`
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn parselimits(policy: &mut Policy, path: &Path) -> Result<()> {
    parse_limits_file(policy, path)
}

#[cfg(test)]
pub(crate) fn sample_policy_for_tests() -> Policy {
    let mut p = Policy {
        datadir: PathBuf::from("/tmp/owamp-policy-test"),
        diskfudge: 1.1,
        fd: Mutex::new(-1),
        root: None,
        limits: HashMap::new(),
        idents: HashMap::new(),
        pfs: HashMap::new(),
        session_class: Mutex::new(HashMap::new()),
    };
    parse_limit_line(
        &mut p,
        "root with bandwidth=1000,disk=1M,test_sessions=2",
        5,
    )
    .unwrap();
    parse_limit_line(&mut p, "child with parent=root,delete_on_fetch=on", 5).unwrap();
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    fn sample_policy() -> Policy {
        sample_policy_for_tests()
    }

    fn empty_policy(datadir: PathBuf) -> Policy {
        Policy {
            datadir,
            diskfudge: 1.1,
            fd: Mutex::new(-1),
            root: None,
            limits: HashMap::new(),
            idents: HashMap::new(),
            pfs: HashMap::new(),
            session_class: Mutex::new(HashMap::new()),
        }
    }

    #[test]
    fn parse_limit_line_parent_inherit_and_bool() {
        let mut p = empty_policy(PathBuf::from("/tmp"));
        parse_limit_line(
            &mut p,
            "root with bandwidth=2K,disk=1M,allow_open_mode=off",
            max_lim_count(),
        )
        .unwrap();
        parse_limit_line(
            &mut p,
            "leaf with parent=root,delete_on_fetch=on,bandwidth=500",
            max_lim_count(),
        )
        .unwrap();
        let leaf = p.node("leaf").unwrap();
        assert_eq!(leaf.get_limit(OWPD_LIM_BANDWIDTH), 500);
        assert_eq!(leaf.get_limit(OWPD_LIM_DISK), 1_000_000); // inherited
        assert_eq!(leaf.get_limit(OWPD_LIM_DELETE_ON_FETCH), 1);
        assert_eq!(leaf.get_limit(OWPD_LIM_ALLOW_OPEN_MODE), 0); // inherited off
        assert_eq!(leaf.parent.as_deref(), Some("root"));
    }

    #[test]
    fn parse_limit_line_rejects_dup_class_and_orphan() {
        let mut p = empty_policy(PathBuf::from("/tmp"));
        parse_limit_line(&mut p, "root with bandwidth=1", max_lim_count()).unwrap();
        assert!(parse_limit_line(&mut p, "root with bandwidth=2", max_lim_count()).is_err());
        assert!(parse_limit_line(&mut p, "kid with bandwidth=1", max_lim_count()).is_err());
        assert!(parse_limit_line(
            &mut p,
            "kid with parent=missing,bandwidth=1",
            max_lim_count()
        )
        .is_err());
    }

    #[test]
    fn parse_assign_net_user_default() {
        let mut p = empty_policy(PathBuf::from("/tmp"));
        p.pfs.insert("alice".into(), b"secret".to_vec());
        parse_limit_line(&mut p, "root with", max_lim_count()).unwrap();
        parse_limit_line(&mut p, "netclass with parent=root", max_lim_count()).unwrap();
        parse_assign_line(&mut p, "default root").unwrap();
        parse_assign_line(&mut p, "user alice root").unwrap();
        parse_assign_line(&mut p, "net 10.0.0.0/8 netclass").unwrap();
        assert!(parse_assign_line(&mut p, "default root").is_err());
        assert!(parse_assign_line(&mut p, "net 10.0.0.1/8 netclass").is_err()); // host bits
        assert!(parse_assign_line(&mut p, "user bob root").is_err());
        assert!(parse_assign_line(&mut p, "user alice nosuch").is_err());

        let n = node_from_addr(&p, "10.1.2.3:9".parse().unwrap()).unwrap();
        assert_eq!(n.nodename, "netclass");
        let n = node_from_userid(&p, "alice").unwrap();
        assert_eq!(n.nodename, "root");
        let n = node_from_addr(&p, "192.0.2.1:9".parse().unwrap()).unwrap();
        assert_eq!(n.nodename, "root"); // default
    }

    #[test]
    fn parse_pfs_and_limits_files() {
        let dir = std::env::temp_dir().join(format!("owamp-pol-parse-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let pfs = dir.join("owampd.pfs");
        let lim = dir.join("owampd.limits");
        {
            let mut f = File::create(&pfs).unwrap();
            writeln!(f, "# comment").unwrap();
            writeln!(f, "  # indented comment ok").unwrap();
            writeln!(f, "bob deadbeef").unwrap();
            writeln!(f, "carol 6e6f7468657870617373").unwrap(); // "nothexpass" hex
        }
        {
            let mut f = File::create(&lim).unwrap();
            writeln!(f, "limit root with bandwidth=100,disk=10K").unwrap();
            writeln!(f, "limit staff with parent=root,test_sessions=3").unwrap();
            writeln!(f, "assign default root").unwrap();
            writeln!(f, "assign user bob staff").unwrap();
            writeln!(f, "assign net 192.168.0.0/16 staff").unwrap();
        }
        let mut p = empty_policy(dir.clone());
        parse_pfs_file(&pfs, &mut p.pfs).unwrap();
        assert_eq!(p.pfs.get("bob").unwrap(), &hex::decode("deadbeef").unwrap());
        assert_eq!(p.pfs.get("carol").unwrap(), b"nothexpass");
        parse_limits_file(&mut p, &lim).unwrap();
        assert_eq!(p.root.as_deref(), Some("root"));
        assert_eq!(p.node("staff").unwrap().get_limit(OWPD_LIM_DISK), 10_000);
        assert_eq!(
            p.node("staff").unwrap().get_limit(OWPD_LIM_TEST_SESSIONS),
            3
        );
        assert!(parse_pfs_file(&pfs, &mut p.pfs).is_err()); // duplicate
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_pfs_rejects_plaintext_and_bad_hex() {
        let dir = std::env::temp_dir().join(format!("owamp-pol-pfsbad-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let pfs = dir.join("bad.pfs");
        {
            let mut f = File::create(&pfs).unwrap();
            writeln!(f, "alice nothex!!").unwrap(); // non-hex chars
        }
        let mut map = HashMap::new();
        assert!(parse_pfs_file(&pfs, &mut map).is_err());
        {
            let mut f = File::create(&pfs).unwrap();
            writeln!(f, "alice aabbc").unwrap(); // odd length
        }
        assert!(parse_pfs_file(&pfs, &mut map).is_err());
        {
            let mut f = File::create(&pfs).unwrap();
            writeln!(f, "  alice aabb").unwrap(); // leading spaces
        }
        assert!(parse_pfs_file(&pfs, &mut map).is_err());
        {
            let mut f = File::create(&pfs).unwrap();
            writeln!(f, "alice aabb trailing").unwrap();
        }
        assert!(parse_pfs_file(&pfs, &mut map).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_limits_missing_installs_default() {
        let dir = std::env::temp_dir().join(format!("owamp-pol-def-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mut p = empty_policy(dir.clone());
        parse_limits_file(&mut p, &dir.join("missing.limits")).unwrap();
        assert_eq!(p.root.as_deref(), Some("default"));
        assert!(p.node("default").is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn get_pf_lookup_matches_owpdgetpf() {
        let dir = std::env::temp_dir().join(format!("owamp-pol-pf-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("conf");
        fs::create_dir_all(&conf).unwrap();
        {
            let mut f = File::create(conf.join("owampd.pfs")).unwrap();
            writeln!(f, "dave aabb").unwrap();
        }
        {
            let mut f = File::create(conf.join("owampd.limits")).unwrap();
            writeln!(f, "limit root with").unwrap();
            writeln!(f, "assign user dave root").unwrap();
        }
        let mut p = empty_policy(dir.clone());
        parse_pfs_file(&conf.join("owampd.pfs"), &mut p.pfs).unwrap();
        parse_limits_file(&mut p, &conf.join("owampd.limits")).unwrap();
        // OWPDGetPF: known userid → bytes; unknown → miss
        assert_eq!(
            p.pfs.get("dave").map(std::vec::Vec::as_slice),
            Some(&hex::decode("aabb").unwrap()[..])
        );
        assert!(!p.pfs.contains_key("nope"));
        assert_eq!(node_from_userid(&p, "dave").unwrap().nodename, "root");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn bandwidth_and_claim_fudge() {
        let p = sample_policy();
        let node = p.node("root").unwrap();
        assert!(resource_demand(
            &p,
            &node,
            OWPD_MESG_REQUEST,
            LimRec {
                limit: OWPD_LIM_BANDWIDTH,
                value: 500
            }
        ));
        assert!(!resource_demand(
            &p,
            &node,
            OWPD_MESG_REQUEST,
            LimRec {
                limit: OWPD_LIM_BANDWIDTH,
                value: 600
            }
        ));
        assert!(resource_demand(
            &p,
            &node,
            OWPD_MESG_REQUEST,
            LimRec {
                limit: OWPD_LIM_DISK,
                value: 1_000_000
            }
        ));
        assert!(resource_demand(
            &p,
            &node,
            OWPD_MESG_CLAIM,
            LimRec {
                limit: OWPD_LIM_DISK,
                value: 50_000
            }
        ));
        // CLAIM beyond fudge (1.1 * 1M = 1.1M; used=1M → room 100k) fails
        assert!(!resource_demand(
            &p,
            &node,
            OWPD_MESG_CLAIM,
            LimRec {
                limit: OWPD_LIM_DISK,
                value: 200_000
            }
        ));
    }

    #[test]
    fn disk_accounting_tree_and_release() {
        let p = sample_policy();
        let child = p.node("child").unwrap();
        // Inherited disk=1M from root
        assert!(resource_demand(
            &p,
            &child,
            OWPD_MESG_REQUEST,
            LimRec {
                limit: OWPD_LIM_DISK,
                value: 400_000
            }
        ));
        assert_eq!(child.get_used(OWPD_LIM_DISK), 400_000);
        assert_eq!(p.node("root").unwrap().get_used(OWPD_LIM_DISK), 400_000);
        assert!(resource_demand(
            &p,
            &child,
            OWPD_MESG_RELEASE,
            LimRec {
                limit: OWPD_LIM_DISK,
                value: 100_000
            }
        ));
        assert_eq!(child.get_used(OWPD_LIM_DISK), 300_000);
        assert_eq!(p.node("root").unwrap().get_used(OWPD_LIM_DISK), 300_000);
    }

    #[test]
    fn broker_response_roundtrip() {
        let (a, b) = UnixStream::pair().unwrap();
        let fd_a = a.as_raw_fd();
        let fd_b = b.as_raw_fd();
        assert_eq!(send_response(fd_a, OWPD_MESG_OK), 0);
        assert_eq!(read_response(fd_b), OWPD_MESG_OK);
    }

    #[test]
    fn broker_class_and_query_edge() {
        let p = sample_policy();
        let node = p.node("root").unwrap();

        // Local path when fd < 0
        policy_clear_broker_fd();
        *p.fd.lock().unwrap() = -1;
        assert_eq!(
            query(
                &p,
                &node,
                OWPD_MESG_REQUEST,
                LimRec {
                    limit: OWPD_LIM_BANDWIDTH,
                    value: 1
                }
            ),
            OWPD_MESG_OK
        );

        // Invalid response framing → INVALID
        let (a, b) = UnixStream::pair().unwrap();
        let junk = [0u8; 12];
        assert!(write_all_fd(a.as_raw_fd(), &junk));
        assert_eq!(read_response(b.as_raw_fd()), OWPD_MESG_INVALID);

        // Class roundtrip over socketpair
        let (c, par) = UnixStream::pair().unwrap();
        policy_set_broker_fd(&p, c.as_raw_fd());
        let pname = node.nodename.clone();
        let t = std::thread::spawn({
            let p2 = sample_policy();
            move || read_class(&p2, par.as_raw_fd())
        });
        let ret = send_class(&p, &node);
        let got = t.join().unwrap().unwrap();
        assert_eq!(ret, OWPD_MESG_OK);
        assert_eq!(got.unwrap().nodename, pname);

        // Denied class name
        let (c2, par2) = UnixStream::pair().unwrap();
        let fake = PolicyNode {
            nodename: "nosuch".into(),
            parent: None,
            limits: vec![],
            used: Mutex::new(vec![]),
            initdisk: Mutex::new(0),
        };
        policy_set_broker_fd(&p, c2.as_raw_fd());
        let t2 = std::thread::spawn({
            let p2 = sample_policy();
            move || read_class(&p2, par2.as_raw_fd())
        });
        let ret2 = send_class(&p, &fake);
        let got2 = t2.join().unwrap().unwrap();
        assert_eq!(ret2, OWPD_MESG_DENIED);
        assert!(got2.is_none());
        policy_clear_broker_fd();
    }

    #[test]
    fn session_filename_check() {
        assert!(is_session_filename("0123456789abcdef0123456789abcdef.owp"));
        assert!(!is_session_filename("short.owp"));
        assert!(!is_session_filename("nothex_chars_here!!!!!!!!!!!.owp"));
    }

    #[test]
    fn query_local_ok() {
        let p = sample_policy();
        let node = p.node("child").unwrap();
        let r = query(
            &p,
            &node,
            OWPD_MESG_REQUEST,
            LimRec {
                limit: OWPD_LIM_TEST_SESSIONS,
                value: 1,
            },
        );
        assert_eq!(r, OWPD_MESG_OK);
    }

    #[test]
    fn parse_num_suffixes() {
        assert_eq!(parse_num_fixed("10").unwrap(), 10);
        assert_eq!(parse_num_fixed("2K").unwrap(), 2_000);
        assert_eq!(parse_num_fixed("1M").unwrap(), 1_000_000);
        assert!(parse_num_fixed("").is_err());
        assert!(parse_num_fixed("x").is_err());
    }

    #[test]
    fn diskfudge_claim_corners_and_bool_limits() {
        let mut p = empty_policy(PathBuf::from("/tmp"));
        p.diskfudge = 1.1;
        parse_limit_line(
            &mut p,
            "root with bandwidth=100,disk=1000,allow_open_mode=off,delete_on_fetch=on",
            max_lim_count(),
        )
        .unwrap();
        let node = p.node("root").unwrap();

        // Bool: REQUEST matches configured value
        assert!(resource_demand(
            &p,
            &node,
            OWPD_MESG_REQUEST,
            LimRec {
                limit: OWPD_LIM_DELETE_ON_FETCH,
                value: 1
            }
        ));
        assert!(!resource_demand(
            &p,
            &node,
            OWPD_MESG_REQUEST,
            LimRec {
                limit: OWPD_LIM_ALLOW_OPEN_MODE,
                value: 1
            }
        ));
        assert!(resource_demand(
            &p,
            &node,
            OWPD_MESG_RELEASE,
            LimRec {
                limit: OWPD_LIM_ALLOW_OPEN_MODE,
                value: 1
            }
        ));

        // CLAIM only valid for disk
        assert!(!resource_demand(
            &p,
            &node,
            OWPD_MESG_CLAIM,
            LimRec {
                limit: OWPD_LIM_BANDWIDTH,
                value: 1
            }
        ));
        assert!(!resource_demand(
            &p,
            &node,
            OWPD_MESG_REQUEST,
            LimRec {
                limit: 99,
                value: 1
            }
        )); // unknown lim

        assert!(resource_demand(
            &p,
            &node,
            OWPD_MESG_REQUEST,
            LimRec {
                limit: OWPD_LIM_DISK,
                value: 1000
            }
        ));
        // Exact fudge edge: used=1000, limit*1.1=1100 → claim 100 ok, 101 fails
        assert!(resource_demand(
            &p,
            &node,
            OWPD_MESG_CLAIM,
            LimRec {
                limit: OWPD_LIM_DISK,
                value: 100
            }
        ));
        assert!(!resource_demand(
            &p,
            &node,
            OWPD_MESG_CLAIM,
            LimRec {
                limit: OWPD_LIM_DISK,
                value: 1
            }
        ));
        // Over-release
        assert!(!resource_demand(
            &p,
            &node,
            OWPD_MESG_RELEASE,
            LimRec {
                limit: OWPD_LIM_DISK,
                value: 9_999
            }
        ));
    }

    #[test]
    fn broker_invalid_query_and_class_frames() {
        let p = sample_policy();
        let (a, b) = UnixStream::pair().unwrap();
        // Bad mark in query
        let mut bad = [0u8; 28];
        bad[0..4].copy_from_slice(&u32_bytes(0xdead_beef));
        assert!(write_all_fd(a.as_raw_fd(), &bad));
        assert!(read_query(b.as_raw_fd()).is_err());

        let (a2, b2) = UnixStream::pair().unwrap();
        // Valid marks but unknown query opcode
        let mut buf = [0u8; 28];
        buf[0..4].copy_from_slice(&u32_bytes(OWPD_MESG_MARK));
        buf[4..8].copy_from_slice(&u32_bytes(OWPD_MESG_RESOURCE));
        buf[8..12].copy_from_slice(&u32_bytes(0x1111));
        buf[12..16].copy_from_slice(&u32_bytes(OWPD_LIM_DISK));
        buf[16..24].copy_from_slice(&u64_bytes(1));
        buf[24..28].copy_from_slice(&u32_bytes(OWPD_MESG_MARK));
        assert!(write_all_fd(a2.as_raw_fd(), &buf));
        assert_eq!(read_query(b2.as_raw_fd()).unwrap_err(), 1);

        let (a3, b3) = UnixStream::pair().unwrap();
        // Class frame with wrong type
        let mut ch = Vec::new();
        ch.extend_from_slice(&u32_bytes(OWPD_MESG_MARK));
        ch.extend_from_slice(&u32_bytes(OWPD_MESG_RESOURCE));
        ch.push(0);
        ch.extend_from_slice(&u32_bytes(OWPD_MESG_MARK));
        assert!(write_all_fd(a3.as_raw_fd(), &ch));
        assert!(read_class(&p, b3.as_raw_fd()).is_err());

        // Oversized class name
        let (a4, b4) = UnixStream::pair().unwrap();
        let mut longn = Vec::new();
        longn.extend_from_slice(&u32_bytes(OWPD_MESG_MARK));
        longn.extend_from_slice(&u32_bytes(OWPD_MESG_CLASS));
        longn.extend(std::iter::repeat_n(b'x', OWPD_MAX_CLASS_LEN + 2));
        assert!(write_all_fd(a4.as_raw_fd(), &longn));
        assert!(read_class(&p, b4.as_raw_fd()).is_err());
    }

    #[test]
    fn open_close_file_hierarchy_and_diskfudge_claim() {
        let dir = std::env::temp_dir().join(format!("owamp-pol-files-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mut p = empty_policy(dir.clone());
        p.diskfudge = 1.1;
        parse_limit_line(
            &mut p,
            "root with disk=100,test_sessions=2,delete_on_fetch=on",
            max_lim_count(),
        )
        .unwrap();
        parse_limit_line(
            &mut p,
            "child with parent=root,delete_on_fetch=on",
            max_lim_count(),
        )
        .unwrap();
        let p = Arc::new(p);
        policy_post_install(&p).unwrap();

        let node = p.node("child").unwrap();
        assert!(resource_demand(
            &p,
            &node,
            OWPD_MESG_REQUEST,
            LimRec {
                limit: OWPD_LIM_DISK,
                value: 50
            }
        ));

        let sid = [0x11u8; 16];
        let mut tinfo: Box<dyn std::any::Any> = Box::new(TestClosure {
            itype: InfoType::Test,
            classname: "child".into(),
            bandwidth: LimRec { limit: 0, value: 0 },
            disk: Mutex::new(LimRec {
                limit: OWPD_LIM_DISK,
                value: 50,
            }),
            finfo: Mutex::new(None),
        });
        let (mut fp, path) = open_file(&p, tinfo.as_mut(), &sid).unwrap();
        assert!(path.to_string_lossy().contains("hierarchy"));
        assert!(path.to_string_lossy().contains("child"));
        let link = dir
            .join(OWP_CATALOG_DIR)
            .join(format!("{}{}", hex::encode(sid), OWP_FILE_EXT));
        assert!(link.exists());

        // Write more than reserved but within fudge (50 + claim ≤ 100*1.1)
        fp.write_all(&[0u8; 80]).unwrap();
        close_file(&p, tinfo.as_mut(), fp, AcceptType::Accept).unwrap();
        assert!(link.exists());
        assert_eq!(node.get_used(OWPD_LIM_DISK), 80);

        // Fetch full session → delete_on_fetch
        let mut finfo: Box<dyn std::any::Any> = Box::new(FetchClosure {
            itype: InfoType::Fetch,
            classname: "root".into(), // connection class ≠ file class
            begin: 0,
            end: 0xffff_ffff,
            finfo: Mutex::new(None),
        });
        let (fp2, _) = open_file(&p, finfo.as_mut(), &sid).unwrap();
        // Class comes from hierarchy path (child), not connection.
        {
            let fc = finfo.downcast_ref::<FetchClosure>().unwrap();
            let fi = fc.finfo.lock().unwrap();
            assert_eq!(fi.as_ref().unwrap().node_classname, "child");
        }
        close_file(&p, finfo.as_mut(), fp2, AcceptType::Accept).unwrap();
        assert!(!link.exists());
        assert!(!path.exists());
        assert_eq!(node.get_used(OWPD_LIM_DISK), 0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn close_file_exact_size_skips_broker_and_claim_denied_deletes() {
        let dir = std::env::temp_dir().join(format!("owamp-pol-exact-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mut p = empty_policy(dir.clone());
        p.diskfudge = 1.0; // no fudge room
        parse_limit_line(&mut p, "root with disk=40", max_lim_count()).unwrap();
        let p = Arc::new(p);
        policy_post_install(&p).unwrap();
        let node = p.node("root").unwrap();
        assert!(resource_demand(
            &p,
            &node,
            OWPD_MESG_REQUEST,
            LimRec {
                limit: OWPD_LIM_DISK,
                value: 40
            }
        ));

        let sid = [0x22u8; 16];
        let mut tinfo: Box<dyn std::any::Any> = Box::new(TestClosure {
            itype: InfoType::Test,
            classname: "root".into(),
            bandwidth: LimRec { limit: 0, value: 0 },
            disk: Mutex::new(LimRec {
                limit: OWPD_LIM_DISK,
                value: 40,
            }),
            finfo: Mutex::new(None),
        });
        let (mut fp, path) = open_file(&p, tinfo.as_mut(), &sid).unwrap();
        fp.write_all(&[1u8; 40]).unwrap();
        close_file(&p, tinfo.as_mut(), fp, AcceptType::Accept).unwrap();
        assert_eq!(node.get_used(OWPD_LIM_DISK), 40);
        assert!(path.exists());

        // Free the exact-sized session so we can probe CLAIM denial next.
        let _ = resource_demand(
            &p,
            &node,
            OWPD_MESG_RELEASE,
            LimRec {
                limit: OWPD_LIM_DISK,
                value: 40,
            },
        );
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(dir.join(OWP_CATALOG_DIR).join(format!(
            "{}{}",
            hex::encode(sid),
            OWP_FILE_EXT
        )));

        // Reserved 40, write 41 → CLAIM denied with fudge=1.0 → delete + full release.
        let sid2 = [0x33u8; 16];
        let mut t2: Box<dyn std::any::Any> = Box::new(TestClosure {
            itype: InfoType::Test,
            classname: "root".into(),
            bandwidth: LimRec { limit: 0, value: 0 },
            disk: Mutex::new(LimRec {
                limit: OWPD_LIM_DISK,
                value: 40,
            }),
            finfo: Mutex::new(None),
        });
        assert!(resource_demand(
            &p,
            &node,
            OWPD_MESG_REQUEST,
            LimRec {
                limit: OWPD_LIM_DISK,
                value: 40
            }
        ));
        let (mut fp2, path2) = open_file(&p, t2.as_mut(), &sid2).unwrap();
        fp2.write_all(&[1u8; 41]).unwrap();
        close_file(&p, t2.as_mut(), fp2, AcceptType::Accept).unwrap();
        assert!(!path2.exists());
        assert_eq!(node.get_used(OWPD_LIM_DISK), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn control_session_class_survives_test_complete_clear_helper() {
        let p = sample_policy();
        p.session_class.lock().unwrap().insert(7, "root".into());
        // Helper clears only on explicit control teardown — not TestComplete.
        clear_session_class(&p, 7);
        assert!(p.session_class.lock().unwrap().get(&7).is_none());
        assert!(allow_open_mode(&p, "127.0.0.1:9".parse().unwrap()).unwrap());
    }
}
