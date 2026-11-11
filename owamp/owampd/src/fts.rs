//! `fts(3)`-style directory walker — port of bits from `owampd/fts.c` / `fts.h`.
//!
//! Enough for catalog/hierarchy maintenance in `policy.rs` (`clean_catalog`,
//! `verify_datadir`): pre-order `FTS_D`, leaf entries, post-order `FTS_DP`,
//! `FTS_SKIP`, cycle detection (`FTS_DC`), `FTS_XDEV`, and error paths
//! (`FTS_ERR` / `FTS_DNR` / `FTS_NS`). Walking is always path-based (no
//! `chdir`), matching policy's `FTS_NOCHDIR|FTS_PHYSICAL` usage.

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

// Info codes — match `fts.h` values used by policy.c.
pub const FTS_D: i32 = 1;
pub const FTS_DC: i32 = 2;
pub const FTS_DEFAULT: i32 = 3;
pub const FTS_DNR: i32 = 4;
pub const FTS_DOT: i32 = 5;
pub const FTS_DP: i32 = 6;
pub const FTS_ERR: i32 = 7;
pub const FTS_F: i32 = 8;
pub const FTS_INIT: i32 = 9;
pub const FTS_NS: i32 = 10;
pub const FTS_NSOK: i32 = 11;
pub const FTS_SL: i32 = 12;
pub const FTS_SLNONE: i32 = 13;
pub const FTS_W: i32 = 14; // whiteout (fts.h); unused on macOS/Linux policy walks

pub const FTS_ROOTPARENTLEVEL: i32 = -1;
pub const FTS_ROOTLEVEL: i32 = 0;

// Option bits — match `fts.h`.
pub const FTS_COMFOLLOW: i32 = 0x001;
pub const FTS_LOGICAL: i32 = 0x002;
pub const FTS_NOCHDIR: i32 = 0x004;
pub const FTS_NOSTAT: i32 = 0x008;
pub const FTS_PHYSICAL: i32 = 0x010;
pub const FTS_SEEDOT: i32 = 0x020;
pub const FTS_XDEV: i32 = 0x040;
pub const FTS_OPTIONMASK: i32 = 0x0ff;
/// Private option bits from `fts.h` (not in user OPTIONMASK).
pub const FTS_NAMEONLY: i32 = 0x100;
pub const FTS_STOP: i32 = 0x200;

/// Private `fts_flags` bits from `fts.h`.
pub const FTS_DONTCHDIR: i32 = 0x01;
pub const FTS_SYMFOLLOW: i32 = 0x02;
pub const FTS_ISW: i32 = 0x04;

/// `fts_set` instructions — match `fts.h`.
pub const FTS_AGAIN: i32 = 1;
pub const FTS_FOLLOW: i32 = 2;
pub const FTS_NOINSTR: i32 = 3;
pub const FTS_SKIP: i32 = 4;

#[derive(Debug, Clone)]
pub struct FtsEntry {
    pub path: PathBuf,
    pub name: String,
    pub info: i32,
    pub level: i32,
    pub errno: i32,
    pub size: u64,
    pub is_dir: bool,
    /// Parent directory path (for hierarchy verification).
    pub parent_path: Option<PathBuf>,
    pub ino: u64,
    pub dev: u64,
    /// Cycle partner path when `info == FTS_DC`.
    pub cycle_path: Option<PathBuf>,
}

pub struct Fts {
    stack: Vec<FtsEntry>,
    skip: Option<PathBuf>,
    options: i32,
    /// Device of the walk root(s) — for `FTS_XDEV`.
    root_dev: Option<u64>,
}

#[derive(Clone, Copy)]
struct Ancestor {
    ino: u64,
    dev: u64,
}

impl Fts {
    /// `fts_open` — collect a depth-first walk (D → children → DP).
    ///
    /// Rejects unknown option bits (`EINVAL`) like C. `FTS_LOGICAL` forces
    /// `FTS_NOCHDIR`. Physical walks do not follow directory symlinks.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying operation fails.
    pub fn open(paths: &[&Path], options: i32) -> io::Result<Self> {
        if options & !FTS_OPTIONMASK != 0 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let mut options = options;
        if options & FTS_LOGICAL != 0 {
            options |= FTS_NOCHDIR;
        }
        // C requires PHYSICAL or LOGICAL; policy always passes PHYSICAL.
        if options & (FTS_LOGICAL | FTS_PHYSICAL) == 0 {
            options |= FTS_PHYSICAL;
        }

        let mut out = Vec::new();
        let mut root_dev = None;
        for p in paths {
            if p.as_os_str().is_empty() {
                return Err(io::Error::from_raw_os_error(libc::ENOENT));
            }
            walk_collect(
                p,
                FTS_ROOTLEVEL,
                None,
                options,
                &[],
                &mut root_dev,
                &mut out,
            )?;
        }
        // `read` pops from the end → reverse so first entry is yielded first.
        out.reverse();
        Ok(Self {
            stack: out,
            skip: None,
            options,
            root_dev,
        })
    }

    pub fn read(&mut self) -> Option<FtsEntry> {
        while let Some(ent) = self.stack.pop() {
            if let Some(ref skip) = self.skip {
                if &ent.path == skip {
                    if ent.info == FTS_DP {
                        self.skip = None;
                        return Some(ent);
                    }
                    continue;
                }
                if ent.path.starts_with(skip) {
                    continue;
                }
            }
            return Some(ent);
        }
        None
    }

    /// `fts_set` — `FTS_SKIP` / `FTS_AGAIN` / `FTS_FOLLOW`.
    ///
    /// `FTS_AGAIN` / `FTS_FOLLOW` are accepted for API parity; on a fully
    /// pre-collected walk they have limited effect (FOLLOW only re-stats SL).
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying operation fails.
    pub fn set(&mut self, ent: &FtsEntry, instr: i32) -> io::Result<()> {
        match instr {
            FTS_SKIP => {
                self.skip(ent);
                Ok(())
            },
            FTS_AGAIN => {
                // Re-push a freshly stated copy so the next read sees it again.
                if let Some(refreshed) = restat_entry(ent, self.options) {
                    self.stack.push(refreshed);
                }
                Ok(())
            },
            FTS_FOLLOW => {
                if ent.info == FTS_SL || ent.info == FTS_SLNONE {
                    if let Ok(meta) = fs::metadata(&ent.path) {
                        if meta.is_dir() {
                            // Descend into symlink target once (logical follow).
                            let mut kids = Vec::new();
                            let mut root_dev = self.root_dev;
                            let _ = walk_collect(
                                &ent.path,
                                ent.level,
                                ent.parent_path.clone(),
                                self.options | FTS_LOGICAL,
                                &[],
                                &mut root_dev,
                                &mut kids,
                            );
                            kids.reverse();
                            self.stack.extend(kids);
                        } else {
                            let mut e = ent.clone();
                            e.info = if meta.is_file() { FTS_F } else { FTS_DEFAULT };
                            e.size = meta.len();
                            e.ino = meta.ino();
                            e.dev = meta.dev();
                            self.stack.push(e);
                        }
                    }
                }
                Ok(())
            },
            FTS_NOINSTR => Ok(()),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported fts_set instruction",
            )),
        }
    }

    pub fn skip(&mut self, ent: &FtsEntry) {
        self.skip = Some(ent.path.clone());
    }

    #[must_use]
    pub const fn options(&self) -> i32 {
        self.options
    }

    #[must_use]
    pub const fn root_dev(&self) -> Option<u64> {
        self.root_dev
    }

    pub fn close(self) {
        drop(self);
    }
}

fn restat_entry(ent: &FtsEntry, options: i32) -> Option<FtsEntry> {
    let physical = (options & FTS_PHYSICAL) != 0 && (options & FTS_LOGICAL) == 0;
    let meta = if physical {
        fs::symlink_metadata(&ent.path).ok()?
    } else {
        fs::metadata(&ent.path)
            .or_else(|_| fs::symlink_metadata(&ent.path))
            .ok()?
    };
    let mut e = ent.clone();
    e.errno = 0;
    e.size = meta.len();
    e.ino = meta.ino();
    e.dev = meta.dev();
    e.cycle_path = None;
    if meta.file_type().is_symlink() && physical {
        e.info = FTS_SL;
        e.is_dir = false;
    } else if meta.is_dir() {
        e.info = FTS_D;
        e.is_dir = true;
    } else if meta.is_file() {
        e.info = FTS_F;
        e.is_dir = false;
    } else {
        e.info = FTS_DEFAULT;
        e.is_dir = false;
    }
    Some(e)
}

fn entry_name(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.to_string_lossy().into_owned(),
        |s| s.to_string_lossy().into_owned(),
    )
}

fn walk_collect(
    path: &Path,
    level: i32,
    parent_path: Option<PathBuf>,
    options: i32,
    ancestors: &[Ancestor],
    root_dev: &mut Option<u64>,
    out: &mut Vec<FtsEntry>,
) -> io::Result<()> {
    let physical = (options & FTS_PHYSICAL) != 0 && (options & FTS_LOGICAL) == 0;
    let follow = !physical || (level == FTS_ROOTLEVEL && (options & FTS_COMFOLLOW) != 0);

    let meta = if follow {
        match fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                // Logical/comfollow: dangling symlink → SLNONE if lstat works.
                if let Ok(lm) = fs::symlink_metadata(path) {
                    if lm.file_type().is_symlink() {
                        out.push(FtsEntry {
                            path: path.to_path_buf(),
                            name: entry_name(path),
                            info: FTS_SLNONE,
                            level,
                            errno: 0,
                            size: lm.len(),
                            is_dir: false,
                            parent_path,
                            ino: lm.ino(),
                            dev: lm.dev(),
                            cycle_path: None,
                        });
                        return Ok(());
                    }
                }
                out.push(FtsEntry {
                    path: path.to_path_buf(),
                    name: entry_name(path),
                    info: FTS_NS,
                    level,
                    errno: e.raw_os_error().unwrap_or(0),
                    size: 0,
                    is_dir: false,
                    parent_path,
                    ino: 0,
                    dev: 0,
                    cycle_path: None,
                });
                return Ok(());
            },
        }
    } else {
        match fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) => {
                out.push(FtsEntry {
                    path: path.to_path_buf(),
                    name: entry_name(path),
                    info: FTS_NS,
                    level,
                    errno: e.raw_os_error().unwrap_or(0),
                    size: 0,
                    is_dir: false,
                    parent_path,
                    ino: 0,
                    dev: 0,
                    cycle_path: None,
                });
                return Ok(());
            },
        }
    };

    let name = entry_name(path);
    let ino = meta.ino();
    let dev = meta.dev();
    if level == FTS_ROOTLEVEL && root_dev.is_none() {
        *root_dev = Some(dev);
    }

    if meta.file_type().is_symlink() && physical && !follow {
        out.push(FtsEntry {
            path: path.to_path_buf(),
            name,
            info: FTS_SL,
            level,
            errno: 0,
            size: meta.len(),
            is_dir: false,
            parent_path,
            ino,
            dev,
            cycle_path: None,
        });
        return Ok(());
    }

    if meta.is_dir() {
        // Cycle detection (C fts_stat brute-force parent walk).
        for a in ancestors {
            if a.ino == ino && a.dev == dev {
                out.push(FtsEntry {
                    path: path.to_path_buf(),
                    name,
                    info: FTS_DC,
                    level,
                    errno: 0,
                    size: meta.len(),
                    is_dir: true,
                    parent_path,
                    ino,
                    dev,
                    cycle_path: None,
                });
                return Ok(());
            }
        }

        out.push(FtsEntry {
            path: path.to_path_buf(),
            name: name.clone(),
            info: FTS_D,
            level,
            errno: 0,
            size: meta.len(),
            is_dir: true,
            parent_path: parent_path.clone(),
            ino,
            dev,
            cycle_path: None,
        });

        // FTS_XDEV: do not descend into mount points (still emit DP).
        let cross_dev = (options & FTS_XDEV) != 0
            && root_dev.is_some_and(|rd| rd != dev)
            && level > FTS_ROOTLEVEL;
        if !cross_dev {
            match fs::read_dir(path) {
                Ok(rd) => {
                    let mut kids: Vec<PathBuf> = Vec::new();
                    let mut dots: Vec<PathBuf> = Vec::new();
                    for e in rd {
                        let e = match e {
                            Ok(e) => e,
                            Err(err) => {
                                out.push(FtsEntry {
                                    path: path.to_path_buf(),
                                    name: name.clone(),
                                    info: FTS_DNR,
                                    level,
                                    errno: err.raw_os_error().unwrap_or(0),
                                    size: 0,
                                    is_dir: true,
                                    parent_path: parent_path.clone(),
                                    ino,
                                    dev,
                                    cycle_path: None,
                                });
                                // Still emit DP below.
                                kids.clear();
                                break;
                            },
                        };
                        let fname = e.file_name();
                        if fname == "." || fname == ".." {
                            if (options & FTS_SEEDOT) != 0 {
                                dots.push(e.path());
                            }
                            continue;
                        }
                        kids.push(e.path());
                    }
                    kids.sort();
                    let mut next_anc = ancestors.to_vec();
                    next_anc.push(Ancestor { ino, dev });
                    for dot in dots {
                        let dname = entry_name(&dot);
                        out.push(FtsEntry {
                            path: dot,
                            name: dname,
                            info: FTS_DOT,
                            level: level + 1,
                            errno: 0,
                            size: 0,
                            is_dir: true,
                            parent_path: Some(path.to_path_buf()),
                            ino: 0,
                            dev: 0,
                            cycle_path: None,
                        });
                    }
                    for kid in kids {
                        walk_collect(
                            &kid,
                            level + 1,
                            Some(path.to_path_buf()),
                            options,
                            &next_anc,
                            root_dev,
                            out,
                        )?;
                    }
                },
                Err(err) => {
                    out.push(FtsEntry {
                        path: path.to_path_buf(),
                        name: name.clone(),
                        info: FTS_DNR,
                        level,
                        errno: err.raw_os_error().unwrap_or(0),
                        size: 0,
                        is_dir: true,
                        parent_path: parent_path.clone(),
                        ino,
                        dev,
                        cycle_path: None,
                    });
                },
            }
        }

        out.push(FtsEntry {
            path: path.to_path_buf(),
            name,
            info: FTS_DP,
            level,
            errno: 0,
            size: meta.len(),
            is_dir: true,
            parent_path,
            ino,
            dev,
            cycle_path: None,
        });
    } else if meta.is_file() {
        out.push(FtsEntry {
            path: path.to_path_buf(),
            name,
            info: FTS_F,
            level,
            errno: 0,
            size: meta.len(),
            is_dir: false,
            parent_path,
            ino,
            dev,
            cycle_path: None,
        });
    } else {
        out.push(FtsEntry {
            path: path.to_path_buf(),
            name,
            info: FTS_DEFAULT,
            level,
            errno: 0,
            size: meta.len(),
            is_dir: false,
            parent_path,
            ino,
            dev,
            cycle_path: None,
        });
    }
    Ok(())
}

///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn remove_tree(path: &Path) -> io::Result<()> {
    if path.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
}

///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn ensure_datastore(datadir: &Path) -> io::Result<()> {
    fs::create_dir_all(datadir.join(crate::policy::OWP_CATALOG_DIR))?;
    fs::create_dir_all(datadir.join(crate::policy::OWP_HIER_DIR))?;
    Ok(())
}

///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn list_catalog_sids(datadir: &Path) -> io::Result<Vec<PathBuf>> {
    let catalog = datadir.join(crate::policy::OWP_CATALOG_DIR);
    let mut out = Vec::new();
    if !catalog.exists() {
        return Ok(out);
    }
    for entry in fs::read_dir(catalog)? {
        out.push(entry?.path());
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// C-name public API wrappers (`fts.c` internals + public surface)
// ---------------------------------------------------------------------------

/// `fts_alloc` — allocate a single walk entry (path-based stand-in).
#[must_use]
pub fn fts_alloc(path: &Path, level: i32, info: i32) -> FtsEntry {
    FtsEntry {
        path: path.to_path_buf(),
        name: entry_name(path),
        info,
        level,
        errno: 0,
        size: 0,
        is_dir: info == FTS_D || info == FTS_DP || info == FTS_DC,
        parent_path: None,
        ino: 0,
        dev: 0,
        cycle_path: None,
    }
}

/// `fts_build` — (re)collect children under `path` into a new stack vector.
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn fts_build(path: &Path, options: i32) -> io::Result<Vec<FtsEntry>> {
    let mut out = Vec::new();
    let mut root_dev = None;
    walk_collect(
        path,
        FTS_ROOTLEVEL,
        None,
        options,
        &[],
        &mut root_dev,
        &mut out,
    )?;
    Ok(out)
}

/// `fts_children` — shallow listing of entries immediately under `ent`.
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn fts_children(ent: &FtsEntry, options: i32) -> io::Result<Vec<FtsEntry>> {
    if !ent.is_dir && ent.info != FTS_D {
        return Ok(Vec::new());
    }
    let mut shallow = Vec::new();
    for e in fs::read_dir(&ent.path)? {
        let e = e?;
        let p = e.path();
        let name = entry_name(&p);
        if (name == "." || name == "..") && options & FTS_SEEDOT == 0 {
            continue;
        }
        let meta = fs::symlink_metadata(&p);
        let (info, is_dir, size, ino, dev, errno) = match meta {
            Ok(m) if m.file_type().is_symlink() => (FTS_SL, false, m.len(), m.ino(), m.dev(), 0),
            Ok(m) if m.is_dir() => (FTS_D, true, m.len(), m.ino(), m.dev(), 0),
            Ok(m) if m.is_file() => (FTS_F, false, m.len(), m.ino(), m.dev(), 0),
            Ok(m) => (FTS_DEFAULT, false, m.len(), m.ino(), m.dev(), 0),
            Err(err) => (FTS_NS, false, 0, 0, 0, err.raw_os_error().unwrap_or(0)),
        };
        shallow.push(FtsEntry {
            path: p,
            name,
            info,
            level: ent.level + 1,
            errno,
            size,
            is_dir,
            parent_path: Some(ent.path.clone()),
            ino,
            dev,
            cycle_path: None,
        });
    }
    Ok(shallow)
}

/// `fts_close`
pub fn fts_close(fts: Fts) {
    fts.close();
}

/// `fts_lfree` — drop a list of entries (Rust Vec clear).
pub fn fts_lfree(list: &mut Vec<FtsEntry>) {
    list.clear();
}

/// `fts_load` — push `ent` onto the walk stack so the next `fts_read` yields it.
pub fn fts_load(fts: &mut Fts, ent: FtsEntry) {
    fts.stack.push(ent);
}

/// `fts_maxarglen` — max path length among argv roots (bytes).
#[must_use]
pub fn fts_maxarglen(paths: &[&Path]) -> usize {
    paths.iter().map(|p| p.as_os_str().len()).max().unwrap_or(0)
}

/// `fts_padjust` — no-op for path-based walks (C adjusts internal path buffer pointers).
pub const fn fts_padjust(_fts: &Fts, _head: Option<&FtsEntry>) {}

/// `fts_palloc` — ensure walk capacity; path-based port only reserves stack space.
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn fts_palloc(fts: &mut Fts, more: usize) -> io::Result<()> {
    fts.stack.reserve(more);
    Ok(())
}

/// `fts_read`
pub fn fts_read(fts: &mut Fts) -> Option<FtsEntry> {
    fts.read()
}

/// `fts_safe_changedir` — always succeeds under `FTS_NOCHDIR` (path-based walks).
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub const fn fts_safe_changedir(_fts: &Fts, _ent: &FtsEntry) -> io::Result<()> {
    Ok(())
}

/// `fts_sort` — sort entries by path name (C uses caller compar; default strcmp).
pub fn fts_sort(list: &mut [FtsEntry]) {
    list.sort_by(|a, b| a.path.cmp(&b.path));
}

/// Walk `path` and remove contents (files + subdirs), leaving `path` itself.
/// Behavioural cousin of policy.c catalog cleanup via `fts`.
///
/// # Errors
///
/// Returns an error when the underlying operation fails.
pub fn clean_tree_contents(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    let mut fts = Fts::open(&[path], FTS_PHYSICAL)?;
    while let Some(ent) = fts.read() {
        match ent.info {
            FTS_D | FTS_DC => {},
            FTS_ERR if ent.errno != libc::ENOENT => {
                return Err(io::Error::from_raw_os_error(ent.errno));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    #[test]
    fn walk_order_d_file_dp() {
        let dir = std::env::temp_dir().join(format!("owamp-fts-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("a.txt"), b"hi").unwrap();

        let mut fts = Fts::open(&[&dir], FTS_PHYSICAL | FTS_NOCHDIR).unwrap();
        let infos: Vec<i32> = std::iter::from_fn(|| fts.read().map(|e| e.info)).collect();
        assert_eq!(infos.first().copied(), Some(FTS_D));
        assert!(infos.contains(&FTS_F));
        assert_eq!(infos.last().copied(), Some(FTS_DP));
        assert_eq!(FTS_PHYSICAL, 0x010);
        assert_eq!(FTS_NOCHDIR, 0x004);
        assert_eq!(FTS_DP, 6);
        assert!(fts.root_dev().is_some());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn skip_subtree() {
        let dir = std::env::temp_dir().join(format!("owamp-fts-skip-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let sub = dir.join("sub");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("x"), b"1").unwrap();
        fs::write(dir.join("y"), b"2").unwrap();

        let mut fts = Fts::open(&[&dir], FTS_PHYSICAL).unwrap();
        let mut saw_x = false;
        while let Some(ent) = fts.read() {
            if ent.info == FTS_D && ent.path == sub {
                fts.set(&ent, FTS_SKIP).unwrap();
            }
            if ent.path.ends_with("x") {
                saw_x = true;
            }
        }
        assert!(!saw_x, "skipped subtree should not yield file x");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_invalid_options() {
        let dir = std::env::temp_dir().join(format!("owamp-fts-opt-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let Err(err) = Fts::open(&[&dir], 0x1000) else {
            panic!("expected EINVAL for invalid fts options");
        };
        assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn physical_reports_symlink_not_followed() {
        let dir = std::env::temp_dir().join(format!("owamp-fts-sl-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("inside"), b"1").unwrap();
        let link = dir.join("link");
        symlink(&target, &link).unwrap();

        let mut fts = Fts::open(&[&dir], FTS_PHYSICAL | FTS_NOCHDIR).unwrap();
        let mut saw_sl = false;
        let mut saw_inside = false;
        while let Some(ent) = fts.read() {
            if ent.path == link {
                assert_eq!(ent.info, FTS_SL);
                saw_sl = true;
            }
            if ent.path.ends_with("inside") && ent.path.starts_with(&link) {
                saw_inside = true;
            }
        }
        assert!(saw_sl);
        assert!(!saw_inside);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn seedot_option_accepted() {
        // Many filesystems' readdir(3) omit "."/".."; SEEDOT only surfaces them
        // when the OS returns them. Verify open accepts the flag.
        let dir = std::env::temp_dir().join(format!("owamp-fts-dot-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let fts = Fts::open(&[&dir], FTS_PHYSICAL | FTS_SEEDOT).unwrap();
        assert_eq!(fts.options() & FTS_SEEDOT, FTS_SEEDOT);
        assert_eq!(FTS_DOT, 5);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_path_yields_ns() {
        let missing = std::env::temp_dir().join(format!("owamp-fts-ns-{}", std::process::id()));
        let _ = fs::remove_dir_all(&missing);
        let mut fts = Fts::open(&[&missing], FTS_PHYSICAL | FTS_NOCHDIR).unwrap();
        let ent = fts.read().unwrap();
        assert_eq!(ent.info, FTS_NS);
        assert_ne!(ent.errno, 0);
    }

    #[test]
    fn cycle_via_hardlink_dir_if_supported() {
        // On most Unix filesystems directory hardlinks are forbidden; simulate
        // cycle detection by walking a tree where we inject ancestor collision
        // via bind-mount is heavy — instead verify FTS_DC constant + that a
        // self-referential symlink as physical is FTS_SL (not descended).
        assert_eq!(FTS_DC, 2);
        let dir = std::env::temp_dir().join(format!("owamp-fts-cyc-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let link = dir.join("loop");
        symlink(&dir, &link).unwrap();
        let mut fts = Fts::open(&[&dir], FTS_PHYSICAL).unwrap();
        let mut infos = Vec::new();
        while let Some(ent) = fts.read() {
            if ent.path == link {
                infos.push(ent.info);
            }
        }
        assert_eq!(infos, vec![FTS_SL]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn clean_tree_leaves_root() {
        let dir = std::env::temp_dir().join(format!("owamp-fts-clean-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let sub = dir.join("a").join("b");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("f"), b"x").unwrap();
        clean_tree_contents(&dir).unwrap();
        assert!(dir.is_dir());
        assert!(fs::read_dir(&dir).unwrap().next().is_none());
        let _ = fs::remove_dir_all(&dir);
    }
}
