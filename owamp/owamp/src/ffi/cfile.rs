//! `FILE*` adapter implementing Rust [`Read`]/[`Write`]/[`Seek`].

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::raw::c_int;

use libc::{c_void, off_t, FILE};

pub struct CFile {
    pub fp: *mut FILE,
}

impl CFile {
    pub const fn new(fp: *mut FILE) -> Self {
        Self { fp }
    }
}

impl Read for CFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.fp.is_null() {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        let n = unsafe { libc::fread(buf.as_mut_ptr().cast::<c_void>(), 1, buf.len(), self.fp) };
        if n < buf.len() && unsafe { libc::ferror(self.fp) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n)
    }
}

impl Write for CFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.fp.is_null() {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        let n = unsafe { libc::fwrite(buf.as_ptr().cast::<c_void>(), 1, buf.len(), self.fp) };
        if n < buf.len() {
            return Err(io::Error::last_os_error());
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.fp.is_null() {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        if unsafe { libc::fflush(self.fp) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Seek for CFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        if self.fp.is_null() {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        let (off, whence) = match pos {
            SeekFrom::Start(n) => (n as i64, libc::SEEK_SET),
            SeekFrom::End(n) => (n, libc::SEEK_END),
            SeekFrom::Current(n) => (n, libc::SEEK_CUR),
        };
        if unsafe { libc::fseeko(self.fp, off as off_t, whence as c_int) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let cur = unsafe { libc::ftello(self.fp) };
        if cur < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(cur as u64)
    }
}

/// Write UTF-8 text to a C `FILE*`.
pub fn write_str(fp: *mut FILE, s: &str) -> bool {
    if fp.is_null() {
        return false;
    }
    let mut f = CFile::new(fp);
    f.write_all(s.as_bytes()).is_ok()
}

#[allow(dead_code)]
pub fn tell(fp: *mut FILE) -> Option<u64> {
    if fp.is_null() {
        return None;
    }
    let cur = unsafe { libc::ftello(fp) };
    if cur < 0 {
        None
    } else {
        Some(cur as u64)
    }
}

#[allow(dead_code)]
pub fn seek_set(fp: *mut FILE, off: i64) -> bool {
    if fp.is_null() {
        return false;
    }
    unsafe { libc::fseeko(fp, off as off_t, libc::SEEK_SET) == 0 }
}
