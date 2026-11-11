//! Protocol/path constants from `owamp.h` / `owampP.h`.

/// Path separator used in OWAMP file paths.
pub const OWP_PATH_SEPARATOR: &str = "/";
pub const OWP_PATH_SEPARATOR_LEN: usize = 1;
pub const OWP_FILE_EXT: &str = ".owp";
/// Character between start/end timestamps in `.owp` filenames.
pub const OWP_NAME_SEP: &str = "_";
/// Decimal digit count for a 64-bit timestamp (`log10(2^64)`).
pub const OWP_TSTAMPCHARS: usize = 20;

pub const OWP_CONTROL_SERVICE_NAME: &str = "861";
pub const TWP_CONTROL_SERVICE_NAME: &str = "862";
pub const OWP_LISTEN_BACKLOG: i32 = 64;

pub const OWP_MODE_UNDEFINED: u32 = 0;
pub const OWP_MODE_OPEN: u32 = 0o01;
pub const OWP_MODE_AUTHENTICATED: u32 = 0o02;
pub const OWP_MODE_ENCRYPTED: u32 = 0o04;
pub const TWP_MODE_MIXED: u32 = 0o10;

/// Modes where test sessions are authenticated or encrypted.
pub const OWP_MODE_DOCIPHER_TEST: u32 = OWP_MODE_AUTHENTICATED | OWP_MODE_ENCRYPTED;
/// Modes where control sessions are authenticated or encrypted.
pub const OWP_MODE_DOCIPHER_CNTRL: u32 = OWP_MODE_DOCIPHER_TEST | TWP_MODE_MIXED;

pub const OWP_DEFAULT_OFFERED_MODE: u32 =
    OWP_MODE_OPEN | OWP_MODE_AUTHENTICATED | OWP_MODE_ENCRYPTED;
pub const TWP_DEFAULT_OFFERED_MODE: u32 = OWP_DEFAULT_OFFERED_MODE | TWP_MODE_MIXED;

pub const OWP_USERID_LEN: usize = 80;

pub const OWP_RIJNDAEL_BLOCK_SIZE: usize = 16;
pub const OWP_TOKEN_SIZE: usize = 64;
pub const OWP_SALT_SIZE: usize = 16;
pub const OWP_DEFAULT_PBKDF2_COUNT: u32 = 2_048;
pub const OWP_DEFAULT_TMPDIR: &str = "/tmp";
pub const OWP_SKIPFILE_FMT: &str = "owpskips.XXXXXX";

pub const TWP_DEFAULT_TEST_TIMEOUT: u32 = 900;

/// Seconds between NTP epoch (1900-01-01) and Unix epoch (1970-01-01).
pub const OWP_JAN_1970: u32 = 0x83aa_7e80;

pub const OWP_ERR_MAXSTRING: usize = 1_024;
pub const OWP_MAGIC_FILETYPE: &[u8; 3] = b"OwA";
pub const OWP_DEFAULT_FUZZTIME: f64 = 1.0;

// File / record sizes (`owampP.h`)
pub const OWP_TESTREC_OFFSET: usize = 40;
pub const OWP_DATARECV2_SIZE: usize = 24;
pub const OWP_DATARECV3_SIZE: usize = 25;
pub const OWP_DATAREC_TWV3_SIZE: usize = 50;
pub const OWP_DATAREC_SIZE: usize = OWP_DATARECV3_SIZE;
pub const OWP_MAXDATAREC_SIZE: usize = OWP_DATAREC_SIZE;
pub const OWP_SKIPREC_SIZE: usize = 8;
pub const OWP_VERSION_TWOWAY: u32 = 128;

pub const OWP_FETCHV2_BUFFSIZE: usize = 48;
pub const OWP_FETCHV2_AES_BLOCKS: usize = 3;
pub const OWP_FETCHV2_DATAREC_BLOCKS: usize = 2;
pub const OWP_FETCHV3_BUFFSIZE: usize = 400;
pub const OWP_FETCHV3_AES_BLOCKS: usize = 25;
pub const OWP_FETCHV3_DATAREC_BLOCKS: usize = 16;
pub const OWP_FETCH_BUFFSIZE: usize = OWP_FETCHV3_BUFFSIZE;
pub const OWP_FETCH_AES_BLOCKS: usize = OWP_FETCHV3_AES_BLOCKS;
pub const OWP_FETCH_DATAREC_BLOCKS: usize = OWP_FETCHV3_DATAREC_BLOCKS;

// Control message lengths in 16-byte blocks
pub const OWP_TEST_REQUEST_BLK_LEN: usize = 7;
pub const OWP_START_SESSIONS_BLK_LEN: usize = 2;
pub const OWP_STOP_SESSIONS_BLK_LEN: usize = 2;
pub const OWP_FETCH_SESSION_BLK_LEN: usize = 3;
pub const OWP_START_ACK_BLK_LEN: usize = 2;
pub const OWP_FETCH_ACK_BLK_LEN: usize = 2;
pub const OWP_MAX_MSG_BLK_LEN: usize = OWP_FETCHV3_AES_BLOCKS;
pub const OWP_MAX_MSG_SIZE: usize = OWP_MAX_MSG_BLK_LEN * OWP_RIJNDAEL_BLOCK_SIZE;
pub const OWP_TEST_REQUEST_PREAMBLE_SIZE: usize =
    OWP_TEST_REQUEST_BLK_LEN * OWP_RIJNDAEL_BLOCK_SIZE;

// Control connection state bits
pub const OWP_STATE_INITIAL: u32 = 0x0000;
pub const OWP_STATE_INVALID: u32 = 0x0000;
pub const OWP_STATE_SETUP: u32 = 0x0001;
pub const OWP_STATE_UPTIME: u32 = OWP_STATE_SETUP << 1;
pub const OWP_STATE_REQUEST: u32 = OWP_STATE_UPTIME << 1;
pub const OWP_STATE_TEST: u32 = OWP_STATE_REQUEST << 1;
pub const OWP_STATE_TEST_REQUEST: u32 = OWP_STATE_TEST << 1;
pub const OWP_STATE_TEST_REQUEST_SLOTS: u32 = OWP_STATE_TEST_REQUEST << 1;
pub const OWP_STATE_START_SESSIONS: u32 = OWP_STATE_TEST_REQUEST_SLOTS << 1;
pub const OWP_STATE_STOP_SESSIONS: u32 = OWP_STATE_START_SESSIONS << 1;
pub const OWP_STATE_FETCH_SESSION: u32 = OWP_STATE_STOP_SESSIONS << 1;
pub const OWP_STATE_TEST_REQUEST_TW: u32 = OWP_STATE_FETCH_SESSION << 1;
pub const OWP_STATE_ACCEPT_SESSION: u32 = OWP_STATE_TEST_REQUEST_TW << 1;
pub const OWP_STATE_START_ACK: u32 = OWP_STATE_ACCEPT_SESSION << 1;
pub const OWP_STATE_FETCH_ACK: u32 = OWP_STATE_START_ACK << 1;
pub const OWP_STATE_FETCHING: u32 = OWP_STATE_FETCH_ACK << 1;
pub const OWP_STATE_FETCHING_RECORDS: u32 = OWP_STATE_FETCHING << 1;

pub const OWP_STATE_READING: u32 = OWP_STATE_TEST_REQUEST
    | OWP_STATE_START_SESSIONS
    | OWP_STATE_STOP_SESSIONS
    | OWP_STATE_FETCH_SESSION;
pub const OWP_STATE_PENDING: u32 =
    OWP_STATE_ACCEPT_SESSION | OWP_STATE_START_ACK | OWP_STATE_STOP_SESSIONS | OWP_STATE_FETCH_ACK;

pub const OWP_CONTEXT_TABLE_SIZE: usize = 64;
pub const OWP_CONTEXT_MAX_KEYLEN: usize = 64;
pub const OWP_SLOT_BUFSIZE: usize = 10;

pub const OWP_PKT_TYPE_NUM: usize = 2;
pub const OWP_DELAY_TYPE_NUM: usize = 3;
pub const OWP_DELAY_TYPE_NUM_INC_PROC: usize = OWP_DELAY_TYPE_NUM + 1;
pub const OWP_TTL_TYPE_NUM: usize = 2;

// Context config key names
pub const OWP_INTERRUPT_IO: &str = "OWPInterruptIO";
pub const OWP_TEST_PORT_RANGE: &str = "OWPTestPortRange";
pub const OWP_GET_PF: &str = "OWPGetPF";
pub const OWP_CHECK_CONTROL_POLICY: &str = "OWPCheckControlPolicy";
pub const OWP_CHECK_TEST_POLICY: &str = "OWPCheckTestPolicy";
pub const OWP_CHECK_FETCH_POLICY: &str = "OWPCheckFetchPolicy";
pub const OWP_TEST_COMPLETE: &str = "OWPTestComplete";
pub const OWP_OPEN_FILE: &str = "OWPOpenFile";
pub const OWP_CLOSE_FILE: &str = "OWPCloseFile";
pub const OWP_DETACH_PROCESSES: &str = "OWPDetachProcesses";
pub const OWP_KEY_DERIVATION_COUNT: &str = "OWPKeyDerivationCount";
pub const TWP_TEST_TIMEOUT: &str = "TWPTestTimeout";
pub const OWP_END_DELAY: &str = "OWPEndDelay";
pub const OWP_IPV4_ONLY: &str = "OWPIPv4Only";
pub const OWP_IPV6_ONLY: &str = "OWPIPv6Only";
/// `OWPChildWait` (C `#ifdef DEBUG`).
pub const OWP_CHILD_WAIT: &str = "OWPChildWait";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_buffer_sizes_match_c_asserts() {
        assert_eq!(
            OWP_FETCH_BUFFSIZE,
            OWP_RIJNDAEL_BLOCK_SIZE * OWP_FETCH_AES_BLOCKS
        );
        assert_eq!(
            OWP_FETCH_BUFFSIZE,
            OWP_DATARECV3_SIZE * OWP_FETCH_DATAREC_BLOCKS
        );
    }

    #[test]
    fn mode_octal_values() {
        assert_eq!(OWP_MODE_OPEN, 1);
        assert_eq!(OWP_MODE_AUTHENTICATED, 2);
        assert_eq!(OWP_MODE_ENCRYPTED, 4);
        assert_eq!(TWP_MODE_MIXED, 8);
    }
}
