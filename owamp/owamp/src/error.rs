//! Error handling — port of `error.c` / OWAMP error codes.

use thiserror::Error;

use crate::owamp::{OwampAcceptType, OwampErrSeverity, OwampErrType};

pub type Result<T> = std::result::Result<T, OwampError>;

#[derive(Debug, Error)]
pub enum OwampError {
    #[error("{0}")]
    Message(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("OWAMP fatal: {0}")]
    Fatal(String),

    #[error("OWAMP policy error: {0}")]
    Policy(String),

    #[error("OWAMP invalid: {0}")]
    Invalid(String),

    #[error("OWAMP unsupported: {0}")]
    Unsupported(String),

    #[error("session rejected: {0:?}")]
    Rejected(OwampAcceptType),

    #[error("crypto error: {0}")]
    Crypto(String),
}

impl OwampError {
    pub fn message(msg: impl Into<String>) -> Self {
        Self::Message(msg.into())
    }

    pub fn from_err_type(etype: OwampErrType, msg: impl Into<String>) -> Self {
        let msg = msg.into();
        match etype {
            OwampErrType::Policy => Self::Policy(msg),
            OwampErrType::Invalid => Self::Invalid(msg),
            OwampErrType::Unsupported => Self::Unsupported(msg),
            OwampErrType::Unknown => Self::Message(msg),
        }
    }

    #[must_use]
    pub const fn severity(&self) -> OwampErrSeverity {
        match self {
            Self::Rejected(_) => OwampErrSeverity::Ok,
            Self::Policy(_) => OwampErrSeverity::Warning,
            Self::Unsupported(_) | Self::Invalid(_) | Self::Fatal(_) | Self::Crypto(_) => {
                OwampErrSeverity::Fatal
            },
            Self::Io(_) | Self::Message(_) => OwampErrSeverity::Fatal,
        }
    }
}

/// Port of `OWPReportLevelByName` — maps a name to a syslog-like priority.
///
/// Returns `Some(severity as i32)`, `Some(0)` for `"none"`, or `None` if unknown.
#[must_use]
pub fn report_level_by_name(name: &str) -> Option<i32> {
    let lower = name.to_ascii_lowercase();
    // C uses strncasecmp with length = keyword_len+1 so an exact match is required
    // (the trailing NUL is included in the compare length).
    match lower.as_str() {
        "fatal" => Some(OwampErrSeverity::Fatal as i32),
        "warning" => Some(OwampErrSeverity::Warning as i32),
        "info" => Some(OwampErrSeverity::Info as i32),
        "debug" => Some(OwampErrSeverity::Debug as i32),
        "all" => Some(OwampErrSeverity::Ok as i32),
        "none" => Some(0),
        _ => None,
    }
}

/// Port of `I2ErrLogSyslogFacility` — maps a facility name to a `LOG_*` constant.
///
/// Returns `None` if the name is unknown (C returns `-1`).
#[must_use]
pub fn syslog_facility_by_name(name: &str) -> Option<i32> {
    match name.to_ascii_lowercase().as_str() {
        "kern" => Some(libc::LOG_KERN),
        "user" => Some(libc::LOG_USER),
        "mail" => Some(libc::LOG_MAIL),
        "daemon" => Some(libc::LOG_DAEMON),
        "auth" => Some(libc::LOG_AUTH),
        "syslog" => Some(libc::LOG_SYSLOG),
        "lpr" => Some(libc::LOG_LPR),
        "news" => Some(libc::LOG_NEWS),
        "uucp" => Some(libc::LOG_UUCP),
        "cron" => Some(libc::LOG_CRON),
        "authpriv" => Some(libc::LOG_AUTHPRIV),
        "ftp" => Some(libc::LOG_FTP),
        "local0" => Some(libc::LOG_LOCAL0),
        "local1" => Some(libc::LOG_LOCAL1),
        "local2" => Some(libc::LOG_LOCAL2),
        "local3" => Some(libc::LOG_LOCAL3),
        "local4" => Some(libc::LOG_LOCAL4),
        "local5" => Some(libc::LOG_LOCAL5),
        "local6" => Some(libc::LOG_LOCAL6),
        "local7" => Some(libc::LOG_LOCAL7),
        _ => None,
    }
}

/// Fallback logger used when no context error handle is available (`OWPError_`).
pub fn log_fallback(fmt_msg: &str) {
    eprintln!("{fmt_msg}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_level_names() {
        assert_eq!(report_level_by_name("fatal"), Some(3));
        assert_eq!(report_level_by_name("WARNING"), Some(4));
        assert_eq!(report_level_by_name("info"), Some(6));
        assert_eq!(report_level_by_name("debug"), Some(7));
        assert_eq!(report_level_by_name("all"), Some(8));
        assert_eq!(report_level_by_name("none"), Some(0));
        assert_eq!(report_level_by_name("nope"), None);
        // C strncasecmp("fatal", name, 6) rejects longer strings
        assert_eq!(report_level_by_name("fatality"), None);
    }

    #[test]
    fn syslog_facility_names() {
        assert_eq!(syslog_facility_by_name("user"), Some(libc::LOG_USER));
        assert_eq!(syslog_facility_by_name("LOCAL0"), Some(libc::LOG_LOCAL0));
        assert_eq!(syslog_facility_by_name("daemon"), Some(libc::LOG_DAEMON));
        assert_eq!(syslog_facility_by_name("nope"), None);
    }
}
