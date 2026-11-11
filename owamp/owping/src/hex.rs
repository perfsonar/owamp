//! SID hex encode/decode — mirrors `I2HexEncode` / `I2HexDecode` usage in `owping.c`.

use std::fmt::Write;

use owamp::OwampSid;

/// Encode 16-byte SID as lowercase hex (32 chars).
pub fn sid_hex_encode(sid: &OwampSid) -> String {
    let mut s = String::with_capacity(32);
    for b in sid {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decode a hex SID string into 16 bytes (`I2HexDecode`).
pub fn sid_hex_decode(s: &str) -> Result<OwampSid, String> {
    let s = s.trim();
    if s.len() != 32 {
        return Err(format!("Invalid SID length (expected 32 hex chars): {s}"));
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        let byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!("Invalid SID hex: {s}"))?;
        out[i] = byte;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_sid() {
        let sid = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let hex = sid_hex_encode(&sid);
        assert_eq!(hex, "0123456789abcdeffedcba9876543210");
        assert_eq!(sid_hex_decode(&hex).unwrap(), sid);
    }

    #[test]
    fn decode_rejects_bad() {
        assert!(sid_hex_decode("abc").is_err());
        assert!(sid_hex_decode("zz23456789abcdeffedcba9876543210").is_err());
    }
}
