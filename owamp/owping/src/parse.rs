//! Parsers for schedule, DSCP (`-D`), and percentiles — from `owping.c`.

use owamp::arithm64::double_to_num64;
use owamp::context::{Slot, SlotType};
use owamp::stats::scale_factor;

const MAX_PADDING_SIZE: u32 = 65_000;

pub const fn max_padding_size() -> u32 {
    MAX_PADDING_SIZE
}

/// Parse `-i` schedule: `0.1`, `0.1e`, `0.05f`, comma-separated.
pub fn parse_slots(sched: &str) -> Result<Vec<Slot>, String> {
    let mut slots = Vec::new();
    for part in sched.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err("Invalid Schedule.".into());
        }
        let (num_s, ty) = match part.chars().last() {
            Some(c) if c.is_ascii_alphabetic() => (&part[..part.len() - 1], c.to_ascii_lowercase()),
            _ => (part, 'e'),
        };
        let dval: f64 = num_s
            .parse()
            .map_err(|_| format!("Invalid numeric value ({part}) for schedule"))?;
        let slot = match ty {
            'e' | '\0' => Slot {
                slot_type: SlotType::RandExp,
                time: double_to_num64(dval),
            },
            'f' => Slot {
                slot_type: SlotType::Literal,
                time: double_to_num64(dval),
            },
            other => {
                return Err(format!("Invalid slot type ({other}) for schedule"));
            },
        };
        slots.push(slot);
    }
    if slots.is_empty() {
        return Err("Invalid Schedule.".into());
    }
    Ok(slots)
}

/// `parse_percentile` — C singular name; alias of [`parse_percentiles`].
#[allow(dead_code)] // C-parity alias (`parse_percentile` in owping.c)
pub fn parse_percentile(s: &str) -> Result<Vec<f32>, String> {
    parse_percentiles(s)
}

/// Parse `-a` percentile list.
pub fn parse_percentiles(s: &str) -> Result<Vec<f32>, String> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        let dval: f64 = part
            .parse()
            .map_err(|_| format!("Invalid numeric value ({part}) for percentile"))?;
        if !(0.0..=100.0).contains(&dval) {
            return Err(format!("Invalid numeric value ({part}) for percentile"));
        }
        out.push(dval as f32);
    }
    if out.is_empty() {
        return Err("Invalid '-a' alpha list .".into());
    }
    Ok(out)
}

/// Parse `-D` DSCP / symbolic TOS into OWAMP `typeP` (low 6 bits of high byte).
pub fn parse_type_p(tspec: &str) -> Result<u32, String> {
    let tstr = tspec.trim();

    if let Ok(tlng) = parse_int_auto(tstr) {
        if tlng & !0x3f == 0 {
            let tosbyte = (tlng as u8) << 2;
            return Ok(u32::from(tosbyte) << 22);
        }
    }

    let lower = tstr.to_ascii_lowercase();
    let tosbyte: u8 = if matches!(lower.as_str(), "none" | "default" | "df" | "cs0") {
        0
    } else if lower == "ef" {
        0xb8
    } else if lower.len() == 3 && lower.starts_with("cs") {
        match lower.as_bytes()[2] {
            b'0' => 0x00,
            b'1' => 0x20,
            b'2' => 0x40,
            b'3' => 0x60,
            b'4' => 0x80,
            b'5' => 0xa0,
            b'6' => 0xc0,
            b'7' => 0xe0,
            _ => return Err(format!("Invalid DSCP value (-D): \"{tspec}\"")),
        }
    } else if lower.len() == 4 && lower.starts_with("af") {
        let class = match lower.as_bytes()[2] {
            b'1' => 0x20u8,
            b'2' => 0x40,
            b'3' => 0x60,
            b'4' => 0x80,
            _ => return Err(format!("Invalid DSCP value (-D): \"{tspec}\"")),
        };
        let drop = match lower.as_bytes()[3] {
            b'1' => 0x08u8,
            b'2' => 0x10,
            b'3' => 0x18,
            _ => return Err(format!("Invalid DSCP value (-D): \"{tspec}\"")),
        };
        class | drop
    } else {
        return Err(format!("Invalid DSCP value (-D): \"{tspec}\""));
    };

    Ok(u32::from(tosbyte) << 22)
}

fn parse_int_auto(s: &str) -> Result<u64, ()> {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .map_or_else(
            || {
                if s.starts_with('0') && s.len() > 1 && s.bytes().all(|b| b.is_ascii_digit()) {
                    u64::from_str_radix(s, 8).map_err(|_| ())
                } else {
                    s.parse().map_err(|_| ())
                }
            },
            |hex| u64::from_str_radix(hex, 16).map_err(|_| ()),
        )
}

pub fn validate_units(c: char) -> Result<(), String> {
    if scale_factor(c).0 == 0.0 {
        Err("Invalid '-n' value.".into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use owamp::context::SlotType;

    #[test]
    fn parse_slots_default_exp() {
        let s = parse_slots("0.1").unwrap();
        assert_eq!(s.len(), 1);
        assert!(matches!(s[0].slot_type, SlotType::RandExp));
    }

    #[test]
    fn parse_slots_literal_and_mixed() {
        let s = parse_slots("0.05f,0.1e").unwrap();
        assert_eq!(s.len(), 2);
        assert!(matches!(s[0].slot_type, SlotType::Literal));
        assert!(matches!(s[1].slot_type, SlotType::RandExp));
    }

    #[test]
    fn parse_percentiles_bounds() {
        assert!(parse_percentiles("50,95,99").is_ok());
        assert!(parse_percentiles("101").is_err());
        assert!(parse_percentiles("-1").is_err());
    }

    #[test]
    fn parse_type_p_numeric_and_symbolic() {
        let t = parse_type_p("0x2e").unwrap(); // EF as DSCP
        assert_ne!(t, 0);
        assert_eq!(parse_type_p("ef").unwrap(), (0xb8u32) << 22);
        assert_eq!(parse_type_p("cs0").unwrap(), 0);
        assert!(parse_type_p("bogus").is_err());
    }

    #[test]
    fn validate_units_ok() {
        for c in ['n', 'u', 'm', 's'] {
            assert!(validate_units(c).is_ok());
        }
        assert!(validate_units('x').is_err());
    }
}
