use qrcode::{EcLevel, QrCode};

pub const SIDE: i32 = 147;
pub const QUIET_ZONE: usize = 4;
// Version 6-M holds 106 bytes. Including its quiet zone, 49 modules fit at
// three logical pixels per module in the compact preview.
pub const MAX_BYTES: usize = 106;
const MAX_MODULES: usize = 41;

pub fn encode(link: &str) -> Option<QrCode> {
    if link.is_empty() || link.len() > MAX_BYTES {
        return None;
    }
    let code = QrCode::with_error_correction_level(link.as_bytes(), EcLevel::M).ok()?;
    (code.width() <= MAX_MODULES).then_some(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_full_byte_limit_without_reducing_module_size() {
        let link = format!("https://example.com/{}", "x".repeat(MAX_BYTES - 20));
        assert_eq!(link.len(), MAX_BYTES);
        let code = encode(&link).expect("link at byte limit should fit");
        assert!(SIDE as usize / (code.width() + QUIET_ZONE * 2) >= 3);
        assert_eq!(code.error_correction_level(), EcLevel::M);
        assert!(encode(&(link + "x")).is_none());
    }

    #[test]
    fn measures_utf8_bytes_and_never_truncates_input() {
        let prefix = "https://example.com/";
        let link = format!("{prefix}{}", "é".repeat((MAX_BYTES - prefix.len()) / 2));
        assert!(encode(&link).is_some());
        assert!(encode(&(link + "é")).is_none());
        assert!(encode(&"x".repeat(100_000)).is_none());
        assert!(encode("").is_none());
    }
}
