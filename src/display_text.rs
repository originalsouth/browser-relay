//! Display untrusted identity text without control or bidirectional overrides.
pub fn unsafe_character(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}
pub fn safe_chars(value: &str) -> impl Iterator<Item = char> + '_ {
    value.chars().filter(|c| !unsafe_character(*c))
}
pub fn clean(value: &str) -> String {
    safe_chars(value).collect()
}
pub fn escaped(value: &str) -> String {
    let mut text = String::new();
    for c in value.chars() {
        if unsafe_character(c) {
            text.extend(c.escape_default());
        } else {
            text.push(c);
        }
    }
    text
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strips_formatting_without_erasing_international_names() {
        let input = "Acme\n\u{202e}\u{202c}\u{2066}\u{2069}\u{061c}\u{200e}\u{200f} · 日本 العربية";
        assert_eq!(clean(input), "Acme · 日本 العربية");
        assert!(!escaped(input).chars().any(unsafe_character));
        assert!(escaped(input).contains("\\u{202e}"));
    }
}
