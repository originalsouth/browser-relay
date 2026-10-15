//! Independent popularity and blocklist signals; neither overrides the other.
use crate::{blocklist, inspect::Cancel, tranco};
pub struct Report {
    pub oisd: blocklist::Report,
    pub tranco: tranco::Report,
}
impl Report {
    pub fn detail(&self) -> String {
        format!(
            "{}\n{}\n\n{}",
            self.oisd.summary, self.oisd.detail, self.tranco.detail
        )
    }
}
pub fn check(names: &[String]) -> Report {
    Report {
        oisd: blocklist::check(names),
        tranco: tranco::check(names),
    }
}
/// Each publisher's cache is atomic; one failed update does not erase the other.
pub fn update(cancel: &Cancel) -> (String, bool) {
    let mut failed = false;
    let mut messages = Vec::new();
    for result in [blocklist::update(cancel), tranco::update(cancel)] {
        match result {
            Ok(message) => messages.push(message),
            Err(error) => {
                failed = true;
                messages.push(format!("Update failed: {error}"));
            }
        }
    }
    (messages.join("\n"), failed)
}
