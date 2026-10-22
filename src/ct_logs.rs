//! Signed CT metadata. Updates are opt-in; reading or verifying never uses a network.
use crate::{Cancel, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::{digest, signature};
use serde_json::Value;
use std::{
    io::Read,
    path::Path,
    sync::{Arc, Mutex, OnceLock},
};
use x509_parser::prelude::*;
pub const LIST_URL: &str = "https://www.gstatic.com/ct/log_list/v3/log_list.json";
pub const SIGNATURE_URL: &str = "https://www.gstatic.com/ct/log_list/v3/log_list.sig";
pub const MAX_LIST: usize = 1024 * 1024;
pub const MAX_SIGNATURE: usize = 8192;
pub const FILE: &str = "ct-logs.signed";
pub const DISCLOSURE: &str = "Download the CT log list and its signature from www.gstatic.com? Google sees your connection IP and requests for these two public files. No inspected hostname, certificate or URL is sent. The pinned signing key verifies the update; invalid or older data never replaces a working snapshot. Updates are manual.";
pub struct Log {
    pub id: Vec<u8>,
    pub key: Vec<u8>,
    pub name: String,
    pub operator: String,
    pub state: String,
    pub state_at: i64,
    pub start: i64,
    pub end: i64,
    pub url: Option<url::Url>,
}
pub struct Logs {
    pub date: String,
    pub timestamp: i64,
    pub logs: Vec<Log>,
}
pub(crate) fn date(value: &str) -> Result<i64> {
    ::time::OffsetDateTime::parse(value, &::time::format_description::well_known::Rfc3339)
        .map(|t| t.unix_timestamp())
        .map_err(|_| "Invalid CT date.".into())
}

fn parse(bytes: &[u8]) -> Result<Logs> {
    if bytes.len() > MAX_LIST {
        return Err("CT log list exceeds 1 MiB.".into());
    }
    let data: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let text = |v: &Value| {
        v.as_str()
            .ok_or_else(|| "Invalid CT log metadata.".to_string())
            .and_then(|s| {
                if s.len() <= 2048 {
                    Ok(s.to_owned())
                } else {
                    Err("CT metadata field too long.".into())
                }
            })
    };
    let published = text(&data["log_list_timestamp"])?;
    let mut logs = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for operator in data["operators"]
        .as_array()
        .ok_or("Missing CT operators.")?
    {
        for source in ["logs", "tiled_logs"] {
            for log in operator[source].as_array().into_iter().flatten() {
                let key = STANDARD
                    .decode(text(&log["key"])?)
                    .map_err(|e| e.to_string())?;
                let id = STANDARD
                    .decode(text(&log["log_id"])?)
                    .map_err(|e| e.to_string())?;
                if digest::digest(&digest::SHA256, &key).as_ref() != id {
                    return Err("CT log key does not match its ID.".into());
                }
                let state = log["state"]
                    .as_object()
                    .filter(|s| s.len() == 1)
                    .and_then(|s| s.iter().next())
                    .ok_or("Missing CT log state.")?;
                if logs.len() >= 2048 || !seen.insert(id.clone()) || key.len() > 2048 {
                    return Err("Oversized or duplicate CT log metadata.".into());
                }
                logs.push(Log {
                    id,
                    key,
                    name: text(&log["description"])?,
                    operator: text(&operator["name"])?,
                    state: state.0.clone(),
                    state_at: date(&text(&state.1["timestamp"])?)?,
                    start: date(&text(&log["temporal_interval"]["start_inclusive"])?)?,
                    end: date(&text(&log["temporal_interval"]["end_exclusive"])?)?,
                    url: if source == "logs" {
                        log["url"].as_str().and_then(|s| url::Url::parse(s).ok())
                    } else {
                        None
                    },
                });
            }
        }
    }
    Ok(Logs {
        timestamp: date(&published)?,
        date: published,
        logs,
    })
}
fn authenticated(bytes: &[u8], sig: &[u8]) -> Result<Logs> {
    if bytes.len() > MAX_LIST || sig.len() > MAX_SIGNATURE {
        return Err("CT metadata exceeds its size limit.".into());
    }
    let (_, key) = SubjectPublicKeyInfo::from_der(include_bytes!("../assets/ct-log-list-key.der"))
        .map_err(|_| "Invalid pinned CT signing key.")?;
    signature::UnparsedPublicKey::new(
        &signature::RSA_PKCS1_2048_8192_SHA256,
        key.subject_public_key.data.as_ref(),
    )
    .verify(bytes, sig)
    .map_err(|_| "CT log-list signature did not verify; previous snapshot kept.")?;
    parse(bytes)
}
pub fn bundled() -> Result<Arc<Logs>> {
    static LOGS: OnceLock<Result<Arc<Logs>>> = OnceLock::new();
    LOGS.get_or_init(|| {
        authenticated(
            include_bytes!("../assets/ct-logs.json"),
            include_bytes!("../assets/ct-logs.sig"),
        )
        .map(Arc::new)
    })
    .as_ref()
    .cloned()
    .map_err(Clone::clone)
}
fn decode(bytes: &[u8]) -> Result<Logs> {
    let length = u32::from_be_bytes(
        bytes
            .get(..4)
            .ok_or("Truncated CT snapshot.")?
            .try_into()
            .unwrap(),
    ) as usize;
    if length > MAX_SIGNATURE || bytes.len() < 4 + length {
        return Err("Invalid CT signature framing.".into());
    }
    authenticated(&bytes[4 + length..], &bytes[4..4 + length])
}
pub fn load(path: &Path) -> Result<Arc<Logs>> {
    static CACHE: Mutex<Option<crate::cache::Cached<Logs>>> = Mutex::new(None);
    let logs = crate::cache::load(path.to_owned(), &CACHE, |mut reader, size| {
        if size > MAX_LIST + MAX_SIGNATURE + 4 {
            return Err("CT snapshot exceeds its size limit.".into());
        }
        let mut bytes = Vec::new();
        reader
            .by_ref()
            .take((MAX_LIST + MAX_SIGNATURE + 5) as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        let logs = decode(&bytes)?;
        if logs.timestamp < bundled()?.timestamp {
            return Err("CT snapshot predates the bundled metadata.".into());
        }
        Ok(logs)
    })?;
    if logs.timestamp > crate::cache::now() as i64 + 86400 {
        return Err("CT snapshot is dated in the future.".into());
    }
    Ok(logs)
}
pub fn current(path: Option<&Path>) -> Result<(Arc<Logs>, Option<String>)> {
    if let Some(path) = path {
        match load(path) {
            Ok(logs) => return Ok((logs, None)),
            Err(error) if path.exists() => {
                return Ok((
                    bundled()?,
                    Some(format!(
                        "Local CT snapshot unavailable ({error}); using bundled keys."
                    )),
                ));
            }
            Err(_) => {}
        }
    }
    Ok((bundled()?, None))
}
fn check_update(next: &Logs, previous: i64, now: i64) -> Result<()> {
    if next.timestamp < previous
        || next.timestamp > now.saturating_add(86400)
        || now.saturating_sub(next.timestamp) > 90 * 86400
    {
        return Err("CT snapshot is older than the current one, stale, or dated in the future; previous snapshot kept.".into());
    }
    if next.logs.is_empty() {
        return Err("Empty CT log list; previous snapshot kept.".into());
    }
    Ok(())
}
pub fn update(path: &Path, bytes: &[u8], sig: &[u8], cancel: &Cancel) -> Result<String> {
    // Serialize validation + replacement so two concurrent updates cannot roll back.
    static UPDATE: Mutex<()> = Mutex::new(());
    let _guard = crate::recover_lock(&UPDATE);
    let next = authenticated(bytes, sig)?;
    let parent = path.parent().ok_or("Invalid CT cache path.")?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path.with_extension("lock"))
        .map_err(|e| e.to_string())?;
    lock.try_lock().map_err(|_| "Another CT update is running or the update lock is unavailable; previous snapshot kept.")?;
    let previous = current(Some(path))?.0;
    let now = crate::cache::now() as i64;
    check_update(&next, previous.timestamp, now)?;
    let mut packed = (sig.len() as u32).to_be_bytes().to_vec();
    packed.extend_from_slice(sig);
    packed.extend_from_slice(bytes);
    crate::cache::write(path.to_owned(), &packed, cancel)?;
    Ok(format!(
        "CT log keys updated · {} · {} logs. Reopen inspection to use them.",
        next.date,
        next.logs.len()
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_snapshot_rejects_tampering_and_truncation() {
        let json = include_bytes!("../assets/ct-logs.json");
        let sig = include_bytes!("../assets/ct-logs.sig");
        assert!(authenticated(json, sig).unwrap().logs.len() > 10);
        let mut changed = json.to_vec();
        changed[10] ^= 1;
        assert!(authenticated(&changed, sig).is_err());
        assert!(authenticated(json, &sig[1..]).is_err());
        assert!(authenticated(&vec![0; MAX_LIST + 1], sig).is_err());
        assert!(decode(&[255; 4]).is_err());
    }
    #[test]
    fn update_rejects_rollback_future_and_stale_metadata() {
        let next = bundled().unwrap();
        assert!(check_update(&next, next.timestamp, next.timestamp + 100).is_ok());
        assert!(check_update(&next, next.timestamp + 1, next.timestamp + 100).is_err());
        assert!(check_update(&next, next.timestamp - 1, next.timestamp - 86401).is_err());
        assert!(check_update(&next, next.timestamp, next.timestamp + 91 * 86400).is_err());
    }
    #[test]
    fn bad_update_preserves_working_snapshot() {
        let root = std::env::temp_dir().join(format!("relay-ct-update-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join(FILE);
        let json = include_bytes!("../assets/ct-logs.json");
        let sig = include_bytes!("../assets/ct-logs.sig");
        let mut packed = (sig.len() as u32).to_be_bytes().to_vec();
        packed.extend_from_slice(sig);
        packed.extend_from_slice(json);
        std::fs::write(&path, &packed).unwrap();
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        assert!(update(&path, b"forged", sig, &cancel).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), packed);
        assert!(load(&path).is_ok());
        std::fs::remove_dir_all(root).unwrap();
    }
}
