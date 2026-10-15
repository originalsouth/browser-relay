//! Bounded, shared on-device indexes; updates replace a complete snapshot atomically.
use crate::{Result, inspect::Cancel};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::PathBuf,
    sync::{Arc, Mutex, atomic::Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
pub struct Cached<T> {
    path: PathBuf,
    inode: u64,
    modified: SystemTime,
    size: u64,
    database: Arc<T>,
}
pub fn path(variable: &str, filename: &str) -> Result<PathBuf> {
    let dir = if let Some(dir) = std::env::var_os(variable) {
        PathBuf::from(dir)
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
            .ok_or("No user data directory configured.")?
            .join("browser-relay")
    };
    Ok(dir.join(filename))
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn load<T>(
    path: PathBuf,
    shared: &Mutex<Option<Cached<T>>>,
    limit: usize,
    decode: impl FnOnce(&[u8]) -> Result<T>,
) -> Result<Arc<T>> {
    let file = fs::File::open(&path)
        .map_err(|_| "No readable local index. Use Update lists to download it.")?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    let modified = metadata.modified().map_err(|e| e.to_string())?;
    let mut cache = shared.lock().map_err(|_| "Index cache lock unavailable.")?;
    if let Some(cached) = &*cache
        && cached.path == path
        && cached.inode == metadata.ino()
        && cached.modified == modified
        && cached.size == metadata.len()
    {
        return Ok(cached.database.clone());
    }
    if metadata.len() > limit as u64 {
        return Err("Index cache exceeds its size limit.".into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let database = Arc::new(decode(&bytes)?);
    *cache = Some(Cached {
        path,
        inode: metadata.ino(),
        modified,
        size: metadata.len(),
        database: database.clone(),
    });
    Ok(database)
}
pub fn write(path: PathBuf, data: &[u8], cancel: &Cancel) -> Result<()> {
    fs::create_dir_all(path.parent().ok_or("Invalid cache path.")?).map_err(|e| e.to_string())?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp = path.with_extension(format!("{}.{nonce}.tmp", std::process::id()));
    // Only remove temporary files this invocation actually created.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|e| e.to_string())?;
    let result = (|| -> Result<()> {
        file.write_all(data)
            .and_then(|_| file.sync_all())
            .map_err(|e| e.to_string())?;
        if cancel.load(Ordering::Relaxed) {
            return Err("Cancelled".into());
        }
        fs::rename(&temp, &path).map_err(|e| e.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}
pub async fn download(client: &reqwest::Client, url: &str, limit: usize) -> Result<Vec<u8>> {
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|e| e.without_url().to_string())?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(format!(
            "List download returned HTTP {}. Redirects are not followed; the previous cache was kept.",
            response.status()
        ));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| e.without_url().to_string())?
    {
        if bytes.len() + chunk.len() > limit {
            return Err(
                "List download exceeds its size limit; the previous cache was kept.".into(),
            );
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancelled_update_preserves_previous_cache_and_cleans_its_tempfile() {
        let dir = std::env::temp_dir().join(format!(
            "relay-atomic-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("cache.bin");
        fs::write(&path, b"original").unwrap();
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(true));
        assert!(write(path.clone(), b"replacement", &cancel).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"original");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        cancel.store(false, Ordering::Relaxed);
        write(path.clone(), b"replacement", &cancel).unwrap();
        assert_eq!(fs::read(path).unwrap(), b"replacement");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }
}
