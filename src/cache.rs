//! Bounded, shared on-device indexes; updates replace a complete snapshot atomically.
use crate::{Cancel, Result};
use std::{
    fs,
    io::{BufReader, Write},
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
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn load<T>(
    path: PathBuf,
    shared: &Mutex<Option<Cached<T>>>,
    decode: impl FnOnce(BufReader<fs::File>, usize) -> Result<T>,
) -> Result<Arc<T>> {
    let file = fs::File::open(&path)
        .map_err(|_| "No readable local index. Use Update lists to download it.")?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    let modified = metadata.modified().map_err(|e| e.to_string())?;
    let mut cache = crate::recover_lock(shared);
    if let Some(cached) = &*cache
        && cached.path == path
        && cached.inode == metadata.ino()
        && cached.modified == modified
        && cached.size == metadata.len()
    {
        return Ok(cached.database.clone());
    }
    if !metadata.is_file() {
        return Err("Expected a regular index file.".into());
    }
    let size = usize::try_from(metadata.len()).map_err(|_| "Index cache is too large.")?;
    // Release an idle obsolete snapshot before decoding its replacement. Active
    // readers keep their own Arc; no raw-file buffer is retained alongside either.
    *cache = None;
    // The format decoder owns size limits and budgets allocations from this size.
    let reader = BufReader::with_capacity(64 * 1024, file);
    let database = Arc::new(decode(reader, size)?);
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
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    #[test]
    fn panicking_decoder_does_not_disable_future_loads() {
        let path = std::env::temp_dir().join(format!("relay-poison-{}", std::process::id()));
        fs::write(&path, b"index").unwrap();
        let shared: Mutex<Option<Cached<Vec<u8>>>> = Mutex::new(None);
        let panic = std::panic::catch_unwind(|| {
            let _ = load(path.clone(), &shared, |_, _| panic!("decoder panic"));
        });
        assert!(panic.is_err());
        assert!(shared.is_poisoned());
        let loaded = load(path.clone(), &shared, |mut reader, _| {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
            Ok(bytes)
        })
        .unwrap();
        assert_eq!(&**loaded, b"index");
        assert!(!shared.is_poisoned());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn forged_files_cannot_allocate_more_than_their_size_allowance() {
        use crate::domain_list::{List, Rankings, Snapshot};
        let path = std::env::temp_dir().join(format!("relay-budget-{}", std::process::id()));
        let mut bytes = Snapshot {
            big: List::parse("||example.org^").unwrap(),
            nsfw: List::parse("||xxx^").unwrap(),
            downloaded: 1,
        }
        .encode();
        bytes[20..24].copy_from_slice(&1_000_000u32.to_le_bytes());
        fs::write(&path, &bytes).unwrap();
        let error = load(path.clone(), &Mutex::new(None), Snapshot::read_sized)
            .err()
            .unwrap();
        assert!(error.contains("memory budget"), "{error}");
        let mut bytes = Rankings::parse("1,example.org", "TEST", "date", 1)
            .unwrap()
            .encode();
        // Header + list ID + date length precede the forged domain count.
        bytes[32..36].copy_from_slice(&1_000_000u32.to_le_bytes());
        fs::write(&path, &bytes).unwrap();
        let error = load(path.clone(), &Mutex::new(None), Rankings::read_sized)
            .err()
            .unwrap();
        assert!(error.contains("memory budget"), "{error}");
        fs::remove_file(path).unwrap();
    }

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
