//! Linux storage locations and HTTP download adapter.
use crate::Result;
pub use browser_relay::cache::{Cached, load, now, write};
use std::path::PathBuf;
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
pub async fn download(client: &reqwest::Client, url: &str, limit: usize) -> Result<Vec<u8>> {
    let response = client
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
    crate::http::body(
        response,
        limit,
        "List download exceeds its size limit; the previous cache was kept.",
    )
    .await
}
