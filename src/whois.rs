//! Linux transport for opt-in RDAP. Protocol and disclosure rules live in the shared core.
use crate::{
    Result,
    inspect::{self, Cancel},
};
use browser_relay::registration::summary;
pub use browser_relay::registration::{Lookup, prepare};
use serde_json::Value;
use std::net::SocketAddr;
pub fn run(lookup: &Lookup, cancel: &Cancel) -> Result<String> {
    inspect::run_async(cancel, async {
        if inspect::proxy_configured() {
            return Err("Domain lookups are unavailable while a proxy is configured; no DNS request was sent.".into());
        }
        let host = lookup.url.host_str().ok_or("Missing registry hostname.")?;
        let ips = inspect::addresses(host).await?;
        if ips.is_empty() || ips.iter().any(|ip| !inspect::public_ip(*ip)) {
            return Err("The registry resolved to a non-public address; lookup stopped.".into());
        }
        let sockets: Vec<_> = ips.iter().map(|ip| SocketAddr::new(*ip, 443)).collect();
        let client = inspect::client_builder()
            .https_only(true)
            .resolve_to_addrs(host, &sockets)
            .build()
            .map_err(|e| e.to_string())?;
        let response = client
            .get(lookup.url.clone())
            .header(reqwest::header::ACCEPT, "application/rdap+json")
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err("No registration record returned. This does not establish whether the domain is available or safe.".into());
        }
        if response.status() != reqwest::StatusCode::OK {
            return Err(format!(
                "Registry returned HTTP {}. Redirects and referrals are not followed.",
                response.status()
            ));
        }
        let bytes = crate::http::body(response, 1_048_576, "RDAP response exceeded 1 MiB.").await?;
        let data: Value =
            serde_json::from_slice(&bytes).map_err(|_| "Registry returned invalid RDAP JSON.")?;
        summary(&data, lookup)
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "Explicitly contacts example.com's authoritative RDAP registry"]
    fn live_registry_lookup() {
        let lookup = prepare("private.example.com").unwrap();
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let output = run(&lookup, &cancel).unwrap();
        assert!(output.contains("Domain: example.com"));
        println!("{output}");
    }
}
