//! Desktop TLS-chain observation and the explicitly requested history lookup.
//! WebPKI remains responsible for certificate/hostname and handshake verification.
use crate::{
    Result,
    inspect::{self, Cancel},
};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use std::sync::{Arc, Mutex};
#[derive(Debug, Default)]
pub struct Capture(Mutex<Option<(Vec<u8>, Vec<u8>)>>);
impl Capture {
    pub fn issuer_for(&self, leaf: &[u8]) -> Option<Vec<u8>> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .filter(|(cert, _)| cert == leaf)
            .map(|(_, issuer)| issuer.clone())
    }
}
#[derive(Debug)]
struct Verifier {
    inner: Arc<WebPkiServerVerifier>,
    capture: Arc<Capture>,
}
impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let verified = self
            .inner
            .verify_server_cert(leaf, intermediates, name, ocsp, now)?;
        let mut captured = self.capture.0.lock().unwrap_or_else(|e| e.into_inner());
        *captured = None;
        if leaf.len() <= browser_relay::transparency::MAX_CERT
            && let Ok((_, cert)) = x509_parser::parse_x509_certificate(leaf)
        {
            for issuer in intermediates
                .iter()
                .take(8)
                .filter(|c| c.len() <= browser_relay::transparency::MAX_CERT)
            {
                if let Ok((_, ca)) = x509_parser::parse_x509_certificate(issuer)
                    && cert.issuer() == ca.subject()
                    && cert.verify_signature(Some(ca.public_key())).is_ok()
                {
                    *captured = Some((leaf.to_vec(), issuer.to_vec()));
                    break;
                }
            }
        }
        Ok(verified)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
pub fn tls(capture: Arc<Capture>) -> Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| e.to_string())?;
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Verifier { inner, capture }))
        .with_no_client_auth())
}
pub fn log_path() -> Result<std::path::PathBuf> {
    crate::list_cache::path("BROWSER_RELAY_CT_DIR", browser_relay::ct_logs::FILE)
}
pub fn update_logs(cancel: &Cancel) -> Result<String> {
    use browser_relay::ct_logs;
    inspect::run_async(cancel, async {
        let client = inspect::client_builder()
            .https_only(true)
            .build()
            .map_err(|e| e.to_string())?;
        let (list, signature) = tokio::try_join!(
            crate::list_cache::download(&client, ct_logs::LIST_URL, ct_logs::MAX_LIST),
            crate::list_cache::download(&client, ct_logs::SIGNATURE_URL, ct_logs::MAX_SIGNATURE),
        )?;
        ct_logs::update(&log_path()?, &list, &signature, cancel)
    })
}

pub fn inclusion(proof: &browser_relay::ct_proof::Proof, cancel: &Cancel) -> Result<String> {
    use browser_relay::ct_proof::MAX_RESPONSE;
    inspect::run_async(cancel, async {
        if inspect::proxy_configured() {
            return Err(
                "CT proof lookup is disabled with a proxy; no DNS request was sent.".into(),
            );
        }
        let head_url = proof.head_url()?;
        let host = head_url.host_str().ok_or("Missing CT log host.")?;
        let ips = inspect::addresses(host).await?;
        if ips.is_empty() || ips.iter().any(|ip| !inspect::public_ip(*ip)) {
            return Err("CT log resolved to a non-public address.".into());
        }
        let sockets: Vec<_> = ips
            .into_iter()
            .map(|ip| std::net::SocketAddr::new(ip, 443))
            .collect();
        let client = inspect::client_builder()
            .https_only(true)
            .resolve_to_addrs(host, &sockets)
            .build()
            .map_err(|e| e.to_string())?;
        async fn get(client: &reqwest::Client, url: url::Url) -> Result<Vec<u8>> {
            let response = client
                .get(url)
                .send()
                .await
                .map_err(|e| e.without_url().to_string())?;
            if response.status() != reqwest::StatusCode::OK {
                return Err(format!(
                    "CT log returned HTTP {}. Proof unavailable; this is not a site-safety verdict. No redirects or retries.",
                    response.status()
                ));
            }
            crate::http::body(response, MAX_RESPONSE, "CT proof response exceeds 64 KiB.").await
        }
        let head = get(&client, head_url.clone()).await?;
        let now = browser_relay::cache::now() as i64;
        let audit = get(&client, proof.audit_url(&head, now)?).await?;
        proof.verify(&head, &audit, now)
    })
}

fn history_auth(key: &str) -> Result<Option<reqwest::header::HeaderValue>> {
    browser_relay::certificate_history::validate_key(key)?;
    if key.is_empty() {
        return Ok(None);
    }
    let mut value = reqwest::header::HeaderValue::from_str(&format!("Bearer {key}"))
        .map_err(|_| "Invalid API key format.")?;
    value.set_sensitive(true);
    Ok(Some(value))
}
pub fn history(
    lookup: &browser_relay::certificate_history::Lookup,
    after: Option<&str>,
    key: &str,
    cancel: &Cancel,
) -> Result<browser_relay::certificate_history::Page> {
    use browser_relay::certificate_history::{
        MAX_RESPONSE, PROVIDER, page, page_url, status_error,
    };
    let url = page_url(lookup, after)?;
    let auth = history_auth(key)?;
    inspect::run_async(cancel, async {
        if inspect::proxy_configured() {
            return Err("Certificate history is unavailable while a proxy is configured; no DNS request was sent.".into());
        }
        let ips = inspect::addresses(PROVIDER).await?;
        if ips.is_empty() || ips.iter().any(|ip| !inspect::public_ip(*ip)) {
            return Err("History provider resolved to a non-public address.".into());
        }
        let sockets: Vec<_> = ips
            .into_iter()
            .map(|ip| std::net::SocketAddr::new(ip, 443))
            .collect();
        let client = inspect::client_builder()
            .https_only(true)
            .resolve_to_addrs(PROVIDER, &sockets)
            .build()
            .map_err(|e| e.to_string())?;
        let mut request = client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(auth) = auth {
            request = request.header(reqwest::header::AUTHORIZATION, auth);
        }
        let response = request
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        status_error(response.status().as_u16())?;
        let bytes =
            crate::http::body(response, MAX_RESPONSE, "Certificate history exceeds 1 MiB.").await?;
        let mut page = page(&bytes, lookup, after)?;
        if !key.is_empty() {
            page.summary = page.summary.replace(key, "[redacted]");
        }
        Ok(page)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn api_key_headers_are_sensitive_and_errors_do_not_echo_secrets() {
        let header = history_auth("test-only-secret").unwrap().unwrap();
        assert!(header.is_sensitive());
        assert!(!format!("{header:?}").contains("test-only-secret"));
        let error = history_auth("secret\ninvalid").unwrap_err();
        assert!(!error.contains("secret"));
    }
    #[test]
    fn observation_does_not_accept_an_untrusted_certificate() {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(
                include_bytes!("../tests/fixtures/certificate.der").to_vec(),
            ))
            .unwrap();
        let inner = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap();
        let capture = Arc::new(Capture::default());
        let verifier = Verifier {
            inner,
            capture: capture.clone(),
        };
        let leaf =
            CertificateDer::from(include_bytes!("../tests/fixtures/ct-github-leaf.der").to_vec());
        let issuer =
            CertificateDer::from(include_bytes!("../tests/fixtures/ct-github-issuer.der").to_vec());
        assert!(
            verifier
                .verify_server_cert(
                    &leaf,
                    &[issuer],
                    &ServerName::try_from("github.com").unwrap(),
                    &[],
                    UnixTime::since_unix_epoch(std::time::Duration::from_secs(1792670400))
                )
                .is_err()
        );
        assert!(capture.issuer_for(&leaf).is_none());
    }
}

#[cfg(test)]
mod live_tests {
    #[test]
    #[ignore = "Explicitly asks the public GitHub certificate's log for an inclusion proof"]
    fn live_github_log_inclusion() {
        let report = browser_relay::transparency::verify(
            include_bytes!("../tests/fixtures/ct-github-leaf.der"),
            Some(include_bytes!("../tests/fixtures/ct-github-issuer.der")),
            browser_relay::cache::now() as i64,
        );
        let proof = report.proof.expect("fixture has a supported log");
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let result = super::inclusion(&proof, &cancel).unwrap();
        assert!(result.starts_with("Inclusion verified"));
        println!("{result}");
    }

    #[test]
    #[ignore = "Explicitly sends the public hostname github.com to SSLMate Cert Spotter"]
    fn live_github_certificate_history() {
        let lookup = browser_relay::certificate_history::prepare("github.com").unwrap();
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let report = super::history(&lookup, None, "", &cancel).unwrap();
        assert!(report.summary.contains("One page only"));
        println!("{}", report.summary);
    }
}
