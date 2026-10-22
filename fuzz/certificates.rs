#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len() > browser_relay::transparency::MAX_CERT { return; }
    let issuer = include_bytes!("../tests/fixtures/ct-github-issuer.der");
    let _ = browser_relay::transparency::verify(data, Some(issuer), 1792670400);
    let _ = browser_relay::certificate::certificate_info(data);
    static PROOF: std::sync::OnceLock<Option<Box<browser_relay::ct_proof::Proof>>> = std::sync::OnceLock::new();
    if let Some(proof) = PROOF.get_or_init(|| browser_relay::transparency::verify(
        include_bytes!("../tests/fixtures/ct-github-leaf.der"), Some(issuer), 1792670400).proof) {
        let _ = proof.audit_url(data, 1792670400);
        let _ = proof.verify(data, data, 1792670400);
    }
    let lookup = browser_relay::certificate_history::prepare("github.com").unwrap();
    let _ = browser_relay::certificate_history::summary(data, &lookup);
});
