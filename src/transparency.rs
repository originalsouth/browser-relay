//! Offline RFC 6962 embedded-SCT signature checks. These are logging promises,
//! not inclusion proofs, browser CT-policy compliance, or a verdict on content.
use crate::Result;
use ring::{digest, signature};
use std::collections::HashSet;
use x509_parser::prelude::*;

pub const MAX_CERT: usize = 32 * 1024;
const SCT_OID: &[u8] = &[0x2b, 6, 1, 4, 1, 0xd6, 0x79, 2, 4, 2];
const POISON_OID: &str = "1.3.6.1.4.1.11129.2.4.3";
const LIMIT: usize = 32;
const EXPLANATION: &str = "Embedded RFC 6962 timestamps only. Signatures verify log promises; no inclusion proof or browser CT-policy compliance was checked. This does not establish site safety. No network lookup was made.";
#[derive(Debug, Clone)]
pub struct Report {
    pub summary: String,
    pub detail: String,
    pub proof: Option<Box<crate::ct_proof::Proof>>,
}
use crate::ct_logs::Logs;
#[cfg(test)]
use crate::ct_logs::bundled;
// Minimal bounded DER framing. Unchanged certificate fields retain their exact
// bytes; only the SCT extension and enclosing lengths are removed/re-encoded.
fn tlv(input: &mut &[u8]) -> Result<(u8, Vec<u8>, Vec<u8>)> {
    let original = *input;
    let (&tag, rest) = input.split_first().ok_or("Truncated DER.")?;
    let (&first, rest) = rest.split_first().ok_or("Truncated DER length.")?;
    let (length, body) = if first < 128 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 127);
        if n == 0 || n > 4 || rest.len() < n || rest[0] == 0 {
            return Err("Invalid DER length.".into());
        }
        let length = rest[..n]
            .iter()
            .try_fold(0usize, |n, b| {
                n.checked_mul(256)
                    .and_then(|n| n.checked_add(usize::from(*b)))
            })
            .ok_or("DER length overflow.")?;
        if length < 128 {
            return Err("Noncanonical DER length.".into());
        }
        (length, &rest[n..])
    };
    if length > MAX_CERT || body.len() < length {
        return Err("DER field exceeds certificate bounds.".into());
    }
    *input = &body[length..];
    Ok((
        tag,
        body[..length].to_vec(),
        original[..original.len() - input.len()].to_vec(),
    ))
}
fn wrap(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 128 {
        out.push(body.len() as u8);
    } else {
        let length = body.len().to_be_bytes();
        let start = length.iter().position(|b| *b != 0).unwrap();
        out.push(128 | (length.len() - start) as u8);
        out.extend_from_slice(&length[start..]);
    }
    out.extend_from_slice(body);
    out
}
fn content(bytes: &[u8], expected: u8) -> Result<Vec<u8>> {
    let mut remaining = bytes;
    let (tag, body, _) = tlv(&mut remaining)?;
    if tag != expected || !remaining.is_empty() {
        return Err("Unexpected DER field.".into());
    }
    Ok(body)
}
fn precertificate(tbs: &[u8]) -> Result<Vec<u8>> {
    let body = content(tbs, 0x30)?;
    let mut fields = body.as_slice();
    let mut output = Vec::new();
    let mut removed = 0;
    while !fields.is_empty() {
        let (tag, body, raw) = tlv(&mut fields)?;
        if tag != 0xa3 {
            output.extend(raw);
            continue;
        }
        let extensions = content(&body, 0x30)?;
        let mut remaining = extensions.as_slice();
        let mut keep = Vec::new();
        while !remaining.is_empty() {
            let (tag, extension, raw) = tlv(&mut remaining)?;
            if tag != 0x30 {
                return Err("Invalid certificate extension.".into());
            }
            let mut extension = extension.as_slice();
            let (tag, oid, _) = tlv(&mut extension)?;
            if tag != 6 {
                return Err("Missing extension OID.".into());
            }
            if oid == SCT_OID {
                removed += 1;
            } else {
                keep.extend(raw);
            }
        }
        if !keep.is_empty() {
            output.extend(wrap(0xa3, &wrap(0x30, &keep)));
        }
    }
    if removed != 1 {
        return Err("Expected one embedded SCT extension.".into());
    }
    Ok(wrap(0x30, &output))
}
struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.0.len() {
            return Err("Truncated SCT.".into());
        }
        let (v, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(v)
    }
    fn vector(&mut self) -> Result<&'a [u8]> {
        let n = u16::from_be_bytes(self.take(2)?.try_into().unwrap());
        self.take(usize::from(n))
    }
}
fn verify_one(
    bytes: &[u8],
    tbs: &[u8],
    issuer_hash: &[u8],
    logs: &Logs,
    now: i64,
    expires: i64,
) -> Result<(String, String, Option<crate::ct_proof::Proof>)> {
    let mut sct = Cursor(bytes);
    if sct.take(1)? != [0] {
        return Err("Unsupported SCT version.".into());
    }
    let id = sct.take(32)?;
    let timestamp = u64::from_be_bytes(sct.take(8)?.try_into().unwrap());
    let extensions = sct.vector()?;
    let algorithm = sct.take(2)?;
    let sig = sct.vector()?;
    if !sct.0.is_empty() {
        return Err("Trailing SCT data.".into());
    }
    let log = logs
        .logs
        .iter()
        .find(|log| log.id == id)
        .ok_or("Unknown log in bundled snapshot.")?;
    let seconds = i64::try_from(timestamp / 1000).map_err(|_| "Invalid SCT time.")?;
    if seconds > now.saturating_add(300) || seconds > expires {
        return Err(format!(
            "{}: timestamp is in the future or after expiry.",
            log.name
        ));
    }
    if !(log.start..log.end).contains(&expires) {
        return Err(format!(
            "{}: certificate outside log's temporal interval.",
            log.name
        ));
    }
    let qualified = matches!(log.state.as_str(), "usable" | "readonly")
        || (log.state == "retired" && seconds < log.state_at);
    if !qualified {
        return Err(format!(
            "{}: log state {} is not eligible for this timestamp.",
            log.name, log.state
        ));
    }
    let mut message = vec![0, 0]; // v1, certificate_timestamp
    message.extend_from_slice(&timestamp.to_be_bytes());
    message.extend_from_slice(&[0, 1]); // precert_entry
    message.extend_from_slice(issuer_hash);
    let len = (tbs.len() as u32).to_be_bytes();
    message.extend_from_slice(&len[1..]);
    message.extend_from_slice(tbs);
    message.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    message.extend_from_slice(extensions);
    let (_, key) =
        SubjectPublicKeyInfo::from_der(&log.key).map_err(|_| "Invalid log public key.")?;
    let verifier: &dyn signature::VerificationAlgorithm = match algorithm {
        [4, 3] => &signature::ECDSA_P256_SHA256_ASN1,
        [4, 1] => &signature::RSA_PKCS1_2048_8192_SHA256,
        _ => {
            return Err(format!(
                "{}: unsupported SCT signature algorithm.",
                log.name
            ));
        }
    };
    signature::UnparsedPublicKey::new(verifier, key.subject_public_key.data.as_ref())
        .verify(&message, sig)
        .map_err(|_| format!("{}: SCT signature did not verify.", log.name))?;
    let proof = crate::ct_proof::Proof::from_entry(log, &message, timestamp).ok();
    Ok((log.name.clone(), log.operator.clone(), proof))
}
fn check_with_logs(der: &[u8], issuer: Option<&[u8]>, now: i64, logs: &Logs) -> Result<Report> {
    if der.len() > MAX_CERT {
        return Err("Certificate exceeds 32 KiB.".into());
    }
    let (rest, cert) = parse_x509_certificate(der).map_err(|_| "Invalid certificate.")?;
    if !rest.is_empty() {
        return Err("Trailing certificate data.".into());
    }
    let ext = cert
        .get_extension_unique(&x509_parser::oid_registry::OID_CT_LIST_SCT)
        .map_err(|_| "Duplicate SCT extension.")?
        .ok_or("No embedded SCTs; TLS/OCSP-delivered timestamps were not checked.")?;
    if cert
        .extensions()
        .iter()
        .any(|e| e.oid.to_id_string() == POISON_OID)
    {
        return Err("Precertificate poison present in final certificate.".into());
    }
    let issuer = issuer
        .ok_or("Issuer certificate unavailable; embedded SCT signatures could not be checked.")?;
    if issuer.len() > MAX_CERT {
        return Err("Issuer certificate exceeds 32 KiB.".into());
    }
    let (rest, issuer) =
        parse_x509_certificate(issuer).map_err(|_| "Invalid issuer certificate.")?;
    if !rest.is_empty()
        || cert.issuer() != issuer.subject()
        || cert.verify_signature(Some(issuer.public_key())).is_err()
    {
        return Err("Supplied issuer does not sign this certificate.".into());
    }
    let issuer_hash = digest::digest(&digest::SHA256, issuer.public_key().raw);
    let tbs = precertificate(cert.tbs_certificate.as_ref())?;
    let inner = content(ext.value, 4)?;
    let mut list = Cursor(&inner);
    let entries = list.vector()?;
    if !list.0.is_empty() {
        return Err("Trailing SCT list data.".into());
    }
    let mut list = Cursor(entries);
    let mut total = 0;
    let mut verified = 0;
    let mut seen = HashSet::new();
    let mut operators = HashSet::new();
    let mut lines = Vec::new();
    let mut proof = None;
    while !list.0.is_empty() {
        total += 1;
        if total > LIMIT {
            return Err("Too many embedded SCTs (maximum 32).".into());
        }
        let bytes = list.vector()?;
        if !seen.insert(bytes.to_vec()) {
            lines.push("Duplicate SCT ignored.".into());
            continue;
        }
        match verify_one(
            bytes,
            &tbs,
            issuer_hash.as_ref(),
            logs,
            now,
            cert.validity().not_after.timestamp(),
        ) {
            Ok((name, operator, candidate)) => {
                if proof.is_none() {
                    proof = candidate.map(Box::new);
                }
                verified += 1;
                operators.insert(operator.clone());
                lines.push(format!("Verified: {name} ({operator})"));
            }
            Err(reason) => lines.push(reason),
        }
    }
    if total == 0 {
        return Err("Empty embedded SCT list.".into());
    }
    let stale = now.saturating_sub(logs.timestamp) > 90 * 86400
        || logs.timestamp > now.saturating_add(86400);
    let summary = format!(
        "{verified}/{total} SCT signatures verified{}",
        if stale { " · log list stale" } else { "" }
    );
    Ok(Report {
        proof,
        summary: summary.clone(),
        detail: format!(
            "{summary}\n{} log operator(s) verified\n{}\nLog-key snapshot: {}{}\n{EXPLANATION}",
            operators.len(),
            lines.join("\n"),
            logs.date,
            if stale {
                " · use Update log keys for newer metadata"
            } else {
                ""
            }
        ),
    })
}
#[cfg(test)]
fn check(der: &[u8], issuer: Option<&[u8]>, now: i64) -> Result<Report> {
    check_with_logs(der, issuer, now, bundled()?.as_ref())
}
pub fn verify(der: &[u8], issuer: Option<&[u8]>, now: i64) -> Report {
    verify_cached(der, issuer, now, None)
}
pub fn verify_cached(
    der: &[u8],
    issuer: Option<&[u8]>,
    now: i64,
    path: Option<&std::path::Path>,
) -> Report {
    let result = crate::ct_logs::current(path).and_then(|(logs, warning)| {
        let mut report = check_with_logs(der, issuer, now, &logs)?;
        if let Some(warning) = warning {
            report.detail.push_str(&format!("\n{warning}"));
        }
        Ok(report)
    });
    result.unwrap_or_else(|e| Report {
        proof: None,
        summary: "CT not verified".into(),
        detail: format!("{e}\n{EXPLANATION}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const LEAF: &[u8] = include_bytes!("../tests/fixtures/ct-github-leaf.der");
    const ISSUER: &[u8] = include_bytes!("../tests/fixtures/ct-github-issuer.der");
    fn now() -> i64 {
        crate::ct_logs::date("2026-10-22T12:00:00Z").unwrap()
    }
    #[test]
    fn public_fixture_verifies_and_missing_issuer_is_not_success() {
        let report = check(LEAF, Some(ISSUER), now()).unwrap();
        println!("{}", report.detail);
        assert!(report.summary.starts_with("2/2"), "{}", report.detail);
        assert!(
            verify(LEAF, None, now())
                .detail
                .contains("Issuer certificate unavailable")
        );
        assert!(
            verify(LEAF, Some(LEAF), now())
                .detail
                .contains("does not sign")
        );
        assert!(
            check(LEAF, Some(ISSUER), now() + 100 * 86400)
                .unwrap()
                .summary
                .contains("stale")
        );
    }
    #[test]
    fn altered_signature_timestamp_and_signed_certificate_are_rejected() {
        let (_, cert) = parse_x509_certificate(LEAF).unwrap();
        let (_, issuer) = parse_x509_certificate(ISSUER).unwrap();
        let ext = cert
            .get_extension_unique(&x509_parser::oid_registry::OID_CT_LIST_SCT)
            .unwrap()
            .unwrap();
        let inner = content(ext.value, 4).unwrap();
        let mut list = Cursor(&inner);
        let mut entries = Cursor(list.vector().unwrap());
        let bytes = entries.vector().unwrap().to_vec();
        let tbs = precertificate(cert.tbs_certificate.as_ref()).unwrap();
        let hash = digest::digest(&digest::SHA256, issuer.public_key().raw);
        let validate = |sct: &[u8], tbs: &[u8]| {
            verify_one(
                sct,
                tbs,
                hash.as_ref(),
                bundled().unwrap().as_ref(),
                now(),
                cert.validity().not_after.timestamp(),
            )
        };
        assert!(validate(&bytes, &tbs).is_ok());
        let mut bad = bytes.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(validate(&bad, &tbs).is_err());
        bad = bytes.clone();
        bad[33] ^= 1;
        assert!(validate(&bad, &tbs).is_err());
        bad = bytes.clone();
        bad[1] ^= 1;
        assert!(validate(&bad, &tbs).is_err());
        bad = bytes.clone();
        bad.push(0);
        assert!(validate(&bad, &tbs).is_err());
        let mut altered = tbs.clone();
        *altered.last_mut().unwrap() ^= 1;
        assert!(validate(&bytes, &altered).is_err());
        for n in 0..bytes.len() {
            assert!(validate(&bytes[..n], &tbs).is_err());
        }
    }
    #[test]
    fn truncation_and_invalid_der_are_bounded() {
        for n in 0..LEAF.len() {
            assert_eq!(
                verify(&LEAF[..n], Some(ISSUER), now()).summary,
                "CT not verified"
            );
        }
        for bad in [
            &[0x30, 0x80][..],
            &[0x30, 0xff, 0xff][..],
            &[0x30, 0x81, 0][..],
        ] {
            assert!(precertificate(bad).is_err());
        }
        assert!(
            verify(&vec![0; MAX_CERT + 1], None, now())
                .detail
                .contains("32 KiB")
        );
    }
}
