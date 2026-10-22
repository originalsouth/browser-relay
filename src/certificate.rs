//! Certificate identity parsing, shared with the iOS inspector.
use crate::Result;

#[derive(Debug)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub detail: String,
    pub not_before: i64,
    pub not_after: i64,
}

pub fn certificate_info(der: &[u8]) -> Result<CertificateInfo> {
    use crate::display_text::clean;
    use x509_parser::{extensions::GeneralName, x509::X509Name};
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|_| "Could not read certificate identity fields.")?;
    let display_name = |name: &X509Name<'_>| {
        let org = name
            .iter_organization()
            .filter_map(|value| value.as_str().ok())
            .collect::<Vec<_>>()
            .join(", ");
        let cn = name
            .iter_common_name()
            .filter_map(|value| value.as_str().ok())
            .collect::<Vec<_>>()
            .join(", ");
        match (org.is_empty(), cn.is_empty()) {
            (false, false) if org != cn => format!("{org} · {cn}"),
            (false, _) => org,
            (_, false) => cn,
            _ => name.to_string(),
        }
    };
    let names = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|extension| {
            extension
                .value
                .general_names
                .iter()
                .filter_map(|name| {
                    if let GeneralName::DNSName(name) = name {
                        Some(*name)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let names = clean(&names);
    let mut subject = display_name(cert.subject());
    if subject.is_empty() {
        subject = if names.is_empty() {
            "Not stated".into()
        } else {
            names.clone()
        };
    }
    let subject = clean(&subject);
    let issuer = clean(&display_name(cert.issuer()));
    let issuer = if issuer.is_empty() {
        "Not stated".into()
    } else {
        issuer
    };
    let detail = format!(
        "Issued to: {subject}\nSigned by: {issuer}\nSubject: {}\nIssuer: {}\nDNS names: {}\nValid from: {}\nValid until: {}\nIdentity fields come from the connected server's certificate. A domain certificate does not establish the owner's legal identity or site trust.",
        clean(&cert.subject().to_string()),
        clean(&cert.issuer().to_string()),
        if names.is_empty() {
            "Not stated"
        } else {
            &names
        },
        cert.validity().not_before,
        cert.validity().not_after
    );
    Ok(CertificateInfo {
        subject,
        issuer,
        detail,
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validity_is_exposed_as_unix_seconds() {
        let cert = certificate_info(include_bytes!("../tests/fixtures/certificate.der")).unwrap();
        assert!(cert.not_before > 0 && cert.not_after > cert.not_before);
    }
    #[test]
    fn certificate_identity_does_not_emit_bidi_overrides() {
        // Alter UTF-8 name values without changing DER lengths. Parsing identity
        // does not verify signatures; the transport performs trust validation.
        let mut der = include_bytes!("../tests/fixtures/certificate.der").to_vec();
        let mut replacements = 0;
        for start in 0..der.len() - 3 {
            if &der[start..start + 3] == b"Exa" {
                der[start..start + 3].copy_from_slice("\u{202e}".as_bytes());
                replacements += 1;
            }
        }
        assert!(replacements >= 2);
        let cert = certificate_info(&der).unwrap();
        assert!(cert.subject.contains("mple Service"));
        assert!(cert.issuer.contains("mple Issuer"));
        for field in [&cert.subject, &cert.issuer, &cert.detail] {
            assert!(!field.contains('\u{202e}'));
        }
    }
}
