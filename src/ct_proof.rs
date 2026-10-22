//! Opt-in RFC 6962 inclusion proofs. No networking; both platform adapters use this verifier.
use crate::{
    Result,
    ct_logs::{Log, current},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::{digest, signature};
use serde_json::{Value, json};
use url::Url;
use x509_parser::prelude::*;
pub const MAX_RESPONSE: usize = 64 * 1024;
#[derive(Debug, Clone)]
pub struct Proof {
    id: Vec<u8>,
    leaf: [u8; 32],
    timestamp: u64,
    key: Vec<u8>,
    name: String,
    base: Url,
}
struct Head {
    size: u64,
    root: [u8; 32],
    timestamp: u64,
}
fn hash(data: &[u8]) -> [u8; 32] {
    digest::digest(&digest::SHA256, data)
        .as_ref()
        .try_into()
        .unwrap()
}
fn decoded_hash(value: &Value) -> Result<[u8; 32]> {
    let text = value
        .as_str()
        .filter(|s| s.len() <= 44)
        .ok_or("Missing CT hash.")?;
    STANDARD
        .decode(text)
        .map_err(|_| "Invalid CT hash.")?
        .try_into()
        .map_err(|_| "Invalid CT hash length.".into())
}
fn response(bytes: &[u8]) -> Result<Value> {
    if bytes.len() > MAX_RESPONSE {
        return Err("CT proof response exceeds 64 KiB.".into());
    }
    serde_json::from_slice(bytes).map_err(|_| "Invalid CT proof JSON.".into())
}
impl Proof {
    fn new(log: &Log, leaf: [u8; 32], timestamp: u64) -> Result<Self> {
        let base = log
            .url
            .clone()
            .ok_or("This log uses an unsupported proof protocol.")?;
        if base.scheme() != "https"
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || base.port_or_known_default() != Some(443)
            || !base.path().ends_with('/')
            || !base.host_str().is_some_and(crate::link::public_name)
        {
            return Err("Unsupported CT log endpoint.".into());
        }
        Ok(Self {
            id: log.id.clone(),
            leaf,
            timestamp,
            key: log.key.clone(),
            name: log.name.clone(),
            base,
        })
    }
    pub(crate) fn from_entry(log: &Log, entry: &[u8], timestamp: u64) -> Result<Self> {
        let mut leaf = vec![0]; // Merkle leaf domain separator; entry starts with version/leaf type.
        leaf.extend_from_slice(entry);
        Self::new(log, hash(&leaf), timestamp)
    }
    pub fn data(&self) -> Value {
        json!({"id":STANDARD.encode(&self.id),"leaf":STANDARD.encode(self.leaf),"timestamp":self.timestamp})
    }
    pub fn from_data(value: &Value, path: Option<&std::path::Path>) -> Result<Self> {
        let id = decoded_hash(&value["id"])?;
        let (logs, _) = current(path)?;
        let log = logs
            .logs
            .iter()
            .find(|l| l.id == id)
            .ok_or("CT log is absent from current metadata.")?;
        Self::new(
            log,
            decoded_hash(&value["leaf"])?,
            value["timestamp"].as_u64().ok_or("Missing SCT time.")?,
        )
    }
    pub fn disclosure(&self) -> String {
        format!(
            "Request an inclusion proof from {} ({})? Two HTTPS requests fetch a signed tree head and a proof for this certificate's log-entry hash. The log sees your IP and a hash that can identify the certificate and its hostnames. No URL path, query, cookies or API key are sent. Only this log is checked. Inclusion is not site safety or a consistency audit of the log.",
            self.name,
            self.base.host_str().unwrap_or("unknown")
        )
    }
    pub fn head_url(&self) -> Result<Url> {
        self.base.join("ct/v1/get-sth").map_err(|e| e.to_string())
    }
    fn head(&self, bytes: &[u8], now: i64) -> Result<Head> {
        let value = response(bytes)?;
        let size = value["tree_size"]
            .as_u64()
            .filter(|n| *n > 0)
            .ok_or("Invalid CT tree size.")?;
        let timestamp = value["timestamp"].as_u64().ok_or("Missing CT tree time.")?;
        if timestamp < self.timestamp || timestamp / 1000 > now.max(0) as u64 + 300 {
            return Err("CT tree head predates the SCT or is dated in the future.".into());
        }
        let root = decoded_hash(&value["sha256_root_hash"])?;
        let encoded = value["tree_head_signature"]
            .as_str()
            .filter(|s| s.len() <= 4096)
            .ok_or("Missing CT tree signature.")?;
        let sig = STANDARD
            .decode(encoded)
            .map_err(|_| "Invalid CT tree signature.")?;
        if sig.len() < 4 || usize::from(u16::from_be_bytes([sig[2], sig[3]])) != sig.len() - 4 {
            return Err("Invalid CT signature framing.".into());
        }
        let algorithm: &dyn signature::VerificationAlgorithm = match sig[..2] {
            [4, 3] => &signature::ECDSA_P256_SHA256_ASN1,
            [4, 1] => &signature::RSA_PKCS1_2048_8192_SHA256,
            _ => return Err("Unsupported CT tree signature algorithm.".into()),
        };
        let (_, key) =
            SubjectPublicKeyInfo::from_der(&self.key).map_err(|_| "Invalid CT log key.")?;
        let mut message = vec![0, 1]; // v1, tree_hash
        message.extend_from_slice(&timestamp.to_be_bytes());
        message.extend_from_slice(&size.to_be_bytes());
        message.extend_from_slice(&root);
        signature::UnparsedPublicKey::new(algorithm, key.subject_public_key.data.as_ref())
            .verify(&message, &sig[4..])
            .map_err(|_| "CT tree-head signature did not verify.")?;
        Ok(Head {
            size,
            root,
            timestamp,
        })
    }
    pub fn audit_url(&self, head: &[u8], now: i64) -> Result<Url> {
        let head = self.head(head, now)?;
        let mut url = self
            .base
            .join("ct/v1/get-proof-by-hash")
            .map_err(|e| e.to_string())?;
        url.query_pairs_mut()
            .append_pair("hash", &STANDARD.encode(self.leaf))
            .append_pair("tree_size", &head.size.to_string());
        Ok(url)
    }
    pub fn verify(&self, head: &[u8], audit: &[u8], now: i64) -> Result<String> {
        let head = self.head(head, now)?;
        let value = response(audit)?;
        let index = value["leaf_index"]
            .as_u64()
            .ok_or("Missing CT leaf index.")?;
        let path = value["audit_path"]
            .as_array()
            .filter(|p| p.len() <= 64)
            .ok_or("Invalid or oversized CT audit path.")?;
        let path = path.iter().map(decoded_hash).collect::<Result<Vec<_>>>()?;
        audit_path(self.leaf, index, head.size, &path, head.root)?;
        let date = ::time::OffsetDateTime::from_unix_timestamp((head.timestamp / 1000) as i64)
            .ok()
            .and_then(|date| {
                date.format(&::time::format_description::well_known::Rfc3339)
                    .ok()
            })
            .unwrap_or_else(|| format!("{} ms since Unix epoch", head.timestamp));
        Ok(format!(
            "Inclusion verified · {}\nLeaf {} of {} · signed tree {}.\nThis certificate's log entry is included in this signed tree. No consistency, split-view or browser-policy audit was performed; site trust remains unknown.",
            self.name, index, head.size, date
        ))
    }
}
fn audit_path(
    mut node: [u8; 32],
    mut index: u64,
    size: u64,
    path: &[[u8; 32]],
    root: [u8; 32],
) -> Result<()> {
    if size == 0 || index >= size || path.len() > 64 {
        return Err("Invalid CT leaf position.".into());
    }
    let mut last = size - 1;
    for sibling in path {
        if last == 0 {
            return Err("Extra CT audit nodes.".into());
        }
        let mut bytes = vec![1]; // Merkle interior-node domain separator
        if index & 1 == 1 || index == last {
            bytes.extend_from_slice(sibling);
            bytes.extend_from_slice(&node);
            while index != 0 && index & 1 == 0 {
                index >>= 1;
                last >>= 1;
            }
        } else {
            bytes.extend_from_slice(&node);
            bytes.extend_from_slice(sibling);
        }
        node = hash(&bytes);
        index >>= 1;
        last >>= 1;
    }
    if last != 0 || node != root {
        return Err("CT inclusion proof did not match the signed root.".into());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn tree(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.len() == 1 {
            return leaves[0];
        }
        let split = leaves.len().next_power_of_two() / 2;
        let mut bytes = vec![1];
        bytes.extend(tree(&leaves[..split]));
        bytes.extend(tree(&leaves[split..]));
        hash(&bytes)
    }
    fn path(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
        if leaves.len() == 1 {
            return vec![];
        }
        let split = leaves.len().next_power_of_two() / 2;
        if index < split {
            let mut p = path(&leaves[..split], index);
            p.push(tree(&leaves[split..]));
            p
        } else {
            let mut p = path(&leaves[split..], index - split);
            p.push(tree(&leaves[..split]));
            p
        }
    }
    #[test]
    fn tree_signature_timestamp_and_proof_are_all_required() {
        use ring::{rand::SystemRandom, signature::KeyPair};
        let rng = SystemRandom::new();
        let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rng,
        )
        .unwrap();
        let pair = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();
        // P-256 SPKI header plus the uncompressed EC point.
        let mut key = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0,
        ];
        key.extend_from_slice(pair.public_key().as_ref());
        let leaf = hash(b"\0test leaf");
        let proof = Proof {
            id: hash(&key).to_vec(),
            leaf,
            timestamp: 1000,
            key,
            name: "Fixture".into(),
            base: Url::parse("https://ct.googleapis.com/test/").unwrap(),
        };
        let mut message = vec![0, 1];
        message.extend_from_slice(&2000u64.to_be_bytes());
        message.extend_from_slice(&1u64.to_be_bytes());
        message.extend_from_slice(&leaf);
        let signature = pair.sign(&rng, &message).unwrap();
        let mut wire = vec![4, 3];
        wire.extend_from_slice(&(signature.as_ref().len() as u16).to_be_bytes());
        wire.extend_from_slice(signature.as_ref());
        let head = json!({"tree_size":1,"timestamp":2000,"sha256_root_hash":STANDARD.encode(leaf),"tree_head_signature":STANDARD.encode(wire)});
        let audit = br#"{"leaf_index":0,"audit_path":[]}"#;
        let bytes = serde_json::to_vec(&head).unwrap();
        assert!(proof.verify(&bytes, audit, 3).is_ok());
        assert!(
            proof
                .audit_url(&bytes, 3)
                .unwrap()
                .as_str()
                .contains("tree_size=1")
        );
        for key in [
            "tree_size",
            "timestamp",
            "sha256_root_hash",
            "tree_head_signature",
        ] {
            let mut bad = head.clone();
            bad[key] = json!("tampered");
            assert!(
                proof
                    .verify(&serde_json::to_vec(&bad).unwrap(), audit, 3)
                    .is_err()
            );
        }
        let mut bad_time = proof.clone();
        bad_time.timestamp = 3000;
        assert!(bad_time.verify(&bytes, audit, 3).is_err());
        let mut changed = proof.clone();
        changed.leaf[0] ^= 1;
        assert!(changed.verify(&bytes, audit, 3).is_err());
        assert!(
            proof
                .verify(&bytes, br#"{"leaf_index":1,"audit_path":[]}"#, 3)
                .is_err()
        );
        assert!(proof.verify(&vec![0; MAX_RESPONSE + 1], audit, 3).is_err());
    }

    #[test]
    fn all_positions_in_balanced_and_unbalanced_trees_reject_tampering() {
        for size in 1..80 {
            let leaves: Vec<_> = (0..size).map(|n| hash(&[0, n as u8])).collect();
            for index in 0..size {
                let proof = path(&leaves, index);
                let root = tree(&leaves);
                assert!(audit_path(leaves[index], index as u64, size as u64, &proof, root).is_ok());
                let mut bad = root;
                bad[0] ^= 1;
                assert!(audit_path(leaves[index], index as u64, size as u64, &proof, bad).is_err());
                let mut extra = proof.clone();
                extra.push([0; 32]);
                assert!(
                    audit_path(leaves[index], index as u64, size as u64, &extra, root).is_err()
                );
                if !proof.is_empty() {
                    assert!(
                        audit_path(leaves[index], index as u64, size as u64, &proof[1..], root)
                            .is_err()
                    );
                }
            }
        }
    }
}
