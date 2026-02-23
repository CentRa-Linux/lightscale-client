use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::path::Path;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub private_key: String,
    pub public_key: String,
}

pub fn generate_machine_keys() -> KeyPair {
    let signing = SigningKey::generate(&mut OsRng);
    let verifying = signing.verifying_key();
    KeyPair {
        private_key: STANDARD.encode(signing.to_bytes()),
        public_key: STANDARD.encode(verifying.to_bytes()),
    }
}

pub fn generate_wg_keys() -> KeyPair {
    let secret = StaticSecret::random_from_rng(&mut OsRng);
    let public = PublicKey::from(&secret);
    KeyPair {
        private_key: STANDARD.encode(secret.to_bytes()),
        public_key: STANDARD.encode(public.to_bytes()),
    }
}

pub fn machine_keys_from_private_base64(private_key: &str) -> Result<KeyPair> {
    let bytes = decode_private_key(private_key, "machine", 32)?;
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&bytes);
    let signing = SigningKey::from_bytes(&secret);
    let verifying = signing.verifying_key();
    Ok(KeyPair {
        private_key: STANDARD.encode(secret),
        public_key: STANDARD.encode(verifying.to_bytes()),
    })
}

pub fn wg_keys_from_private_base64(private_key: &str) -> Result<KeyPair> {
    let bytes = decode_private_key(private_key, "wireguard", 32)?;
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&bytes);
    let secret = StaticSecret::from(secret);
    let public = PublicKey::from(&secret);
    Ok(KeyPair {
        private_key: STANDARD.encode(secret.to_bytes()),
        public_key: STANDARD.encode(public.to_bytes()),
    })
}

pub fn read_private_key_file(path: &Path) -> Result<String> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read key file {}", path.display()))?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("key file {} is empty", path.display()));
    }
    Ok(trimmed.to_string())
}

fn decode_private_key(encoded: &str, kind: &str, expected_len: usize) -> Result<Vec<u8>> {
    let bytes = STANDARD
        .decode(encoded.trim())
        .with_context(|| format!("invalid {} private key: not base64", kind))?;
    if bytes.len() != expected_len {
        return Err(anyhow!(
            "invalid {} private key: expected {} bytes, got {} bytes",
            kind,
            expected_len,
            bytes.len()
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_private_key_derives_public_key() {
        let private = STANDARD.encode([7u8; 32]);
        let pair = machine_keys_from_private_base64(&private).expect("machine key parse");
        assert_eq!(pair.private_key, private);
        assert!(!pair.public_key.is_empty());
    }

    #[test]
    fn wg_private_key_derives_public_key() {
        let private = STANDARD.encode([9u8; 32]);
        let pair = wg_keys_from_private_base64(&private).expect("wg key parse");
        assert_eq!(pair.private_key, private);
        assert!(!pair.public_key.is_empty());
    }

    #[test]
    fn machine_private_key_rejects_invalid_len() {
        let private = STANDARD.encode([1u8; 16]);
        let err = machine_keys_from_private_base64(&private).unwrap_err();
        assert!(err.to_string().contains("expected 32 bytes"));
    }
}
