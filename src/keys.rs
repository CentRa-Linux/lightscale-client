use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

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
