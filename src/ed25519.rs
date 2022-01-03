use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use signature::{Signer, Verifier};

pub type Error = signature::Error;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey(ed25519::PublicKey);

impl PublicKey {
    pub fn random(rng: impl Rng + CryptoRng) -> Self {
        SecretKey::random(rng).public_key()
    }

    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        self.0.verify(msg, &signature.0)
    }
}

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(self, f)
    }
}

impl core::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let bytes = self.0.to_bytes();
        write!(f, "i:{}", hex::encode(&bytes[..3]))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretKey(ed25519::Keypair);

impl SecretKey {
    pub fn random(mut rng: impl Rng + CryptoRng) -> Self {
        Self(ed25519::Keypair::generate(&mut rng))
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public)
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(self.0.sign(msg))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature(ed25519::Signature);

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.to_bytes().cmp(&other.0.to_bytes())
    }
}

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Signature {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.to_bytes().cmp(&other.0.to_bytes())
    }
}
