use blsttc::{serde_impl::SerdeSecret, SecretKeyShare};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid Signature")]
    InvalidSignature,
    #[error("Blsttc error: {0}")]
    Blsttc(#[from] blsttc::error::FromBytesError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey(blsttc::PublicKeyShare);

impl PublicKey {
    pub fn random(rng: impl Rng + CryptoRng) -> Self {
        SecretKey::random(rng).public_key()
    }

    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        if self.0.verify(&signature.0, msg) {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    pub fn public_key(&self) -> Result<blsttc::PublicKey, Error> {
        let pk = blsttc::PublicKey::from_bytes(self.0.to_bytes())?;
        Ok(pk)
    }
}

impl core::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let bytes = self.0.to_bytes();
        write!(f, "i:{}", hex::encode(&bytes[..3]))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretKey(SerdeSecret<SecretKeyShare>);

impl SecretKey {
    pub fn from(secret_key_share: SecretKeyShare) -> Self {
        Self(SerdeSecret(secret_key_share))
    }

    pub fn random(mut rng: impl Rng + CryptoRng) -> Self {
        Self(SerdeSecret(rng.gen()))
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0 .0.public_key_share())
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(self.0.sign(msg))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature(blsttc::SignatureShare);

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
