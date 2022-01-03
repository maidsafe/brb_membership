/**
 * This module provides a *broken* "asymmetric" crypto module that is used to
 * mock out real crypto implementation for tests.
 *
 * Don't use this in production.
 */
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed Verification")]
    FailedVerification,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PublicKey(u64);

impl PublicKey {
    pub fn random(rng: impl Rng + CryptoRng) -> Self {
        SecretKey::random(rng).public_key()
    }

    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        let mut hasher = DefaultHasher::new();

        self.0.hash(&mut hasher);
        msg.hash(&mut hasher);

        if hasher.finish() == signature.0 {
            Ok(())
        } else {
            Err(Error::FailedVerification)
        }
    }
}

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(self, f)
    }
}

impl core::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let bytes = self.0.to_le_bytes();
        write!(f, "i:{}", hex::encode(&bytes[..3]))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretKey(u64);

impl SecretKey {
    pub fn random(mut rng: impl Rng + CryptoRng) -> Self {
        Self(rng.gen())
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0)
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        let mut hasher = DefaultHasher::new();

        self.0.hash(&mut hasher);
        msg.hash(&mut hasher);

        Signature(hasher.finish())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Signature(u64);
