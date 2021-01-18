use ed25519::{Digest, Keypair, PublicKey, Sha512, Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};

use rand::rngs::OsRng;
use std::cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd};
use std::convert::TryInto;
use std::fmt;
use std::hash::{Hash, Hasher};

const CONTEXT: &[u8] = b"BRBEd25519DalekSignerPrehashedContext";

#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct Actor(pub PublicKey);

impl Default for Actor {
    fn default() -> Self {
        use crate::SigningActor as SigningActorTrait;
        SigningActor::default().actor()
    }
}

impl Verifier<Sig> for Actor {
    fn verify(&self, msg: &[u8], signature: &Sig) -> Result<(), signature::Error> {
        let mut prehashed: Sha512 = Sha512::new();
        prehashed.update(msg);
        self.0
            .verify_prehashed(prehashed, Some(CONTEXT), &signature.0)
    }
}

impl Hash for Actor {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bytes().hash(state);
    }
}

impl fmt::Display for Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.0.to_bytes();
        write!(f, "i:{}", hex::encode(&bytes[..3]))
    }
}

impl fmt::Debug for Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

impl Ord for Actor {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.to_bytes().cmp(&other.0.to_bytes())
    }
}

impl PartialOrd for Actor {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Actor {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Actor {}

pub struct SigningActor(pub Keypair);

impl Signer<Sig> for SigningActor {
    fn try_sign(&self, msg: &[u8]) -> Result<Sig, signature::Error> {
        let mut prehashed: Sha512 = Sha512::new();
        prehashed.update(msg);
        let sig: Signature = self.0.sign_prehashed(prehashed, Some(CONTEXT))?;
        Ok(Sig(sig))
    }
}

impl crate::SigningActor<Actor, Sig> for SigningActor {
    fn actor(&self) -> Actor {
        Actor(self.0.public)
    }
}

impl fmt::Display for SigningActor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.0.to_bytes();
        write!(f, "SA:{}", hex::encode(&bytes[..3]))
    }
}

impl fmt::Debug for SigningActor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

impl Default for SigningActor {
    fn default() -> Self {
        Self(Keypair::generate(&mut OsRng))
    }
}

impl PartialEq for SigningActor {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

impl Eq for SigningActor {}

#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct Sig(pub Signature);

impl signature::Signature for Sig {
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        let s = bytes.try_into().map_err(signature::Error::from_source)?;
        let sig = Signature::new(s);
        Ok(Self(sig))
    }
}

impl AsRef<[u8]> for Sig {
    fn as_ref(&self) -> &[u8] {
        &self.0.as_ref()
    }
}

impl Hash for Sig {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bytes().hash(state);
    }
}

impl fmt::Display for Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.0.to_bytes();
        write!(f, "sig:{}", hex::encode(&bytes[..3]))
    }
}

impl fmt::Debug for Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

impl Ord for Sig {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.to_bytes().cmp(&other.0.to_bytes())
    }
}

impl PartialOrd for Sig {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Sig {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Sig {}
