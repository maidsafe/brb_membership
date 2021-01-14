use ed25519::{Keypair, PublicKey, Signature, Signer, Verifier, Sha512, Digest};
use serde::{Deserialize, Serialize};

// use crate::{Actor, SigningActor, Sig};
use std::convert::TryInto;
use std::hash::{Hash, Hasher};
use std::fmt;
use std::cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd};
use rand::rngs::OsRng;

#[derive(Clone, Copy, Serialize, Deserialize, Debug, Default)]
pub struct Ed25519Actor(pub PublicKey);

impl Verifier<Ed25519Sig> for Ed25519Actor {
    fn verify(&self, msg: &[u8], signature: &Ed25519Sig) -> Result<(), signature::Error> {
        self.0.verify_strict(msg, &signature.0)
    }
}

// impl Actor<Ed25519Sig> for Ed25519Actor {}

impl Hash for Ed25519Actor {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bytes().hash(state);
    }
}

impl fmt::Display for Ed25519Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({:?})", self.0)
    }
}

impl Ord for Ed25519Actor {
    /// compares this Clock with another.
    /// if counters are unequal, returns -1 or 1 accordingly.
    /// if counters are equal, returns -1, 0, or 1 based on actor_id.
    ///    (this is arbitrary, but deterministic.)
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.to_bytes().cmp(&other.0.to_bytes())
    }
}

impl PartialOrd for Ed25519Actor {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Ed25519Actor {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Ed25519Actor {}




#[derive(Debug)]
pub struct Ed25519SigningActor(pub Keypair);

impl Signer<Ed25519Sig> for Ed25519SigningActor {

    fn try_sign(&self, msg: &[u8]) -> Result<Ed25519Sig, signature::Error> {
        let mut prehashed: Sha512 = Sha512::new();
        prehashed.update(msg);
        let context: &[u8] = b"BRBEd25519DalekSignerPrehashedContext";
        let sig: Signature = self.0.sign_prehashed(prehashed, Some(context))?;
        Ok(Ed25519Sig(sig))
    }

}

impl fmt::Display for Ed25519SigningActor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({:?})", self.0)
    }
}

impl Default for Ed25519SigningActor {
    fn default() -> Self {
        let mut csprng = OsRng{};
        Self(Keypair::generate(&mut csprng))
    }
}



#[derive(Clone, Copy, Serialize, Deserialize, Debug)]
pub struct Ed25519Sig(pub Signature);

impl signature::Signature for Ed25519Sig {
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        // FIXME: pop() panics.
        let sig = Signature::new(pop(bytes));
        Ok(Self(sig))
    }
}

impl AsRef<[u8]> for Ed25519Sig {
    fn as_ref(&self) -> &[u8] {
		&self.0.as_ref()
    }
}

fn pop(barry: &[u8]) -> [u8; 64] {
    // FIXME: panics.
    barry.try_into().expect("slice with incorrect length")
}

impl Hash for Ed25519Sig {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bytes().hash(state);
    }
}

impl fmt::Display for Ed25519Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({:?})", self.0)
    }
}

impl Ord for Ed25519Sig {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.to_bytes().cmp(&other.0.to_bytes())
    }
}

impl PartialOrd for Ed25519Sig {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Ed25519Sig {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Ed25519Sig {}
