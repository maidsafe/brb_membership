use ed25519::{Keypair, PublicKey, Signature, Signer, Verifier, Sha512, Digest};
use serde::{Deserialize, Serialize};

use std::convert::TryInto;
use std::hash::{Hash, Hasher};
use std::fmt;
use std::cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd};
use rand::rngs::OsRng;

#[derive(Clone, Copy, Serialize, Deserialize, Debug, Default)]
pub struct Actor(pub PublicKey);

impl Verifier<Sig> for Actor {
    fn verify(&self, msg: &[u8], signature: &Sig) -> Result<(), signature::Error> {
        self.0.verify_strict(msg, &signature.0)
    }
}

impl Hash for Actor {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bytes().hash(state);
    }
}

impl fmt::Display for Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({:?})", self.0)
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



#[derive(Debug)]
pub struct SigningActor(pub Keypair);

impl Signer<Sig> for SigningActor {

    fn try_sign(&self, msg: &[u8]) -> Result<Sig, signature::Error> {
        let mut prehashed: Sha512 = Sha512::new();
        prehashed.update(msg);
        let context: &[u8] = b"BRBEd25519DalekSignerPrehashedContext";
        let sig: Signature = self.0.sign_prehashed(prehashed, Some(context))?;
        Ok(Sig(sig))
    }

}

impl fmt::Display for SigningActor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({:?})", self.0)
    }
}

impl Default for SigningActor {
    fn default() -> Self {
        let mut csprng = OsRng{};
        Self(Keypair::generate(&mut csprng))
    }
}

/*
impl AsRef<Actor> for SigningActor {
    fn as_ref(&self) -> &Actor {
		&Actor(self.0.public)
    }
}
*/


#[derive(Clone, Copy, Serialize, Deserialize, Debug)]
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
        write!(f, "({:?})", self.0)
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
