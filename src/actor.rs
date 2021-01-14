use std::hash::Hash;
use core::fmt::{Display, Debug};

// use ed25519::{Keypair, PublicKey, Signature, Signer, Verifier};
use signature::{Signature, Signer, Verifier};
use serde::Serialize;

pub trait Actor<S: Signature>: Eq + Clone + Copy + Serialize + Verifier<S> + Default + Hash + Ord + Display + Debug {
}

// any T with all these trait bounds is an actor.
impl<T, S: Signature> Actor<S> for T where
T: Eq + Clone + Copy + Serialize + Verifier<S> + Default + Hash + Ord + Display + Debug
{
}

// (pub PublicKey);

/*    
    pub fn verify(&self, blob: impl Serialize, sig: &Sig) -> Result<bool, bincode::Error> {
        let blob_bytes = bincode::serialize(&blob)?;
        Ok(self.0.verify(&blob_bytes, &sig.0).is_ok())
    }
*/    

pub trait SigningActor<S: Signature>: Actor<S> + Signer<S> + Default + Display + Debug {
//    fn actor(&self) -> Actor;
}

impl<T, S: Signature> SigningActor<S> for T where
T: Actor<S> + Signer<S> + Default + Display + Debug
{
}

pub trait Sig: Signature + Display + Clone + Debug + Eq + Ord + Hash + Serialize {
}

impl<T> Sig for T where
T: Signature + Display + Debug + Clone + Eq + Ord + Hash + Serialize
{
}
