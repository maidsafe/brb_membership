use std::hash::Hash;
use core::fmt::{Display, Debug};

pub mod ed25519;

use signature::{Signature, Signer, Verifier};
use serde::Serialize;

pub trait Actor<S: Signature>: Eq + Clone + Copy + Serialize + Verifier<S> + Default + Hash + Ord + Display + Debug {
}

// any T with all these trait bounds is an actor.
impl<T, S: Signature> Actor<S> for T where
T: Eq + Clone + Copy + Serialize + Verifier<S> + Default + Hash + Ord + Display + Debug
{
}

pub trait SigningActor<S: Signature>: Signer<S> + Default + Display + Debug {
}

impl<T, S: Signature> SigningActor<S> for T where
T: Signer<S> + Default + Display + Debug
{
}

pub trait Sig: Signature + Display + Clone + Debug + Eq + Ord + Hash + Serialize {
}

impl<T> Sig for T where
T: Signature + Display + Debug + Clone + Eq + Ord + Hash + Serialize
{
}
