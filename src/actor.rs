use core::fmt::{Debug, Display};
use std::hash::Hash;

pub mod ed25519;

use serde::Serialize;
use signature::{Signature, Signer, Verifier};

pub trait Actor<S: Signature>:
    Eq + Clone + Copy + Serialize + Verifier<S> + Default + Hash + Ord + Display + Debug
{
}

// any T with all these trait bounds is an actor.
impl<T, S: Signature> Actor<S> for T where
    T: Eq + Clone + Copy + Serialize + Verifier<S> + Default + Hash + Ord + Display + Debug
{
}

pub trait SigningActor<A, S: Signature>: Signer<S> + Default + Display + Debug + Eq {
    fn actor(&self) -> A;
}

pub trait Sig: Signature + Display + Clone + Debug + Eq + Ord + Hash + Serialize {}

impl<T> Sig for T where T: Signature + Display + Debug + Clone + Eq + Ord + Hash + Serialize {}
