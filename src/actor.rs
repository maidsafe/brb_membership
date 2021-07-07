// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! An Actor is an identifiable entity that may initiate actions in the system.
//!
//! An Actor will typically be a PublicKey and a SigningActor will be a keypair.
//!
//! The actor types in this module are kept generic as traits so that different
//! cryptographic algorithms or libraries may be used.
//!
//! We utilize the Signature, Signer, and Verifier traits from the signature crate.
//! Any code that implements the required traits can be a signing actor, which means
//! that external signing devices can be cleanly supported.

use core::fmt::{Debug, Display};
use std::hash::Hash;

pub mod ed25519;

use serde::Serialize;
use signature::{Signature, Signer, Verifier};

/// An Actor is an identifiable entity that may initiate actions in the system.
pub trait Actor<S: Signature>:
    Eq + Clone + Copy + Serialize + Verifier<S> + Default + Hash + Ord + Display + Debug
{
}

// any T with all these trait bounds is an actor.
impl<T, S: Signature> Actor<S> for T where
    T: Eq + Clone + Copy + Serialize + Verifier<S> + Default + Hash + Ord + Display + Debug
{
}

/// A SigningActor is an Actor that can sign messages.
pub trait SigningActor<A, S: Signature>: Signer<S> + Default + Display + Debug + Eq {
    /// returns the Actor associated with this SigningActor
    fn actor(&self) -> A;
}

/// A Sig is a message signature created by a SigningActor
pub trait Sig: Signature + Display + Clone + Debug + Eq + Ord + Hash + Serialize {}

impl<T> Sig for T where T: Signature + Display + Debug + Clone + Eq + Ord + Hash + Serialize {}
