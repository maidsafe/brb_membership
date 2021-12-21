// #![deny(missing_docs)]
#[cfg(any(
    all(feature = "ed25519", feature = "blsttc"),
    not(any(feature = "ed25519", feature = "blsttc"))
))]
compile_error!("Must enable either `ed25519` or `blsttc` feature flags");

pub mod brb_membership;

#[cfg(feature = "blsttc")]
pub mod blsttc;
#[cfg(feature = "ed25519")]
pub mod ed25519;

pub use crate::brb_membership::{Ballot, Generation, Reconfig, State, Vote, VoteMsg};

#[cfg(feature = "blsttc")]
pub use crate::blsttc::{PublicKey, SecretKey, Signature};
#[cfg(feature = "ed25519")]
pub use crate::ed25519::{PublicKey, SecretKey, Signature};

pub mod error;
pub use crate::error::Error;
