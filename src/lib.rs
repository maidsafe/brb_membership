// #![deny(missing_docs)]

pub mod brb_membership;
pub use crate::brb_membership::{
    Ballot, Generation, Reconfig, SignedVote, State, Vote, VotePacket,
};

pub mod error;
pub use crate::error::Error;
pub type Result<T> = core::result::Result<T, Error>;
