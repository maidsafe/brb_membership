// #![deny(missing_docs)]

pub mod brb_membership;
pub use crate::brb_membership::{State, Vote, Reconfig, Ballot, VoteMsg, Generation, Error}; 

pub mod actor;
pub use actor::{Actor, Sig, SigningActor};
