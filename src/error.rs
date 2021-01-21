// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! BRB Membership errors.

use core::fmt::Debug;
use std::collections::BTreeSet;
use thiserror::Error;

use crate::{Ballot, Generation, Reconfig, Vote};

/// BRB Membership errors
#[derive(Error, Debug)]
pub enum Error<A, S>
where
    A: Ord + Debug,
    S: Ord + Debug,
{
    /// We experienced an IO error
    #[error("We experienced an IO error")]
    IO(#[from] std::io::Error),

    /// The operation requested assumes we have at least one member
    #[error("The operation requested assumes we have at least one member")]
    NoMembers,

    /// Vote has an invalid signature
    #[error("Vote has an invalid signature")]
    InvalidSignature(#[from] signature::Error),

    /// Packet was not destined for this actor
    #[error("Packet was not destined for this actor: {dest:?} != {actor:?}")]
    WrongDestination {
        /// destination actor
        dest: A,
        /// source actor
        actor: A,
    },

    /// We can not accept any new join requests, network member size is at capacity
    #[error(
        "We can not accept any new join requests, network member size is at capacity: {members:?}"
    )]
    MembersAtCapacity {
        /// set of voting members
        members: BTreeSet<A>,
    },

    /// An existing member can not request to join again.
    #[error(
        "An existing member `{requester:?}` can not request to join again. (members: {members:?})"
    )]
    JoinRequestForExistingMember {
        /// actor that initiated the join request
        requester: A,
        /// set of voting members
        members: BTreeSet<A>,
    },

    /// You must be a member to request to leave
    #[error("You must be a member to request to leave ({requester:?} not in {members:?})")]
    LeaveRequestForNonMember {
        /// actor that initiated the leave request
        requester: A,
        /// set of voting members
        members: BTreeSet<A>,
    },

    /// A vote is always for the next generation
    #[error("A vote is always for the next generation: vote gen {vote_gen} != {gen} + 1")]
    VoteNotForNextGeneration {
        /// voting generation
        vote_gen: Generation,
        /// present generation
        gen: Generation,
        /// pending generation
        pending_gen: Generation,
    },

    /// Vote from non member
    #[error("Vote from non member ({voter:?} not in {members:?})")]
    VoteFromNonMember {
        /// actor that sent vote
        voter: A,
        /// set of voting actors
        members: BTreeSet<A>,
    },

    /// Voter changed their mind
    #[error("Voter changed their mind: {reconfigs:?}")]
    VoterChangedMind {
        /// set of (Actor, Reconfig) tuples
        reconfigs: BTreeSet<(A, Reconfig<A>)>,
    },

    /// Existing vote not compatible with new vote
    #[error("Existing vote {existing_vote:?} not compatible with new vote")]
    ExistingVoteIncompatibleWithNewVote {
        /// the existing vote
        existing_vote: Vote<A, S>,
    },

    /// The super majority ballot does not actually have supermajority
    #[error("The super majority ballot does not actually have supermajority: {ballot:?} (members: {members:?})")]
    SuperMajorityBallotIsNotSuperMajority {
        /// supermajority ballot
        ballot: Ballot<A, S>,
        /// members that voted/approved the ballot
        members: BTreeSet<A>,
    },

    /// Invalid generation
    #[error("Invalid generation {0}")]
    InvalidGeneration(Generation),

    /// History contains an invalid vote
    #[error("History contains an invalid vote {0:?}")]
    InvalidVoteInHistory(Vote<A, S>),

    /// Failed to encode with bincode
    #[error("Failed to encode with bincode")]
    Encoding(#[from] bincode::Error),

    /// Other error
    #[error("{0}")]
    Other(String),
}

impl<A: Ord + Debug, S: Ord + Debug> From<String> for Error<A, S> {
    fn from(v: String) -> Self {
        Error::Other(v)
    }
}

impl<A: Ord + Debug, S: Ord + Debug> From<&'static str> for Error<A, S> {
    fn from(v: &'static str) -> Self {
        v.to_string().into()
    }
}
