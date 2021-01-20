use core::fmt::Debug;
use std::collections::BTreeSet;
use thiserror::Error;

use crate::{Ballot, Generation, Reconfig, Vote};

#[derive(Error, Debug)]
pub enum Error<A, S>
where
    A: Ord + Debug,
    S: Ord + Debug,
{
    #[error("We experienced an IO error")]
    IO(#[from] std::io::Error),
    #[error("The operation requested assumes we have at least one member")]
    NoMembers,
    #[error("Vote has an invalid signature")]
    InvalidSignature(#[from] signature::Error),
    #[error("Packet was not destined for this actor: {dest:?} != {actor:?}")]
    WrongDestination { dest: A, actor: A },
    #[error(
        "We can not accept any new join requests, network member size is at capacity: {members:?}"
    )]
    MembersAtCapacity { members: BTreeSet<A> },
    #[error(
        "An existing member `{requester:?}` can not request to join again. (members: {members:?})"
    )]
    JoinRequestForExistingMember { requester: A, members: BTreeSet<A> },
    #[error("You must be a member to request to leave ({requester:?} not in {members:?})")]
    LeaveRequestForNonMember { requester: A, members: BTreeSet<A> },
    #[error("A vote is always for the next generation: vote gen {vote_gen} != {gen} + 1")]
    VoteNotForNextGeneration {
        vote_gen: Generation,
        gen: Generation,
        pending_gen: Generation,
    },
    #[error("Vote from non member ({voter:?} not in {members:?})")]
    VoteFromNonMember { voter: A, members: BTreeSet<A> },
    #[error("Voter changed their mind: {reconfigs:?}")]
    VoterChangedMind {
        reconfigs: BTreeSet<(A, Reconfig<A>)>,
    },
    #[error("Existing vote {existing_vote:?} not compatible with new vote")]
    ExistingVoteIncompatibleWithNewVote { existing_vote: Vote<A, S> },
    #[error("The super majority ballot does not actually have supermajority: {ballot:?} (members: {members:?})")]
    SuperMajorityBallotIsNotSuperMajority {
        ballot: Ballot<A, S>,
        members: BTreeSet<A>,
    },
    #[error("Invalid generation {0}")]
    InvalidGeneration(Generation),
    #[error("History contains an invalid vote {0:?}")]
    InvalidVoteInHistory(Vote<A, S>),
    #[error("Failed to encode with bincode")]
    Encoding(#[from] bincode::Error),

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
