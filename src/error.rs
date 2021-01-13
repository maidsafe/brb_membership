use std::collections::BTreeSet;
use thiserror::Error;

use crate::{Actor, Ballot, Generation, Reconfig, Vote};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Vote has an invalid signature")]
    InvalidSignature,
    #[error("Packet was not destined for this actor: {dest} != {actor}")]
    WrongDestination { dest: Actor, actor: Actor },
    #[error(
        "We can not accept any new join requests, network member size is at capacity: {members:?}"
    )]
    MembersAtCapacity { members: BTreeSet<Actor> },
    #[error(
        "An existing member `{requester}` can not request to join again. (members: {members:?})"
    )]
    JoinRequestForExistingMember {
        requester: Actor,
        members: BTreeSet<Actor>,
    },
    #[error("You must be a member to request to leave ({requester} not in {members:?})")]
    LeaveRequestForNonMember {
        requester: Actor,
        members: BTreeSet<Actor>,
    },
    #[error("A vote is always for the next generation: vote gen {vote_gen} != {gen} + 1")]
    VoteNotForNextGeneration {
        vote_gen: Generation,
        gen: Generation,
        pending_gen: Generation,
    },
    #[error("Vote from non member ({voter} not in {members:?})")]
    VoteFromNonMember {
        voter: Actor,
        members: BTreeSet<Actor>,
    },
    #[error("Voter changed their mind: {reconfigs:?}")]
    VoterChangedMind {
        reconfigs: BTreeSet<(Actor, Reconfig)>,
    },
    #[error("Existing vote {existing_vote:?} not compatible with new vote")]
    ExistingVoteIncompatibleWithNewVote { existing_vote: Vote },
    #[error("The super majority ballot does not actually have supermajority: {ballot:?} (members: {members:?})")]
    SuperMajorityBallotIsNotSuperMajority {
        ballot: Ballot,
        members: BTreeSet<Actor>,
    },
    #[error("Invalid generation {0}")]
    InvalidGeneration(Generation),
    #[error("History contains an invalid vote {0:?}")]
    InvalidVoteInHistory(Vote),
    #[error("Failed to encode with bincode")]
    Encoding(#[from] bincode::Error),
}
