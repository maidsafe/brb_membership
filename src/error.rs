use core::fmt::Debug;
use std::collections::BTreeSet;
use thiserror::Error;

use crate::{Ballot, Generation, PublicKey, Reconfig, Vote};

#[derive(Error, Debug)]
pub enum Error {
    #[error("We experienced an IO error")]
    IO(#[from] std::io::Error),
    #[error("The operation requested assumes we have at least one member")]
    NoMembers,
    #[error("Vote has an invalid signature")]
    InvalidSignature(#[from] signature::Error),
    #[error("Packet was not destined for this actor: {dest:?} != {actor:?}")]
    WrongDestination { dest: PublicKey, actor: PublicKey },
    #[error(
        "We can not accept any new join requests, network member size is at capacity: {members:?}"
    )]
    MembersAtCapacity { members: BTreeSet<PublicKey> },
    #[error(
        "An existing member `{requester:?}` can not request to join again. (members: {members:?})"
    )]
    JoinRequestForExistingMember {
        requester: PublicKey,
        members: BTreeSet<PublicKey>,
    },
    #[error("You must be a member to request to leave ({requester:?} not in {members:?})")]
    LeaveRequestForNonMember {
        requester: PublicKey,
        members: BTreeSet<PublicKey>,
    },
    #[error("A vote is always for the next generation: vote gen {vote_gen} != {gen} + 1, pending gen: {pending_gen}")]
    VoteNotForNextGeneration {
        vote_gen: Generation,
        gen: Generation,
        pending_gen: Generation,
    },
    #[error("Vote from non member ({voter:?} not in {members:?})")]
    VoteFromNonMember {
        voter: PublicKey,
        members: BTreeSet<PublicKey>,
    },
    #[error("Voter changed their mind: {reconfigs:?}")]
    VoterChangedMind {
        reconfigs: BTreeSet<(PublicKey, Reconfig)>,
    },
    #[error("Existing vote {existing_vote:?} not compatible with new vote")]
    ExistingVoteIncompatibleWithNewVote { existing_vote: Vote },
    #[error("The super majority ballot does not actually have supermajority: {ballot:?} (members: {members:?})")]
    SuperMajorityBallotIsNotSuperMajority {
        ballot: Ballot,
        members: BTreeSet<PublicKey>,
    },
    #[error("Invalid generation {0}")]
    InvalidGeneration(Generation),
    #[error("History contains an invalid vote {0:?}")]
    InvalidVoteInHistory(Vote),
    #[error("Failed to encode with bincode")]
    Encoding(#[from] bincode::Error),
}
