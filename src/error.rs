use core::fmt::Debug;
use std::collections::BTreeSet;

use crate::{Ballot, Generation, Reconfig, SignedVote};
use blsttc::PublicKeyShare;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("We experienced an IO error")]
    IO(#[from] std::io::Error),
    #[error("The operation requested assumes we have at least one member")]
    NoMembers,
    #[error("Vote has an invalid signature")]
    InvalidSignature,
    #[error("Packet was not destined for this actor: {dest:?} != {actor:?}")]
    WrongDestination {
        dest: PublicKeyShare,
        actor: PublicKeyShare,
    },
    #[error(
        "We can not accept any new join requests, network member size is at capacity: {members:?}"
    )]
    MembersAtCapacity { members: BTreeSet<PublicKeyShare> },
    #[error(
        "An existing member `{requester:?}` can not request to join again. (members: {members:?})"
    )]
    JoinRequestForExistingMember {
        requester: PublicKeyShare,
        members: BTreeSet<PublicKeyShare>,
    },
    #[error("You must be a member to request to leave ({requester:?} not in {members:?})")]
    LeaveRequestForNonMember {
        requester: PublicKeyShare,
        members: BTreeSet<PublicKeyShare>,
    },
    #[error("A vote is always for the next generation: vote gen {vote_gen} != {gen} + 1, pending gen: {pending_gen}")]
    VoteNotForNextGeneration {
        vote_gen: Generation,
        gen: Generation,
        pending_gen: Generation,
    },
    #[error("Vote from non member ({voter:?} not in {members:?})")]
    VoteFromNonMember {
        voter: PublicKeyShare,
        members: BTreeSet<PublicKeyShare>,
    },
    #[error("Voter changed their mind: {reconfigs:?}")]
    VoterChangedMind {
        reconfigs: BTreeSet<(PublicKeyShare, Reconfig)>,
    },
    #[error("Existing vote {existing_vote:?} not compatible with new vote")]
    ExistingVoteIncompatibleWithNewVote { existing_vote: SignedVote },
    #[error("The super majority ballot does not actually have supermajority: {ballot:?} (members: {members:?})")]
    SuperMajorityBallotIsNotSuperMajority {
        ballot: Ballot,
        members: BTreeSet<PublicKeyShare>,
    },
    #[error("Invalid generation {0}")]
    InvalidGeneration(Generation),
    #[error("History contains an invalid vote {0:?}")]
    InvalidVoteInHistory(SignedVote),
    #[error("Encoding Error: {0}")]
    Encoding(#[from] bincode::Error),
    #[error("SignatureError: {0}")]
    Signature(#[from] blsttc::error::Error),
}
