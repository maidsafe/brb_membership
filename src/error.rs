// Copyright (c) 2022, MaidSafe.
// All rights reserved.
//
// This SAFE Network Software is licensed under the BSD-3-Clause license.
// Please see the LICENSE file for more details.
use core::fmt::Debug;
use std::collections::BTreeSet;
use thiserror::Error;

use crate::{Ballot, Generation, PublicKey, Reconfig, SignedVote};

#[derive(Error, Debug)]
pub enum Error {
    #[error("We experienced an IO error")]
    IO(#[from] std::io::Error),
    #[error("The operation requested assumes we have at least one member")]
    NoMembers,
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
    #[error("A merged vote must be from the same generation as the child vote: {child_gen} != {merge_gen}")]
    MergedVotesMustBeFromSameGen {
        child_gen: Generation,
        merge_gen: Generation,
    },
    #[error("A vote is always for the next generation: vote gen {vote_gen} != {gen} + 1, pending gen: {pending_gen}")]
    VoteNotForNextGeneration {
        vote_gen: Generation,
        gen: Generation,
        pending_gen: Generation,
    },
    #[error("({public_key} is not in {members:?})")]
    NonMember {
        public_key: PublicKey,
        members: BTreeSet<PublicKey>,
    },
    #[error("Voter changed their mind: {reconfigs:?}")]
    VoterChangedMind {
        reconfigs: BTreeSet<(PublicKey, Reconfig)>,
    },
    #[error("Existing vote {existing_vote:?} not compatible with new vote")]
    ExistingVoteIncompatibleWithNewVote { existing_vote: SignedVote },
    #[error("The super majority ballot does not actually have supermajority: {ballot:?} (members: {members:?})")]
    SuperMajorityBallotIsNotSuperMajority {
        ballot: Ballot,
        members: BTreeSet<PublicKey>,
    },
    #[error("Invalid generation {0}")]
    InvalidGeneration(Generation),
    #[error("History contains an invalid vote {0:?}")]
    InvalidVoteInHistory(SignedVote),
    #[error("Failed to encode with bincode")]
    Encoding(#[from] bincode::Error),

    #[cfg(feature = "ed25519")]
    #[error("Ed25519 Error {0}")]
    Ed25519(#[from] crate::ed25519::Error),

    #[cfg(feature = "blsttc")]
    #[error("Blsttc Error {0}")]
    Blsttc(#[from] crate::blsttc::Error),

    #[cfg(feature = "bad_crypto")]
    #[error("Failed Signature Verification")]
    BadCrypto(#[from] crate::bad_crypto::Error),
}
