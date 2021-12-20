use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{Actor, Error, Sig, SigningActor};
use core::fmt::Debug;
use log::info;

const SOFT_MAX_MEMBERS: usize = 7;
pub type Generation = u64;

#[derive(Debug)]
pub struct State<A: Ord, SA, S: Ord> {
    pub id: SA,
    pub gen: Generation,
    pub pending_gen: Generation,
    pub forced_reconfigs: BTreeMap<Generation, BTreeSet<Reconfig<A>>>,
    pub history: BTreeMap<Generation, Vote<A, S>>, // for onboarding new procs, the vote proving super majority
    pub votes: BTreeMap<A, Vote<A, S>>,
    pub faulty: bool,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Reconfig<A> {
    Join(A),
    Leave(A),
}

impl<A: Debug> std::fmt::Debug for Reconfig<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reconfig::Join(a) => write!(f, "J{:?}", a),
            Reconfig::Leave(a) => write!(f, "L{:?}", a),
        }
    }
}

impl<A: Ord> Reconfig<A> {
    fn apply(self, members: &mut BTreeSet<A>) {
        match self {
            Reconfig::Join(p) => members.insert(p),
            Reconfig::Leave(p) => members.remove(&p),
        };
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Ballot<A: Ord, S: Ord> {
    Propose(Reconfig<A>),
    Merge(BTreeSet<Vote<A, S>>),
    SuperMajority(BTreeSet<Vote<A, S>>),
}

impl<A, S> std::fmt::Debug for Ballot<A, S>
where
    A: Ord + Debug,
    S: Ord + Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ballot::Propose(r) => write!(f, "P({:?})", r),
            Ballot::Merge(votes) => write!(f, "M{:?}", votes),
            Ballot::SuperMajority(votes) => write!(f, "SM{:?}", votes),
        }
    }
}

fn simplify_votes<A: Ord + Clone, S: Ord + Clone>(
    votes: &BTreeSet<Vote<A, S>>,
) -> BTreeSet<Vote<A, S>> {
    let mut simpler_votes: BTreeSet<Vote<A, S>> = Default::default();
    for v in votes.iter() {
        let mut this_vote_is_superseded = false;
        for other_v in votes.iter() {
            if other_v != v && other_v.supersedes(v) {
                this_vote_is_superseded = true;
            }
        }

        if !this_vote_is_superseded {
            let v_cloned: Vote<A, S> = v.clone();
            simpler_votes.insert(v_cloned);
        }
    }
    simpler_votes
}

impl<A, S> Ballot<A, S>
where
    A: Ord + Clone,
    S: Ord + Clone,
{
    fn simplify(&self) -> Self {
        match &self {
            Ballot::Propose(_) => self.clone(), // already in simplest form
            Ballot::Merge(votes) => Ballot::Merge(simplify_votes(votes)),
            Ballot::SuperMajority(votes) => Ballot::SuperMajority(simplify_votes(votes)),
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Vote<A: Ord, S: Ord> {
    pub gen: Generation,
    pub ballot: Ballot<A, S>,
    pub voter: A,
    pub sig: S,
}

impl<A, S> Debug for Vote<A, S>
where
    A: Ord + Debug,
    S: Ord + Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}@{:?}G{}", self.ballot, self.voter, self.gen)
    }
}

impl<A, S> Vote<A, S>
where
    A: Ord + Clone,
    S: Ord + Clone,
{
    pub fn is_super_majority_ballot(&self) -> bool {
        matches!(self.ballot, Ballot::SuperMajority(_))
    }

    fn unpack_votes(&self) -> BTreeSet<&Vote<A, S>> {
        match &self.ballot {
            Ballot::Propose(_) => std::iter::once(self).collect(),
            Ballot::Merge(votes) | Ballot::SuperMajority(votes) => std::iter::once(self)
                .chain(votes.iter().flat_map(|v| v.unpack_votes()))
                .collect(),
        }
    }

    fn reconfigs(&self) -> BTreeSet<(A, Reconfig<A>)> {
        match &self.ballot {
            Ballot::Propose(reconfig) => vec![(self.voter.clone(), reconfig.clone())]
                .into_iter()
                .collect(),
            Ballot::Merge(votes) | Ballot::SuperMajority(votes) => {
                votes.iter().flat_map(|v| v.reconfigs()).collect()
            }
        }
    }

    fn supersedes(&self, vote: &Vote<A, S>) -> bool {
        if self == vote {
            true
        } else {
            match &self.ballot {
                Ballot::Propose(_) => false,
                Ballot::Merge(votes) | Ballot::SuperMajority(votes) => {
                    votes.iter().any(|v| v.supersedes(vote))
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoteMsg<A: Ord, S: Ord> {
    pub vote: Vote<A, S>,
    pub dest: A,
}

impl<A, SA, S> Default for State<A, SA, S>
where
    A: Actor<S>,
    SA: SigningActor<A, S>,
    S: Sig,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<A, SA, S> State<A, SA, S>
where
    A: Actor<S>,
    SA: SigningActor<A, S>,
    S: Sig,
{
    pub fn new() -> Self {
        Self {
            id: SA::default(),
            gen: 0,
            pending_gen: 0,
            forced_reconfigs: BTreeMap::default(),
            history: BTreeMap::default(),
            votes: BTreeMap::default(),
            faulty: false,
        }
    }

    pub fn force_join(&mut self, actor: A) {
        let forced_reconfigs = self.forced_reconfigs.entry(self.gen).or_default();

        // remove any leave reconfigs for this actor
        forced_reconfigs.remove(&Reconfig::Leave(actor));
        forced_reconfigs.insert(Reconfig::Join(actor));
    }

    pub fn force_leave(&mut self, actor: A) {
        let forced_reconfigs = self.forced_reconfigs.entry(self.gen).or_default();

        // remove any leave reconfigs for this actor
        forced_reconfigs.remove(&Reconfig::Join(actor));
        forced_reconfigs.insert(Reconfig::Leave(actor));
    }

    pub fn members(&self, gen: Generation) -> Result<BTreeSet<A>, Error<A, S>> {
        let mut members = BTreeSet::new();

        self.forced_reconfigs
            .get(&0) // forced reconfigs at generation 0
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .for_each(|r| r.apply(&mut members));

        if gen == 0 {
            return Ok(members);
        }

        for (history_gen, vote) in self.history.iter() {
            self.forced_reconfigs
                .get(history_gen)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .for_each(|r| r.apply(&mut members));

            let votes = match &vote.ballot {
                Ballot::SuperMajority(votes) => votes,
                _ => {
                    return Err(Error::InvalidVoteInHistory(vote.clone()));
                }
            };

            self.resolve_votes(votes)
                .into_iter()
                .for_each(|r| r.apply(&mut members));

            if history_gen == &gen {
                return Ok(members);
            }
        }

        Err(Error::InvalidGeneration(gen))
    }

    pub fn propose(&mut self, reconfig: Reconfig<A>) -> Result<Vec<VoteMsg<A, S>>, Error<A, S>> {
        let vote = self.build_vote(self.gen + 1, Ballot::Propose(reconfig))?;
        self.validate_vote(&vote)?;
        self.cast_vote(vote)
    }

    pub fn anti_entropy(&self, from_gen: Generation, actor: A) -> Vec<VoteMsg<A, S>> {
        info!(
            "[MBR] anti-entropy for {:?}.{} from {:?}",
            actor, from_gen, self.id
        );

        let mut msgs: Vec<_> = self
            .history
            .iter() // history is a BTreeSet, .iter() is ordered by generation
            .filter(|(gen, _)| **gen > from_gen)
            .map(|(_, membership_proof)| self.send(membership_proof.clone(), actor))
            .collect();

        msgs.extend(self.votes.values().cloned().map(|v| self.send(v, actor)));

        msgs
    }

    pub fn handle_vote(&mut self, vote: Vote<A, S>) -> Result<Vec<VoteMsg<A, S>>, Error<A, S>> {
        self.validate_vote(&vote)?;

        self.log_vote(&vote);
        self.pending_gen = vote.gen;

        if self.is_split_vote(&self.votes.values().cloned().collect())? {
            info!("[MBR] Detected split vote");
            let merge_vote = self.build_vote(
                self.pending_gen,
                Ballot::Merge(self.votes.values().cloned().collect()).simplify(),
            )?;

            if let Some(our_vote) = self.votes.get(&self.id.actor()) {
                let reconfigs_we_voted_for: BTreeSet<_> =
                    our_vote.reconfigs().into_iter().map(|(_, r)| r).collect();
                let reconfigs_we_would_vote_for: BTreeSet<_> =
                    merge_vote.reconfigs().into_iter().map(|(_, r)| r).collect();

                if reconfigs_we_voted_for == reconfigs_we_would_vote_for {
                    info!("[MBR] This vote didn't add new information, waiting for more votes...");
                    return Ok(vec![]);
                }
            }

            info!("[MBR] Either we haven't voted or our previous vote didn't fully overlap, merge them.");
            return self.cast_vote(merge_vote);
        }

        if self.is_super_majority_over_super_majorities(&self.votes.values().cloned().collect())? {
            info!("[MBR] Detected super majority over super majorities");

            // store a proof of what the network decided in our history so that we can onboard future procs.
            let sm_vote = if self.members(self.gen)?.contains(&self.id.actor()) {
                // we were a member during this generation, log the votes we have seen as our history.
                let ballot =
                    Ballot::SuperMajority(self.votes.values().cloned().collect()).simplify();

                let blob_bytes = bincode::serialize(&(&ballot, &self.pending_gen))?;
                Some(Vote {
                    voter: self.id.actor(),
                    sig: self.id.sign(&blob_bytes),
                    gen: self.pending_gen,
                    ballot,
                })
            } else {
                // We were not a member, therefore one of the members had sent us this vote to onboard us or to keep us up to date.
                let should_add_vote_to_history = self.is_super_majority_over_super_majorities(
                    &vote.unpack_votes().into_iter().cloned().collect(),
                )?;
                if should_add_vote_to_history {
                    info!("[MBR] Adding vote to history");
                    Some(vote)
                } else {
                    None
                }
            };

            if let Some(sm_vote) = sm_vote {
                self.history.insert(self.pending_gen, sm_vote);
                // clear our pending votes
                self.votes = Default::default();
                self.gen = self.pending_gen;
            }

            return Ok(vec![]);
        }

        if self.is_super_majority(&self.votes.values().cloned().collect())? {
            info!("[MBR] Detected super majority");

            if let Some(our_vote) = self.votes.get(&self.id.actor()) {
                // We voted during this generation.

                // We may have committed to some reconfigs that is not part of this super majority.
                // This happens when the network was able to form super majority without our vote.
                // We can not change our vote since all we know is that a subset of the network saw
                // super majority. It could still be the case that two disjoint subsets of the network
                // see different super majorities, this case will be resolved by the split vote detection
                // as more messages are delivered.

                let super_majority_reconfigs =
                    self.resolve_votes(&self.votes.values().cloned().collect());

                let we_have_comitted_to_reconfigs_not_in_super_majority = self
                    .resolve_votes(&our_vote.unpack_votes().into_iter().cloned().collect())
                    .into_iter()
                    .any(|r| !super_majority_reconfigs.contains(&r));

                if we_have_comitted_to_reconfigs_not_in_super_majority {
                    info!("[MBR] We have committed to reconfigs that the super majority has not seen, waiting till we either have a split vote or SM/SM");
                    return Ok(vec![]);
                } else if our_vote.is_super_majority_ballot() {
                    info!("[MBR] We've already sent a super majority, waiting till we either have a split vote or SM / SM");
                    return Ok(vec![]);
                }
            }

            info!("[MBR] broadcasting super majority");
            let vote = self.build_vote(
                self.pending_gen,
                Ballot::SuperMajority(self.votes.values().cloned().collect()).simplify(),
            )?;
            return self.cast_vote(vote);
        }

        // We have determined that we don't yet have enough votes to take action.
        // If we have not yet voted, this is where we would contribute our vote
        if !self.votes.contains_key(&self.id.actor()) {
            let vote = self.build_vote(self.pending_gen, vote.ballot)?;
            return self.cast_vote(vote);
        }

        Ok(vec![])
    }

    fn build_vote(&self, gen: Generation, ballot: Ballot<A, S>) -> Result<Vote<A, S>, Error<A, S>> {
        let blob_bytes = bincode::serialize(&(&ballot, &gen))?;
        Ok(Vote {
            voter: self.id.actor(),
            sig: self.id.sign(&blob_bytes),
            ballot,
            gen,
        })
    }

    fn cast_vote(&mut self, vote: Vote<A, S>) -> Result<Vec<VoteMsg<A, S>>, Error<A, S>> {
        self.pending_gen = vote.gen;
        self.log_vote(&vote);
        self.broadcast(vote)
    }

    fn log_vote(&mut self, vote: &Vote<A, S>) {
        for vote in vote.unpack_votes() {
            let existing_vote = self.votes.entry(vote.voter).or_insert_with(|| vote.clone());
            if vote.supersedes(existing_vote) {
                *existing_vote = vote.clone()
            }
        }
    }

    fn count_votes(&self, votes: &BTreeSet<Vote<A, S>>) -> BTreeMap<BTreeSet<Reconfig<A>>, usize> {
        let mut count: BTreeMap<BTreeSet<Reconfig<A>>, usize> = Default::default();

        for vote in votes.iter() {
            let c = count
                .entry(
                    vote.reconfigs()
                        .into_iter()
                        .map(|(_, reconfig)| reconfig)
                        .collect(),
                )
                .or_default();
            *c += 1;
        }

        count
    }

    fn is_split_vote(&self, votes: &BTreeSet<Vote<A, S>>) -> Result<bool, Error<A, S>> {
        let counts = self.count_votes(votes);
        let most_votes = counts.values().max().cloned().unwrap_or_default();
        let members = self.members(self.gen)?;
        let voters = &votes.iter().map(|v| v.voter).collect();
        let remaining_voters = members.difference(voters).count();

        // give the remaining votes to the reconfigs with the most votes.
        let predicted_votes = most_votes + remaining_voters;

        Ok(3 * voters.len() > 2 * members.len() && 3 * predicted_votes <= 2 * members.len())
    }

    fn is_super_majority(&self, votes: &BTreeSet<Vote<A, S>>) -> Result<bool, Error<A, S>> {
        // TODO: super majority should always just be the largest 7 members
        let most_votes = self
            .count_votes(votes)
            .values()
            .max()
            .cloned()
            .unwrap_or_default();
        let n = self.members(self.gen)?.len();

        Ok(3 * most_votes > 2 * n)
    }

    fn is_super_majority_over_super_majorities(
        &self,
        votes: &BTreeSet<Vote<A, S>>,
    ) -> Result<bool, Error<A, S>> {
        let winning_reconfigs = self.resolve_votes(votes);

        let count_of_super_majorities = votes
            .iter()
            .filter(|v| {
                v.reconfigs()
                    .into_iter()
                    .map(|(_, r)| r)
                    .collect::<BTreeSet<_>>()
                    == winning_reconfigs
            })
            .filter(|v| v.is_super_majority_ballot())
            .count();

        Ok(3 * count_of_super_majorities > 2 * self.members(self.gen)?.len())
    }

    fn resolve_votes(&self, votes: &BTreeSet<Vote<A, S>>) -> BTreeSet<Reconfig<A>> {
        let (winning_reconfigs, _) = self
            .count_votes(votes)
            .into_iter()
            .max_by(|a, b| (a.1).cmp(&b.1))
            .unwrap_or_default();

        winning_reconfigs
    }

    pub fn validate_vote(&self, vote: &Vote<A, S>) -> Result<(), Error<A, S>> {
        let members = self.members(self.gen)?;
        let blob_bytes = bincode::serialize(&(&vote.ballot, &vote.gen))?;

        vote.voter.verify(&blob_bytes, &vote.sig)?;

        if vote.gen != self.gen + 1 {
            Err(Error::VoteNotForNextGeneration {
                vote_gen: vote.gen,
                gen: self.gen,
                pending_gen: self.pending_gen,
            })
        } else if !members.contains(&vote.voter) {
            Err(Error::VoteFromNonMember {
                voter: vote.voter,
                members,
            })
        } else if self.votes.contains_key(&vote.voter)
            && !vote.supersedes(&self.votes[&vote.voter])
            && !self.votes[&vote.voter].supersedes(vote)
        {
            Err(Error::ExistingVoteIncompatibleWithNewVote {
                existing_vote: self.votes[&vote.voter].clone(),
            })
        } else if self.pending_gen == self.gen {
            // We are starting a vote for the next generation
            self.validate_ballot(vote.gen, &vote.ballot)
        } else {
            // This is a vote for this generation

            // Ensure that nobody is trying to change their reconfig's.
            let reconfigs: BTreeSet<(A, Reconfig<A>)> = self
                .votes
                .values()
                .flat_map(|v| v.reconfigs())
                .chain(vote.reconfigs())
                .collect();

            let voters: BTreeSet<A> = reconfigs.iter().map(|(actor, _)| *actor).collect();
            if voters.len() != reconfigs.len() {
                Err(Error::VoterChangedMind { reconfigs })
            } else {
                self.validate_ballot(vote.gen, &vote.ballot)
            }
        }
    }

    fn validate_ballot(&self, gen: Generation, ballot: &Ballot<A, S>) -> Result<(), Error<A, S>> {
        match ballot {
            Ballot::Propose(reconfig) => self.validate_reconfig(reconfig),
            Ballot::Merge(votes) => {
                for vote in votes.iter() {
                    if vote.gen != gen {
                        return Err(Error::VoteNotForNextGeneration {
                            vote_gen: vote.gen,
                            gen,
                            pending_gen: gen,
                        });
                    }
                    self.validate_vote(vote)?;
                }
                Ok(())
            }
            Ballot::SuperMajority(votes) => {
                let members = self.members(self.gen)?;
                if !self.is_super_majority(
                    &votes
                        .iter()
                        .flat_map(|v| v.unpack_votes())
                        .cloned()
                        .collect(),
                )? {
                    Err(Error::SuperMajorityBallotIsNotSuperMajority {
                        ballot: ballot.clone(),
                        members,
                    })
                } else {
                    for vote in votes.iter() {
                        if vote.gen != gen {
                            return Err(Error::VoteNotForNextGeneration {
                                vote_gen: vote.gen,
                                gen,
                                pending_gen: gen,
                            });
                        }
                        self.validate_vote(vote)?;
                    }
                    Ok(())
                }
            }
        }
    }

    pub fn validate_reconfig(&self, reconfig: &Reconfig<A>) -> Result<(), Error<A, S>> {
        let members = self.members(self.gen)?;
        match reconfig {
            Reconfig::Join(actor) => {
                if members.contains(actor) {
                    Err(Error::JoinRequestForExistingMember {
                        requester: *actor,
                        members,
                    })
                } else if members.len() >= SOFT_MAX_MEMBERS {
                    Err(Error::MembersAtCapacity { members })
                } else {
                    Ok(())
                }
            }
            Reconfig::Leave(actor) => {
                if !members.contains(actor) {
                    Err(Error::LeaveRequestForNonMember {
                        requester: *actor,
                        members,
                    })
                } else {
                    Ok(())
                }
            }
        }
    }

    fn broadcast(&self, vote: Vote<A, S>) -> Result<Vec<VoteMsg<A, S>>, Error<A, S>> {
        Ok(self
            .members(self.gen)?
            .iter()
            .cloned()
            .map(|member| self.send(vote.clone(), member))
            .collect())
    }

    fn send(&self, vote: Vote<A, S>, dest: A) -> VoteMsg<A, S> {
        VoteMsg { vote, dest }
    }
}
