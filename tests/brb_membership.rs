use eyre::eyre;
use net::{Net, Packet};
use rand::{
    prelude::{IteratorRandom, StdRng},
    Rng, SeedableRng,
};
use std::collections::{BTreeMap, BTreeSet};

mod net;

use brb_membership::{
    Ballot, Error, Generation, PublicKey, Reconfig, SecretKey, SignedVote, State, Vote,
};
use quickcheck::{Arbitrary, Gen, TestResult};
use quickcheck_macros::quickcheck;

#[test]
fn test_reject_changing_reconfig_when_one_is_in_progress() -> Result<(), Error> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut proc = State::random(&mut rng);
    proc.force_join(proc.public_key());
    proc.propose(Reconfig::Join(PublicKey::random(&mut rng)))?;
    assert!(matches!(
        proc.propose(Reconfig::Join(PublicKey::random(&mut rng))),
        Err(Error::ExistingVoteIncompatibleWithNewVote { .. })
    ));
    Ok(())
}

#[test]
fn test_reject_vote_from_non_member() -> Result<(), Error> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(2, &mut rng);
    net.procs[1].faulty = true;
    let p0 = net.procs[0].public_key();
    let p1 = net.procs[1].public_key();
    net.force_join(p1, p0);
    net.force_join(p1, p1);

    let resp = net.procs[1].propose(Reconfig::Join(PublicKey::random(&mut rng)))?;
    net.enqueue_packets(resp.into_iter().map(|vote_msg| Packet {
        source: p1,
        vote_msg,
    }));
    net.drain_queued_packets()?;
    Ok(())
}

#[test]
fn test_reject_new_join_if_we_are_at_capacity() -> Result<(), Error> {
    let mut rng = StdRng::from_seed([0u8; 32]);

    let mut proc = State {
        forced_reconfigs: vec![(
            0,
            BTreeSet::from_iter((0..7).map(|_| Reconfig::Join(PublicKey::random(&mut rng)))),
        )]
        .into_iter()
        .collect(),
        ..State::random(&mut rng)
    };
    proc.force_join(proc.public_key());

    assert!(matches!(
        proc.propose(Reconfig::Join(PublicKey::random(&mut rng))),
        Err(Error::MembersAtCapacity { .. })
    ));

    let leaving_member = proc
        .members(proc.gen)?
        .into_iter()
        .next()
        .ok_or(Error::NoMembers)?;
    proc.propose(Reconfig::Leave(leaving_member))?;
    Ok(())
}

#[test]
fn test_reject_join_if_actor_is_already_a_member() -> Result<(), Error> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut proc = State {
        forced_reconfigs: vec![(
            0,
            BTreeSet::from_iter((0..1).map(|_| Reconfig::Join(PublicKey::random(&mut rng)))),
        )]
        .into_iter()
        .collect(),
        ..State::random(&mut rng)
    };
    proc.force_join(proc.public_key());

    let member = proc
        .members(proc.gen)?
        .into_iter()
        .next()
        .ok_or(Error::NoMembers)?;
    assert!(matches!(
        proc.propose(Reconfig::Join(member)),
        Err(Error::JoinRequestForExistingMember { .. })
    ));
    Ok(())
}

#[test]
fn test_reject_leave_if_actor_is_not_a_member() {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut proc = State {
        forced_reconfigs: vec![(
            0,
            BTreeSet::from_iter((0..1).map(|_| Reconfig::Join(PublicKey::random(&mut rng)))),
        )]
        .into_iter()
        .collect(),
        ..State::random(&mut rng)
    };
    proc.force_join(proc.public_key());

    let resp = proc.propose(Reconfig::Leave(PublicKey::random(&mut rng)));
    assert!(matches!(resp, Err(Error::LeaveRequestForNonMember { .. })));
}

#[test]
fn test_handle_vote_rejects_packet_from_previous_gen() -> Result<(), Error> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(2, &mut rng);
    let a_0 = net.procs[0].public_key();
    let a_1 = net.procs[1].public_key();
    net.procs[0].force_join(a_0);
    net.procs[0].force_join(a_1);
    net.procs[1].force_join(a_0);
    net.procs[1].force_join(a_1);

    let packets = net.procs[0]
        .propose(Reconfig::Join(PublicKey::random(&mut rng)))?
        .into_iter()
        .map(|vote_msg| Packet {
            source: a_0,
            vote_msg,
        })
        .collect::<Vec<_>>();

    let stale_packets = net.procs[1]
        .propose(Reconfig::Join(PublicKey::random(&mut rng)))?
        .into_iter()
        .map(|vote_msg| Packet {
            source: a_1,
            vote_msg,
        })
        .collect::<Vec<_>>();

    net.procs[1].pending_gen = 0;
    net.procs[1].votes = Default::default();

    assert_eq!(packets.len(), 2); // two members in the network
    assert_eq!(stale_packets.len(), 2);

    net.enqueue_packets(packets);
    net.drain_queued_packets()?;

    for packet in stale_packets {
        let vote = packet.vote_msg.vote;
        assert!(matches!(
            net.procs[0].handle_signed_vote(vote),
            Err(Error::VoteNotForNextGeneration {
                vote_gen: 1,
                gen: 1,
                pending_gen: 1,
            })
        ));
    }

    Ok(())
}

#[test]
fn test_reject_votes_with_invalid_signatures() -> Result<(), Error> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut proc = State::random(&mut rng);
    let ballot = Ballot::Propose(Reconfig::Join(PublicKey::random(&mut rng)));
    let gen = proc.gen + 1;
    let voter = PublicKey::random(&mut rng);
    let bytes = bincode::serialize(&(&ballot, &gen))?;
    let sig = SecretKey::random(&mut rng).sign(&bytes);
    let vote = Vote { gen, ballot };
    let resp = proc.handle_signed_vote(SignedVote { vote, voter, sig });

    #[cfg(feature = "blsttc")]
    assert!(matches!(resp, Err(Error::Blsttc(_))));

    #[cfg(feature = "ed25519")]
    assert!(matches!(resp, Err(Error::Ed25519(_))));

    #[cfg(feature = "bad_crypto")]
    assert!(matches!(resp, Err(Error::BadCrypto(_))));
    Ok(())
}

#[test]
fn test_split_vote() -> eyre::Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    for nprocs in 1..7 {
        let mut net = Net::with_procs(nprocs * 2, &mut rng);
        for i in 0..nprocs {
            let i_actor = net.procs[i].public_key();
            for j in 0..(nprocs * 2) {
                net.procs[j].force_join(i_actor);
            }
        }

        let joining_members = Vec::from_iter(net.procs[nprocs..].iter().map(State::public_key));
        for (i, member) in joining_members.iter().enumerate() {
            let a_i = net.procs[i].public_key();
            let packets = net.procs[i]
                .propose(Reconfig::Join(*member))?
                .into_iter()
                .map(|vote_msg| Packet {
                    source: a_i,
                    vote_msg,
                });
            net.enqueue_packets(packets);
        }

        net.drain_queued_packets()?;

        for i in 0..(nprocs * 2) {
            for j in 0..(nprocs * 2) {
                net.enqueue_anti_entropy(i, j);
            }
        }
        net.drain_queued_packets()?;

        let proc0_gen = net.procs[0].gen;
        let expected_members = net.procs[0].members(proc0_gen)?;
        assert!(expected_members.len() > nprocs);

        for i in 0..nprocs {
            let proc_i_gen = net.procs[i].gen;
            assert_eq!(proc_i_gen, proc0_gen);
            assert_eq!(net.procs[i].members(proc_i_gen)?, expected_members);
        }

        for member in expected_members.iter() {
            let p = net
                .procs
                .iter()
                .find(|p| &p.public_key() == member)
                .ok_or_else(|| eyre!("Could not find process with id {:?}", member))?;

            assert_eq!(p.members(p.gen)?, expected_members);
        }
    }

    Ok(())
}

#[test]
fn test_round_robin_split_vote() -> eyre::Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    for nprocs in 1..7 {
        let mut net = Net::with_procs(nprocs * 2, &mut rng);
        for i in 0..nprocs {
            let i_actor = net.procs[i].public_key();
            for j in 0..(nprocs * 2) {
                net.procs[j].force_join(i_actor);
            }
        }

        let joining_members = Vec::from_iter(net.procs[nprocs..].iter().map(State::public_key));
        for (i, member) in joining_members.iter().enumerate() {
            let a_i = net.procs[i].public_key();
            let packets = net.procs[i]
                .propose(Reconfig::Join(*member))?
                .into_iter()
                .map(|vote_msg| Packet {
                    source: a_i,
                    vote_msg,
                });
            net.enqueue_packets(packets);
        }

        while !net.packets.is_empty() {
            for i in 0..net.procs.len() {
                net.deliver_packet_from_source(net.procs[i].public_key())?;
            }
        }

        for i in 0..(nprocs * 2) {
            for j in 0..(nprocs * 2) {
                net.enqueue_anti_entropy(i, j);
            }
        }
        net.drain_queued_packets()?;

        net.generate_msc(&format!("round_robin_split_vote_{}.msc", nprocs))?;

        let proc_0_gen = net.procs[0].gen;
        let expected_members = net.procs[0].members(proc_0_gen)?;
        assert!(expected_members.len() > nprocs);

        for i in 0..nprocs {
            let gen = net.procs[i].gen;
            assert_eq!(net.procs[i].members(gen)?, expected_members);
        }

        for member in expected_members.iter() {
            let p = net
                .procs
                .iter()
                .find(|p| &p.public_key() == member)
                .ok_or_else(|| eyre!("Unable to find proc with id {:?}", member))?;
            assert_eq!(p.members(p.gen)?, expected_members);
        }
    }
    Ok(())
}

#[test]
fn test_onboarding_across_many_generations() -> eyre::Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(3, &mut rng);
    let p0 = net.procs[0].public_key();
    let p1 = net.procs[1].public_key();
    let p2 = net.procs[2].public_key();

    for i in 0..3 {
        net.procs[i].force_join(p0);
    }
    let packets = net.procs[0]
        .propose(Reconfig::Join(p1))?
        .into_iter()
        .map(|vote_msg| Packet {
            source: p0,
            vote_msg,
        });
    net.enqueue_packets(packets);
    net.deliver_packet_from_source(p0)?;
    net.deliver_packet_from_source(p0)?;
    net.enqueue_packets(
        net.procs[0]
            .anti_entropy(0, p1)
            .into_iter()
            .map(|vote_msg| Packet {
                source: p0,
                vote_msg,
            }),
    );
    let packets = net.procs[0]
        .propose(Reconfig::Join(p2))?
        .into_iter()
        .map(|vote_msg| Packet {
            source: p0,
            vote_msg,
        });
    net.enqueue_packets(packets);
    for _ in 0..3 {
        net.drain_queued_packets()?;
        for i in 0..3 {
            for j in 0..3 {
                net.enqueue_anti_entropy(i, j);
            }
        }
    }
    assert!(net.packets.is_empty());

    net.drain_queued_packets()?;

    let mut procs_by_gen: BTreeMap<Generation, Vec<State>> = Default::default();

    net.generate_msc("onboarding.msc")?;

    for proc in net.procs {
        procs_by_gen.entry(proc.gen).or_default().push(proc);
    }

    let max_gen = procs_by_gen
        .keys()
        .last()
        .ok_or_else(|| eyre!("No generations logged"))?;
    // The last gen should have at least a super majority of nodes
    let current_members = BTreeSet::from_iter(procs_by_gen[max_gen].iter().map(State::public_key));

    for proc in procs_by_gen[max_gen].iter() {
        assert_eq!(current_members, proc.members(proc.gen)?);
    }
    Ok(())
}

#[test]
fn test_simple_proposal() -> Result<(), Error> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(4, &mut rng);
    for i in 0..4 {
        let a_i = net.procs[i].public_key();
        for j in 0..3 {
            let a_j = net.procs[j].public_key();
            net.force_join(a_i, a_j);
        }
    }

    let proc_0 = net.procs[0].public_key();
    let proc_3 = net.procs[3].public_key();
    let packets = net.procs[0]
        .propose(Reconfig::Join(proc_3))?
        .into_iter()
        .map(|vote_msg| Packet {
            source: proc_0,
            vote_msg,
        });
    net.enqueue_packets(packets);
    net.drain_queued_packets()?;

    net.generate_msc("simple_join.msc")?;

    Ok(())
}

#[derive(Debug, Clone)]
enum Instruction {
    RequestJoin(usize, usize),
    RequestLeave(usize, usize),
    DeliverPacketFromSource(usize),
    AntiEntropy(Generation, usize, usize),
}
impl Arbitrary for Instruction {
    fn arbitrary(g: &mut Gen) -> Self {
        let p: usize = usize::arbitrary(g) % 7;
        let q: usize = usize::arbitrary(g) % 7;
        let gen: Generation = Generation::arbitrary(g) % 20;

        match u8::arbitrary(g) % 4 {
            0 => Instruction::RequestJoin(p, q),
            1 => Instruction::RequestLeave(p, q),
            2 => Instruction::DeliverPacketFromSource(p),
            3 => Instruction::AntiEntropy(gen, p, q),
            i => panic!("unexpected instruction index {}", i),
        }
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        let mut shrunk_ops = Vec::new();
        match self.clone() {
            Instruction::RequestJoin(p, q) => {
                if p > 0 && q > 0 {
                    shrunk_ops.push(Instruction::RequestJoin(p - 1, q - 1));
                }
                if p > 0 {
                    shrunk_ops.push(Instruction::RequestJoin(p - 1, q));
                }
                if q > 0 {
                    shrunk_ops.push(Instruction::RequestJoin(p, q - 1));
                }
            }
            Instruction::RequestLeave(p, q) => {
                if p > 0 && q > 0 {
                    shrunk_ops.push(Instruction::RequestLeave(p - 1, q - 1));
                }
                if p > 0 {
                    shrunk_ops.push(Instruction::RequestLeave(p - 1, q));
                }
                if q > 0 {
                    shrunk_ops.push(Instruction::RequestLeave(p, q - 1));
                }
            }
            Instruction::DeliverPacketFromSource(p) => {
                if p > 0 {
                    shrunk_ops.push(Instruction::DeliverPacketFromSource(p - 1));
                }
            }
            Instruction::AntiEntropy(gen, p, q) => {
                if p > 0 && q > 0 {
                    shrunk_ops.push(Instruction::AntiEntropy(gen, p - 1, q - 1));
                }
                if p > 0 {
                    shrunk_ops.push(Instruction::AntiEntropy(gen, p - 1, q));
                }
                if q > 0 {
                    shrunk_ops.push(Instruction::AntiEntropy(gen, p, q - 1));
                }
                if gen > 0 {
                    shrunk_ops.push(Instruction::AntiEntropy(gen - 1, p, q));
                }
            }
        }

        Box::new(shrunk_ops.into_iter())
    }
}

#[test]
fn test_interpreter_qc1() -> Result<(), Error> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(2, &mut rng);
    let p0 = net.procs[0].public_key();
    let p1 = net.procs[1].public_key();

    for proc in net.procs.iter_mut() {
        proc.force_join(p0);
    }

    let reconfig = Reconfig::Join(p1);
    let q = &mut net.procs[0];
    let propose_vote_msgs = q.propose(reconfig)?;
    let propose_packets = propose_vote_msgs.into_iter().map(|vote_msg| Packet {
        source: p0,
        vote_msg,
    });
    net.reconfigs_by_gen
        .entry(q.pending_gen)
        .or_default()
        .insert(reconfig);
    net.enqueue_packets(propose_packets);

    net.enqueue_anti_entropy(1, 0);
    net.enqueue_anti_entropy(1, 0);

    for _ in 0..3 {
        net.drain_queued_packets()?;
        for i in 0..net.procs.len() {
            for j in 0..net.procs.len() {
                net.enqueue_anti_entropy(i, j);
            }
        }
    }
    assert!(net.packets.is_empty());

    for p in net.procs.iter() {
        assert!(p
            .history
            .iter()
            .all(|(_, v)| v.vote.is_super_majority_ballot()));
    }
    Ok(())
}

#[test]
fn test_interpreter_qc2() -> Result<(), Error> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(3, &mut rng);
    let p0 = net.procs[0].public_key();
    let p1 = net.procs[1].public_key();
    let p2 = net.procs[2].public_key();

    // Assume procs[0] is the genesis proc.
    for proc in net.procs.iter_mut() {
        proc.force_join(p0);
    }

    let propose_packets = net.procs[0]
        .propose(Reconfig::Join(p1))?
        .into_iter()
        .map(|vote_msg| Packet {
            source: p0,
            vote_msg,
        });
    net.enqueue_packets(propose_packets);

    net.deliver_packet_from_source(p0)?;
    net.deliver_packet_from_source(p0)?;

    let propose_packets = net.procs[0]
        .propose(Reconfig::Join(p2))?
        .into_iter()
        .map(|vote_msg| Packet {
            source: p0,
            vote_msg,
        });
    net.enqueue_packets(propose_packets);

    for _ in 0..3 {
        assert!(!net.packets.is_empty());
        net.drain_queued_packets().unwrap();
        for i in 0..net.procs.len() {
            for j in 0..net.procs.len() {
                net.enqueue_anti_entropy(i, j);
            }
        }
    }

    assert!(net.packets.is_empty());

    // We should have no more pending votes.
    for p in net.procs.iter() {
        assert_eq!(p.votes, Default::default());
    }

    Ok(())
}

#[test]
fn test_interpreter_qc3() {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(4, &mut rng);
    let genesis = net.genesis().unwrap();

    for proc in net.procs.iter_mut() {
        proc.force_join(genesis);
    }

    // 1 requests to join genesis
    let p = net.procs[1].public_key();
    let reconfig = Reconfig::Join(p);
    net.reconfigs_by_gen
        .entry(net.procs[0].gen + 1)
        .or_default()
        .insert(reconfig);

    let propose_packets = net.procs[0]
        .propose(reconfig)
        .unwrap()
        .into_iter()
        .map(|vote_msg| Packet {
            source: genesis,
            vote_msg,
        });
    net.enqueue_packets(propose_packets);

    net.deliver_packet_from_source(genesis).unwrap();
    net.deliver_packet_from_source(genesis).unwrap();

    // 1 requests to leave genesis
    let reconfig = Reconfig::Leave(p);
    net.reconfigs_by_gen
        .entry(net.procs[0].gen + 1)
        .or_default()
        .insert(reconfig);

    let propose_packets = net.procs[0]
        .propose(reconfig)
        .unwrap()
        .into_iter()
        .map(|vote_msg| Packet {
            source: genesis,
            vote_msg,
        });

    net.enqueue_packets(propose_packets);

    let q_actor = net.procs[2].public_key();
    let anti_entropy_packets = net.procs[0]
        .anti_entropy(0, q_actor)
        .into_iter()
        .map(|vote_msg| Packet {
            source: genesis,
            vote_msg,
        });

    net.enqueue_packets(anti_entropy_packets);
    net.drain_queued_packets().unwrap();

    for i in 0..net.procs.len() {
        for j in 0..net.procs.len() {
            net.enqueue_anti_entropy(i, j);
        }
    }

    let res = net.drain_queued_packets();

    net.generate_msc("prop_interpreter_qc3.msc").unwrap();

    assert!(res.is_ok());
}

#[quickcheck]
fn prop_interpreter(n: u8, instructions: Vec<Instruction>, seed: u128) -> eyre::Result<TestResult> {
    let mut seed_buf = [0u8; 32];
    seed_buf[0..16].copy_from_slice(&seed.to_le_bytes());
    let mut rng = StdRng::from_seed(seed_buf);

    fn super_majority(m: usize, n: usize) -> bool {
        3 * m > 2 * n
    }

    let n = n.min(7) as usize;
    if n == 0 || instructions.len() > 12 {
        return Ok(TestResult::discard());
    }

    let mut net = Net::with_procs(n, &mut rng);

    // Assume procs[0] is the genesis proc. (trusts itself)
    let gen_proc = net.genesis()?;
    for proc in net.procs.iter_mut() {
        proc.force_join(gen_proc);
    }

    for instruction in instructions {
        match instruction {
            Instruction::RequestJoin(p_idx, q_idx) => {
                // p requests to join q
                let p = net.procs[p_idx.min(n - 1)].public_key();
                let reconfig = Reconfig::Join(p);

                let q = &mut net.procs[q_idx.min(n - 1)];
                let q_actor = q.public_key();
                match q.propose(reconfig) {
                    Ok(propose_vote_msgs) => {
                        let propose_packets =
                            propose_vote_msgs.into_iter().map(|vote_msg| Packet {
                                source: q_actor,
                                vote_msg,
                            });
                        net.reconfigs_by_gen
                            .entry(q.pending_gen)
                            .or_default()
                            .insert(reconfig);
                        net.enqueue_packets(propose_packets);
                    }
                    Err(Error::JoinRequestForExistingMember { .. }) => {
                        assert!(q.members(q.gen)?.contains(&p));
                    }
                    Err(Error::NonMember { .. }) => {
                        assert!(!q.members(q.gen)?.contains(&q.public_key()));
                    }
                    Err(Error::ExistingVoteIncompatibleWithNewVote { existing_vote }) => {
                        // This proc has already committed to a vote this round
                        assert_eq!(q.votes.get(&q.public_key()), Some(&existing_vote));
                    }
                    Err(err) => {
                        // invalid request.
                        panic!("Failure to reconfig is not handled yet: {:?}", err);
                    }
                }
            }
            Instruction::RequestLeave(p_idx, q_idx) => {
                // p requests to leave q
                let p = net.procs[p_idx.min(n - 1)].public_key();
                let reconfig = Reconfig::Leave(p);

                let q = &mut net.procs[q_idx.min(n - 1)];
                let q_actor = q.public_key();
                match q.propose(reconfig) {
                    Ok(propose_vote_msgs) => {
                        let propose_packets =
                            propose_vote_msgs.into_iter().map(|vote_msg| Packet {
                                source: q_actor,
                                vote_msg,
                            });
                        net.reconfigs_by_gen
                            .entry(q.pending_gen)
                            .or_default()
                            .insert(reconfig);
                        net.enqueue_packets(propose_packets);
                    }
                    Err(Error::LeaveRequestForNonMember { .. }) => {
                        assert!(!q.members(q.gen)?.contains(&p));
                    }
                    Err(Error::NonMember { .. }) => {
                        assert!(!q.members(q.gen)?.contains(&q.public_key()));
                    }
                    Err(Error::ExistingVoteIncompatibleWithNewVote { existing_vote }) => {
                        // This proc has already committed to a vote
                        assert_eq!(q.votes.get(&q.public_key()), Some(&existing_vote));
                    }
                    Err(err) => {
                        // invalid request.
                        panic!("Leave Failure is not handled yet: {:?}", err);
                    }
                }
            }
            Instruction::DeliverPacketFromSource(source_idx) => {
                // deliver packet
                let source = net.procs[source_idx.min(n - 1)].public_key();
                net.deliver_packet_from_source(source)?;
            }
            Instruction::AntiEntropy(gen, p_idx, q_idx) => {
                let p = &net.procs[p_idx.min(n - 1)];
                let q_actor = net.procs[q_idx.min(n - 1)].public_key();
                let p_actor = p.public_key();
                let anti_entropy_packets =
                    p.anti_entropy(gen, q_actor)
                        .into_iter()
                        .map(|vote_msg| Packet {
                            source: p_actor,
                            vote_msg,
                        });
                net.enqueue_packets(anti_entropy_packets);
            }
        }
    }

    // 3 rounds of anti-entropy will get everyone in sync
    for _ in 0..3 {
        net.drain_queued_packets()?;
        for i in 0..net.procs.len() {
            for j in 0..net.procs.len() {
                net.enqueue_anti_entropy(i, j);
            }
        }
    }
    assert!(
        net.packets.is_empty(),
        "We should have no more pending packets"
    );

    // We should have no more pending votes.
    for p in net.procs.iter() {
        assert_eq!(p.votes, Default::default());
    }

    let mut procs_by_gen: BTreeMap<Generation, Vec<State>> = Default::default();

    for proc in net.procs {
        procs_by_gen.entry(proc.gen).or_default().push(proc);
    }

    let max_gen = procs_by_gen
        .keys()
        .last()
        .ok_or_else(|| eyre!("No generations logged"))?;

    // And procs at each generation should have agreement on members
    for (gen, procs) in procs_by_gen.iter() {
        let mut proc_iter = procs.iter();
        let first = proc_iter.next().ok_or(Error::NoMembers)?;
        if *gen > 0 {
            // TODO: remove this gen > 0 constraint
            assert_eq!(first.members(first.gen)?, net.members_at_gen[gen]);
        }
        for proc in proc_iter {
            assert_eq!(
                first.members(first.gen)?,
                proc.members(proc.gen)?,
                "gen: {}",
                gen
            );
        }
    }

    // TODO: everyone that a proc at G considers a member is also at generation G

    for (gen, reconfigs) in net.reconfigs_by_gen.iter() {
        let members_at_prev_gen = &net.members_at_gen[&(gen - 1)];
        let members_at_curr_gen = net.members_at_gen[gen].clone();
        let mut reconfigs_applied: BTreeSet<&Reconfig> = Default::default();
        for reconfig in reconfigs {
            match reconfig {
                Reconfig::Join(p) => {
                    assert!(!members_at_prev_gen.contains(p));
                    if members_at_curr_gen.contains(p) {
                        reconfigs_applied.insert(reconfig);
                    }
                }
                Reconfig::Leave(p) => {
                    assert!(members_at_prev_gen.contains(p));
                    if !members_at_curr_gen.contains(p) {
                        reconfigs_applied.insert(reconfig);
                    }
                }
            }
        }

        assert_ne!(reconfigs_applied, Default::default());
    }

    let proc_at_max_gen = procs_by_gen[max_gen].get(0).ok_or(Error::NoMembers)?;
    assert!(
        super_majority(
            procs_by_gen[max_gen].len(),
            proc_at_max_gen.members(*max_gen)?.len()
        ),
        "{:?}",
        procs_by_gen
    );

    Ok(TestResult::passed())
}

#[quickcheck]
fn prop_validate_reconfig(
    join_or_leave: bool,
    actor_idx: u8,
    members: u8,
    seed: u128,
) -> Result<TestResult, Error> {
    let mut seed_buf = [0u8; 32];
    seed_buf[0..16].copy_from_slice(&seed.to_le_bytes());
    let mut rng = StdRng::from_seed(seed_buf);

    if members >= 7 {
        return Ok(TestResult::discard());
    }

    let mut proc = State::random(&mut rng);

    let trusted_actors: Vec<_> = (0..members)
        .map(|_| PublicKey::random(&mut rng))
        .chain(vec![proc.public_key()])
        .collect();

    for a in trusted_actors.iter().copied() {
        proc.force_join(a);
    }

    let all_actors = {
        let mut actors = trusted_actors;
        actors.push(PublicKey::random(&mut rng));
        actors
    };

    let actor = all_actors[actor_idx as usize % all_actors.len()];
    let reconfig = match join_or_leave {
        true => Reconfig::Join(actor),
        false => Reconfig::Leave(actor),
    };

    let valid_res = proc.validate_reconfig(reconfig);
    let proc_members = proc.members(proc.gen)?;
    match reconfig {
        Reconfig::Join(actor) => {
            if proc_members.contains(&actor) {
                assert!(matches!(
                    valid_res,
                    Err(Error::JoinRequestForExistingMember { .. })
                ));
            } else if members + 1 == 7 {
                assert!(matches!(valid_res, Err(Error::MembersAtCapacity { .. })));
            } else {
                assert!(valid_res.is_ok());
            }
        }
        Reconfig::Leave(actor) => {
            if proc_members.contains(&actor) {
                assert!(valid_res.is_ok());
            } else {
                assert!(matches!(
                    valid_res,
                    Err(Error::LeaveRequestForNonMember { .. })
                ));
            }
        }
    };

    Ok(TestResult::passed())
}

#[quickcheck]
fn prop_bft_consensus(
    recursion_limit: u8,
    n: u8,
    faulty: Vec<u8>,
    seed: u128,
) -> Result<TestResult, Error> {
    let n = n % 6 + 1;
    let recursion_limit = recursion_limit % (n / 2).max(1);
    let faulty = BTreeSet::from_iter(
        faulty
            .into_iter()
            .map(|p| p % n)
            .filter(|p| p != &0) // genesis can not be faulty
            .take((n / 3) as usize),
    );
    // All non-faulty nodes eventually decide on a reconfig

    let mut seed_buf = [0u8; 32];
    seed_buf[0..16].copy_from_slice(&seed.to_le_bytes());
    let mut rng = rand::rngs::StdRng::from_seed(seed_buf);

    let mut net = Net::with_procs(n as usize, &mut rng);

    // Set first proc as genesis
    let genesis = net.procs[0].public_key();
    for p in net.procs.iter_mut() {
        p.force_join(genesis);
    }

    let faulty = BTreeSet::from_iter(
        faulty
            .into_iter()
            .map(|idx| net.procs[idx as usize].public_key()),
    );
    let n_actions = rng.gen::<u8>() % 3;

    for _ in 0..n_actions {
        match rng.gen::<u8>() % 3 {
            0 if !faulty.is_empty() => {
                match rng.gen::<bool>() {
                    true => {
                        // send a randomized packet
                        let packet = net.gen_faulty_packet(recursion_limit, &faulty, &mut rng);
                        net.enqueue_packets(vec![packet]);
                    }
                    false => {
                        // drop a random packet
                        let source = net.gen_public_key(&mut rng);
                        net.drop_packet_from_source(source);
                    }
                };
            }
            1 => {
                // node takes honest action
                let pks = BTreeSet::from_iter(net.procs.iter().map(State::public_key));

                let proc = if let Some(proc) = net
                    .procs
                    .iter_mut()
                    .filter(|p| !faulty.contains(&p.public_key())) // filter out faulty nodes
                    .filter(|p| p.members(p.gen).unwrap().contains(&p.public_key())) // filter out non-members
                    .filter(|p| p.gen != p.pending_gen) // filter out nodes who have already voted this round
                    .choose(&mut rng)
                {
                    proc
                } else {
                    // No honest node can take an action
                    continue;
                };

                let source = proc.public_key();

                let reconfig = match rng.gen::<bool>() {
                    true => Reconfig::Join(
                        pks.into_iter()
                            .filter(|pk| !proc.members(proc.gen).unwrap().contains(pk))
                            .choose(&mut rng)
                            .unwrap(),
                    ),
                    false => Reconfig::Leave(
                        pks.into_iter()
                            .filter(|pk| proc.members(proc.gen).unwrap().contains(pk))
                            .choose(&mut rng)
                            .unwrap(),
                    ),
                };

                let packets = Vec::from_iter(
                    proc.propose(reconfig)
                        .unwrap()
                        .into_iter()
                        .map(|vote_msg| Packet { source, vote_msg }),
                );
                net.enqueue_packets(packets);
            }
            _ => {
                // Network delivers a packet
                let source = net.gen_public_key(&mut rng);
                let _ = net.deliver_packet_from_source(source);
            }
        };
    }

    let _ = net.drain_queued_packets();

    let honest_procs = Vec::from_iter(
        net.procs
            .iter()
            .filter(|p| !faulty.contains(&p.public_key())),
    );

    // BFT TERMINATION PROPERTY: all honest procs have decided ==>
    for p in honest_procs.iter() {
        assert_eq!(p.votes, Default::default());
        assert_eq!(p.gen, p.pending_gen);
    }

    // BFT AGREEMENT PROPERTY: all honest procs have decided on the same values
    let reference_proc = &honest_procs[0];
    for p in honest_procs.iter() {
        assert_eq!(reference_proc.gen, p.gen);
        for g in 0..=reference_proc.gen {
            assert_eq!(reference_proc.members(g).unwrap(), p.members(g).unwrap())
        }
    }

    Ok(TestResult::passed())
}
