use eyre::eyre;
use std::collections::{BTreeMap, BTreeSet};

mod net;
use crate::net::{random_pks, random_proc, random_sks, Net, Packet};

use brb_membership::{Ballot, Error, Generation, Reconfig, SignedVote, State, Vote};
use quickcheck::{Arbitrary, Gen, TestResult};
use quickcheck_macros::quickcheck;

#[test]
fn test_reject_changing_reconfig_when_one_is_in_progress() -> Result<(), Error> {
    let mut proc = random_proc();
    proc.force_join(proc.public_key_share());
    proc.propose(Reconfig::Join(random_pks()))?;

    assert!(matches!(
        proc.propose(Reconfig::Join(random_pks())),
        Err(Error::ExistingVoteIncompatibleWithNewVote { .. })
    ));

    Ok(())
}

#[test]
fn test_reject_vote_from_non_member() -> Result<(), Error> {
    let mut net = Net::with_procs(2);
    net.procs[1].faulty = true;
    let p0 = net.procs[0].public_key_share();
    let p1 = net.procs[1].public_key_share();
    net.force_join(p1, p0);
    net.force_join(p1, p1);

    let resp = net.procs[1].propose(Reconfig::Join(random_pks()))?;
    net.enqueue_packets(resp.into_iter().map(|vote_msg| Packet {
        source: p1,
        vote_msg,
    }));
    net.drain_queued_packets()?;
    Ok(())
}

#[test]
fn test_reject_new_join_if_we_are_at_capacity() -> Result<(), Error> {
    let mut proc = State {
        forced_reconfigs: BTreeMap::from_iter([(
            0,
            BTreeSet::from_iter((0..7).map(|_| Reconfig::Join(random_pks()))),
        )]),
        ..random_proc()
    };
    proc.force_join(proc.public_key_share());

    assert!(matches!(
        proc.propose(Reconfig::Join(random_pks())),
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
    let mut proc = State {
        forced_reconfigs: vec![(0, (0..1).map(|_| Reconfig::Join(random_pks())).collect())]
            .into_iter()
            .collect(),
        ..random_proc()
    };
    proc.force_join(proc.public_key_share());

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
    let mut proc = State {
        forced_reconfigs: vec![(0, (0..1).map(|_| Reconfig::Join(random_pks())).collect())]
            .into_iter()
            .collect(),
        ..random_proc()
    };
    proc.force_join(proc.public_key_share());

    let leaving_actor = random_pks();
    let resp = proc.propose(Reconfig::Leave(leaving_actor));
    assert!(matches!(resp, Err(Error::LeaveRequestForNonMember { .. })));
}

#[test]
fn test_handle_vote_rejects_packet_from_previous_gen() -> Result<(), Error> {
    let mut net = Net::with_procs(2);
    let a_0 = net.procs[0].public_key_share();
    let a_1 = net.procs[1].public_key_share();
    net.procs[0].force_join(a_0);
    net.procs[0].force_join(a_1);
    net.procs[1].force_join(a_0);
    net.procs[1].force_join(a_1);

    let packets = net.procs[0]
        .propose(Reconfig::Join(random_pks()))?
        .into_iter()
        .map(|vote_msg| Packet {
            source: a_0,
            vote_msg,
        })
        .collect::<Vec<_>>();

    let stale_packets = net.procs[1]
        .propose(Reconfig::Join(random_pks()))?
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
            net.procs[0].handle_vote(vote),
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
    let mut proc = random_proc();
    let ballot = Ballot::Propose(Reconfig::Join(random_pks()));
    let gen = proc.gen + 1;
    let voter = random_pks();
    let vote = Vote { gen, ballot };
    let sig = random_sks().sign(&vote.to_bytes()?);
    let resp = proc.handle_vote(SignedVote { vote, voter, sig });

    assert!(matches!(resp, Err(Error::InvalidSignature)));
    Ok(())
}

#[test]
fn test_split_vote() -> eyre::Result<()> {
    for nprocs in 1..7 {
        let mut net = Net::with_procs(nprocs * 2);
        for i in 0..nprocs {
            let i_actor = net.procs[i].public_key_share();
            for j in 0..(nprocs * 2) {
                net.procs[j].force_join(i_actor);
            }
        }

        let joining_members =
            Vec::from_iter(net.procs[nprocs..].iter().map(State::public_key_share));
        for (i, member) in joining_members.into_iter().enumerate() {
            let a_i = net.procs[i].public_key_share();
            let packets = net.procs[i]
                .propose(Reconfig::Join(member))?
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
                .find(|p| &p.public_key_share() == member)
                .ok_or_else(|| eyre!("Could not find process with id {:?}", member))?;

            assert_eq!(p.members(p.gen)?, expected_members);
        }
    }

    Ok(())
}

#[test]
fn test_round_robin_split_vote() -> eyre::Result<()> {
    for nprocs in 1..7 {
        let mut net = Net::with_procs(nprocs * 2);
        for i in 0..nprocs {
            let i_actor = net.procs[i].public_key_share();
            for j in 0..(nprocs * 2) {
                net.procs[j].force_join(i_actor);
            }
        }

        let joining_members =
            Vec::from_iter(net.procs[nprocs..].iter().map(State::public_key_share));
        for (i, member) in joining_members.into_iter().enumerate() {
            let a_i = net.procs[i].public_key_share();
            let packets = net.procs[i]
                .propose(Reconfig::Join(member))?
                .into_iter()
                .map(|vote_msg| Packet {
                    source: a_i,
                    vote_msg,
                });
            net.enqueue_packets(packets);
        }

        while !net.packets.is_empty() {
            for i in 0..net.procs.len() {
                net.deliver_packet_from_source(net.procs[i].public_key_share())?;
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
                .find(|p| &p.public_key_share() == member)
                .ok_or_else(|| eyre!("Unable to find proc with id {:?}", member))?;
            assert_eq!(p.members(p.gen)?, expected_members);
        }
    }
    Ok(())
}

#[test]
fn test_onboarding_across_many_generations() -> eyre::Result<()> {
    let mut net = Net::with_procs(3);
    let p0 = net.procs[0].public_key_share();
    let p1 = net.procs[1].public_key_share();
    let p2 = net.procs[2].public_key_share();

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
    loop {
        net.drain_queued_packets()?;
        for i in 0..3 {
            for j in 0..3 {
                net.enqueue_anti_entropy(i, j);
            }
        }
        if net.packets.is_empty() {
            break;
        }
    }
    assert!(net.packets.is_empty());

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
    let current_members: BTreeSet<_> = procs_by_gen[max_gen]
        .iter()
        .map(|p| p.public_key_share())
        .collect();

    for proc in procs_by_gen[max_gen].iter() {
        assert_eq!(current_members, proc.members(proc.gen)?);
    }
    Ok(())
}

#[test]
fn test_simple_proposal() -> Result<(), Error> {
    let mut net = Net::with_procs(4);
    for i in 0..4 {
        let a_i = net.procs[i].public_key_share();
        for j in 0..3 {
            let a_j = net.procs[j].public_key_share();
            net.force_join(a_i, a_j);
        }
    }

    let proc_0 = net.procs[0].public_key_share();
    let proc_3 = net.procs[3].public_key_share();
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

// #[derive(Debug, Clone)]
// enum FaultyAction {
//     RandomVote(SignedVote),
//     RandomStateChange(StateChange),
//     DropPacket { source: PublicKeyShare },
//     ReplayPacket { source: PublicKeyShare },
// }

// #[quickcheck]
// fn prop_termination(n: u8, faulty: BTreeSet<u8>, seed: u8) -> Result<TestResult, Error> {
//     // All non-faulty nodes eventually decide on a reconfig
//     if n > 7 || 3 * faulty.len() > n as usize || faulty.iter().any(|p| p >= &n) {
//         // n > 7 is just wasteful.
//         // We can't handle >= 1/3 of procs being faulty (Limitation of BFT)
//         // Make sure all faulty nodes index into our list
//         return Ok(TestResult::discard());
//     }

//     let net = Net::with_procs(n as usize);

//     let mut rng = rand::rngs::StdRng::from_seed([seed; 32]);
//     let n_actions = rng.next_u32() % 3;

//     for i in 0..n_actions {
//         let faulty_action = rng.gen();
//         if faulty_action {
//             let faulty_node = &net.procs[*faulty.iter().choose(&mut rng).unwrap() as usize];
//             let action = match rng.next_u32() % 4 {
//                 0 => {
//                     let vote = net.gen_faulty_vote(&mut rng);
//                     let signed_vote = faulty_node.sign_vote(vote).unwrap();

//                     // change the voter to a random proc
//                     signed_vote.voter = net
//                         .procs
//                         .iter()
//                         .choose(&mut rng)
//                         .unwrap()
//                         .public_key_share();

//                     FaultyAction::RandomVote(signed_vote)
//                 }
//                 1 => FaultyAction::RandomStateChange(net.gen_state_change(&mut rng)),
//                 2 => FaultyAction::DropPacket { source: todo!() },
//                 3 => FaultyAction::ReplayPacket { source: todo!() },
//             };

//             println!(
//                 "Faulty node {:?} is taking action",
//                 faulty_node.public_key_share(),
//                 action
//             );

//             // Faulty Actions
//             // 1. sends bad message
//             // 2. bad state change
//             // 3. drop packet
//             // 4. replay packet
//             // 5. attempt to impersonate
//         } else {
//         };
//     }

//     Ok(TestResult::passed())
// }

#[derive(Debug, Clone)]
enum Instruction {
    RequestJoin {
        joining: u8,
        recipient: u8,
        gen: Generation,
    },
    RequestLeave {
        leaving: u8,
        recipient: u8,
        gen: Generation,
    },
    DeliverPacketFromSource(u8),
    AntiEntropy(Generation, u8, u8),
}
impl Arbitrary for Instruction {
    fn arbitrary(g: &mut Gen) -> Self {
        let p: u8 = u8::arbitrary(g) % 7;
        let q: u8 = u8::arbitrary(g) % 7;
        let gen: Generation = Generation::arbitrary(g) % 20;

        match u8::arbitrary(g) % 4 {
            0 => Instruction::RequestJoin {
                joining: p,
                recipient: q,
                gen,
            },
            1 => Instruction::RequestLeave {
                leaving: p,
                recipient: q,
                gen,
            },
            2 => Instruction::DeliverPacketFromSource(p),
            3 => Instruction::AntiEntropy(gen, p, q),
            i => panic!("unexpected instruction index {}", i),
        }
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        let mut shrunk_ops = Vec::new();
        match self.clone() {
            Instruction::RequestJoin {
                joining,
                recipient,
                gen,
            } => {
                if joining > 0 && recipient > 0 {
                    shrunk_ops.push(Instruction::RequestJoin {
                        joining: joining - 1,
                        recipient: recipient - 1,
                        gen,
                    });
                }
                if joining > 0 {
                    shrunk_ops.push(Instruction::RequestJoin {
                        joining: joining - 1,
                        recipient,
                        gen,
                    });
                }
                if recipient > 0 {
                    shrunk_ops.push(Instruction::RequestJoin {
                        joining,
                        recipient: recipient - 1,
                        gen,
                    });
                }
                if gen > 0 {
                    shrunk_ops.push(Instruction::RequestJoin {
                        joining,
                        recipient,
                        gen: gen - 1,
                    });
                }
            }
            Instruction::RequestLeave {
                leaving,
                recipient,
                gen,
            } => {
                if leaving > 0 && recipient > 0 {
                    shrunk_ops.push(Instruction::RequestLeave {
                        leaving: leaving - 1,
                        recipient: recipient - 1,
                        gen,
                    });
                }
                if leaving > 0 {
                    shrunk_ops.push(Instruction::RequestLeave {
                        leaving: leaving - 1,
                        recipient,
                        gen,
                    });
                }
                if recipient > 0 {
                    shrunk_ops.push(Instruction::RequestLeave {
                        leaving,
                        recipient: recipient - 1,
                        gen,
                    });
                }
                if gen > 0 {
                    shrunk_ops.push(Instruction::RequestLeave {
                        leaving,
                        recipient,
                        gen: gen - 1,
                    });
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
    let mut net = Net::with_procs(2);
    let p0 = net.procs[0].public_key_share();
    let p1 = net.procs[1].public_key_share();

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

    loop {
        net.drain_queued_packets()?;
        for i in 0..net.procs.len() {
            for j in 0..net.procs.len() {
                net.enqueue_anti_entropy(i, j);
            }
        }
        if net.packets.is_empty() {
            break;
        }
    }

    for p in net.procs.iter() {
        assert!(p.history.iter().all(|(_, v)| v.is_super_majority_ballot()));
    }
    Ok(())
}

#[test]
fn test_interpreter_qc2() -> Result<(), Error> {
    let mut net = Net::with_procs(3);
    let p0 = net.procs[0].public_key_share();
    let p1 = net.procs[1].public_key_share();
    let p2 = net.procs[2].public_key_share();

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

    loop {
        net.drain_queued_packets()?;
        for i in 0..net.procs.len() {
            for j in 0..net.procs.len() {
                net.enqueue_anti_entropy(i, j);
            }
        }
        if net.packets.is_empty() {
            break;
        }
    }

    // We should have no more pending votes.
    for p in net.procs.iter() {
        assert_eq!(p.votes, Default::default());
    }

    Ok(())
}

#[quickcheck]
fn prop_interpreter(n: u8, instructions: Vec<Instruction>) -> eyre::Result<TestResult> {
    fn super_majority(m: usize, n: usize) -> bool {
        3 * m > 2 * n
    }
    let n = n.min(7);

    if n == 0 || instructions.len() > 12 {
        return Ok(TestResult::discard());
    }

    let mut net = Net::with_procs(n as usize);

    // Assume procs[0] is the genesis proc. (trusts itself)
    let gen_proc = net.genesis()?;
    for proc in net.procs.iter_mut() {
        proc.force_join(gen_proc);
    }

    for instruction in instructions {
        match instruction {
            Instruction::RequestJoin {
                joining,
                recipient,
                gen,
            } => {
                // p requests to join q
                let joining = net.procs[joining.min(n - 1) as usize].public_key_share();
                let reconfig = Reconfig::Join(joining);

                let recipient = &mut net.procs[recipient.min(n - 1) as usize];
                let recipient_pks = recipient.public_key_share();
                let signed_vote = recipient.sign_vote(Vote {
                    gen,
                    ballot: Ballot::Propose(reconfig),
                })?;
                match recipient.cast_vote(signed_vote.clone()) {
                    Ok(propose_vote_msgs) => {
                        let propose_packets =
                            propose_vote_msgs.into_iter().map(|vote_msg| Packet {
                                source: recipient_pks,
                                vote_msg,
                            });
                        net.reconfigs_by_gen
                            .entry(signed_vote.vote.gen)
                            .or_default()
                            .insert(reconfig);
                        net.enqueue_packets(propose_packets);
                    }
                    Err(Error::JoinRequestForExistingMember { .. }) => {
                        assert!(recipient.members(recipient.gen)?.contains(&joining));
                    }
                    Err(Error::VoteFromNonMember { .. }) => {
                        assert!(!recipient
                            .members(recipient.gen)?
                            .contains(&recipient.public_key_share()));
                    }
                    Err(Error::ExistingVoteIncompatibleWithNewVote { existing_vote }) => {
                        // This proc has already committed to a vote this round
                        assert_eq!(
                            recipient.votes.get(&recipient.public_key_share()),
                            Some(&existing_vote)
                        );
                    }
                    Err(err) => {
                        // invalid request.
                        panic!("Failure to reconfig is not handled yet: {:?}", err);
                    }
                }
            }
            Instruction::RequestLeave {
                leaving,
                recipient,
                gen,
            } => {
                let leaving = net.procs[leaving.min(n - 1) as usize].public_key_share();
                let reconfig = Reconfig::Leave(leaving);

                let recipient = &mut net.procs[recipient.min(n - 1) as usize];
                let recipient_pks = recipient.public_key_share();
                let signed_vote = recipient.sign_vote(Vote {
                    gen,
                    ballot: Ballot::Propose(reconfig),
                })?;
                match recipient.cast_vote(signed_vote.clone()) {
                    Ok(propose_vote_msgs) => {
                        let propose_packets =
                            propose_vote_msgs.into_iter().map(|vote_msg| Packet {
                                source: recipient_pks,
                                vote_msg,
                            });
                        net.reconfigs_by_gen
                            .entry(signed_vote.vote.gen)
                            .or_default()
                            .insert(reconfig);
                        net.enqueue_packets(propose_packets);
                    }
                    Err(Error::LeaveRequestForNonMember { .. }) => {
                        assert!(!recipient.members(recipient.gen)?.contains(&leaving));
                    }
                    Err(Error::VoteFromNonMember { .. }) => {
                        assert!(!recipient
                            .members(recipient.gen)?
                            .contains(&recipient.public_key_share()));
                    }
                    Err(Error::ExistingVoteIncompatibleWithNewVote { existing_vote }) => {
                        // This proc has already committed to a vote
                        assert_eq!(
                            recipient.votes.get(&recipient.public_key_share()),
                            Some(&existing_vote)
                        );
                    }
                    Err(err) => {
                        // invalid request.
                        panic!("Leave Failure is not handled yet: {:?}", err);
                    }
                }
            }
            Instruction::DeliverPacketFromSource(source_idx) => {
                // deliver packet
                let source = net.procs[source_idx.min(n - 1) as usize].public_key_share();
                net.deliver_packet_from_source(source)?;
            }
            Instruction::AntiEntropy(gen, p_idx, q_idx) => {
                let p = &net.procs[p_idx.min(n - 1) as usize];
                let q_actor = net.procs[q_idx.min(n - 1) as usize].public_key_share();
                let p_actor = p.public_key_share();
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

    loop {
        net.drain_queued_packets()?;
        for i in 0..net.procs.len() {
            for j in 0..net.procs.len() {
                net.enqueue_anti_entropy(i, j);
            }
        }
        if net.packets.is_empty() {
            break;
        }
    }

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
        let members_at_prev_gen = net.members_at_gen[&(gen - 1)].clone();
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
    actor_idx: usize,
    members: u8,
) -> Result<TestResult, Error> {
    if members > 7 - 1 {
        // make sure there's room for the joining proc
        return Ok(TestResult::discard());
    }

    let mut proc = random_proc();

    let trusted_actors: Vec<_> = (0..members)
        .map(|_| random_pks())
        .chain(vec![proc.public_key_share()])
        .collect();

    for a in trusted_actors.iter() {
        proc.force_join(*a);
    }

    let all_actors = {
        let mut actors = trusted_actors;
        actors.push(random_pks());
        actors
    };

    let actor = all_actors[actor_idx % all_actors.len()];
    let reconfig = match join_or_leave {
        true => Reconfig::Join(actor),
        false => Reconfig::Leave(actor),
    };

    let valid_res = proc.validate_reconfig(&reconfig);
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
