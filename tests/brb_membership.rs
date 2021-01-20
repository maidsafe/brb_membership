use std::collections::{BTreeMap, BTreeSet};

mod net;
use crate::net::{Net, Packet};

//use brb_membership::{Actor, Ballot, Error, Generation, Reconfig, SigningActor, State, Vote};
use brb_membership::actor::ed25519::{Actor, Sig, SigningActor};
use brb_membership::{Generation, SigningActor as SigningActorTrait};
use crdts::quickcheck::{quickcheck, Arbitrary, Gen, TestResult};
use signature::Signer;

type Vote = brb_membership::Vote<Actor, Sig>;
type State = brb_membership::State<Actor, brb_membership::actor::ed25519::SigningActor, Sig>;
type Reconfig = brb_membership::Reconfig<Actor>;
type Error = brb_membership::Error<Actor, Sig>;
type Ballot = brb_membership::Ballot<Actor, Sig>;

#[test]
fn test_reject_changing_reconfig_when_one_is_in_progress() -> Result<(), Error> {
    let mut proc = State::default();
    proc.force_join(proc.id.actor());
    proc.propose(Reconfig::Join(Actor::default()))?;
    assert!(matches!(
        proc.propose(Reconfig::Join(Actor::default())),
        Err(Error::ExistingVoteIncompatibleWithNewVote { .. })
    ));
    Ok(())
}

#[test]
fn test_reject_vote_from_non_member() -> Result<(), Error> {
    let mut net = Net::with_procs(2);
    net.procs[1].faulty = true;
    let p0 = net.procs[0].id.actor();
    let p1 = net.procs[1].id.actor();
    net.force_join(p1, p0);
    net.force_join(p1, p1);

    let resp = net.procs[1].propose(Reconfig::Join(Default::default()))?;
    net.enqueue_packets(resp.into_iter().map(|vote_msg| Packet {
        source: p1,
        vote_msg,
    }));
    net.drain_queued_packets()?;
    Ok(())
}

#[test]
fn test_reject_new_join_if_we_are_at_capacity() {
    let mut proc = State {
        forced_reconfigs: vec![(
            0,
            (0..7).map(|_| Reconfig::Join(Actor::default())).collect(),
        )]
        .into_iter()
        .collect(),
        ..State::default()
    };
    proc.force_join(proc.id.actor());

    assert!(matches!(
        proc.propose(Reconfig::Join(Actor::default())),
        Err(Error::MembersAtCapacity { .. })
    ));

    assert!(proc
        .propose(Reconfig::Leave(
            proc.members(proc.gen).unwrap().into_iter().next().unwrap()
        ))
        .is_ok())
}

#[test]
fn test_reject_join_if_actor_is_already_a_member() {
    let mut proc = State {
        forced_reconfigs: vec![(
            0,
            (0..1).map(|_| Reconfig::Join(Actor::default())).collect(),
        )]
        .into_iter()
        .collect(),
        ..State::default()
    };
    proc.force_join(proc.id.actor());

    let member = proc.members(proc.gen).unwrap().into_iter().next().unwrap();
    assert!(matches!(
        proc.propose(Reconfig::Join(member)),
        Err(Error::JoinRequestForExistingMember { .. })
    ));
}

#[test]
fn test_reject_leave_if_actor_is_not_a_member() {
    let mut proc = State {
        forced_reconfigs: vec![(
            0,
            (0..1).map(|_| Reconfig::Join(Actor::default())).collect(),
        )]
        .into_iter()
        .collect(),
        ..State::default()
    };
    proc.force_join(proc.id.actor());

    let leaving_actor = Actor::default();
    let resp = proc.propose(Reconfig::Leave(leaving_actor));
    println!("Proc state {:#?}", proc);
    println!("PROPOSE RESP: {:?}", resp);
    assert!(matches!(resp, Err(Error::LeaveRequestForNonMember { .. })));
}

#[test]
fn test_handle_vote_rejects_packet_from_previous_gen() -> Result<(), Error> {
    let mut net = Net::with_procs(2);
    let a_0 = net.procs[0].id.actor();
    let a_1 = net.procs[1].id.actor();
    net.procs[0].force_join(a_0);
    net.procs[0].force_join(a_1);
    net.procs[1].force_join(a_0);
    net.procs[1].force_join(a_1);

    let packets = net.procs[0]
        .propose(Reconfig::Join(Actor::default()))
        .unwrap()
        .into_iter()
        .map(|vote_msg| Packet {
            source: a_0,
            vote_msg,
        })
        .collect::<Vec<_>>();

    let mut stale_packets = net.procs[1]
        .propose(Reconfig::Join(Actor::default()))
        .unwrap()
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

    println!("net: {:#?}", net);
    let vote = stale_packets.pop().unwrap().vote_msg.vote;

    assert!(matches!(
        net.procs[0].handle_vote(vote),
        Err(Error::VoteNotForNextGeneration {
            vote_gen: 1,
            gen: 1,
            pending_gen: 1,
        })
    ));

    Ok(())
}

#[test]
fn test_reject_votes_with_invalid_signatures() {
    let mut proc = State::default();
    let ballot = Ballot::Propose(Reconfig::Join(Default::default()));
    let gen = proc.gen + 1;
    let voter = Default::default();
    let bytes = bincode::serialize(&(&ballot, &gen)).unwrap();
    let sig = SigningActor::default().sign(&bytes);
    let resp = proc.handle_vote(Vote {
        ballot,
        gen,
        voter,
        sig,
    });

    assert!(matches!(resp, Err(Error::InvalidSignature(_))));
}

#[test]
fn test_split_vote() -> Result<(), Error> {
    for nprocs in 1..7 {
        let mut net = Net::with_procs(nprocs * 2);
        for i in 0..nprocs {
            let i_actor = net.procs[i].id.actor();
            for j in 0..(nprocs * 2) {
                net.procs[j].force_join(i_actor);
            }
        }

        let joining_members: Vec<Actor> =
            net.procs[nprocs..].iter().map(|p| p.id.actor()).collect();
        for (i, member) in joining_members.into_iter().enumerate() {
            let a_i = net.procs[i].id.actor();
            let packets = net.procs[i]
                .propose(Reconfig::Join(member))
                .unwrap()
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
        let expected_members = net.procs[0].members(proc0_gen).unwrap();
        assert!(expected_members.len() > nprocs);

        for i in 0..nprocs {
            let proc_i_gen = net.procs[i].gen;
            assert_eq!(proc_i_gen, proc0_gen);
            assert_eq!(net.procs[i].members(proc_i_gen).unwrap(), expected_members);
        }

        for member in expected_members.iter() {
            let p = net.procs.iter().find(|p| &p.id.actor() == member).unwrap();
            assert_eq!(p.members(p.gen).unwrap(), expected_members);
        }
    }

    Ok(())
}

#[test]
fn test_round_robin_split_vote() -> Result<(), Error> {
    for nprocs in 1..7 {
        let mut net = Net::with_procs(nprocs * 2);
        for i in 0..nprocs {
            let i_actor = net.procs[i].id.actor();
            for j in 0..(nprocs * 2) {
                net.procs[j].force_join(i_actor);
            }
        }

        let joining_members: Vec<Actor> =
            net.procs[nprocs..].iter().map(|p| p.id.actor()).collect();
        for (i, member) in joining_members.into_iter().enumerate() {
            let a_i = net.procs[i].id.actor();
            let packets = net.procs[i]
                .propose(Reconfig::Join(member))
                .unwrap()
                .into_iter()
                .map(|vote_msg| Packet {
                    source: a_i,
                    vote_msg,
                });
            net.enqueue_packets(packets);
        }

        while !net.packets.is_empty() {
            println!("{:?}", net);
            for i in 0..net.procs.len() {
                net.deliver_packet_from_source(net.procs[i].id.actor())?;
            }
        }

        for i in 0..(nprocs * 2) {
            for j in 0..(nprocs * 2) {
                net.enqueue_anti_entropy(i, j);
            }
        }
        net.drain_queued_packets()?;

        net.generate_msc(&format!("round_robin_split_vote_{}.msc", nprocs));

        let proc_0_gen = net.procs[0].gen;
        let expected_members = net.procs[0].members(proc_0_gen).unwrap();
        assert!(expected_members.len() > nprocs);

        for i in 0..nprocs {
            let gen = net.procs[i].gen;
            assert_eq!(net.procs[i].members(gen).unwrap(), expected_members);
        }

        for member in expected_members.iter() {
            let p = net.procs.iter().find(|p| &p.id.actor() == member).unwrap();
            assert_eq!(p.members(p.gen).unwrap(), expected_members);
        }
    }
    Ok(())
}

#[test]
fn test_onboarding_across_many_generations() -> Result<(), Error> {
    let mut net = Net::with_procs(3);
    let p0 = net.procs[0].id.actor();
    let p1 = net.procs[1].id.actor();
    let p2 = net.procs[2].id.actor();

    for i in 0..3 {
        net.procs[i].force_join(p0);
    }
    let packets = net.procs[0]
        .propose(Reconfig::Join(p1))
        .unwrap()
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
        .propose(Reconfig::Join(p2))
        .unwrap()
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
    net.drain_queued_packets()?;

    let mut procs_by_gen: BTreeMap<Generation, Vec<State>> = Default::default();

    net.generate_msc("onboarding.msc");

    for proc in net.procs {
        procs_by_gen.entry(proc.gen).or_default().push(proc);
    }

    let max_gen = procs_by_gen.keys().last().unwrap();
    // The last gen should have at least a super majority of nodes
    let current_members: BTreeSet<_> = procs_by_gen[max_gen].iter().map(|p| p.id.actor()).collect();

    for proc in procs_by_gen[max_gen].iter() {
        assert_eq!(current_members, proc.members(proc.gen).unwrap());
    }
    Ok(())
}

#[test]
fn test_simple_proposal() -> Result<(), Error> {
    let mut net = Net::with_procs(4);
    for i in 0..4 {
        let a_i = net.procs[i].id.actor();
        for j in 0..3 {
            let a_j = net.procs[j].id.actor();
            net.force_join(a_i, a_j);
        }
    }

    let proc_0 = net.procs[0].id.actor();
    let proc_3 = net.procs[3].id.actor();
    let packets = net.procs[0]
        .propose(Reconfig::Join(proc_3))
        .unwrap()
        .into_iter()
        .map(|vote_msg| Packet {
            source: proc_0,
            vote_msg,
        });
    net.enqueue_packets(packets);
    net.drain_queued_packets()?;

    net.generate_msc("simple_join.msc");

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
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
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
fn test_prop_interpreter_qc1() -> Result<(), Error> {
    let mut net = Net::with_procs(2);
    let p0 = net.procs[0].id.actor();
    let p1 = net.procs[1].id.actor();

    for proc in net.procs.iter_mut() {
        proc.force_join(p0);
    }

    let reconfig = Reconfig::Join(p1);
    let q = &mut net.procs[0];
    let propose_vote_msgs = q.propose(reconfig.clone()).unwrap();
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
fn test_prop_interpreter_qc2() -> Result<(), Error> {
    let mut net = Net::with_procs(3);
    let p0 = net.procs[0].id.actor();
    let p1 = net.procs[1].id.actor();
    let p2 = net.procs[2].id.actor();

    // Assume procs[0] is the genesis proc.
    for proc in net.procs.iter_mut() {
        proc.force_join(p0);
    }

    let propose_packets = net.procs[0]
        .propose(Reconfig::Join(p1))
        .unwrap()
        .into_iter()
        .map(|vote_msg| Packet {
            source: p0,
            vote_msg,
        });
    net.enqueue_packets(propose_packets);

    net.deliver_packet_from_source(p0)?;
    net.deliver_packet_from_source(p0)?;

    let propose_packets = net.procs[0]
        .propose(Reconfig::Join(p2))
        .unwrap()
        .into_iter()
        .map(|vote_msg| Packet {
            source: p0,
            vote_msg,
        });
    net.enqueue_packets(propose_packets);

    println!("{:#?}", net);
    println!("--  [DRAINING]  --");

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

quickcheck! {
    fn prop_interpreter(n: usize, instructions: Vec<Instruction>) -> Result<TestResult, Error> {
        fn super_majority(m: usize, n: usize) -> bool {
            3 * m > 2 * n
        }
        let n = n.min(7);
        if n == 0 || instructions.len() > 12{
            return Ok(TestResult::discard());
        }

        println!("--------------------------------------");

        let mut net = Net::with_procs(n);

        // Assume procs[0] is the genesis proc. (trusts itself)
        let gen_proc = net.genesis()?;
        for proc in net.procs.iter_mut() {
            proc.force_join(gen_proc);
        }


        for instruction in instructions {
            match instruction {
                Instruction::RequestJoin(p_idx, q_idx) => {
                    // p requests to join q
                    let p = net.procs[p_idx.min(n - 1)].id.actor();
                    let reconfig = Reconfig::Join(p);

                    let q = &mut net.procs[q_idx.min(n - 1)];
                    let q_actor = q.id.actor();
                    match q.propose(reconfig.clone()) {
                        Ok(propose_vote_msgs) => {
                            let propose_packets = propose_vote_msgs
                                .into_iter()
                                .map(|vote_msg| Packet { source: q_actor, vote_msg });
                            net.reconfigs_by_gen.entry(q.pending_gen).or_default().insert(reconfig);
                            net.enqueue_packets(propose_packets);
                        }
                        Err(Error::JoinRequestForExistingMember { .. }) => {
                            assert!(q.members(q.gen).unwrap().contains(&p));
                        }
                        Err(Error::VoteFromNonMember { .. }) => {
                            assert!(!q.members(q.gen).unwrap().contains(&q.id.actor()));
                        }
                        Err(Error::ExistingVoteIncompatibleWithNewVote { existing_vote }) => {
                            // This proc has already committed to a vote this round
                            assert_eq!(q.votes.get(&q.id.actor()), Some(&existing_vote));
                        }
                        Err(err) => {
                            // invalid request.
                            panic!("Failure to reconfig is not handled yet: {:?}", err);
                        }
                    }
                },
                Instruction::RequestLeave(p_idx, q_idx) => {
                    // p requests to leave q
                    let p = net.procs[p_idx.min(n - 1)].id.actor();
                    let reconfig = Reconfig::Leave(p);

                    let q = &mut net.procs[q_idx.min(n - 1)];
                    let q_actor = q.id.actor();
                    match q.propose(reconfig.clone()) {
                        Ok(propose_vote_msgs) => {
                            let propose_packets = propose_vote_msgs.
                                into_iter().
                                map(|vote_msg| Packet { source: q_actor, vote_msg });
                            net.reconfigs_by_gen.entry(q.pending_gen).or_default().insert(reconfig);
                            net.enqueue_packets(propose_packets);
                        }
                        Err(Error::LeaveRequestForNonMember { .. }) => {
                            assert!(!q.members(q.gen).unwrap().contains(&p));
                        }
                        Err(Error::VoteFromNonMember { .. }) => {
                            assert!(!q.members(q.gen).unwrap().contains(&q.id.actor()));
                        }
                        Err(Error::ExistingVoteIncompatibleWithNewVote { existing_vote }) => {
                            // This proc has already committed to a vote
                            assert_eq!(q.votes.get(&q.id.actor()), Some(&existing_vote));
                        }
                        Err(err) => {
                            // invalid request.
                            panic!("Leave Failure is not handled yet: {:?}", err);
                        }
                    }
                },
                Instruction::DeliverPacketFromSource(source_idx) => {
                    // deliver packet
                    let source = net.procs[source_idx.min(n - 1)].id.actor();
                    net.deliver_packet_from_source(source)?;
                }
                Instruction::AntiEntropy(gen, p_idx, q_idx) => {
                    let p = &net.procs[p_idx.min(n - 1)];
                    let q_actor = net.procs[q_idx.min(n - 1)].id.actor();
                    let p_actor = p.id.actor();
                    let anti_entropy_packets = p.anti_entropy(gen, q_actor)
                        .into_iter()
                        .map(|vote_msg| Packet { source: p_actor, vote_msg });
                    net.enqueue_packets(anti_entropy_packets);
                }
            }
        }

        println!("{:#?}", net);
        println!("--  [DRAINING]  --");

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
            net.drain_queued_packets()?;
        }

        // We should have no more pending votes.
        for p in net.procs.iter() {
            assert_eq!(p.votes, Default::default());
        }

        let mut procs_by_gen: BTreeMap<Generation, Vec<State>> = Default::default();

        for proc in net.procs {
            procs_by_gen.entry(proc.gen).or_default().push(proc);
        }

        let max_gen = procs_by_gen.keys().last().unwrap();

        // And procs at each generation should have agreement on members
        for (gen, procs) in procs_by_gen.iter() {
            let mut proc_iter = procs.iter();
            let first = proc_iter.next().unwrap();
            if *gen > 0 {
                // TODO: remove this gen > 0 constraint
                assert_eq!(first.members(first.gen).unwrap(), net.members_at_gen[&gen]);
            }
            for proc in proc_iter {
                assert_eq!(first.members(first.gen).unwrap(), proc.members(proc.gen).unwrap(), "gen: {}", gen);
            }
        }

        // TODO: everyone that a proc at G considers a member is also at generation G

        for (gen, reconfigs) in net.reconfigs_by_gen.iter() {
            let members_at_prev_gen = net.members_at_gen[&(gen - 1)].clone();
            let members_at_curr_gen = net.members_at_gen[&gen].clone();
            let mut reconfigs_applied: BTreeSet<&Reconfig> = Default::default();
            for reconfig in reconfigs {
                match reconfig {
                    Reconfig::Join(p) => {
                        assert!(!members_at_prev_gen.contains(&p));
                        if members_at_curr_gen.contains(&p) {
                            reconfigs_applied.insert(reconfig);
                        }
                    }
                    Reconfig::Leave(p) => {
                        assert!(members_at_prev_gen.contains(&p));
                        if !members_at_curr_gen.contains(&p) {
                            reconfigs_applied.insert(reconfig);
                        }
                    }
                }
            }

            assert_ne!(reconfigs_applied, Default::default());
        }

        let proc_at_max_gen = procs_by_gen[max_gen].get(0).unwrap();
        assert!(super_majority(procs_by_gen[max_gen].len(), proc_at_max_gen.members(*max_gen).unwrap().len()), "{:?}", procs_by_gen);

        Ok(TestResult::passed())
    }

    fn prop_validate_reconfig(join_or_leave: bool, actor_idx: usize, members: u8) -> TestResult {
        if members + 1 > 7 {
            // + 1 from the initial proc
            return TestResult::discard();
        }

        let mut proc = State::default();

        let trusted_actors: Vec<_> = (0..members)
            .map(|_| Actor::default())
            .chain(vec![proc.id.actor()])
            .collect();

        for a in trusted_actors.iter() {
            proc.force_join(*a);
        }

        let all_actors = {
            let mut actors = trusted_actors;
            actors.push(Actor::default());
            actors
        };

        let actor = all_actors[actor_idx % all_actors.len()];
        let reconfig = match join_or_leave {
            true => Reconfig::Join(actor),
            false => Reconfig::Leave(actor),
        };

        let valid_res = proc.validate_reconfig(&reconfig);
        let proc_members = proc.members(proc.gen).unwrap();
        match reconfig {
            Reconfig::Join(actor) => {
                if proc_members.contains(&actor) {
                    assert!(matches!(valid_res, Err(Error::JoinRequestForExistingMember {..})));
                } else if members + 1 == 7 {
                    assert!(matches!(valid_res, Err(Error::MembersAtCapacity {..})));
                } else {
                    assert!(valid_res.is_ok());
                }
            }
            Reconfig::Leave(actor) => {
                if proc_members.contains(&actor) {
                    assert!(valid_res.is_ok());
                } else {
                    assert!(matches!(valid_res, Err(Error::LeaveRequestForNonMember {..})));

                }
            }
        };

        TestResult::passed()
    }
}
