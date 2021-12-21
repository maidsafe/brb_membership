use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::File;
use std::io::Write;

use blsttc::{PublicKeyShare, SecretKeySet, SecretKeyShare};
//use brb_membership::{Error, Generation, Reconfig, State, VoteMsg};
use brb_membership::{Error, Generation, Reconfig, SignedVote, State, VotePacket};

pub fn random_sks() -> SecretKeyShare {
    SecretKeySet::random(0, &mut rand::thread_rng()).secret_key_share(0usize)
}

pub fn random_pks() -> PublicKeyShare {
    random_sks().public_key_share()
}

pub fn random_proc() -> State {
    State {
        secret_key_share: random_sks(),
        gen: 0,
        pending_gen: 0,
        forced_reconfigs: Default::default(),
        history: Default::default(),
        votes: Default::default(),
        faulty: false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub source: PublicKeyShare,
    pub vote_msg: VotePacket,
}

// #[derive(Debug, Clone)]
// enum StateChange {
//     SetGen(u8),
//     SetPendingGen(u8),
//     AddForcedReconfig {
//         gen: u8,
//         reconfig: Reconfig,
//     },
//     RemoveForcedReconfig {
//         gen: u8,
//         reconfig: Reconfig,
//     },
//     SetHistory {
//         gen: u8,
//         vote: SignedVote,
//     },
//     RemoveHistory {
//         gen: u8,
//     },
//     SetVote {
//         source: PublicKeyShare,
//         vote: SignedVote,
//     },
//     DropVote {
//         source: PublicKeyShare,
//     },
// }

#[derive(Default, Debug)]
pub struct Net {
    pub procs: Vec<State>,
    pub reconfigs_by_gen: BTreeMap<Generation, BTreeSet<Reconfig>>,
    pub members_at_gen: BTreeMap<Generation, BTreeSet<PublicKeyShare>>,
    pub packets: BTreeMap<PublicKeyShare, VecDeque<Packet>>,
    pub delivered_packets: Vec<Packet>,
    pub seen_votes: BTreeSet<SignedVote>,
}

impl Net {
    pub fn with_procs(n: usize) -> Self {
        let mut procs: Vec<_> = (0..n).into_iter().map(|_| random_proc()).collect();
        procs.sort_by_key(|p| p.public_key_share());
        Self {
            procs,
            ..Default::default()
        }
    }

    pub fn genesis(&self) -> Result<PublicKeyShare, Error> {
        self.procs
            .get(0)
            .map(|p| p.public_key_share())
            .ok_or(Error::NoMembers)
    }

    // pub fn gen_state_change(&self, mut rng: impl Rng) -> StateChange {
    //     todo!()
    // }

    // pub fn gen_faulty_vote(&self, mut rng: impl Rng) -> Vote {
    //     Vote {
    //         gen: rng.gen(),
    //         ballot: todo!(),
    //     }
    // }

    pub fn deliver_packet_from_source(&mut self, source: PublicKeyShare) -> Result<(), Error> {
        let packet = match self.packets.get_mut(&source).map(|ps| ps.pop_front()) {
            Some(Some(p)) => p,
            _ => return Ok(()), // nothing to do
        };
        self.purge_empty_queues();

        let dest = packet.vote_msg.dest;
        println!("delivering {:?}->{:?} {:#?}", packet.source, dest, packet);

        self.delivered_packets.push(packet.clone());

        let dest_proc_opt = self.procs.iter_mut().find(|p| p.public_key_share() == dest);

        let dest_proc = match dest_proc_opt {
            Some(proc) => proc,
            None => {
                println!("[NET] destination proc does not exist, dropping packet");
                return Ok(());
            }
        };

        let dest_members = dest_proc.members(dest_proc.gen)?;
        let vote = packet.vote_msg.vote;

        let resp = dest_proc.handle_vote(vote);
        println!("[NET] resp: {:#?}", resp);
        match resp {
            Ok(vote_msgs) => {
                let dest_actor = dest_proc.public_key_share();
                self.enqueue_packets(vote_msgs.into_iter().map(|vote_msg| Packet {
                    source: dest_actor,
                    vote_msg,
                }));
            }
            Err(Error::VoteFromNonMember { voter, members }) => {
                assert_eq!(members, dest_members);
                assert!(
                    !dest_members.contains(&voter),
                    "{:?} should not be in {:?}",
                    source,
                    dest_members
                );
            }
            Err(Error::VoteNotForNextGeneration {
                vote_gen,
                gen,
                pending_gen,
            }) => {
                assert!(vote_gen <= gen || vote_gen > pending_gen);
                assert_eq!(dest_proc.gen, gen);
                assert_eq!(dest_proc.pending_gen, pending_gen);
            }
            Err(err) => return Err(err),
        }

        match self.procs.iter().find(|p| p.public_key_share() == dest) {
            Some(proc) if !proc.faulty => {
                let (mut proc_members, gen) = (proc.members(proc.gen)?, proc.gen);

                let expected_members_at_gen = self
                    .members_at_gen
                    .entry(gen)
                    .or_insert_with(|| proc_members.clone());

                assert_eq!(expected_members_at_gen, &mut proc_members);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    pub fn enqueue_packets(&mut self, packets: impl IntoIterator<Item = Packet>) {
        for packet in packets {
            self.packets
                .entry(packet.source)
                .or_default()
                .push_back(packet)
        }
    }

    pub fn drain_queued_packets(&mut self) -> Result<(), Error> {
        while let Some(source) = self.packets.keys().next().cloned() {
            self.deliver_packet_from_source(source)?;
            self.purge_empty_queues();
        }
        Ok(())
    }

    pub fn purge_empty_queues(&mut self) {
        self.packets = core::mem::take(&mut self.packets)
            .into_iter()
            .filter(|(_, queue)| !queue.is_empty())
            .collect();
    }

    pub fn force_join(&mut self, p: PublicKeyShare, q: PublicKeyShare) {
        if let Some(proc) = self
            .procs
            .iter_mut()
            .find(|proc| proc.public_key_share() == p)
        {
            proc.force_join(q);
        }
    }

    pub fn enqueue_anti_entropy(&mut self, i: usize, j: usize) {
        let i_gen = self.procs[i].gen;
        let i_actor = self.procs[i].public_key_share();
        let j_actor = self.procs[j].public_key_share();

        self.enqueue_packets(self.procs[j].anti_entropy(i_gen, i_actor).into_iter().map(
            |vote_msg| Packet {
                source: j_actor,
                vote_msg,
            },
        ));
    }

    pub fn generate_msc(&self, name: &str) -> Result<(), Error> {
        // See: http://www.mcternan.me.uk/mscgen/
        let mut msc = String::from(
            "
msc {\n
  hscale = \"2\";\n
",
        );
        let procs = self
            .procs
            .iter()
            .map(|p| p.public_key_share())
            .collect::<BTreeSet<_>>() // sort by actor id
            .into_iter()
            .map(|id| format!("{:?}", id))
            .collect::<Vec<_>>()
            .join(",");
        msc.push_str(&procs);
        msc.push_str(";\n");
        for packet in self.delivered_packets.iter() {
            msc.push_str(&format!(
                "{:?} -> {:?} [ label=\"{:?}\"];\n",
                packet.source, packet.vote_msg.dest, packet.vote_msg.vote
            ));
        }

        msc.push_str("}\n");

        // Replace process identifiers with friendlier numbers
        // 1, 2, 3 ... instead of i:3b2, i:7def, ...
        for (idx, proc_id) in self.procs.iter().map(|p| p.public_key_share()).enumerate() {
            let proc_id_as_str = format!("{:?}", proc_id);
            msc = msc.replace(&proc_id_as_str, &format!("{}", idx + 1));
        }

        let mut msc_file = File::create(name)?;
        msc_file.write_all(msc.as_bytes())?;
        Ok(())
    }
}
