use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Write;

use brb_membership::{Actor, Error, Generation, Reconfig, State, VoteMsg};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub source: Actor,
    pub vote_msg: VoteMsg,
}

#[derive(Default, Debug)]
pub struct Net {
    pub procs: Vec<State>,
    pub reconfigs_by_gen: BTreeMap<Generation, BTreeSet<Reconfig>>,
    pub members_at_gen: BTreeMap<Generation, BTreeSet<Actor>>,
    pub packets: BTreeMap<Actor, Vec<Packet>>,
    pub delivered_packets: Vec<Packet>,
}

impl Net {
    pub fn with_procs(n: usize) -> Self {
        let mut procs: Vec<_> = (0..n).into_iter().map(|_| State::default()).collect();
        procs.sort_by_key(|p| p.id.actor());
        Self {
            procs,
            ..Default::default()
        }
    }

    pub fn genesis(&self) -> Actor {
        assert!(!self.procs.is_empty());
        self.procs[0].id.actor()
    }

    pub fn deliver_packet_from_source(&mut self, source: Actor) {
        let packet = if let Some(packets) = self.packets.get_mut(&source) {
            assert!(!packets.is_empty());
            packets.remove(0)
        } else {
            return;
        };

        let dest = packet.vote_msg.dest;

        assert_eq!(packet.source, source);

        println!(
            "delivering {:?}->{:?} {:#?}",
            packet.source, packet.vote_msg.dest, packet
        );

        self.delivered_packets.push(packet.clone());

        self.packets = self
            .packets
            .clone()
            .into_iter()
            .filter(|(_, queue)| !queue.is_empty())
            .collect();

        assert_eq!(packet.source, source);

        let dest_proc_opt = self
            .procs
            .iter_mut()
            .find(|p| p.id.actor() == packet.vote_msg.dest);

        let dest_proc = match dest_proc_opt {
            Some(proc) => proc,
            None => {
                println!("[NET] destination proc does not exist, dropping packet");
                return;
            }
        };

        let dest_members = dest_proc.members(dest_proc.gen).unwrap();
        let vote = packet.vote_msg.vote;

        let resp = dest_proc.handle_vote(vote);
        println!("[NET] resp: {:#?}", resp);
        match resp {
            Ok(vote_msgs) => {
                let dest_actor = dest_proc.id.actor();
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
            Err(err) => {
                panic!("Unexpected err: {:?} {:?}", err, self);
            }
        }

        let proc = self.procs.iter().find(|p| p.id.actor() == dest).unwrap();
        if !proc.faulty {
            let (mut proc_members, gen) = (proc.members(proc.gen).unwrap(), proc.gen);

            let expected_members_at_gen = self
                .members_at_gen
                .entry(gen)
                .or_insert_with(|| proc_members.clone());

            assert_eq!(expected_members_at_gen, &mut proc_members);
        }
    }

    pub fn enqueue_packets(&mut self, packets: impl IntoIterator<Item = Packet>) {
        for packet in packets {
            self.packets.entry(packet.source).or_default().push(packet);
        }
    }

    pub fn drain_queued_packets(&mut self) {
        while !self.packets.is_empty() {
            let source = *self.packets.keys().next().unwrap();
            self.deliver_packet_from_source(source);
        }
    }

    pub fn force_join(&mut self, p: Actor, q: Actor) {
        if let Some(proc) = self.procs.iter_mut().find(|proc| proc.id.actor() == p) {
            proc.force_join(q);
        }
    }

    pub fn enqueue_anti_entropy(&mut self, i: usize, j: usize) {
        let i_gen = self.procs[i].gen;
        let i_actor = self.procs[i].id.actor();
        let j_actor = self.procs[j].id.actor();

        self.enqueue_packets(self.procs[j].anti_entropy(i_gen, i_actor).into_iter().map(
            |vote_msg| Packet {
                source: j_actor,
                vote_msg,
            },
        ));
    }

    pub fn generate_msc(&self, name: &str) {
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
            .map(|p| p.id.actor())
            .collect::<BTreeSet<_>>() // sort by actor id
            .into_iter()
            .map(|id| format!("{:?}", id))
            .collect::<Vec<_>>()
            .join(",");
        msc.push_str(&procs);
        msc.push_str(";\n");
        for packet in self.delivered_packets.iter() {
            msc.push_str(&format!(
                "{} -> {} [ label=\"{:?}\"];\n",
                packet.source, packet.vote_msg.dest, packet.vote_msg.vote
            ));
        }

        msc.push_str("}\n");

        // Replace process identifiers with friendlier numbers
        // 1, 2, 3 ... instead of i:3b2, i:7def, ...
        for (idx, proc_id) in self.procs.iter().map(|p| p.id.actor()).enumerate() {
            let proc_id_as_str = format!("{}", proc_id);
            msc = msc.replace(&proc_id_as_str, &format!("{}", idx + 1));
        }

        let mut msc_file = File::create(name).unwrap();
        msc_file.write_all(msc.as_bytes()).unwrap();
    }
}
