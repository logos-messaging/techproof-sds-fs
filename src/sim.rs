//! A group on a lossy network. Every frame is archived; only online members get it live.

use std::collections::{BTreeMap, HashSet};

use crate::construction::Epoch;
use crate::member::{Frame, Member, Outbound, Receipt};
use crate::store::Store;

/// The simulator's omniscient record of a published frame.
#[derive(Clone, Debug)]
pub struct Published {
    pub sender: String,
    pub message_id: String,
    /// Epoch the header was sealed in.
    pub epoch: Epoch,
    pub kind: Kind,
    pub frame: Frame,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    App(String),
    Commit,
}

#[derive(Debug)]
pub struct Sim {
    lag: u64,
    members: BTreeMap<String, Member>,
    offline: HashSet<String>,
    store: Store,
    ledger: Vec<Published>,
    receipts: BTreeMap<String, Receipt>,
}

impl Sim {
    pub fn new(lag: u64, creator: &str) -> Self {
        let mut member = Member::new(creator, lag);
        member.create_group();
        Self {
            lag,
            members: BTreeMap::from([(creator.to_owned(), member)]),
            offline: HashSet::new(),
            store: Store::default(),
            ledger: Vec::new(),
            receipts: BTreeMap::new(),
        }
    }

    pub fn lag(&self) -> u64 {
        self.lag
    }

    pub fn member(&self, name: &str) -> &Member {
        &self.members[name]
    }

    pub fn member_mut(&mut self, name: &str) -> &mut Member {
        self.members.get_mut(name).expect("known member")
    }

    pub fn names(&self) -> Vec<String> {
        self.members.keys().cloned().collect()
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn ledger(&self) -> &[Published] {
        &self.ledger
    }

    pub fn is_online(&self, name: &str) -> bool {
        !self.offline.contains(name)
    }

    /// What each live recipient got from the last broadcast.
    pub fn receipt(&self, name: &str) -> Option<&Receipt> {
        self.receipts.get(name)
    }

    pub fn invite(&mut self, by: &str, who: &str) {
        let mut joiner = Member::new(who, self.lag);
        let (out, invite) = self.member_mut(by).add(joiner.key_package());
        self.broadcast(by, out, Kind::Commit);
        joiner.join(&invite);
        self.members.insert(who.to_owned(), joiner);
    }

    pub fn send(&mut self, from: &str, text: &str) -> Published {
        let out = self.member_mut(from).send(text);
        self.broadcast(from, out, Kind::App(text.to_owned()))
    }

    pub fn rotate(&mut self, by: &str) -> Published {
        let out = self.member_mut(by).rotate();
        self.broadcast(by, out, Kind::Commit)
    }

    pub fn remove(&mut self, by: &str, who: &str) -> Published {
        let out = self.member_mut(by).remove(who);
        self.broadcast(by, out, Kind::Commit)
    }

    pub fn set_online(&mut self, name: &str, online: bool) {
        if online {
            self.offline.remove(name);
        } else {
            self.offline.insert(name.to_owned());
        }
    }

    /// Back online, the client pulls the latest frame from the store.
    pub fn reconnect(&mut self, name: &str) -> Receipt {
        self.set_online(name, true);
        let latest = self.store.latest().expect("something published").clone();
        self.deliver(name, &latest)
    }

    /// Hands a frame straight to one member, bypassing the network.
    pub fn deliver(&mut self, to: &str, frame: &Frame) -> Receipt {
        let member = self.members.get_mut(to).expect("known member");
        member.receive(frame, &self.store)
    }

    fn broadcast(&mut self, from: &str, out: Outbound, kind: Kind) -> Published {
        let published = Published {
            sender: from.to_owned(),
            message_id: out.message_id,
            epoch: out.epoch,
            kind,
            frame: out.frame,
        };
        self.store.put(published.frame.clone());
        self.ledger.push(published.clone());
        self.receipts.clear();
        for (name, member) in &mut self.members {
            if name != from && !self.offline.contains(name) {
                let receipt = member.receive(&published.frame, &self.store);
                self.receipts.insert(name.clone(), receipt);
            }
        }
        published
    }
}
