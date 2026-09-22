//! Minimal SDS: Lamport clock, causal history, gap detection. No bloom filter or repair.

use std::collections::{HashSet, VecDeque};

use chat_proto::logoschat::reliability::{HistoryEntry, ReliablePayload};

use crate::construction::hash;

/// Most-recently-seen messages referenced by each outbound message.
pub const HISTORY_LEN: usize = 10;

#[derive(Debug)]
pub struct Sds {
    channel_id: String,
    sender_id: String,
    lamport: i32,
    seen: HashSet<String>,
    recent: VecDeque<HistoryEntry>,
}

impl Sds {
    pub fn new(channel_id: &str, sender_id: &str) -> Self {
        Self {
            channel_id: channel_id.to_owned(),
            sender_id: sender_id.to_owned(),
            lamport: 0,
            seen: HashSet::new(),
            recent: VecDeque::new(),
        }
    }

    /// Header for an outbound message, `content` unset. Call [`Sds::record`] once framed.
    pub fn outbound(&mut self, content_ciphertext: &[u8]) -> ReliablePayload {
        self.lamport += 1;
        let mut id_input =
            format!("{}|{}|{}|", self.channel_id, self.sender_id, self.lamport).into_bytes();
        id_input.extend_from_slice(content_ciphertext);
        ReliablePayload {
            message_id: hex::encode(&hash(&id_input)[..16]),
            channel_id: self.channel_id.clone(),
            sender_id: self.sender_id.clone(),
            lamport_timestamp: self.lamport,
            causal_history: self.recent.iter().cloned().collect(),
            ..Default::default()
        }
    }

    /// Marks a message seen; `hint` is how others can fetch it from a store.
    pub fn record(&mut self, message: &ReliablePayload, hint: Vec<u8>) {
        self.lamport = self.lamport.max(message.lamport_timestamp);
        if self.seen.insert(message.message_id.clone()) {
            self.recent.push_back(HistoryEntry {
                message_id: message.message_id.clone(),
                retrieval_hint: hint.into(),
                sender_id: message.sender_id.clone(),
            });
            if self.recent.len() > HISTORY_LEN {
                self.recent.pop_front();
            }
        }
    }

    pub fn is_seen(&self, message_id: &str) -> bool {
        self.seen.contains(message_id)
    }

    /// Causal-history entries this member has not seen.
    pub fn missing(&self, message: &ReliablePayload) -> Vec<HistoryEntry> {
        message
            .causal_history
            .iter()
            .filter(|e| !self.seen.contains(&e.message_id))
            .cloned()
            .collect()
    }
}
