//! One MLS member running SDS, with headers sealed by SDS-FS.
//!
//! `epoch_secret` is the MLS exporter secret of the current epoch, so the ring
//! advances exactly when the MLS group does.

use std::collections::{HashSet, VecDeque};
use std::fmt;

use ed25519_dalek::{Signer as _, SigningKey};
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::*;
use openmls_libcrux_crypto::CryptoProvider as LibcruxCryptoProvider;
use openmls_memory_storage::MemoryStorage;
use openmls_traits::OpenMlsProvider;
use openmls_traits::signatures::{Signer, SignerError};
use prost::Message;

use crate::construction::{EncryptedSdsHeader, Epoch, KeyBundle, KeyRing, Opened, hash};
use crate::sds::Sds;
use crate::store::Store;

/// The suite libchat uses.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
const EXPORTER_LABEL: &str = "sds-fs epoch_secret";

/// On the wire: the encrypted header alongside the content ciphertext (an MLS message).
#[derive(Clone, PartialEq, Message)]
pub struct Frame {
    #[prost(message, optional, tag = "1")]
    pub header: Option<EncryptedSdsHeader>,
    #[prost(bytes = "vec", tag = "2")]
    pub content: Vec<u8>,
}

impl Frame {
    /// Transport hash: what a store indexes and a retrieval hint names.
    pub fn hint(&self) -> Vec<u8> {
        hash(&self.encode_to_vec()).to_vec()
    }
}

/// Welcome plus reliability keys, delivered 1:1 to the joiner.
#[derive(Clone, Debug)]
pub struct Invite {
    pub welcome: Vec<u8>,
    pub keys: KeyBundle,
}

#[derive(Clone, Debug)]
pub struct Outbound {
    pub frame: Frame,
    pub message_id: String,
    /// Epoch the header was sealed in.
    pub epoch: Epoch,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivered {
    pub message_id: String,
    pub sender: String,
    pub text: String,
    pub epoch: Epoch,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Receipt {
    /// No held key opens the header.
    Unreadable,
    Duplicate,
    Opened(Report),
}

impl Receipt {
    pub fn opened(&self) -> Option<&Report> {
        match self {
            Receipt::Opened(r) => Some(r),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Epoch whose key opened the incoming header.
    pub epoch: Epoch,
    /// In application order; includes messages recovered from the store.
    pub applied: Vec<Applied>,
    /// Referenced messages that could not be fetched or opened.
    pub dangling: usize,
}

impl Report {
    pub fn recovered(&self) -> usize {
        self.applied.iter().filter(|a| a.recovered).count()
    }

    pub fn rejected(&self) -> usize {
        self.applied
            .iter()
            .filter(|a| a.outcome == Outcome::Rejected)
            .count()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Applied {
    pub epoch: Epoch,
    pub message_id: String,
    pub recovered: bool,
    pub outcome: Outcome,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Message(String),
    Commit,
    /// Header opened, content did not (MLS rejected it).
    Rejected,
}

struct Provider {
    crypto: LibcruxCryptoProvider,
    storage: MemoryStorage,
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = LibcruxCryptoProvider;
    type RandProvider = LibcruxCryptoProvider;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

struct Ed25519(SigningKey);

impl Signer for Ed25519 {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(self.0.sign(payload).to_bytes().to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

struct Joined {
    group: MlsGroup,
    ring: KeyRing,
    sds: Sds,
    join_epoch: Epoch,
    /// Referenced ids we could not recover; not retried.
    given_up: HashSet<String>,
}

pub struct Member {
    name: String,
    lag: u64,
    provider: Provider,
    signer: Ed25519,
    joined: Option<Joined>,
    delivered: Vec<Delivered>,
}

impl fmt::Debug for Member {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Member")
            .field("name", &self.name)
            .field("epoch", &self.joined.as_ref().map(|j| j.ring.epoch()))
            .finish_non_exhaustive()
    }
}

impl Member {
    pub fn new(name: &str, lag: u64) -> Self {
        Self {
            name: name.to_owned(),
            lag,
            provider: Provider {
                crypto: LibcruxCryptoProvider::new().expect("libcrux provider"),
                storage: MemoryStorage::default(),
            },
            signer: Ed25519(SigningKey::from_bytes(&rand::random())),
            joined: None,
            delivered: Vec::new(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Current epoch; the ring and the MLS group always agree.
    pub fn epoch(&self) -> Epoch {
        self.joined().ring.epoch()
    }

    pub fn join_epoch(&self) -> Epoch {
        self.joined().join_epoch
    }

    pub fn ring(&self) -> &KeyRing {
        &self.joined().ring
    }

    /// False once a commit has removed us.
    pub fn is_active(&self) -> bool {
        self.joined().group.is_active()
    }

    /// This epoch's secret. Exposed only so tests can check nothing ships it.
    pub fn epoch_secret(&self) -> Vec<u8> {
        epoch_secret(&self.joined().group, &self.provider)
    }

    pub fn delivered(&self) -> &[Delivered] {
        &self.delivered
    }

    pub fn key_package(&self) -> KeyPackage {
        KeyPackage::builder()
            .leaf_node_capabilities(capabilities())
            .build(CIPHERSUITE, &self.provider, &self.signer, self.credential())
            .expect("key package")
            .key_package()
            .clone()
    }

    pub fn create_group(&mut self) {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .capabilities(capabilities())
            .use_ratchet_tree_extension(true)
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .build();
        let group = MlsGroup::new(&self.provider, &self.signer, &config, self.credential())
            .expect("create group");
        let ring = KeyRing::genesis(self.lag, &epoch_secret(&group, &self.provider));
        self.joined = Some(Joined::new(group, ring, &self.name));
    }

    pub fn join(&mut self, invite: &Invite) {
        let MlsMessageBodyIn::Welcome(welcome) =
            MlsMessageIn::tls_deserialize_exact(&invite.welcome)
                .expect("welcome")
                .extract()
        else {
            panic!("invite carries a welcome");
        };
        let join_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .build();
        let group = StagedWelcome::new_from_welcome(&self.provider, &join_config, welcome, None)
            .and_then(|staged| staged.into_group(&self.provider))
            .expect("join from welcome");
        assert_eq!(group.epoch().as_u64(), invite.keys.epoch);
        let ring = KeyRing::from_bundle(self.lag, invite.keys.clone());
        self.joined = Some(Joined::new(group, ring, &self.name));
    }

    pub fn send(&mut self, text: &str) -> Outbound {
        let j = self.joined.as_mut().expect("joined");
        let content = j
            .group
            .create_message(&self.provider, &self.signer, text.as_bytes())
            .expect("create message")
            .to_bytes()
            .expect("serialize");
        self.publish(content)
    }

    /// Commit that adds `key_package`; returns the commit and the joiner's invite.
    pub fn add(&mut self, key_package: KeyPackage) -> (Outbound, Invite) {
        let j = self.joined.as_mut().expect("joined");
        let (commit, welcome, _) = j
            .group
            .add_members(&self.provider, &self.signer, &[key_package])
            .expect("add member");
        let out = self.publish(commit.to_bytes().expect("serialize"));
        self.merge_own_commit();
        let invite = Invite {
            welcome: welcome.to_bytes().expect("serialize"),
            keys: self.ring().bundle(),
        };
        (out, invite)
    }

    /// Empty commit: advances the epoch without a membership change.
    pub fn rotate(&mut self) -> Outbound {
        let j = self.joined.as_mut().expect("joined");
        let bundle = j
            .group
            .self_update(&self.provider, &self.signer, LeafNodeParameters::default())
            .expect("self update");
        let out = self.publish(bundle.into_commit().to_bytes().expect("serialize"));
        self.merge_own_commit();
        out
    }

    pub fn remove(&mut self, name: &str) -> Outbound {
        let j = self.joined.as_mut().expect("joined");
        let leaf = j
            .group
            .members()
            .find(|m| identity(&m.credential) == name)
            .expect("is a member")
            .index;
        let (commit, _, _) = j
            .group
            .remove_members(&self.provider, &self.signer, &[leaf])
            .expect("remove member");
        let out = self.publish(commit.to_bytes().expect("serialize"));
        self.merge_own_commit();
        out
    }

    /// Opens the header, recovers every missing message its causal history leads
    /// to, then applies them all in the order MLS needs.
    pub fn receive(&mut self, frame: &Frame, store: &Store) -> Receipt {
        let j = self.joined.as_mut().expect("joined");
        let Some(first) = open(&j.ring, frame) else {
            return Receipt::Unreadable;
        };
        if j.sds.is_seen(&first.message.message_id) {
            return Receipt::Duplicate;
        }

        let mut report = Report {
            epoch: first.epoch,
            ..Default::default()
        };
        let mut queued = HashSet::from([first.message.message_id.clone()]);
        let mut todo: VecDeque<_> = j.sds.missing(&first.message).into();
        let mut pending = vec![(first, frame.hint(), false)];
        while let Some(entry) = todo.pop_front() {
            if j.given_up.contains(&entry.message_id) || !queued.insert(entry.message_id.clone()) {
                continue;
            }
            let fetched = store.fetch(&entry.retrieval_hint);
            // A store is untrusted: the header must open and carry the id we asked for.
            match fetched.and_then(|f| open(&j.ring, f).map(|o| (o, f.hint()))) {
                Some((o, hint)) if o.message.message_id == entry.message_id => {
                    todo.extend(j.sds.missing(&o.message));
                    pending.push((o, hint, true));
                }
                _ => {
                    report.dangling += 1;
                    j.given_up.insert(entry.message_id);
                }
            }
        }

        // By epoch; within one, application messages before the commit that closes it.
        pending.sort_by_key(|(o, _, _)| {
            (
                o.epoch,
                is_commit(&o.message.content),
                o.message.lamport_timestamp,
            )
        });
        for (opened, hint, recovered) in pending {
            let outcome = self.apply(&opened);
            let j = self.joined.as_mut().expect("joined");
            j.sds.record(&opened.message, hint);
            report.applied.push(Applied {
                epoch: opened.epoch,
                message_id: opened.message.message_id,
                recovered,
                outcome,
            });
        }
        Receipt::Opened(report)
    }

    /// MLS alone, bypassing SDS-FS. Only for showing a failure: success consumes the message.
    pub fn try_mls_alone(&mut self, content: &[u8]) -> Result<(), String> {
        let j = self.joined.as_mut().expect("joined");
        let message = protocol_message(content).ok_or("not an MLS message")?;
        j.group
            .process_message(&self.provider, message)
            .map(drop)
            .map_err(|e| e.to_string())
    }

    fn apply(&mut self, opened: &Opened) -> Outcome {
        let j = self.joined.as_mut().expect("joined");
        let Some(message) = protocol_message(&opened.message.content) else {
            return Outcome::Rejected;
        };
        let Ok(processed) = j.group.process_message(&self.provider, message) else {
            return Outcome::Rejected;
        };
        let sender = identity(processed.credential());
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(m) => {
                let text = String::from_utf8_lossy(&m.into_bytes()).into_owned();
                self.delivered.push(Delivered {
                    message_id: opened.message.message_id.clone(),
                    sender,
                    text: text.clone(),
                    epoch: opened.epoch,
                });
                Outcome::Message(text)
            }
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                j.group
                    .merge_staged_commit(&self.provider, *commit)
                    .expect("merge commit");
                // Removed by this commit: no further epoch secrets, the ring stays put.
                if j.group.is_active() {
                    j.ring.advance(&epoch_secret(&j.group, &self.provider));
                }
                Outcome::Commit
            }
            _ => Outcome::Rejected,
        }
    }

    fn publish(&mut self, content: Vec<u8>) -> Outbound {
        let j = self.joined.as_mut().expect("joined");
        let header = j.sds.outbound(&content);
        let frame = Frame {
            header: Some(j.ring.seal(&header, &content)),
            content,
        };
        j.sds.record(&header, frame.hint());
        Outbound {
            message_id: header.message_id,
            epoch: j.ring.epoch(),
            frame,
        }
    }

    fn merge_own_commit(&mut self) {
        let j = self.joined.as_mut().expect("joined");
        j.group
            .merge_pending_commit(&self.provider)
            .expect("merge own commit");
        j.ring.advance(&epoch_secret(&j.group, &self.provider));
    }

    fn joined(&self) -> &Joined {
        self.joined.as_ref().expect("joined")
    }

    fn credential(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(self.name.as_bytes().to_vec()).into(),
            signature_key: self.signer.0.verifying_key().to_bytes().to_vec().into(),
        }
    }
}

impl Joined {
    fn new(group: MlsGroup, ring: KeyRing, name: &str) -> Self {
        assert_eq!(ring.epoch(), group.epoch().as_u64());
        Self {
            sds: Sds::new(&hex::encode(group.group_id().as_slice()), name),
            join_epoch: ring.epoch(),
            group,
            ring,
            given_up: HashSet::new(),
        }
    }
}

/// The MLS epoch in the content's cleartext framing, if it parses.
pub fn content_epoch(content: &[u8]) -> Option<Epoch> {
    protocol_message(content).map(|m| m.epoch().as_u64())
}

fn open(ring: &KeyRing, frame: &Frame) -> Option<Opened> {
    ring.open(frame.header.as_ref()?, &frame.content)
}

fn epoch_secret(group: &MlsGroup, provider: &Provider) -> Vec<u8> {
    group
        .export_secret(provider.crypto(), EXPORTER_LABEL, &[], 32)
        .expect("active group")
}

fn capabilities() -> Capabilities {
    Capabilities::builder()
        .ciphersuites(vec![CIPHERSUITE])
        .build()
}

fn protocol_message(content: &[u8]) -> Option<ProtocolMessage> {
    MlsMessageIn::tls_deserialize_exact(content)
        .ok()?
        .try_into_protocol_message()
        .ok()
}

fn is_commit(content: &[u8]) -> bool {
    protocol_message(content).is_some_and(|m| m.content_type() == ContentType::Commit)
}

fn identity(credential: &Credential) -> String {
    BasicCredential::try_from(credential.clone())
        .map(|c| String::from_utf8_lossy(c.identity()).into_owned())
        .unwrap_or_default()
}
