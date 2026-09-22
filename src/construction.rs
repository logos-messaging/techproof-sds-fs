//! The SDS-FS construction, as specified. Everything else in this crate is harness.
//!
//! ```text
//! KDF_DOM(ikm, domain) = HKDF-Expand-SHA256(ikm, domain, 32)
//! HASH(data)           = SHA-256(data)
//! ENC / DEC            = XChaCha20-Poly1305, random 192-bit nonce
//!
//! epoch_reliability_key[i + LAG] = KDF_DOM(epoch_secret[i], "sds-enc-v1")
//! HeaderAAD(label, i, h)         = uint8(len(label)) || label || uint64_be(i) || h
//! ```

use std::collections::BTreeMap;
use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use chat_proto::logoschat::reliability::ReliablePayload;
use hkdf::Hkdf;
use prost::Message;
use sha2::{Digest, Sha256};

pub const HEADER_LABEL: &[u8] = b"sds-hdr-v1";
pub const KDF_DOMAIN: &[u8] = b"sds-enc-v1";
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;

pub type Epoch = u64;
pub type Digest32 = [u8; 32];

#[derive(Clone, PartialEq, Eq)]
pub struct ReliabilityKey([u8; KEY_LEN]);

impl ReliabilityKey {
    fn random() -> Self {
        Self(rand::random())
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for ReliabilityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReliabilityKey(..)")
    }
}

pub fn kdf_dom(ikm: &[u8], domain: &[u8]) -> ReliabilityKey {
    let hk = Hkdf::<Sha256>::from_prk(ikm).expect("ikm is at least one hash length");
    let mut okm = [0u8; KEY_LEN];
    hk.expand(domain, &mut okm)
        .expect("32 bytes is a valid HKDF length");
    ReliabilityKey(okm)
}

pub fn hash(data: &[u8]) -> Digest32 {
    Sha256::digest(data).into()
}

pub fn header_aad(label: &[u8], i: Epoch, h: &Digest32) -> Vec<u8> {
    let label_len = u8::try_from(label.len()).expect("label fits a u8 length");
    let mut aad = Vec::with_capacity(1 + label.len() + 8 + h.len());
    aad.push(label_len);
    aad.extend_from_slice(label);
    aad.extend_from_slice(&i.to_be_bytes());
    aad.extend_from_slice(h);
    aad
}

/// Wire format from the spec.
#[derive(Clone, PartialEq, Message)]
pub struct EncryptedSdsHeader {
    #[prost(bytes = "vec", tag = "1")]
    pub nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub ciphertext: Vec<u8>,
}

pub fn enc(key: &ReliabilityKey, aad: &[u8], plaintext: &[u8]) -> EncryptedSdsHeader {
    let nonce: [u8; NONCE_LEN] = rand::random();
    let ciphertext = XChaCha20Poly1305::new(key.0.as_ref().into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("encryption is infallible for in-memory buffers");
    EncryptedSdsHeader {
        nonce: nonce.to_vec(),
        ciphertext,
    }
}

pub fn dec(key: &ReliabilityKey, aad: &[u8], header: &EncryptedSdsHeader) -> Option<Vec<u8>> {
    if header.nonce.len() != NONCE_LEN {
        return None;
    }
    XChaCha20Poly1305::new(key.0.as_ref().into())
        .decrypt(
            XNonce::from_slice(&header.nonce),
            Payload {
                msg: &header.ciphertext,
                aad,
            },
        )
        .ok()
}

/// What an invite carries: the keys for `E..=E+LAG`. Never an epoch secret.
#[derive(Clone, Debug)]
pub struct KeyBundle {
    pub epoch: Epoch,
    pub keys: Vec<ReliabilityKey>,
}

/// A header that opened, with `content` restored and the epoch whose key opened it.
#[derive(Clone, Debug)]
pub struct Opened {
    pub epoch: Epoch,
    pub message: ReliablePayload,
}

/// The reliability keys a member holds at epoch `E`: exactly `E..=E+LAG`.
#[derive(Clone, Debug)]
pub struct KeyRing {
    lag: u64,
    epoch: Epoch,
    keys: BTreeMap<Epoch, ReliabilityKey>,
}

impl KeyRing {
    /// Group creator at epoch 0: `0..LAG` are random, `LAG` derives from `epoch_secret[0]`.
    pub fn genesis(lag: u64, epoch_secret: &[u8]) -> Self {
        let mut keys: BTreeMap<_, _> = (0..lag).map(|i| (i, ReliabilityKey::random())).collect();
        keys.insert(lag, kdf_dom(epoch_secret, KDF_DOMAIN));
        Self {
            lag,
            epoch: 0,
            keys,
        }
    }

    pub fn from_bundle(lag: u64, bundle: KeyBundle) -> Self {
        assert_eq!(bundle.keys.len() as u64, lag + 1, "bundle covers E..=E+LAG");
        let keys = (bundle.epoch..).zip(bundle.keys).collect();
        Self {
            lag,
            epoch: bundle.epoch,
            keys,
        }
    }

    pub fn bundle(&self) -> KeyBundle {
        KeyBundle {
            epoch: self.epoch,
            keys: self.keys.values().cloned().collect(),
        }
    }

    /// `E -> E+1`: derive `E+1+LAG` from the new epoch's secret, delete `E`.
    pub fn advance(&mut self, epoch_secret: &[u8]) {
        self.keys.remove(&self.epoch);
        self.epoch += 1;
        self.keys
            .insert(self.epoch + self.lag, kdf_dom(epoch_secret, KDF_DOMAIN));
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub fn lag(&self) -> u64 {
        self.lag
    }

    pub fn held_epochs(&self) -> Vec<Epoch> {
        self.keys.keys().copied().collect()
    }

    pub fn key(&self, epoch: Epoch) -> Option<&ReliabilityKey> {
        self.keys.get(&epoch)
    }

    /// Encrypts `header` (content unset) under `epoch_reliability_key[E]`.
    pub fn seal(&self, header: &ReliablePayload, content_ciphertext: &[u8]) -> EncryptedSdsHeader {
        assert!(header.content.is_empty(), "content travels alongside");
        let aad = header_aad(HEADER_LABEL, self.epoch, &hash(content_ciphertext));
        enc(&self.keys[&self.epoch], &aad, &header.encode_to_vec())
    }

    /// Trial decryption over `E..=E+LAG`; the first key that opens wins.
    pub fn open(&self, header: &EncryptedSdsHeader, content_ciphertext: &[u8]) -> Option<Opened> {
        let h = hash(content_ciphertext);
        self.keys.iter().find_map(|(&j, key)| {
            let plaintext = dec(key, &header_aad(HEADER_LABEL, j, &h), header)?;
            let mut message = ReliablePayload::decode(plaintext.as_slice()).ok()?;
            message.content = content_ciphertext.to_vec().into();
            Some(Opened { epoch: j, message })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /// RFC 5869 test case 1: pins `KDF_DOM` to HKDF-Expand (OKM is prefix-stable in L).
    #[test]
    fn kdf_dom_is_hkdf_expand() {
        let prk = unhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let info = unhex("f0f1f2f3f4f5f6f7f8f9");
        let okm = unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf");
        assert_eq!(kdf_dom(&prk, &info).as_bytes().as_slice(), okm);
    }

    #[test]
    fn header_aad_layout() {
        let h = [0xab; 32];
        let aad = header_aad(HEADER_LABEL, 5, &h);
        let mut expected = vec![10];
        expected.extend_from_slice(b"sds-hdr-v1");
        expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 5]);
        expected.extend_from_slice(&h);
        assert_eq!(aad, expected);
    }

    #[test]
    fn genesis_randomises_the_first_lag_keys_only() {
        let es0 = [7u8; 32];
        let a = KeyRing::genesis(3, &es0);
        let b = KeyRing::genesis(3, &es0);
        assert_eq!(a.held_epochs(), vec![0, 1, 2, 3]);
        for i in 0..3 {
            assert_ne!(a.key(i), b.key(i), "epoch {i} key is random");
        }
        assert_eq!(a.key(3), Some(&kdf_dom(&es0, KDF_DOMAIN)));
        assert_eq!(a.key(3), b.key(3), "epoch LAG key is derived");
    }

    /// A ring at `E` opens what a ring at `E + k` sealed, for `k <= LAG` only.
    #[test]
    fn trial_decryption_covers_the_lag_window() {
        let lag = 2;
        let secrets: Vec<[u8; 32]> = (0..8).map(|i| [i; 32]).collect();
        let ring_at = |e: usize| {
            let mut ring = KeyRing::genesis(lag, &secrets[0]);
            secrets[1..=e].iter().for_each(|s| ring.advance(s));
            ring
        };
        let receiver = ring_at(3);
        let content = b"content ciphertext";
        let header = ReliablePayload {
            message_id: "m".into(),
            ..Default::default()
        };
        for sender in 3..8 {
            let opened = receiver.open(&ring_at(sender).seal(&header, content), content);
            if sender as u64 <= 3 + lag {
                let opened = opened.expect("inside the window");
                assert_eq!(opened.epoch, sender as u64);
                assert_eq!(opened.message.message_id, "m");
                assert_eq!(opened.message.content.as_ref(), content, "content restored");
            } else {
                assert!(opened.is_none(), "epoch {sender} is beyond LAG");
            }
        }
    }

    #[test]
    fn ring_holds_exactly_lag_plus_one_keys() {
        for lag in 0..4 {
            let mut ring = KeyRing::genesis(lag, &[0u8; 32]);
            for e in 0..10u64 {
                assert_eq!(ring.held_epochs(), (e..=e + lag).collect::<Vec<_>>());
                ring.advance(&[e as u8 + 1; 32]);
            }
        }
    }
}
