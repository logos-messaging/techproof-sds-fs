//! Proof of concept for SDS-FS: forward-secret encryption of SDS headers, on real MLS epochs.
//!
//! ```text
//! MLS epoch i ──exporter──▶ epoch_secret[i] ──KDF_DOM──▶ epoch_reliability_key[i+LAG]
//!                                                               │
//!                                               KeyRing: keys E..=E+LAG
//!                                                               │ seal / trial-open
//! ReliablePayload (content unset) ◀────────────────▶ EncryptedSdsHeader ─┐
//! MLS message (content_ciphertext) ──HASH──▶ HeaderAAD ──────────────────┘
//! ```
//!
//! `construction` is the spec. `sds`, `member`, `store` and `sim` are harness.

pub mod construction;
pub mod member;
pub mod sds;
pub mod sim;
pub mod store;
