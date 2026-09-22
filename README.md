# sds-fs-poc

Proof of concept for [SDS-FS](https://github.com/logos-co/logos-lips/blob/master/docs/messaging/core/raw/sds-fs.md) on real MLS epochs (openmls 0.8, the X-Wing suite libchat uses). Not production code.

```text
epoch_secret[i]  = MLS-Exporter("sds-fs epoch_secret", "", 32) at epoch i
KDF_DOM          = HKDF-Expand-SHA256        HASH = SHA-256
ENC / DEC        = XChaCha20-Poly1305, random 192-bit nonce
header           = chat-proto ReliablePayload, content unset
frame            = EncryptedSdsHeader + MLS message (content_ciphertext)
store            = opaque frames keyed by transport hash (= SDS retrieval_hint)
```

`src/construction.rs` is the spec. Everything else is harness: a minimal SDS (`sds.rs`), an MLS member (`member.rs`), an untrusted store, and a lossy network (`sim.rs`).

```sh
cargo run  -p sds-fs-poc --example figure1        # Figure 1, narrated
cargo test -p sds-fs-poc                          # every claim below
cargo test -p sds-fs-poc --test fuzz -- --nocapture
```

| Spec section | Claim | Test |
| --- | --- | --- |
| Key Schedule, Fig. 1 | Raya at 3 reads Saro at 5, recovers what she missed | `figure_1_raya_at_epoch_3_reads_saro_at_epoch_5` |
| Motivation | MLS alone can't read ahead | `mls_alone_cannot_read_ahead` |
| External Parameters | `LAG` behind recovers, `LAG + 1` does not (LAG 0..=3) | `lag_bounds_how_far_behind_a_member_can_fall` |
| Key Schedule | first `LAG` keys random at genesis | `genesis_randomises_the_first_lag_keys_only`, `joiner_recovers_through_random_genesis_keys` |
| Key Derivation, Initialization | `key[i+LAG] = KDF_DOM(epoch_secret[i])`; invites never ship an epoch secret | `invite_carries_derived_keys_not_epoch_secrets` |
| Initialization | joiner holds `E..=E+LAG`, nothing earlier | `joiner_holds_keys_from_its_join_epoch_only` |
| Header Decryption | trial decryption over `E..=E+LAG` | `trial_decryption_covers_the_lag_window` |
| Header Substitution | header opens only on its own content; tampering fails | `header_is_bound_to_its_content` |
| Associated Data and Binding | replay is an SDS duplicate | `replayed_frame_is_a_duplicate` |
| Member removal | headers for `LAG + 1` epochs, never content | `removed_member_reads_headers_for_lag_more_epochs_and_no_content` |
| Compromised Reliability Keys | removed member can forge headers inside its window only | `removed_member_can_forge_headers_inside_its_window_only` |
| Security, Retention | stolen state at `E` exposes `E..=E+LAG` only | `compromise_at_epoch_e_exposes_only_e_through_e_plus_lag` |
| Security, Retention | ring holds exactly `LAG + 1` keys | `ring_holds_exactly_lag_plus_one_keys` |
| Security, Retention | closed epoch is lost to header and content together | `late_frame_from_a_closed_epoch_is_lost_to_both_layers` |
| Wire Format, Metadata | nonce + ciphertext only; no id, sender or channel visible | `encrypted_header_hides_ids_and_epoch` |
| Construction | `KDF_DOM` matches RFC 5869; `HeaderAAD` layout | `kdf_dom_is_hkdf_expand`, `header_aad_layout` |
| All of the above | random schedules: recover **iff** ≤ `LAG` behind; LAG 0 is the control | `fuzz::recovers_iff_at_most_lag_epochs_behind` |
