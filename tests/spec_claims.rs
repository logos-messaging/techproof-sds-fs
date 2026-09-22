//! One test per claim in the SDS-FS spec, on real MLS epochs. Section names match the spec.

use std::collections::{BTreeSet, HashSet};

use chat_proto::logoschat::reliability::{HistoryEntry, ReliablePayload};
use prost::Message;
use sds_fs_poc::construction::{HEADER_LABEL, KDF_DOMAIN, enc, hash, header_aad, kdf_dom};
use sds_fs_poc::member::{Frame, Member, Outcome, Receipt, content_epoch};
use sds_fs_poc::sim::Sim;

fn texts(member: &Member) -> Vec<&str> {
    member.delivered().iter().map(|d| d.text.as_str()).collect()
}

/// Key Schedule, Figure 1 (LAG = 2): Raya, at epoch 3, reads Saro's epoch-5 header,
/// and its causal history leads her back to everything she missed.
#[test]
fn figure_1_raya_at_epoch_3_reads_saro_at_epoch_5() {
    let mut sim = Sim::new(2, "saro");
    sim.invite("saro", "raya"); // epoch 1
    sim.rotate("saro"); // 2
    sim.rotate("saro"); // 3
    assert_eq!(sim.member("raya").epoch(), 3);

    sim.set_online("raya", false);
    sim.send("saro", "sent at 3");
    sim.rotate("saro"); // 4
    sim.send("saro", "sent at 4");
    sim.rotate("saro"); // 5
    sim.set_online("raya", true);

    let hello = sim.send("saro", "hello at 5");
    assert_eq!(hello.epoch, 5);
    assert_eq!(content_epoch(&hello.frame.content), Some(5));

    let report = sim
        .receipt("raya")
        .unwrap()
        .opened()
        .expect("key 5 = KDF(epoch_secret[3])");
    assert_eq!(report.epoch, 5);
    assert_eq!(report.recovered(), 4, "two messages and two commits");
    assert_eq!(report.dangling, 0);
    assert_eq!(sim.member("raya").epoch(), 5);
    assert_eq!(
        texts(sim.member("raya")),
        ["sent at 3", "sent at 4", "hello at 5"]
    );
}

/// Motivation: without the header path, MLS alone cannot read a future epoch's content.
#[test]
fn mls_alone_cannot_read_ahead() {
    let mut sim = Sim::new(2, "saro");
    sim.invite("saro", "raya");
    sim.set_online("raya", false);
    sim.rotate("saro");
    let ahead = sim.send("saro", "at 2");
    assert!(
        sim.member_mut("raya")
            .try_mls_alone(&ahead.frame.content)
            .is_err()
    );
}

/// External Parameters: a member up to LAG epochs behind recovers; LAG + 1 does not.
#[test]
fn lag_bounds_how_far_behind_a_member_can_fall() {
    for lag in 0..=3 {
        for behind in [lag, lag + 1] {
            let mut sim = Sim::new(lag, "saro");
            sim.invite("saro", "raya"); // epoch 1
            sim.set_online("raya", false);
            for _ in 0..behind {
                sim.send("saro", "missed");
                sim.rotate("saro");
            }
            sim.set_online("raya", true);
            sim.send("saro", "now");

            let receipt = sim.receipt("raya").unwrap();
            let raya = sim.member("raya");
            if behind <= lag {
                assert!(receipt.opened().is_some(), "lag {lag}, behind {behind}");
                assert_eq!(raya.epoch(), 1 + behind);
                assert_eq!(raya.delivered().len() as u64, behind + 1);
            } else {
                assert_eq!(receipt, &Receipt::Unreadable, "lag {lag}, behind {behind}");
                assert_eq!(raya.epoch(), 1);
                assert!(raya.delivered().is_empty());
            }
        }
    }
}

/// Initialization: an invite carries keys for E..=E+LAG, which match the group's,
/// and nothing that opens an earlier epoch.
#[test]
fn joiner_holds_keys_from_its_join_epoch_only() {
    let mut sim = Sim::new(2, "saro");
    sim.invite("saro", "raya"); // 1
    sim.rotate("saro"); // 2
    let before = sim.send("saro", "before tom");
    sim.invite("saro", "tom"); // 3

    let tom = sim.member("tom");
    assert_eq!(tom.ring().held_epochs(), [3, 4, 5]);
    for e in 3..=5 {
        assert_eq!(tom.ring().key(e), sim.member("saro").ring().key(e));
    }
    assert_eq!(sim.deliver("tom", &before.frame), Receipt::Unreadable);

    sim.send("raya", "welcome tom");
    assert_eq!(texts(sim.member("tom")), ["welcome tom"]);
}

/// Epoch Reliability Key Derivation, Initialization: key[i + LAG] = KDF_DOM(epoch_secret[i]),
/// and an invite ships only such keys, never an epoch secret.
#[test]
fn invite_carries_derived_keys_not_epoch_secrets() {
    let lag = 2;
    let mut sim = Sim::new(lag, "saro");
    let mut secrets = vec![sim.member("saro").epoch_secret()];
    for _ in 0..4 {
        sim.rotate("saro");
        secrets.push(sim.member("saro").epoch_secret());
    }
    sim.invite("saro", "tom"); // 5
    secrets.push(sim.member("saro").epoch_secret());

    let saro = sim.member("saro");
    for (i, secret) in (0..).zip(&secrets).skip(3) {
        let expected = kdf_dom(secret, KDF_DOMAIN);
        assert_eq!(saro.ring().key(i + lag), Some(&expected));
    }
    let tom = sim.member("tom");
    for e in tom.ring().held_epochs() {
        let key = tom.ring().key(e).unwrap().as_bytes();
        assert!(
            !secrets.iter().any(|s| s == key),
            "epoch {e} key is an epoch secret"
        );
    }
}

/// Key Schedule, first LAG epochs: the creator's random keys reach a joiner through the
/// invite and carry it through a gap that starts at its join epoch.
#[test]
fn joiner_recovers_through_random_genesis_keys() {
    let mut sim = Sim::new(2, "saro");
    sim.invite("saro", "raya"); // raya at 1: key 1 random, keys 2, 3 derived
    sim.set_online("raya", false);
    sim.send("saro", "at 1");
    sim.rotate("saro");
    sim.send("saro", "at 2");
    sim.rotate("saro");
    sim.set_online("raya", true);
    sim.send("saro", "at 3");

    let report = sim.receipt("raya").unwrap().opened().unwrap();
    assert_eq!(report.recovered(), 4);
    assert_eq!(texts(sim.member("raya")), ["at 1", "at 2", "at 3"]);
}

/// Header Substitution: a valid header opens on its own content and nothing else.
#[test]
fn header_is_bound_to_its_content() {
    let mut sim = Sim::new(2, "saro");
    sim.invite("saro", "raya");
    sim.set_online("raya", false);
    let a = sim.send("saro", "a");
    let b = sim.send("saro", "b");

    let swapped = Frame {
        header: a.frame.header.clone(),
        content: b.frame.content.clone(),
    };
    assert_eq!(sim.deliver("raya", &swapped), Receipt::Unreadable);

    let tampered: [fn(&mut Frame); 3] = [
        |f| f.header.as_mut().unwrap().nonce[0] ^= 1,
        |f| f.header.as_mut().unwrap().ciphertext[0] ^= 1,
        |f| *f.content.last_mut().unwrap() ^= 1,
    ];
    for tamper in tampered {
        let mut frame = a.frame.clone();
        tamper(&mut frame);
        assert_eq!(sim.deliver("raya", &frame), Receipt::Unreadable);
    }

    assert!(sim.deliver("raya", &a.frame).opened().is_some());
}

/// Associated Data and Binding: an unmodified replay opens, and SDS drops it by message_id.
#[test]
fn replayed_frame_is_a_duplicate() {
    let mut sim = Sim::new(2, "saro");
    sim.invite("saro", "raya");
    let once = sim.send("saro", "once");
    assert_eq!(sim.deliver("raya", &once.frame), Receipt::Duplicate);
    assert_eq!(texts(sim.member("raya")), ["once"]);
}

/// Member removal: a removed member reads headers for the removal epoch and LAG more,
/// never content.
#[test]
fn removed_member_reads_headers_for_lag_more_epochs_and_no_content() {
    let mut sim = Sim::new(2, "saro");
    sim.invite("saro", "raya"); // 1
    sim.invite("saro", "tom"); // 2
    let removal = sim.remove("saro", "tom"); // sealed at 2, group moves to 3
    assert_eq!(removal.epoch, 2);
    assert!(!sim.member("tom").is_active());
    assert_eq!(sim.member("tom").ring().held_epochs(), [2, 3, 4]);

    for epoch in 3..=4 {
        let sent = sim.send("saro", "not for tom");
        assert_eq!(sent.epoch, epoch);
        let report = sim
            .receipt("tom")
            .unwrap()
            .opened()
            .expect("inside the window");
        assert_eq!(report.applied[0].outcome, Outcome::Rejected);
        sim.rotate("saro");
    }

    sim.send("saro", "past the window");
    assert_eq!(sim.receipt("tom"), Some(&Receipt::Unreadable));
    assert!(sim.member("tom").delivered().is_empty());
    assert_eq!(texts(sim.member("raya")).len(), 3);
}

/// Member removal: header access ends LAG epochs after the removal and never returns.
/// The ring freezes at removal, so of the whole archive the removed member opens only
/// headers sealed in the removal epoch through LAG more.
#[test]
fn removed_member_eventually_cannot_read_headers() {
    for lag in 0..=3 {
        let mut sim = Sim::new(lag, "saro");
        sim.invite("saro", "raya"); // 1
        sim.invite("saro", "tom"); // 2
        let removed = sim.remove("saro", "tom").epoch;
        let window = removed..=removed + lag;
        let held = sim.member("tom").ring().held_epochs();
        assert_eq!(held, window.clone().collect::<Vec<_>>());

        for _ in 0..lag + 5 {
            let sent = sim.send("raya", "after tom");
            let opened = sim.receipt("tom").unwrap().opened().is_some();
            assert_eq!(
                opened,
                window.contains(&sent.epoch),
                "lag {lag}, epoch {}",
                sent.epoch
            );
            sim.rotate("saro");
        }

        let tom = sim.member("tom");
        assert_eq!(
            tom.ring().held_epochs(),
            held,
            "lag {lag}: no keys after removal"
        );
        assert!(tom.delivered().is_empty());
        let readable: BTreeSet<_> = sim
            .ledger()
            .iter()
            .filter(|p| {
                tom.ring()
                    .open(p.frame.header.as_ref().unwrap(), &p.frame.content)
                    .is_some()
            })
            .map(|p| p.epoch)
            .collect();
        assert_eq!(readable, window.collect(), "lag {lag}");
    }
}

/// Compromised Reliability Keys: inside its window a removed member can forge headers that
/// members accept. It cannot forge content; the harm is fetches for messages that don't exist.
#[test]
fn removed_member_can_forge_headers_inside_its_window_only() {
    let mut sim = Sim::new(2, "saro");
    sim.invite("saro", "raya"); // 1
    sim.invite("saro", "tom"); // 2
    sim.remove("saro", "tom"); // group at 3, tom keeps keys 2..=4

    let forge = |sim: &Sim, id: &str| {
        let ring = sim.member("tom").ring();
        let epoch = 4;
        let header = ReliablePayload {
            message_id: id.into(),
            sender_id: "saro".into(),
            causal_history: vec![HistoryEntry {
                message_id: format!("ghost-{id}"),
                retrieval_hint: vec![0; 32].into(),
                sender_id: "saro".into(),
            }],
            ..Default::default()
        };
        let content = b"not an MLS message".to_vec();
        let aad = header_aad(HEADER_LABEL, epoch, &hash(&content));
        Frame {
            header: Some(enc(ring.key(epoch).unwrap(), &aad, &header.encode_to_vec())),
            content,
        }
    };

    let report = sim.deliver("raya", &forge(&sim, "f1"));
    let report = report.opened().expect("forged header accepted");
    assert_eq!(
        (report.epoch, report.dangling, report.rejected()),
        (4, 1, 1)
    );

    sim.rotate("saro"); // 4
    sim.rotate("saro"); // 5: raya holds 5..=7
    assert_eq!(sim.deliver("raya", &forge(&sim, "f2")), Receipt::Unreadable);
}

/// Security, Retention: state stolen at epoch E opens headers from E..=E+LAG, no others.
#[test]
fn compromise_at_epoch_e_exposes_only_e_through_e_plus_lag() {
    let mut sim = Sim::new(2, "saro");
    sim.invite("saro", "raya"); // 1
    let mut stolen = None;
    for _ in 1..=9 {
        if sim.member("raya").epoch() == 4 {
            stolen = Some(sim.member("raya").ring().clone());
        }
        sim.send("saro", "traffic");
        sim.rotate("saro");
    }
    let stolen = stolen.unwrap();

    let all: BTreeSet<_> = sim.ledger().iter().map(|p| p.epoch).collect();
    assert_eq!(all, (0..=9).collect());
    let exposed: BTreeSet<_> = sim
        .ledger()
        .iter()
        .filter(|p| {
            stolen
                .open(p.frame.header.as_ref().unwrap(), &p.frame.content)
                .is_some()
        })
        .map(|p| p.epoch)
        .collect();
    assert_eq!(exposed, BTreeSet::from([4, 5, 6]));
}

/// Security, Retention: a frame from a closed epoch is lost to both layers at once,
/// so dropping its header key loses nothing further.
#[test]
fn late_frame_from_a_closed_epoch_is_lost_to_both_layers() {
    let mut sim = Sim::new(2, "saro");
    sim.invite("saro", "raya"); // 1
    sim.invite("saro", "tom"); // 2
    // Tom's frame is held up in transit while the group moves on.
    let late = sim.member_mut("tom").send("late");
    sim.rotate("saro"); // 3

    assert_eq!(sim.deliver("raya", &late.frame), Receipt::Unreadable);
    assert!(
        sim.member_mut("raya")
            .try_mls_alone(&late.frame.content)
            .is_err()
    );
}

/// Wire Format, Metadata Exposure: the header frame is a random 192-bit nonce and a
/// ciphertext; no id, sender, channel or epoch is visible in it.
#[test]
fn encrypted_header_hides_ids_and_epoch() {
    let mut sim = Sim::new(2, "saro");
    sim.invite("saro", "raya");
    for i in 0..5 {
        sim.send("saro", &format!("m{i}"));
        sim.send("raya", &format!("r{i}"));
    }

    let mut nonces = HashSet::new();
    for p in sim.ledger().iter().skip(1) {
        let header = p.frame.header.as_ref().unwrap();
        assert_eq!(header.nonce.len(), 24);
        assert!(nonces.insert(header.nonce.clone()), "nonces are random");

        let wire = header.encode_to_vec();
        let opened = sim.member("raya").ring().open(header, &p.frame.content);
        let plain = opened.map(|o| o.message).unwrap();
        for leaked in [&plain.message_id, &plain.sender_id, &plain.channel_id] {
            assert!(!contains(&wire, leaked.as_bytes()), "{leaked} visible");
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
