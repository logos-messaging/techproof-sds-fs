//! Seeded random schedules on real MLS: sends, commits, joins and offline windows.
//!
//! Claim: a reconnecting member recovers everything it missed iff it is at most LAG
//! epochs behind the newest frame. LAG = 0 is the control: plain per-epoch header keys.

use std::collections::{BTreeSet, HashSet};

use rand::rngs::StdRng;
use rand::seq::IndexedRandom;
use rand::{Rng, SeedableRng};
use sds_fs_poc::member::Receipt;
use sds_fs_poc::sim::{Kind, Sim};

const STEPS: usize = 150;
const SEEDS: [u64; 3] = [1, 2, 3];
const MAX_MEMBERS: usize = 6;

#[derive(Debug, Default)]
struct Stats {
    reconnects: usize,
    /// Recovered after missing at least one epoch.
    caught_up: usize,
    /// Fell more than LAG epochs behind.
    stuck: usize,
    recovered_frames: usize,
}

fn run(lag: u64, seed: u64) -> Stats {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut sim = Sim::new(lag, "m0");
    let mut stuck = HashSet::new();
    let mut stats = Stats::default();

    for step in 0..STEPS {
        let names = sim.names();
        let live: Vec<_> = names.iter().filter(|n| !stuck.contains(*n)).collect();
        let online: Vec<_> = live.iter().filter(|n| sim.is_online(n)).copied().collect();
        let offline: Vec<_> = live.iter().filter(|n| !sim.is_online(n)).copied().collect();
        let actor = online.choose(&mut rng).unwrap().as_str();

        match rng.random_range(0..100) {
            0..20 => {
                sim.rotate(actor);
            }
            20..32 if online.len() > 1 => sim.set_online(actor, false),
            32..50 if !offline.is_empty() => {
                let who = offline.choose(&mut rng).unwrap().as_str();
                reconnect(&mut sim, who, &mut stuck, &mut stats);
            }
            50..55 if names.len() < MAX_MEMBERS => {
                sim.invite(actor, &format!("m{}", names.len()));
            }
            _ => {
                sim.send(actor, &format!("step {step} from {actor}"));
            }
        }
    }

    for who in sim.names() {
        if !stuck.contains(&who) && !sim.is_online(&who) {
            reconnect(&mut sim, &who, &mut stuck, &mut stats);
        }
    }
    for who in sim.names().iter().filter(|n| !stuck.contains(*n)) {
        assert_delivered_everything(&sim, who);
    }
    stats
}

fn reconnect(sim: &mut Sim, who: &str, stuck: &mut HashSet<String>, stats: &mut Stats) {
    let newest = sim.ledger().last().unwrap().epoch;
    let epoch = sim.member(who).epoch();
    let receipt = sim.reconnect(who);
    stats.reconnects += 1;
    let group_epoch = sim.names().iter().map(|n| sim.member(n).epoch()).max();

    // Newest frame predates our epoch (e.g. the commit that added us): nothing new.
    let Some(behind) = newest.checked_sub(epoch) else {
        assert_eq!(Some(epoch), group_epoch, "{who} nothing missed");
        return;
    };
    if behind <= sim.lag() {
        assert_ne!(receipt, Receipt::Unreadable, "{who} {behind} behind");
        assert_eq!(
            Some(sim.member(who).epoch()),
            group_epoch,
            "{who} caught up"
        );
        stats.caught_up += usize::from(behind > 0);
        stats.recovered_frames += receipt.opened().map_or(0, |r| r.recovered());
    } else {
        assert_eq!(receipt, Receipt::Unreadable, "{who} {behind} behind");
        stuck.insert(who.to_owned());
        sim.set_online(who, false);
        stats.stuck += 1;
    }
}

/// Every application message since the member joined, in epoch order.
fn assert_delivered_everything(sim: &Sim, who: &str) {
    let member = sim.member(who);
    let expected: BTreeSet<_> = sim
        .ledger()
        .iter()
        .filter(|p| matches!(p.kind, Kind::App(_)))
        .filter(|p| p.sender != who && p.epoch >= member.join_epoch())
        .map(|p| p.message_id.as_str())
        .collect();
    let delivered: BTreeSet<_> = member
        .delivered()
        .iter()
        .map(|d| d.message_id.as_str())
        .collect();
    assert_eq!(delivered, expected, "{who}");
    assert!(member.delivered().is_sorted_by_key(|d| d.epoch));
}

#[test]
fn recovers_iff_at_most_lag_epochs_behind() {
    for lag in 0..=3 {
        let mut total = Stats::default();
        for seed in SEEDS {
            let s = run(lag, seed);
            total.reconnects += s.reconnects;
            total.caught_up += s.caught_up;
            total.stuck += s.stuck;
            total.recovered_frames += s.recovered_frames;
        }
        println!("LAG={lag}: {total:?}");

        // Both sides of the claim were exercised.
        assert!(total.stuck > 0, "LAG={lag}: nobody fell beyond the window");
        if lag > 0 {
            assert!(total.caught_up > 0, "LAG={lag}: nobody used the window");
        }
    }
}
