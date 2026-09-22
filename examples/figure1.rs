//! Figure 1 of the spec, narrated: `cargo run -p sds-fs-poc --example figure1`.

use sds_fs_poc::member::{Outcome, Receipt, content_epoch};
use sds_fs_poc::sim::Sim;

fn main() {
    let lag = 2;
    let mut sim = Sim::new(lag, "saro");
    sim.invite("saro", "raya");
    sim.rotate("saro");
    sim.rotate("saro");
    println!("LAG = {lag}. Saro and Raya are at MLS epoch 3.\n");

    println!("Raya goes offline. Saro keeps going:");
    sim.set_online("raya", false);
    for (text, commit) in [("sent at 3", true), ("sent at 4", true)] {
        let p = sim.send("saro", text);
        println!("  epoch {}: message {:?}", p.epoch, text);
        if commit {
            let c = sim.rotate("saro");
            println!("  epoch {}: commit -> epoch {}", c.epoch, c.epoch + 1);
        }
    }
    sim.set_online("raya", true);
    let (epoch, held) = (
        sim.member("raya").epoch(),
        sim.member("raya").ring().held_epochs(),
    );

    let hello = sim.send("saro", "hello at 5");
    println!(
        "\nRaya is back at epoch {epoch}. Saro sends {:?}.",
        "hello at 5"
    );
    println!(
        "  content: MLS epoch {}; Raya's MLS state is epoch {epoch} -> cannot decrypt",
        content_epoch(&hello.frame.content).unwrap(),
    );
    println!("  header:  Raya holds reliability keys for epochs {held:?}");

    let Some(Receipt::Opened(report)) = sim.receipt("raya") else {
        panic!("header should open");
    };
    println!(
        "  header opened with key {} = KDF_DOM(epoch_secret[{}])",
        report.epoch,
        report.epoch - lag
    );
    println!("\nIts causal history leads to the store. Applied in MLS order:");
    for a in &report.applied {
        let what = match &a.outcome {
            Outcome::Message(t) => format!("message {t:?}"),
            Outcome::Commit => "commit".into(),
            Outcome::Rejected => "rejected".into(),
        };
        let how = if a.recovered { "recovered" } else { "live" };
        println!("  epoch {}: {what} ({how})", a.epoch);
    }

    let raya = sim.member("raya");
    println!("\nRaya is at epoch {} and has read:", raya.epoch());
    for d in raya.delivered() {
        println!("  [{}] {}: {}", d.epoch, d.sender, d.text);
    }
}
