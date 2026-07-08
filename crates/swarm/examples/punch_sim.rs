//! Watch the hole-punch strategy across every NAT pairing.
//!
//! Run with: `cargo run -p swarm --example punch_sim`

use swarm::punch::{attempt_punch, PunchParams};
use swarm::sim::Rng;
use swarm::{plan, Firewall, Outcome};

fn main() {
    let params = PunchParams::default();
    println!(
        "Punch parameters: {} birthday sockets, {} spray probes, ports {}..={}\n",
        params.birthday_sockets, params.spray_probes, params.port_min, params.port_max
    );

    let types = [Firewall::Open, Firewall::Consistent, Firewall::Random];
    let trials = 5000;
    let mut rng = Rng::new(0x50C1A7);

    println!(
        "{:<12} {:<12} {:<22} {:>10}",
        "local", "remote", "strategy", "direct-rate"
    );
    println!("{}", "-".repeat(58));

    for &local in &types {
        for &remote in &types {
            let strategy = plan(local, remote);
            let direct = (0..trials)
                .filter(|_| {
                    !matches!(
                        attempt_punch(local, remote, &mut rng, &params),
                        Outcome::Relayed
                    )
                })
                .count();
            let rate = direct as f64 / trials as f64;
            println!(
                "{:<12} {:<12} {:<22} {:>9.1}%",
                format!("{local:?}"),
                format!("{remote:?}"),
                format!("{strategy:?}"),
                rate * 100.0
            );
        }
    }

    println!(
        "\nOnly Random/Random needs a relay. The one-sided-random cases punch\n\
         directly ~99.9% of the time thanks to the {}-socket birthday trick.",
        params.birthday_sockets
    );
}
