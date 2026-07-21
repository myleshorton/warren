//! Repro for the ~5s find_node stall measured on the live network.
//!
//! Hypothesis: a lookup stalls in proportion to the number of *unreachable*
//! contacts in the routing table, because the iterative search only terminates
//! once the top-K closest contacts are all resolved — and a dead contact isn't
//! "resolved" until its `REQUEST_TIMEOUT` (1s) fires. With `ALPHA=3` in flight,
//! N dead contacts cost ~ceil(N/3) seconds.
//!
//! This test isolates the *lookup* behavior from how dead contacts get into the
//! table: it seeds them explicitly. Run with `--nocapture` to see the latency
//! curve; the deterministic sim makes the numbers stable.

use swarm::dht::Event;
use swarm::routing::EVICTION_THRESHOLD;
use swarm::sim::Sim;

/// Virtual-time (ms) a `find_node` takes on a searcher whose routing table holds
/// one reachable VPS plus `dead` unreachable contacts.
fn find_node_ms(dead: usize, seed: u64) -> u64 {
    let mut sim = Sim::new(10, seed); // 10ms one-way latency, like a nearby VPS

    let searcher_id = sim.rng().node_id();
    let (searcher, _) = sim.add_node(searcher_id);

    // One reachable node the searcher knows (stands in for the bootstrap VPS).
    let vps_id = sim.rng().node_id();
    let (vps, _) = sim.add_node(vps_id);
    let vps_contact = sim.contact(vps);
    sim.dht_mut(searcher).add_contact(vps_contact);

    // `dead` contacts that live in the routing table but never answer: real nodes
    // taken offline, so a FindNode to them is silently dropped and the request can
    // only time out (exactly a departed / NAT'd-and-now-cold client).
    for _ in 0..dead {
        let id = sim.rng().node_id();
        let (d, _) = sim.add_node(id);
        let c = sim.contact(d);
        sim.disable_node(d);
        sim.dht_mut(searcher).add_contact(c);
    }

    let target = sim.rng().node_id();
    let start = sim.now();
    let q = sim.find_node(searcher, target);
    sim.run(10_000_000);
    let finished = sim.take_events().into_iter().any(
        |(n, ev)| matches!(ev, Event::QueryFinished { query, .. } if n == searcher && query == q),
    );
    assert!(
        finished,
        "find_node with {dead} dead contacts never finished"
    );
    sim.now() - start
}

#[test]
fn find_node_latency_vs_dead_contacts() {
    let seed = 0xD00D;
    let t0 = find_node_ms(0, seed);
    let t5 = find_node_ms(5, seed);
    let t10 = find_node_ms(10, seed);
    let t15 = find_node_ms(15, seed);
    let t20 = find_node_ms(20, seed);
    println!(
        "\nfind_node latency vs. dead contacts in the routing table:\n  \
         0 dead  = {t0} ms\n  5 dead  = {t5} ms\n  10 dead = {t10} ms\n  \
         15 dead = {t15} ms\n  20 dead = {t20} ms\n"
    );

    // A lookup with only a reachable VPS is one round-trip — fast.
    assert!(
        t0 < 500,
        "baseline lookup (no dead contacts) should be fast, got {t0} ms"
    );
    // The claim under test: unreachable contacts inflate lookup latency into the
    // seconds. This characterizes the *unfixed* find_node/bootstrap path — it still
    // stalls (fixing it needs dead-node eviction / a client-server split, since a
    // find_node must rule out closer-by-id dead contacts, which costs their
    // timeout). Connect is the path we fix below.
    assert!(
        t15 > t0 + 2_000,
        "dead contacts should inflate raw find_node latency by seconds (t0={t0}ms, t15={t15}ms)"
    );
}

/// Virtual-time (ms) for a *connect* to resolve, with `dead` unreachable contacts
/// in the initiator's routing table. The target has announced itself, so a
/// reachable VPS holds its record and can broker.
fn connect_ms(dead: usize, seed: u64) -> u64 {
    let mut sim = Sim::new(10, seed);

    let searcher_id = sim.rng().node_id();
    let (searcher, _) = sim.add_node(searcher_id);
    let vps_id = sim.rng().node_id();
    let (vps, _) = sim.add_node(vps_id);
    let target_id = sim.rng().node_id();
    let (target, _) = sim.add_node(target_id);

    // Searcher and target both know the reachable VPS; the target self-announces so
    // the VPS ends up holding its record (the coordinator a connect brokers through).
    let vps_contact = sim.contact(vps);
    sim.dht_mut(searcher).add_contact(vps_contact);
    sim.dht_mut(target).add_contact(vps_contact);
    sim.announce(target, target_id);
    sim.run(1_000_000);

    // Bury the coordinator among unreachable contacts in the searcher's table.
    for _ in 0..dead {
        let id = sim.rng().node_id();
        let (d, _) = sim.add_node(id);
        let c = sim.contact(d);
        sim.disable_node(d);
        sim.dht_mut(searcher).add_contact(c);
    }
    sim.take_events();

    let start = sim.now();
    sim.connect(searcher, target_id);
    sim.run(1_000_000);
    let resolved = sim
        .take_events()
        .into_iter()
        .any(|(n, ev)| matches!(ev, Event::Connected { .. } if n == searcher));
    assert!(resolved, "connect with {dead} dead contacts never resolved");
    sim.now() - start
}

#[test]
fn connect_stalls_on_dead_contacts_too() {
    let seed = 0xC0DE;
    let c0 = connect_ms(0, seed);
    let c15 = connect_ms(15, seed);
    println!("\nconnect latency vs. dead contacts: 0 dead = {c0} ms, 15 dead = {c15} ms\n");

    // Connect stalls just like find_node — and crucially, a "broker as soon as a
    // coordinator is found" termination does NOT help: reaching the coordinator is
    // gated by grinding through the dead contacts that are closer-to-target by XOR
    // distance. So the effective fix must keep dead contacts OUT of the query path
    // (client/server split + eviction / shorter timeout), not just terminate early.
    assert!(
        c15 > c0 + 2_000,
        "connect stalls on dead contacts too (c0={c0}ms, c15={c15}ms)"
    );
}

/// The fix, end-to-end: dead contacts don't stall *forever*. A searcher that
/// keeps looking up (reusing one routing table, unlike `find_node_ms` above)
/// counts each unanswered FindNode against the contact; after `EVICTION_THRESHOLD`
/// silent rounds the departed servers are evicted, and lookups return to baseline.
#[test]
fn repeated_lookups_evict_dead_contacts() {
    let mut sim = Sim::new(10, 0xE0E0);

    let searcher_id = sim.rng().node_id();
    let (searcher, _) = sim.add_node(searcher_id);

    // One reachable VPS the searcher will always be able to reach.
    let vps_id = sim.rng().node_id();
    let (vps, _) = sim.add_node(vps_id);
    let vps_contact = sim.contact(vps);
    sim.dht_mut(searcher).add_contact(vps_contact);

    // Six departed servers buried in the table — every lookup queries them
    // (7 contacts < K), so each round times out on all six.
    let dead = 6usize;
    for _ in 0..dead {
        let id = sim.rng().node_id();
        let (d, _) = sim.add_node(id);
        let c = sim.contact(d);
        sim.disable_node(d);
        sim.dht_mut(searcher).add_contact(c);
    }
    assert_eq!(sim.dht(searcher).routing_len(), dead + 1);

    // Run one lookup against a fresh random target and return its latency.
    let run_lookup = |sim: &mut Sim| -> u64 {
        let target = sim.rng().node_id();
        let start = sim.now();
        let q = sim.find_node(searcher, target);
        sim.run(10_000_000);
        let finished = sim.take_events().into_iter().any(
            |(n, ev)| matches!(ev, Event::QueryFinished { query, .. } if n == searcher && query == q),
        );
        assert!(finished, "lookup never finished");
        sim.now() - start
    };

    // The first lookup stalls: the dead contacts are still in the table (a
    // contact isn't evicted until its threshold-th consecutive failure).
    let first = run_lookup(&mut sim);
    assert!(
        first > 500,
        "the first lookup should stall on the dead contacts, got {first} ms"
    );

    // Drive the remaining rounds needed to reach the eviction threshold.
    for _ in 1..EVICTION_THRESHOLD {
        run_lookup(&mut sim);
    }

    // The departed servers have now failed EVICTION_THRESHOLD lookups each and
    // been evicted; only the reachable VPS remains.
    assert_eq!(
        sim.dht(searcher).routing_len(),
        1,
        "dead contacts should be evicted after {EVICTION_THRESHOLD} silent rounds"
    );

    // With the table cleaned up, a lookup is a single round-trip again.
    let after = run_lookup(&mut sim);
    println!("\neviction: first lookup {first} ms → post-eviction {after} ms\n");
    assert!(
        after < 500,
        "post-eviction lookup should be fast again, got {after} ms"
    );
    assert!(after < first, "eviction should reduce lookup latency");
}
