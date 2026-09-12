# Preserving supplied lookup paths

The [malicious-peer baseline](dht-adversarial.md) established that an honest starting
point matters but did not place it outside the lookup frontier. Follow-up inspection
found two ways the default policy could skip an explicitly supplied path:

1. Fresh candidates were re-ranked when referrals arrived. A closer referral using
   an admitted seed's IP could evict that seed under the one-identity-per-IP limit.
2. Origin balancing happened after selecting the nearest 20 candidates. Once those
   candidates completed, an untouched farther seed did not prevent completion.

Both targeted regression tests failed before the change. Under `Diverse`, admitted
explicit seeds now stay pinned during referral insertion and remain eligible outside
the nearest-20 frontier. `Unrestricted` retains its existing behavior. A separate
regression checks that cached routes alone do not expand the frontier.

## Wire-level experiment

The added `seed_outside_frontier` scenario uses 33 real authenticated server
identities on distinct /24s. The server farthest from the provider's topic holds its
registration. All 32 closer servers withhold that registration and useful referrals.
The caller receives all 33 endpoints as seeds. The scenario checks both provider
discovery and whether the useful endpoint was actually contacted.

The follow-up matrix has 20 seeds × 22 scenario/policy combinations: 440 trials.
The original 400 cases are retained, with 40 additional frontier trials. Raw results
are in [dht-seed-hardening.csv](dht-seed-hardening.csv). The normal test suite runs
three seeds (66 trials).

```sh
WARREN_ADVERSARIAL_TRIALS=20 cargo test -p dht-next --lib adversarial_matrix -- --nocapture > /tmp/warren-seed-hardening.log 2>&1
```

After verifying that the command succeeded:

```sh
sed -n 's/^ADVERSARIAL,//p' /tmp/warren-seed-hardening.log > /tmp/warren-seed-hardening.csv
```

## Results

All 440 trials met their assertions. In the new frontier scenario:

| Policy | Provider found | Caller contacts | Emitted datagrams | Phase settles |
| --- | --- | --- | --- | --- |
| Hardened `Diverse` | 20/20 | 33 | 132 | 1,609–1,751 ms |
| Unchanged `Unrestricted` | 0/20 | 20 | 80 | 993–1,104 ms |

The extra 52 datagrams are the cost of contacting 13 additional supplied seeds in
this cold-session experiment. The shorter unrestricted run terminates without
finding the provider; it is not a successful faster lookup. This is a policy
comparison within the current build, not a separate historical-build benchmark.
The before-change evidence consists of the two failing targeted regression tests.

The original scenarios retain their asserted availability outcomes: independent
honest bootstrap succeeds, captured bootstrap fails, signaling survives up to two
withholding coordinators, and retrieval survives up to two discarding holders.
The existing concentration limits and their distributed-identity limitation remain.

## Bounds and tradeoffs

Protection applies only to explicit seed endpoints that survive initial admission;
it does not exempt seeds from identity, address, prefix or capacity checks. The
protected set is query-local and bounded by the existing 128-candidate ceiling.
Cached routing contacts are not automatically protected.

Queries may send additional requests to farther supplied seeds. Existing concurrency
limits and deadlines remain unchanged, and verified immutable content can still
complete a lookup early. A deadline can still expire before every seed responds.
This change is not an RTT optimization or a promise to exhaust arbitrary graphs.

The defenses do not identify independent operators, recover an honest peer from an
entirely captured bootstrap, or establish storage durability. A caller can supply
multiple attacker-controlled seeds. Protecting them preserves caller intent, not
trustworthiness. See the baseline report for the simulator and measurement limits;
`elapsed_ms` is time until the measurement phase settles, not first-result latency.
