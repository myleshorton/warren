# Malicious-peer availability baseline

The harness in `crates/dht-next/src/attacks/network.rs` runs real DHT cores over an
in-memory packet scheduler. It is compiled only in tests and opens no sockets.
The baseline is 20 seeds × 20 scenario/policy combinations: 400 trials.
Raw results are in [dht-adversarial.csv](dht-adversarial.csv).

## Attacks and controls

- **Referral withholding:** 32 cooperating servers authenticate normally but learn
  and advertise only their collaborators. A separate honest server holds the
  provider registration. Compare an honest-only bootstrap, a malicious seed plus
  an independent honest seed, and an entirely captured bootstrap. Both `Diverse`
  and `Unrestricted` policies run against the same identities and topology.
- **Signaling blackholes:** the provider first obtains three real registrations.
  Zero through three coordinators then drop their provider-bound traffic while
  remaining responsive to the caller. The provider answers immediately upon
  receiving a valid offer. Success requires the caller's authenticated answer
  event; all-three failure requires an explicit signaling timeout.
- **Acknowledgement without retention:** zero through three holders erase their
  storage immediately after processing each request. Their normal DHT cores
  generate valid successful write acknowledgements. The caller independently
  reads every holder, then performs integrated value lookup. This distinguishes
  storage claims from observed availability.
- **Identity concentration:** 48 distinct authenticated server identities contact
  a client through one IP with different ports, one IPv4 /24 with different IPs,
  or different IPv4 /24s. Compare admission under both policies. These are active
  routing-table counts, not replacement-cache counts or estimates of operators.

The concentration trial also requires all 48 probes to authenticate successfully,
so ingress loss cannot masquerade as routing admission protection.

Every trial asserts packet-size and per-node pending-request limits, lookup
candidate bounds, eventual termination, and its expected availability outcome.
Referral attacks must actually cause queries to collaborators beyond the seed.
Blackhole cases must actually drop traffic. All storage cases must produce three
successful write acknowledgements before retention is assessed.

## Recorded results

All 400 trials met their assertions, including the expected availability failures.
Each row below represents 20 seeds per policy unless indicated otherwise.

| Experiment | Default `Diverse` | `Unrestricted` |
| --- | --- | --- |
| Honest-only discovery | 20/20 found provider | 20/20 found provider |
| Malicious referrals plus independent honest seed | 20/20 found provider | 20/20 found provider |
| Captured bootstrap | 0/20 found provider | 0/20 found provider |
| 48 identities on one IP | 1 route admitted | 39–48 routes admitted |
| 48 identities in one /24 | 8 routes admitted | 39–48 routes admitted |
| 48 identities across /24s | 39–48 routes admitted | 39–48 routes admitted |

Signaling succeeded in 20/20 trials for each of zero, one and two withholding
coordinators. All three withholding caused an explicit 20-second timeout in
20/20 trials. These signaling experiments use the default policy.

Every storage trial obtained three successful write acknowledgements. Independent
reads found exactly 3, 2, 1 and 0 retained copies with zero, one, two and three
discarding holders respectively. Integrated lookup succeeded in all 60 trials
with an honest holder and failed to find content in all 20 all-dishonest trials.
These storage experiments also use the default policy.

The referral scenario shows **no availability advantage** for either policy in
this topology. It establishes the importance of the supplied honest seed, not a
proof of independent-path discovery. Distributed identities also evade the
concentration limits in this experiment. These are explicit baselines for later
defense changes, rather than claims that every attack was prevented.

## Reproduce

The original baseline ran three seeds (60 trials) in the normal suite. The
[seed-preservation follow-up](dht-seed-hardening.md) adds two cases per seed, so the
current harness runs 66 trials normally and 440 with the command below. The linked
400-row baseline CSV is retained as historical evidence.

```sh
WARREN_ADVERSARIAL_TRIALS=20 cargo test -p dht-next --lib adversarial_matrix -- --nocapture > /tmp/warren-adversarial.log 2>&1
```

After checking that the command succeeded, extract rows:

```sh
sed -n 's/^ADVERSARIAL,//p' /tmp/warren-adversarial.log > /tmp/warren-adversarial.csv
```

Identity seeds and 25–49 ms packet delays are repeatable. Normal cryptographic
session creation remains enabled; the harness does not replace cryptographic RNGs.
The trial count is bounded to 1–100. Protocol time is virtual, not wall-clock time.

## Reading the data

`operation_succeeded=false` is an expected availability failure for captured
bootstrap, three signaling blackholes, or three discarding holders. It is not a
failed assertion. For concentration rows, true means the admission experiment
completed; `observed` gives the admitted identities, not a claim of Sybil resistance.

`claims`/`observed` mean respectively: zero/provider-found for referral trials;
registered coordinators/answered-session for signaling; acknowledged writes/holders
returning the exact value for storage; offered identities/admitted routes for
concentration. `elapsed_ms` measures the phase until its packet queue, RPCs,
queries and outgoing signaling operations settle, including losing-path retries.
It is **not** time to first useful response. Storage timing covers writes,
individual reads and integrated lookup together.

Packets and bytes count emitted DHT datagrams, including dropped datagrams and
cookie/session setup. They exclude IP/UDP headers. Registration/topology preparation
is excluded for referral and signaling rows. `caller_contacts` counts distinct
destinations contacted by the caller; `caller_routes` counts its active routes.
`peak_pending` is the maximum aggregate pending RPC count sampled after actions.

## Limits and next experiments

This is a bounded availability baseline, not evidence of general eclipse resistance.
It does not simulate targeted identity grinding, adaptive attackers, independent
operators sharing infrastructure, forged value contents, background packet loss,
NATs, process restarts, or a public network. Prefix diversity cannot identify one
operator spread across many prefixes. The mixed referral case supplies an honest
seed directly; it does not prove that independent paths can always be discovered.

The storage trial exercises the core protocol, not the driver's managed publication
worker. A readback detects a missing copy at that instant; a dishonest holder could
retain content only until challenged or selectively answer the publisher. Neither
an acknowledgement nor one successful read is a proof of durable replication.

Separate driver-level loopback tests now exercise managed repair against immediate
discard, missing/stale/silent readbacks and later selective withholding; see the
[managed publication behavior](../dht-next.md#immutable-and-signed-mutable-storage).
Those tests do not change the historical core-only results above. Follow-on defense
work should measure independently discovered honest paths, lookup steering with
target-near identities, and retention that discriminates between publishers and readers. The original baseline changed no production routing or replication policy; the
seed-preservation follow-up changes lookup policy as documented separately.
