# DHT implementation completion audit

This audit covers the opt-in Warren DHT layer and its existing transfer adapter.
The default legacy backend is unchanged. It does not certify public deployment,
complete Pear SDK parity, or protection against arbitrary Sybil operators.

## Implemented scope

| Area | Implemented behavior | Primary evidence |
| --- | --- | --- |
| Core and wire | Bounded signed v6 packets, cookie challenge, encrypted peer sessions, replay protection, separate monotonic and signed-expiry clocks | Fixed vectors, adversarial/property tests, fuzz targets |
| Routing and lookup | Authenticated admission, maintenance, replacements, adaptive retries/hedging, prefix/origin quotas, explicit-seed preservation | Core/network tests and topology/adversarial reports |
| Decentralized signaling | Discovered coordinators, signed registrations, encrypted offers/answers, automatic failover, lease renewal and keepalives | Real-UDP signaling soak and core loss/churn simulations |
| Values | Immutable content addressing, mutable signatures/CAS, integrated lookup, fork/newer-value detection | Core storage tests and external immutable-value comparison |
| Managed replication | Readback verification, replica repair, lease/expiry renewal, remembered-holder audits, peer cooldowns, local-capacity retries | Managed-publication tests, including dishonest storage and displaced holders |
| Lifecycle | Bounded cleanup of publication lookups/reads/writes, cancellation under queue pressure, network rebind and bootstrap snapshots | Cancellation race matrix and real driver tests |
| Connectivity and transfer | Direct/public-key connections, birthday punching with outbound probes, opt-in PCP/UPnP leases, authenticated feed/blob transfer and resumption | Puncher, portmap, driver and transfer suites |
| Validation tooling | Coverage-guided fuzzing, 100-trial signaling soak, bounded CI jobs, pinned external runners with source/runtime fingerprints | `fuzz/`, `.github/workflows/dht-fuzz.yml`, `tools/dht-compare/` |

The protocol and API details are in [dht-next.md](dht-next.md).

## Issues closed during the final audit

### PR readiness: moved peers and recovery scheduling

Lifecycle validation reproduced a lookup failure after a holder changed its UDP
port: a cached route appeared before the caller's fresh seed, so identity
deduplication kept the stale address. New lookups now consider explicit seeds
before cached routes. The seed remains subject to authentication and candidate
quotas; it does not rewrite an admitted routing contact. Regressions cover both
routing policies and storage/lookup/signaling recovery after a holder moves.

A separate harness issue skipped subsecond retry deadlines by advancing recovery
in one-second jumps. A warmed connection to a restarted peer could expire before
the retry that starts a fresh handshake. Recovery now services `poll_timeout()`
deadlines, with a focused regression that failed under the old scheduler. Fault
injection still deliberately delays timers during the disruption phase.

The first lifecycle fuzz campaign also found that cleanup rejected a legitimate
background liveness probe. Cleanup now permits only probes owned by routing
maintenance, alongside maintenance-owned lookups; unrelated application work
still fails the assertion. The minimized input is a checked-in regression and
fuzz seed in `crates/dht-next/tests/lifecycle/`.

The lifecycle fuzz target is included in the CI matrix, seeded from the operation
matrix and saved property regressions. The first remote fuzz run also exposed the
repository's stable toolchain overriding the installed nightly; fuzz commands now
select the pinned nightly explicitly. Normal workspace tests enable lifecycle
properties through the driver's `test-support` dev dependency.

### Dual-stack ephemeral port collisions

A macOS socket-only reproducer showed an IPv6 wildcard port-zero bind selecting a
port already held by an IPv4 loopback listener. A request reached the IPv4 listener,
but its reply returned to that same listener instead of the IPv6 client. A separate
close/rebind reproducer also hit an occupied IPv4 port. These reproduce the failure
mechanism behind missing startup responses and intermittent rebind failures without
using DHT code.

The shared puncher helper now picks a port candidate through IPv4 and explicitly binds the
IPv6 wildcard socket, retrying address conflicts at most 16 times. Explicit user
ports are preserved. DHT, direct-connect and birthday-punch sockets use this helper.
The deterministic test supplies a conflicting port first and
then verifies an IPv4 request/reply exchange through the resulting dual-stack socket.
The socket-only comparison passed 10,000 close/rebind cycles with 44 bind retries.
This is bounded conflict handling, not an atomic reservation across both families.

### Publication startup redundancy

Previously, if one of two bootstrap paths timed out, obtaining one coordinator
reset publication backoff and postponed discovery for 30–35 seconds. Restoring the
missing path did not promptly restore redundancy. A deterministic dropped-path
regression failed before the change and passes after it.

A shortfall against known distinct-IP hints/results, capped at three coordinators,
now uses the existing bounded exponential retry schedule. Reaching the target
restores normal refresh timing. Hints change scheduling, not admission or trust.

### Canonical packet lengths

Coverage-guided signed-body fuzzing found an overlong variable-length integer that
decoded successfully but changed bytes when re-encoded. This was a canonicalization
assertion failure, not a memory-safety finding. Signed and compact DHT packets now
reject nonminimal integers; legacy wire decoding remains permissive. Both forms
have deterministic regression tests, and the minimized body is a checked-in fuzz
seed. The original crashing input passes after the fix.

### Validation and reproducibility

Fuzzing now exercises both arbitrary datagrams and signed, cookie-authorized bodies,
including replay, output sizes and state bounds. The separate workspace uses
AddressSanitizer and does not change production dependencies. Seeds are reconstructed
from checked-in v5/v6 vectors. CI jobs are configured for bounded fuzz campaigns and
the UDP soak; their remote execution has not been observed in this local session.

External benchmark metadata now includes source hashes for the relevant Rust crates,
runner scripts and dependency locks, plus runtime versions and the executable hash.
Historical comparison reports remain historical; they are not silently overwritten.

## Validation results

PR-readiness follow-up on September 11, 2026 (local date): all five lifecycle
tests passed after the fixes above, including the saved property regression and
minimized fuzz input. The repaired lifecycle fuzzer completed 7,026 executions
in 121 seconds without a failure. The explicit real-UDP signaling soak passed
all 100 trials in 86.76 seconds. These are bounded validation runs, not a security
certification. The earlier completion-run results below remain historical.

Local completion run on September 11, 2026:

- `make verify`: passed formatting, warning-free workspace Clippy, 585 tests
  (two opt-in tests ignored), and warning-free documentation generation.
- Explicit `signaling_soak`: all 100 real-UDP trials passed in 83.74 seconds.
- Signed-body fuzzing after canonical-decoder repair: 255,675 executions in
  181 seconds, with no further failure; original crash replay also passed.
- Raw-packet fuzzing against the repaired decoder: 981,528 executions in
  121 seconds, with no failure.
- `PROPTEST_CASES=10000 cargo test -p dht-next attacks::`: all 60 selected
  adversarial/property tests passed in 23.18 seconds.
- Fuzz workspace formatting and warning-free Clippy: passed.

The [fresh external comparison](benchmarks/dht-completion-comparison.md) completed
12 trials per backend at each of 8 and 32 routing nodes: all 144 measured
operations succeeded. Warren's median reads were faster than HyperDHT's at both
sizes, while libtorrent retained lower median read latency. The report includes
raw samples, source/runtime fingerprints and replication limitations.

## Explicit boundaries

The locally implemented DHT scope above is distinct from these research and public-
deployment gates:

- Independent protocol/cryptographic review and sustained fuzz campaigns beyond the
  bounded runs recorded here.
- Independent-region, long-running and consumer-router/NAT trials; loopback and
  simulated networks cannot establish these results.
- Stronger operator-diversity and disjoint-path defenses, bootstrap availability,
  routing-identity separation, and a decision on mandatory outer encryption.
- Application wiring for OS network-change notifications, reachability policy,
  durable application checkpoints, and any decision to switch the default backend.
- Pear SDK features above the DHT/connection layer and a comparable cross-backend
  signaling/NAT/adversarial benchmark. The current external workload measures
  immutable storage/read latency with differing replication semantics.

These are not completed or implied by passing local tests. The current protocol
continues to be experimental until the relevant deployment gates are satisfied.
