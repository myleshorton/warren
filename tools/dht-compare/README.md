# Actual DHT comparison runners

All peers bind to loopback and use explicit local bootstrap addresses. Public DHT
bootstrap, multicast discovery, and router port mapping are disabled. HyperDHT is
pinned by npm lockfile; libtorrent's Python wheel is pinned in `requirements.txt`.

From the repository root:

```sh
npm ci --prefix tools/dht-compare
uv venv --python 3.12 tools/dht-compare/.venv
uv pip install --python tools/dht-compare/.venv/bin/python -r tools/dht-compare/requirements.txt
cargo build --release -p driver --example compare_dht
python3 tools/dht-compare/run.py --trials 12 --output docs/benchmarks/dht-value-lookup-comparison.csv
```

Run after other CPU-intensive checks finish. The orchestrator runs backends
sequentially, preserves CSV results, checks exact-value reads, and writes platform
and command metadata next to the CSV. Metadata includes workspace Rust source,
manifest and lockfile hashes, runner/dependency-pin hashes, runtime versions, and
the Warren executable hash. Failure aborts the run; any partial CSV is not
a completed benchmark. Bootstrap uses real protocol operations and bounded waits.

Each network has 8 or 32 routing nodes, including the writer, plus a separate
nonrouting reader. Each trial writes a new 256-byte immutable value and reads it from the
other client. A 1.1-second gap between trials avoids repeatedly exhausting Warren's
64-packet-per-prefix input budget. At most 16 trials per fresh network avoids its
16-values-per-owner storage cap. This is idle API latency, not throughput. Trial 0
is retained as the first measured operation after joining; subsequent operations
benefit from whatever caches each implementation maintains.

The API semantics are deliberately visible: Warren locates and writes three
replicas; its v6 immutable fetch reads during traversal and finishes on its first
verified match. HyperDHT/libtorrent use their default replication
and read-completion behavior. `replica_contacts` means acknowledged replicas for
Warren puts, validated traversal responses (including misses) for Warren gets, closest-node list length for
HyperDHT puts, and `num_success` for libtorrent puts. It is blank for external gets.
Those counts are not interchangeable durability guarantees.

Private single-IP routing requires Warren's `Unrestricted` policy and libtorrent's
routing/search IP restrictions and node-ID enforcement to be disabled. Libtorrent
also uses `dht_block_ratelimit=1000` for the shared loopback IP and only operational
alerts. Its Python binding uses nonblocking `set_alert_fd`, avoiding GIL callbacks. Resource
quotas remain enabled in Warren. HyperDHT nodes are explicitly persistent rather
than waiting for adaptive persistence. This setup does not test public-network
admission defenses, NAT traversal, DHT signaling, mutable writes, or WAN behavior.

See [the integrated-read report](../../docs/benchmarks/dht-value-lookup-comparison.md) for results and
limitations. The scripts are a starting point for a broader comparison, not a
feature-parity certification.

To reproduce the separately reported libtorrent read-only writer behavior:

```sh
tools/dht-compare/.venv/bin/python tools/dht-compare/libtorrent_bench.py 8 3 --readonly-writer
```

This mode adds a nonrouting writer outside the routing-node count. It is excluded
from the baseline orchestrator; later puts can take about 15 seconds each.

## Controlled replication and execution experiment

```sh
cargo build --release -p driver --example compare_dht
python3 tools/dht-compare/run.py --controlled --trials 12 --output docs/benchmarks/dht-controlled-comparison.csv
```

This mode uses 9 or 33 routing nodes (writer included), plus one nonrouting reader.
Nine allows eight remote replicas even when a backend excludes its own writer.
Every put is verified by reading each possible remote holder; libtorrent is also
checked at the writer because its native placement can include itself. Reads must
return exactly the input bytes. Verification is outside the timed interval and is
followed by a 1.1-second pause. The variants are:

- Warren shared Tokio thread, three replicas: replication control.
- Warren shared Tokio thread, eight replicas.
- Warren one Tokio event-loop thread per node, eight replicas.
- HyperDHT one JS worker/event-loop thread per node, eight replicas.
- Libtorrent native session thread per node, eight replicas.

Warren's normal store API remains three replicas. The benchmark implements eight
using lookup plus individual put RPCs. HyperDHT uses eight nearest known remote
IDs with `onlyClosestNodes`; direct readback confirms actual placement. Libtorrent
uses its native put and verifies `num_success == 8` plus BEP 44 readback. Therefore
**put timings are setup diagnostics, not comparable write benchmarks**: HyperDHT
receives an externally selected candidate list. All timed reads use native lookup
without externally supplying holders. Networks join using their existing private
bootstrap workflows; their routing tables and hash-based placements are not
identical. Worker startup and HyperDHT controller IPC are excluded; Warren's normal
command/event channels and libtorrent's normal Python alert delivery are included.
One event loop per node is a resource-topology control, not identical CPU usage or
an endorsement of that deployment configuration.

`immutable_get` is the first read of each new value; `immutable_get_repeat` is the
immediate repeat. Neither guarantees a cold transport: bootstrap and earlier
trials can populate sessions and routing tables. First reads follow an idle pause;
immediate repeats also benefit from CPU/cache wakeup, so their difference is not
a pure measure of transport setup. `replica_contacts` still counts
Warren traversal responses for reads; successful puts are independently checked
against the configured replica count. The CSV's `warren-shared-3` label identifies
the three-copy control. Trials use fresh values, but share a network within a run.
The orchestrator clears benchmark environment overrides before setting each variant.

For an independent cold/warm core profile:

```sh
cargo build --release -p dht-next --example value_profile
# Run after the build completes and other CPU-heavy work stops.
target/release/examples/value_profile 100 > docs/benchmarks/dht-value-core-uninstrumented.csv
cargo build --release -p dht-next --features diagnostics --example value_profile
target/release/examples/value_profile 100 > docs/benchmarks/dht-value-core-profile.csv
```

The probe creates fresh identities/core instances for each pair, pre-stores one
256-byte value through a separate writer, and delivers one reader's lookup packets
synchronously to one known holder. It verifies cold=4 and warm=2 sequential packet
legs and exact values. It reports packet counts, bytes, and combined synchronous
elapsed time for both endpoints plus harness dispatch. There is no modeled network
latency, socket scheduling, loss, or discovery. Deterministic secrets are confined
to this isolated probe. `diagnostics` adds thread-local wall-clock spans around
RPC-envelope signature signing/verification, peer Noise handshake setup/completion (including session
installation), AEAD calls, and value-key generation. It is off by default, records
no payloads, and aggregates all instances on the calling thread. Each operation's
six region rows repeat its total core time; do not sum that column across regions.
The uninstrumented run emits one row per operation with region `Uninstrumented`.
Use it to assess profiling overhead. These are elapsed spans, not hardware CPU
counters, and cannot attribute the UDP driver's scheduler/queue delay directly.

See the [controlled results and interpretation](../../docs/benchmarks/dht-controlled-comparison.md).
