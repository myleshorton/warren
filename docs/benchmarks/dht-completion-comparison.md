# DHT completion comparison

Fresh release build of the completion-audit source; 12 trials per backend at each
of 8 and 32 routing nodes. All 144 measured operations succeeded, including exact
value checks on reads. All traffic used private loopback bootstrap.

| Nodes | Backend | Read median (ms) | Read p95 (ms) | Put median (ms) | Put p95 (ms) |
| --- | --- | ---: | ---: | ---: | ---: |
| 8 | warren | 2.362 | 3.484 | 9.663 | 12.165 |
| 8 | hyperdht | 2.610 | 5.059 | 11.643 | 14.338 |
| 8 | libtorrent | 1.140 | 2.331 | 9.477 | 12.340 |
| 32 | warren | 1.885 | 5.220 | 17.406 | 25.159 |
| 32 | hyperdht | 2.712 | 6.750 | 30.184 | 35.770 |
| 32 | libtorrent | 1.069 | 3.038 | 10.479 | 12.836 |

p95 uses the nearest-rank definition; with 12 samples it is the maximum observed
value and is not a stable tail-latency estimate. Trial zero is retained.

Warren had lower median read latency than HyperDHT at both sizes in this run;
libtorrent retained the lower median read latency. These results do not establish
WAN performance or a security ranking. Differences from historical runs may
reflect host scheduling and cache state, not just implementation changes.

Put timings are descriptive: Warren acknowledges three replicas, while HyperDHT
and libtorrent use their own replication/placement semantics. They are not
equivalent durability measurements. This idle workload also does not measure
throughput, signaling, NAT traversal, mutable values or adversarial behavior.

Run UTC: `2026-09-12T00:51:25.038235+00:00`. Platform: `macOS-26.5.1-arm64-arm-64bit-Mach-O`.
Runtimes: `{'rustc': 'rustc 1.97.0 (2d8144b78 2026-07-07)', 'node': 'v24.2.0', 'libtorrent': '2.1.1.0'}`.

[Raw CSV](dht-completion-comparison.csv) · [Source/runtime metadata](dht-completion-comparison.json)
· [Runner methodology](../../tools/dht-compare/README.md)
· [Completion audit](../dht-completion.md)
