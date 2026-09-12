# DHT coverage-guided fuzzing

The isolated cargo-fuzz workspace exercises the current DHT with AddressSanitizer
and debug assertions. It does not change the production dependency graph.

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --version 0.13.2 --locked
python3 fuzz/seed_corpus.py
cargo +nightly fuzz run packet -- -max_total_time=120 -max_len=19216 -timeout=5
cargo +nightly fuzz run signed-body -- -max_total_time=120 -max_len=1200 -timeout=5
cargo +nightly fuzz run lifecycle -- -max_total_time=120 -max_len=128 -timeout=5
```

`packet` delivers up to sixteen datagrams to one core, advances monotonic time,
and checks output packet sizes and resource bounds. Its corpus includes old and
current protocol versions. `signed-body` obtains a real cookie, signs mutated
bodies, checks decode/encode consistency, and delivers each body repeatedly to
exercise authenticated handling and replay. Deterministic keys are test fixtures;
no sockets or public bootstrap services are used. The signed-body helper exists
only behind `test-support`, which production builds do not enable.

`lifecycle` runs up to 32 operations across four nodes, including cancellation,
restart, explicit routing-maintenance toggles, address changes, partitions,
dishonest storage, and damaged or reordered
traffic. It checks state bounds throughout, then restores delivery and services
`poll_timeout()` deadlines to require successful storage, lookup, and signaling.
The disruption phase deliberately permits late timers; recovery does not skip
the subsecond retries needed to replace stale peer sessions. The corpus includes
the deterministic operation matrix and saved property-test regression inputs.

Crashes are saved under `fuzz/artifacts/<target>/`; replay with
`cargo +nightly fuzz run <target> <artifact>`. Keep a minimized reproducer as a
normal regression test before fixing the bug. Generated corpora are ignored;
`seed_corpus.py` reconstructs initial inputs from checked-in wire vectors and
`regressions/*.hex`. The noncanonical-length seed records a signed-body finding:
an overlong integer decoded successfully but changed on re-encoding. DHT decoding
now rejects these encodings, with signed and compact packet regression tests.
For longer campaigns, increase `-max_total_time` and retain the corpus between runs.
A short successful campaign is evidence about exercised inputs, not a security audit.

CI explicitly runs the test-support suite, all three fuzz targets, and the real-UDP
signaling soak. Fuzz campaigns run for 120 seconds per target on PRs and main
pushes, and 600 seconds per target on the daily schedule. The schedule takes effect
once the workflow reaches the default branch.
