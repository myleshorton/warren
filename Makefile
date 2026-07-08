.PHONY: verify test lint fmt fmt-check clippy doc clean build

# One command that must pass before any commit. Mirrors CI exactly.
verify: fmt-check clippy test doc
	@echo "\n✓ verify: all checks passed"

build:
	cargo build --workspace --all-targets

test:
	cargo test --workspace --all-targets

# Property/roundtrip suites can be scaled up locally for deeper fuzzing.
test-deep:
	PROPTEST_CASES=100000 cargo test --workspace --all-targets

lint: clippy fmt-check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all --check

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

clean:
	cargo clean
