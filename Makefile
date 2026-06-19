.PHONY: build test run clean

build:
	cargo build

test:
	cargo test

run:
	cargo run

clean:
	cargo clean

test-verbose:
	cargo test -- --nocapture
