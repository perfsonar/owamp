#
# Makefile for the OWAMP package directory (Rust crates)
#

default: build

build:
	cargo build --manifest-path ../Cargo.toml --workspace

test:
	cargo test --manifest-path ../Cargo.toml --workspace -- --test-threads=1

clean:
	cargo clean --manifest-path ../Cargo.toml

.PHONY: default build test clean
