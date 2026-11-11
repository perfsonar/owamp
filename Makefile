#
# Makefile for top-level directory (Rust port)
#

default: build

BUILD_LOG = build-log

ifdef START
CARGO_OPTS += --package $(START)
endif

# The shell command below does the equivalent of BASH's pipefail
# within the confines of POSIX.
# Source: https://unix.stackexchange.com/a/70675/15184
build:
	rm -rf $(BUILD_LOG)
	((( \
	(cargo build --workspace $(CARGO_OPTS); echo $$? >&3) \
	| tee $(BUILD_LOG) >&4) 3>&1) \
	| (read XS; exit $$XS) \
	) 4>&1
TO_CLEAN += $(BUILD_LOG)

test:
	cargo test --workspace -- --test-threads=1

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

check: fmt clippy test

fresh: clean build

clean:
	cargo clean
	rm -rf $(TO_CLEAN)
	find . -name '*~' | xargs rm -f

.PHONY: default build test fmt clippy check fresh clean
