CARGO ?= cargo
ARGS ?=

.PHONY: check test run

check:
	$(CARGO) clippy --all-targets --all-features -- -D warnings

test:
	$(CARGO) nextest run

run:
	$(CARGO) run --bin trusty -- $(ARGS)
