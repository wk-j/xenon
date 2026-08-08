.PHONY: dev release reset test lint fmt check docker help

help:
	@echo "make dev      run locally on :8787 (generates a session secret on first run)"
	@echo "make release  run locally, optimized build"
	@echo "make reset    wipe ./data (accounts, tokens, published resources) then run"
	@echo "make test     unit + end-to-end tests"
	@echo "make lint     clippy, warnings denied"
	@echo "make fmt      rustfmt in place"
	@echo "make check    fmt --check + lint + test (what CI would run)"
	@echo "make docker   build the deployment image"

dev:
	@scripts/dev.sh

release:
	@scripts/dev.sh --release

reset:
	@scripts/dev.sh --reset

test:
	cargo test

lint:
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt

check:
	cargo fmt -- --check
	cargo clippy --all-targets -- -D warnings
	cargo test

docker:
	docker build -t xenon .
