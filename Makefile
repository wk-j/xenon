.PHONY: dev watch release reset test lint fmt check docker help

help:
	@echo "make dev      run locally on :8787 (generates a session secret on first run)"
	@echo "make watch    like dev, but rebuild and restart on every save"
	@echo "make release  run locally, optimized build"
	@echo "make reset    wipe ~/.config/xenon (accounts, tokens, published resources) then run"
	@echo "make test     unit + end-to-end tests (server and xen CLI)"
	@echo "make lint     clippy, warnings denied"
	@echo "make fmt      rustfmt in place"
	@echo "make check    fmt --check + lint + test (what CI would run)"
	@echo "make docker   build the deployment image"

dev:
	@scripts/dev.sh

watch:
	@scripts/dev.sh --watch

release:
	@scripts/dev.sh --release

reset:
	@scripts/dev.sh --reset

test:
	cargo test --workspace

lint:
	cargo clippy --workspace --all-targets -- -D warnings

fmt:
	cargo fmt --all

check:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings
	cargo test --workspace

docker:
	docker build -t xenon .
