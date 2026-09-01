.PHONY: docker lint

docker:
	./scripts/dev.sh image

lint:
	cargo fmt --all
	cargo clippy --fix --allow-dirty --all-targets --all-features -- --deny warnings
