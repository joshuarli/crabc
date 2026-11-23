TARGET := $(shell python3 -B compat/x86_64/native_arch.py "$$(uname -m)" | sed -n 's/^target_triple=//p')

.PHONY: lint test clean

lint:
	scripts/lanes/rust-check.sh
	scripts/lanes/rust-check.sh cargo clippy -q --locked --target $(TARGET) -p crabc-core -p crabc-rs

test:
	python3 -B scripts/test_python.py --directory scripts/tests

clean:
	cargo clean
