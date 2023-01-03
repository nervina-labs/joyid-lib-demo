build:
	cd contracts && cargo fmt --all
	capsule build

build-release:
	cd contracts && cargo fmt --all
	capsule build --release

test:
	cargo fmt --all
	capsule test

test-release:
	cargo fmt --all
	capsule test --release

clean:
	rm -rf build/debug
	rm -rf target/

clean-release:
	rm -rf build/release

.PHONY: build test clean