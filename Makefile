build:
	cargo fmt --all
	capsule build
	cd contracts/c && make via-docker

build-release:
	cargo fmt --all
	capsule build --release
	cd contracts/c && make via-docker

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