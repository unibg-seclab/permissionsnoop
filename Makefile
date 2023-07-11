.PHONY: build clean

all: build

build:
	cargo build --release
	sudo cp target/release/permissionsnoop /usr/local/bin
	sudo setcap =ep /usr/local/bin/permissionsnoop

clean:
	@cargo clean
