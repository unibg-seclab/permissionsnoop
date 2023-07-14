.PHONY: build clean

CC = clang
STD = c17
PROBE = permissionsnoop-probe

all: build

${PROBE}.out:
	$(CC) -std=$(STD) -o $(PROBE).out $(PROBE).c

build: ${PROBE}.out
	cargo build --release
	sudo cp target/release/permissionsnoop /usr/local/bin
	sudo setcap =ep /usr/local/bin/permissionsnoop
	sudo cp $(PROBE).out /usr/local/bin/$(PROBE)

clean:
	@cargo clean
	rm -f $(PROBE).out
	sudo rm -f $(PROBE).out /usr/local/bin/$(PROBE) /usr/local/bin/permissionsnoop
