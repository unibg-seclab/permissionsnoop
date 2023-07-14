.PHONY: build clean addlicense

CC = clang
CFLAGS = -std=c17
PROBE = permissionsnoop-probe
TARGET_DIR = /usr/local/bin

all: build

${PROBE}: $(PROBE).c

build: ${PROBE}.out
	cargo build --release
	sudo cp target/release/permissionsnoop $(TARGET_DIR)
	sudo setcap =ep $(TARGET_DIR)/permissionsnoop
	sudo cp $(PROBE) $(TARGET_DIR)/$(PROBE)

clean:
	@cargo clean
	rm -f $(PROBE)
	sudo rm -f $(PROBE) $(TARGET_DIR)/$(PROBE) $(TARGET_DIR)/permissionsnoop
