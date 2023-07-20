.PHONY: build clean addlicense

CC = clang
CFLAGS = -std=c17
PROBE = permissionsnoop-probe
TARGET_DIR = /usr/local/bin

LICENSE_TYPE   := "mit"
LICENSE_HOLDER := "Unibg Seclab (https://seclab.unibg.it)"

all: build

addlicense:
	go install github.com/google/addlicense@latest
	$(shell go env GOPATH)/bin/addlicense -c $(LICENSE_HOLDER) -l $(LICENSE_TYPE) .

${PROBE}: $(PROBE).c

build: ${PROBE}
	cargo build --release
	sudo cp target/release/permissionsnoop $(TARGET_DIR)
	sudo setcap =ep $(TARGET_DIR)/permissionsnoop
	sudo cp $(PROBE) $(TARGET_DIR)/$(PROBE)

clean:
	@cargo clean
	rm -f $(PROBE)
	sudo rm -f $(PROBE) $(TARGET_DIR)/$(PROBE) $(TARGET_DIR)/permissionsnoop
