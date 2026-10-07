# PacketVelocity Makefile
# High-performance packet capture library

# Platform detection
UNAME_S := $(shell uname -s)

# Compiler selection - use GCC on Linux for better compatibility with VFM
ifeq ($(UNAME_S),Linux)
CC = gcc
else
CC = clang
endif
CFLAGS = -Wall -Wextra -O3 -std=c11
DEBUG_FLAGS = -g -O0 -DDEBUG

# Build mode: development (default) or production
BUILD_MODE ?= development
PREFIX ?= /usr/local

# Special flags for VFM compilation (uses GNU extensions)
VFM_CFLAGS = -Wall -Wextra -O3 -std=gnu11 

# macOS specific flags
MACOS_CFLAGS = -DPLATFORM_MACOS
MACOS_LDFLAGS = 

# Linux specific flags
LINUX_CFLAGS = -DPLATFORM_LINUX
LINUX_LDFLAGS =

# RistrettoDB output backend (OPTIONAL, opt-in, default OFF).
#
# The DEFAULT build is hermetic: it has ZERO RistrettoDB dependency and streams
# captured packets to stdout like tcpdump.
#
# Enable the optional RistrettoDB output backend explicitly with:
#     make RISTRETTO=1
# Point at a RistrettoDB checkout other than ../RistrettoDB with:
#     make RISTRETTO=1 RISTRETTO_ROOT=/path/to/RistrettoDB
#
# The output layer (src/pcv_output_ristretto.c) targets the RistrettoDB V2
# append-only table API and appends one row per captured packet. Route capture
# to a table with: ./packetvelocity -i <if> --output ristretto:<path>
RISTRETTO ?= 0
RISTRETTO_ROOT ?= ../RistrettoDB

# Build mode configuration (controls how VelocityFilterMachine is found)
ifeq ($(BUILD_MODE),development)
    # Development: Use local source libraries with latest changes
    VFM_ROOT = ../VelocityFilterMachine

    VFM_INCLUDES = -I$(VFM_ROOT)/include -I$(VFM_ROOT)/dsl/vflisp
    VFM_LDFLAGS = $(VFM_ROOT)/libvfm.a

    # Include VFLisp sources directly in development mode
    VFLISP_SOURCES = $(VFM_ROOT)/dsl/vflisp/vflisp_parser.c \
                     $(VFM_ROOT)/dsl/vflisp/vflisp_compile.c
else ifeq ($(BUILD_MODE),production)
    # Production: Use installed system libraries
    VFM_INCLUDES = -I$(PREFIX)/include
    VFM_LDFLAGS = -L$(PREFIX)/lib -lvfm

    # No VFLisp sources - use installed library
    VFLISP_SOURCES =
else
    $(error Invalid BUILD_MODE: $(BUILD_MODE). Use 'development' or 'production')
endif

# Optional RistrettoDB output backend (opt-in via RISTRETTO=1).
# Default: nothing to include, link, or compile -> zero dependency.
RISTRETTO_INCLUDES =
RISTRETTO_LDFLAGS =
RISTRETTO_SOURCES =
ifeq ($(RISTRETTO),1)
    CFLAGS += -DHAVE_RISTRETTO=1
    RISTRETTO_INCLUDES = -I$(RISTRETTO_ROOT)/embed
    RISTRETTO_SOURCES = src/pcv_output_ristretto.c
    ifeq ($(BUILD_MODE),production)
        RISTRETTO_LDFLAGS = -L$(PREFIX)/lib -lristretto
    else
        RISTRETTO_LDFLAGS = $(RISTRETTO_ROOT)/lib/libristretto.a
    endif
endif

# Base includes
BASE_INCLUDES = -I./include

# Combined includes
INCLUDES = $(BASE_INCLUDES) $(VFM_INCLUDES) $(RISTRETTO_INCLUDES)

# Combined LDFLAGS
LDFLAGS = $(VFM_LDFLAGS) $(RISTRETTO_LDFLAGS)

# Core source files (terminal/stdout capture pipeline - no external output deps)
CORE_SOURCES = src/pcv_main.c \
               src/pcv_platform.c \
               src/pcv_filter_vfm.c \
               src/pcv_ringbuf.c \
               src/pcv_flow.c

# Optional RistrettoDB output backend sources (only when RISTRETTO=1)
CORE_SOURCES += $(RISTRETTO_SOURCES)

# All sources (core + VFLisp if in development mode)
SOURCES = $(CORE_SOURCES) $(VFLISP_SOURCES)

# Platform-specific sources
ifeq ($(UNAME_S),Darwin)
    SOURCES += src/pcv_bpf_macos.c
    CFLAGS += $(MACOS_CFLAGS)
    LDFLAGS += $(MACOS_LDFLAGS)
else ifeq ($(UNAME_S),Linux)
    SOURCES += src/pcv_raw_linux.c
    CFLAGS += $(LINUX_CFLAGS)
    LDFLAGS += $(LINUX_LDFLAGS)
endif

OBJECTS = $(SOURCES:.c=.o)
TARGET = packetvelocity

# Targets
.PHONY: all build-info clean debug test examples install uninstall install-deps help
.PHONY: dev prod pcv-macos pcv-linux

all: build-info $(TARGET)

# Show build information
build-info:
	@echo "PacketVelocity Build Configuration:"
	@echo "  Build Mode: $(BUILD_MODE)"
	@echo "  Platform: $(UNAME_S)"
	@echo "  Prefix: $(PREFIX)"
ifeq ($(BUILD_MODE),development)
	@echo "  Using local sources (development mode)"
	@echo "  VFM Root: $(VFM_ROOT)"
else
	@echo "  Using installed libraries (production mode)"
endif
	@echo "  RistrettoDB output backend (opt-in): $(RISTRETTO)"
ifeq ($(RISTRETTO),1)
	@echo "  RistrettoDB Root: $(RISTRETTO_ROOT)"
endif

# Convenience targets
dev: BUILD_MODE=development
dev: all

prod: BUILD_MODE=production  
prod: all

# Debug build
debug: CFLAGS += $(DEBUG_FLAGS)
debug: clean all

# Platform-specific targets
ifeq ($(UNAME_S),Darwin)
pcv-macos: $(TARGET)
	@echo "Built PacketVelocity for macOS"
else ifeq ($(UNAME_S),Linux)
pcv-linux: $(TARGET)
	@echo "Built PacketVelocity for Linux"
endif

$(TARGET): $(OBJECTS)
	@echo "Linking $(TARGET)..."
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

# Object file compilation
%.o: %.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Special rule for VFM filter compilation (needs GNU extensions)
src/pcv_filter_vfm.o: src/pcv_filter_vfm.c
ifeq ($(UNAME_S),Darwin)
	@echo "Compiling $< (VFM with GNU extensions)..."
	$(CC) $(VFM_CFLAGS) $(MACOS_CFLAGS) $(INCLUDES) -c $< -o $@
else ifeq ($(UNAME_S),Linux)
	@echo "Compiling $< (VFM with GNU extensions)..."
	$(CC) $(VFM_CFLAGS) $(LINUX_CFLAGS) $(INCLUDES) -c $< -o $@
endif

# Installation targets
install: $(TARGET)
	@echo "Installing PacketVelocity to $(PREFIX)..."
	install -d $(PREFIX)/bin
	install -m 755 $(TARGET) $(PREFIX)/bin/
	@echo "PacketVelocity installed successfully"

uninstall:
	@echo "Uninstalling PacketVelocity from $(PREFIX)..."
	rm -f $(PREFIX)/bin/$(TARGET)
	@echo "PacketVelocity uninstalled"

# Install the required dependency (VelocityFilterMachine).
# RistrettoDB is an OPTIONAL, opt-in output backend and is NOT installed here;
# build it separately and enable it with `make RISTRETTO=1` if you want it.
install-deps:
	@echo "Installing required dependency (VelocityFilterMachine)..."
	$(MAKE) -C ../VelocityFilterMachine install PREFIX=$(PREFIX)
	@echo "VelocityFilterMachine installed to $(PREFIX)"
	@echo "NOTE: RistrettoDB is optional; enable the output backend with 'make RISTRETTO=1'"

# Clean
clean:
	rm -f $(OBJECTS) $(TARGET)
	rm -f tests/*.o benchmarks/*.o
	rm -f tests/test_ringbuf tests/test_flow tests/test_replay tests/test_ristretto
	rm -f examples/simple_capture
	@echo "Cleaned build artifacts"

# ---- Offline tests -------------------------------------------------------
# All tests run WITHOUT root and WITHOUT live packet capture. The capture
# pipeline is exercised with synthetic packets and an in-process pcap replay
# harness (tests/pcap_replay.c), so capture/filter logic is testable in CI.
#
# Tests always build in the DEFAULT configuration (no RistrettoDB dependency).
TEST_DIR = tests

ifeq ($(UNAME_S),Darwin)
    TEST_PLATFORM_CFLAGS = $(MACOS_CFLAGS)
else
    TEST_PLATFORM_CFLAGS = $(LINUX_CFLAGS)
endif

test:
	@echo "Building offline tests (no root, no live capture)..."
	$(CC) $(CFLAGS) $(BASE_INCLUDES) \
	    $(TEST_DIR)/test_ringbuf.c src/pcv_ringbuf.c \
	    -o $(TEST_DIR)/test_ringbuf
	$(CC) $(CFLAGS) $(BASE_INCLUDES) \
	    $(TEST_DIR)/test_flow.c src/pcv_flow.c \
	    -o $(TEST_DIR)/test_flow
	$(CC) $(VFM_CFLAGS) $(TEST_PLATFORM_CFLAGS) $(BASE_INCLUDES) $(VFM_INCLUDES) \
	    $(TEST_DIR)/test_replay.c $(TEST_DIR)/pcap_replay.c \
	    src/pcv_filter_vfm.c src/pcv_flow.c $(VFLISP_SOURCES) \
	    -o $(TEST_DIR)/test_replay $(VFM_LDFLAGS)
ifeq ($(RISTRETTO),1)
	@echo "Building RistrettoDB V2 sink test (RISTRETTO=1)..."
	$(CC) $(CFLAGS) $(BASE_INCLUDES) $(RISTRETTO_INCLUDES) \
	    $(TEST_DIR)/test_ristretto.c $(TEST_DIR)/pcap_replay.c \
	    src/pcv_output_ristretto.c src/pcv_flow.c \
	    -o $(TEST_DIR)/test_ristretto $(RISTRETTO_LDFLAGS)
endif
	@echo ""
	@echo "=== test_ringbuf ==="
	@./$(TEST_DIR)/test_ringbuf
	@echo ""
	@echo "=== test_flow ==="
	@./$(TEST_DIR)/test_flow
	@echo ""
	@echo "=== test_replay (pcap replay -> filter -> flow pipeline) ==="
	@./$(TEST_DIR)/test_replay
ifeq ($(RISTRETTO),1)
	@echo ""
	@echo "=== test_ristretto (RistrettoDB V2 sink round-trip) ==="
	@./$(TEST_DIR)/test_ristretto
endif
	@echo ""
	@echo "All tests passed."

# ---- Example programs ----------------------------------------------------
# NOTE: the Makefile builds the `packetvelocity` CLI binary, not a
# libpacketvelocity archive, so examples are compiled directly against the
# capture sources (plus VelocityFilterMachine).
EXAMPLE_LIB_SOURCES = src/pcv_platform.c src/pcv_filter_vfm.c \
                      src/pcv_ringbuf.c src/pcv_flow.c $(VFLISP_SOURCES)
ifeq ($(UNAME_S),Darwin)
    EXAMPLE_LIB_SOURCES += src/pcv_bpf_macos.c
else ifeq ($(UNAME_S),Linux)
    EXAMPLE_LIB_SOURCES += src/pcv_raw_linux.c
endif

examples: examples/simple_capture
	@echo "Built examples (run live capture with root, e.g. sudo ./examples/simple_capture en0)"

examples/simple_capture: examples/simple_capture.c $(EXAMPLE_LIB_SOURCES)
	$(CC) $(VFM_CFLAGS) $(TEST_PLATFORM_CFLAGS) $(BASE_INCLUDES) $(VFM_INCLUDES) \
	    $< $(EXAMPLE_LIB_SOURCES) -o $@ $(VFM_LDFLAGS)

# Help
help:
	@echo "PacketVelocity Build System"
	@echo "=========================="
	@echo ""
	@echo "Build modes:"
	@echo "  make                    - Build in development mode (default)"
	@echo "  make dev                - Build in development mode (local sources)"
	@echo "  make prod               - Build in production mode (installed libs)"
	@echo "  make BUILD_MODE=development - Explicit development build"
	@echo "  make BUILD_MODE=production  - Explicit production build"
	@echo ""
	@echo ""
	@echo "Optional RistrettoDB output backend (opt-in, default OFF):"
	@echo "  make RISTRETTO=1        - Build with the RistrettoDB V2 output backend"
	@echo "  make RISTRETTO=1 RISTRETTO_ROOT=/path - Use a specific RistrettoDB checkout"
	@echo "  then: ./packetvelocity -i <if> --output ristretto:<path>  (writes <path>.rdb)"
	@echo ""
	@echo "Other targets:"
	@echo "  make debug              - Build with debug symbols"
	@echo "  make clean              - Remove build artifacts"
	@echo "  make test               - Build and run the offline tests (no root)"
	@echo ""
	@echo "Installation:"
	@echo "  make install-deps       - Install the required dependency (VFM)"
	@echo "  make install            - Install PacketVelocity to $(PREFIX)"
	@echo "  make uninstall          - Remove PacketVelocity from $(PREFIX)"
	@echo ""
	@echo "Variables:"
	@echo "  PREFIX=$(PREFIX)        - Installation prefix"
	@echo "  BUILD_MODE=$(BUILD_MODE) - Current build mode (development/production)"
	@echo "  RISTRETTO=$(RISTRETTO)  - Optional RistrettoDB backend (0=off, 1=on)"

# Dependencies
src/pcv_main.o: include/pcv.h include/pcv_platform.h
src/pcv_platform.o: include/pcv_platform.h
src/pcv_bpf_macos.o: include/pcv_platform.h include/pcv_bpf_macos.h
src/pcv_filter_vfm.o: include/pcv_filter.h
src/pcv_output_ristretto.o: include/pcv_output.h
src/pcv_ringbuf.o: include/pcv_ringbuf.h