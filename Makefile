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

# RistrettoDB support (optional)
HAVE_RISTRETTO ?= 0

# Build mode configuration
ifeq ($(BUILD_MODE),development)
    # Development: Use local source libraries with latest changes
    VFM_ROOT = ../VelocityFilterMachine
    RISTRETTO_ROOT = ../RistrettoDB
    
    VFM_INCLUDES = -I$(VFM_ROOT)/include -I$(VFM_ROOT)/dsl/vflisp
    VFM_LDFLAGS = $(VFM_ROOT)/libvfm.a
    
    # Check if RistrettoDB is available in development mode
    ifeq ($(HAVE_RISTRETTO),1)
        RISTRETTO_LDFLAGS = $(RISTRETTO_ROOT)/lib/libristretto.a
        CFLAGS += -DHAVE_RISTRETTO=1
    else ifneq ($(wildcard $(RISTRETTO_ROOT)/lib/libristretto.a),)
        RISTRETTO_LDFLAGS = $(RISTRETTO_ROOT)/lib/libristretto.a
        CFLAGS += -DHAVE_RISTRETTO=1
        HAVE_RISTRETTO = 1
    else
        RISTRETTO_LDFLAGS = 
        CFLAGS += -DHAVE_RISTRETTO=0
    endif
    
    # Include VFLisp sources directly in development mode
    VFLISP_SOURCES = $(VFM_ROOT)/dsl/vflisp/vflisp_parser.c \
                     $(VFM_ROOT)/dsl/vflisp/vflisp_compile.c
else ifeq ($(BUILD_MODE),production)
    # Production: Use installed system libraries
    VFM_INCLUDES = -I$(PREFIX)/include
    VFM_LDFLAGS = -L$(PREFIX)/lib -lvfm
    
    # Check if RistrettoDB is available in production mode
    ifeq ($(HAVE_RISTRETTO),1)
        RISTRETTO_LDFLAGS = -L$(PREFIX)/lib -lristretto
        CFLAGS += -DHAVE_RISTRETTO=1
    else
        RISTRETTO_LDFLAGS = 
        CFLAGS += -DHAVE_RISTRETTO=0
    endif
    
    # No VFLisp sources - use installed library
    VFLISP_SOURCES = 
else
    $(error Invalid BUILD_MODE: $(BUILD_MODE). Use 'development' or 'production')
endif

# Base includes
BASE_INCLUDES = -I./include

# Combined includes
INCLUDES = $(BASE_INCLUDES) $(VFM_INCLUDES)

# Combined LDFLAGS
LDFLAGS = $(VFM_LDFLAGS) $(RISTRETTO_LDFLAGS)

# Core source files
CORE_SOURCES = src/pcv_main.c \
               src/pcv_platform.c \
               src/pcv_filter_vfm.c \
               src/pcv_output_ristretto.c \
               src/pcv_ringbuf.c \
               src/pcv_flow.c \
               src/ristretto_stub.c

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
.PHONY: all clean debug test bench install uninstall install-deps help
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
	@echo "  RistrettoDB Support: $(HAVE_RISTRETTO)"
else
	@echo "  Using installed libraries (production mode)"
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

# Install dependencies (VFM and RistrettoDB)
install-deps:
	@echo "Installing dependencies..."
	@echo "Installing VelocityFilterMachine..."
	$(MAKE) -C ../VelocityFilterMachine install PREFIX=$(PREFIX)
	@echo "Installing RistrettoDB..."
	$(MAKE) -C ../RistrettoDB install PREFIX=$(PREFIX)
	@echo "All dependencies installed to $(PREFIX)"

# Clean
clean:
	rm -f $(OBJECTS) $(TARGET)
	rm -f tests/*.o benchmarks/*.o
	@echo "Cleaned build artifacts"

# Test
TEST_VFM_OBJECTS = $(filter-out src/pcv_main.o, $(OBJECTS))

test_vfm: test_vfm.c $(TEST_VFM_OBJECTS)
	$(CC) $(VFM_CFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS)

test:
	@echo "Running tests..."
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_bpf.c -o tests/test_bpf
	./tests/test_bpf

# Benchmarks
bench:
	@echo "Running benchmarks..."
	$(CC) $(CFLAGS) $(INCLUDES) benchmarks/bench_capture.c -o benchmarks/bench_capture
	./benchmarks/bench_capture

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
	@echo "Other targets:"
	@echo "  make debug              - Build with debug symbols"
	@echo "  make clean              - Remove build artifacts"
	@echo "  make test               - Run tests"
	@echo "  make bench              - Run benchmarks"
	@echo ""
	@echo "Installation:"
	@echo "  make install-deps       - Install VFM and RistrettoDB dependencies"
	@echo "  make install            - Install PacketVelocity to $(PREFIX)"
	@echo "  make uninstall          - Remove PacketVelocity from $(PREFIX)"
	@echo ""
	@echo "Variables:"
	@echo "  PREFIX=$(PREFIX)        - Installation prefix"
	@echo "  BUILD_MODE=$(BUILD_MODE) - Current build mode"
	@echo "  HAVE_RISTRETTO=$(HAVE_RISTRETTO) - RistrettoDB support (0=disabled, 1=enabled)"

# Dependencies
src/pcv_main.o: include/pcv.h include/pcv_platform.h
src/pcv_platform.o: include/pcv_platform.h
src/pcv_bpf_macos.o: include/pcv_platform.h include/pcv_bpf_macos.h
src/pcv_filter_vfm.o: include/pcv_filter.h
src/pcv_output_ristretto.o: include/pcv_output.h
src/pcv_ringbuf.o: include/pcv_ringbuf.h