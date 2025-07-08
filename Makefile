# PacketVelocity Makefile
# High-performance packet capture library

CC = clang
CFLAGS = -Wall -Wextra -O3 -std=c11
INCLUDES = -I./include -I/usr/local/include
LDFLAGS = -L/usr/local/lib -lvfm

# Special flags for VFM compilation (uses GNU extensions)
VFM_CFLAGS = -Wall -Wextra -O3 -std=gnu11 

# macOS specific flags
MACOS_CFLAGS = -DPLATFORM_MACOS
MACOS_LDFLAGS = 

# Linux specific flags
LINUX_CFLAGS = -DPLATFORM_LINUX
LINUX_LDFLAGS = -lxdp -lbpf 

# Platform detection
UNAME_S := $(shell uname -s)

# Source files
SOURCES = src/pcv_main.c \
          src/pcv_platform.c \
          src/pcv_filter_vfm.c \
          src/pcv_output_ristretto.c \
          src/pcv_ringbuf.c \
          src/pcv_flow.c \
          src/ristretto_stub.c

# Platform-specific sources
ifeq ($(UNAME_S),Darwin)
    SOURCES += src/pcv_bpf_macos.c
else ifeq ($(UNAME_S),Linux)
    SOURCES += src/pcv_xdp_linux.c
endif

OBJECTS = $(SOURCES:.c=.o)
TARGET = packetvelocity
ifeq ($(UNAME_S),Darwin)
    CFLAGS += $(MACOS_CFLAGS)
    LDFLAGS += $(MACOS_LDFLAGS)
else ifeq ($(UNAME_S),Linux)
    CFLAGS += $(LINUX_CFLAGS)
    LDFLAGS += $(LINUX_LDFLAGS)
endif

# Targets
.PHONY: all clean test bench pcv-macos pcv-linux pcv-portable

all: $(TARGET)

ifeq ($(UNAME_S),Darwin)
pcv-macos: $(TARGET)
	@echo "Built PacketVelocity for macOS"
else ifeq ($(UNAME_S),Linux)
pcv-linux: $(TARGET)
	@echo "Built PacketVelocity for Linux"
endif

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

TEST_VFM_OBJECTS = $(filter-out src/pcv_main.o, $(OBJECTS))

test_vfm: test_vfm.c $(TEST_VFM_OBJECTS)
	$(CC) $(VFM_CFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Special rule for VFM filter compilation
src/pcv_filter_vfm.o: src/pcv_filter_vfm.c
ifeq ($(UNAME_S),Darwin)
	$(CC) $(VFM_CFLAGS) $(MACOS_CFLAGS) $(INCLUDES) -c $< -o $@
else ifeq ($(UNAME_S),Linux)
	$(CC) $(VFM_CFLAGS) $(LINUX_CFLAGS) $(INCLUDES) -c $< -o $@
endif

clean:
	rm -f $(OBJECTS) $(TARGET)
	rm -f tests/*.o benchmarks/*.o
	@echo "Cleaned build artifacts"

test:
	@echo "Running tests..."
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_bpf.c -o tests/test_bpf
	./tests/test_bpf

bench:
	@echo "Running benchmarks..."
	$(CC) $(CFLAGS) $(INCLUDES) benchmarks/bench_capture.c -o benchmarks/bench_capture
	./benchmarks/bench_capture

# Dependencies
src/pcv_main.o: include/pcv.h include/pcv_platform.h
src/pcv_platform.o: include/pcv_platform.h
src/pcv_bpf_macos.o: include/pcv_platform.h include/pcv_bpf_macos.h
src/pcv_filter_vfm.o: include/pcv_filter.h
src/pcv_output_ristretto.o: include/pcv_output.h
src/pcv_ringbuf.o: include/pcv_ringbuf.h
