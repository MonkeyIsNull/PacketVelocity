# PacketVelocity

High-performance packet capture library with platform-specific optimizations.

<img src="logo.jpg" alt="pvc_logo" width="85%" />

## Status
Please note, this is still a work in progress and very alpha.
I have gotten it to run and log packets to stdout but beyond that you may be in for a wild and broken ride.

- Phase 1, 2, 3 & 4 are complete

- Actual Linux support is untested at this time.


### What's Implemented

**Core Components:**
- Platform abstraction layer (pcv_platform.h)
- macOS BPF backend with mmap() support
- Linux AF_XDP backend with zero-copy support
- Ring buffer for batch processing
- VFM (VelocityFilterMachine)
- CLI tool with filter support
- RistrettoDB output stub

**Platform Support:**

**macOS Features:**
- High-performance capture using /dev/bpf devices
- Zero-copy reads via mmap() when available
- BIOCIMMEDIATE mode for low-latency capture
- Configurable buffer sizes
- Promiscuous mode support

**Linux Features:**
- AF_XDP socket support with zero-copy
- NUMA-aware memory allocation
- CPU core pinning
- Hardware offload capabilities
- XDP program management
- Batch packet processing

## Building

```bash
# macOS or Linux
make clean
make

# Platform-specific targets
make pcv-macos    # macOS only
make pcv-linux    # Linux only
```

## Dependencies

**macOS:** No external dependencies
**Linux:** libxdp, libbpf (optional - stubs provided)

```bash
# Ubuntu/Debian
apt install libxdp-dev libbpf-dev

# RHEL/CentOS
yum install libxdp-devel libbpf-devel
```

## Usage

```bash
# Basic capture on interface
sudo ./packetvelocity -i en0     # macOS
sudo ./packetvelocity -i eth0    # Linux

# Capture with verbose output
sudo ./packetvelocity -i en0 -v

# Enable promiscuous and immediate mode
sudo ./packetvelocity -i en0 -p -I

# With VFM filter (when implemented)
sudo ./packetvelocity -i en0 -f myfilter.vfm
```

## Performance Targets

| Platform | Target | Packet Size | Status |
|----------|--------|-------------|---------|
| macOS BPF | 500K-1M pps | 64 byte | Implemented |
| Linux AF_XDP | 5-10M pps | 64 byte | Implemented (stub) |

## Examples

```bash
# Simple capture example
gcc examples/simple_capture.c -I./include -L. -lpacketvelocity -o simple_capture

# Linux NUMA demo (Linux only)
gcc examples/linux_numa_demo.c -I./include -L. -lpacketvelocity -o numa_demo
```

## Next Steps

### Phase 5: Production Hardening
- Signal handling improvements
- Thread-safe operations
- Performance optimizations
- Documentation

## Architecture

```
PacketVelocity
├── Platform Interface (abstract)
│   ├── macOS: BPF + mmap (implemented)
│   └── Linux: AF_XDP + zero-copy (implemented)
├── Ring Buffer Manager (implemented)
├── Filter Engine (VFM stub)
└── Output Plugins (RistrettoDB stub)
```

## API Design

```c
// Initialize capture
pcv_handle* pcv_open(const char* interface, pcv_config* config);

// Set filter (TinyTotVM bytecode or BPF)
int pcv_set_filter(pcv_handle* h, void* filter, size_t len);

// Capture packets
int pcv_capture(pcv_handle* h, pcv_callback cb, void* user);

// Batch capture for performance
int pcv_capture_batch(pcv_handle* h, pcv_batch_callback cb, void* user);

// Get statistics
pcv_stats* pcv_get_stats(pcv_handle* h);
```

## Linux AF_XDP Features

- **Zero-copy packet access** via UMEM
- **NUMA-aware allocation** for optimal memory placement
- **CPU affinity control** for performance tuning
- **Hardware offload** support where available
- **Batch processing** for high throughput
- **XDP program management** for kernel-space filtering

## Dependencies

- macOS: VFM and possibly RistrettoDB
- Linux: libxdp, libbpf (optional - stubs provided)
- VFM: https://github.com/MonkeyIsNull/VelocityFilterMachine 
- RistrettoDB: https://github.com/MonkeyIsNull/RistrettoDB (stubbed - not tested)

## License

MIT
