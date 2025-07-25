# PacketVelocity

High-performance packet capture library with platform-specific optimizations.

<img src="logo.jpg" alt="pvc_logo" width="85%" />

## Status
Please note, this is still a work in progress and very alpha.
I have gotten it to run and log packets to stdout but beyond that you may be in for a wild and broken ride.

- Actual Linux support is untested at this time.


### What's Implemented

**Core Components:**
- Platform abstraction layer (pcv_platform.h)
- macOS BPF backend with mmap() support
- Linux AF_XDP backend with zero-copy support
- Ring buffer for batch processing
- VFM (VelocityFilterMachine) with full IPv6 support
- VFLisp DSL for intuitive filter programming
- CLI tool with filter support
- RistrettoDB output stub

**IPv6 Support (NEW):**
- Complete IPv6 field access (src-ip6, dst-ip6)
- IPv6 address literal parsing (::1, 2001:db8::1, etc.)
- IPv6 extension header support
- Dynamic offset calculation for IPv6 fields
- 128-bit operations for IPv6 addresses
- ARM64 JIT compilation for IPv6 operations
- Enhanced verifier for IPv6 safety

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
# Build from source
make clean
make

# Platform-specific targets
make pcv-macos    # macOS only
make pcv-linux    # Linux only

# Install system-wide (optional)
sudo make install  # Installs to /usr/local/bin
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

### Quick Start with pcv.sh Script
The easiest way to use PacketVelocity is with the included `pcv.sh` script, which works both from source and when installed system-wide:

```bash
# IPv4 Examples
sudo ./pcv.sh en0 "(= proto 6)"                    # TCP traffic
sudo ./pcv.sh en0 "(= dst-port 443)"               # HTTPS traffic
sudo ./pcv.sh en0 "(and (= proto 6) (= dst-port 80))" # HTTP traffic

# IPv6 Examples  
sudo ./pcv.sh en0 "(= ip-version 6)"               # All IPv6 traffic
sudo ./pcv.sh en0 "(= src-ip6 ::1)"                # IPv6 loopback source
sudo ./pcv.sh en0 "(= dst-ip6 2001:db8::1)"        # Specific IPv6 destination
sudo ./pcv.sh en0 "(and (= proto 6) (!= dst-ip6 ::))" # IPv6 TCP non-null destination

# Mixed IPv4/IPv6 Examples
sudo ./pcv.sh en0 "(or (= src-port 80) (= dst-port 80))" # HTTP on either IP version
sudo ./pcv.sh en0 "(and (= ip-version 6) (= proto 17))"   # IPv6 UDP traffic

# Capture more packets
sudo ./pcv.sh en0 "(= proto 6)" 50                 # Capture 50 TCP packets
```

The `pcv.sh` script automatically detects whether PacketVelocity is installed in `/usr/local` or running from source.

### Direct Binary Usage
```bash
# Basic capture on interface
sudo ./packetvelocity -i en0     # macOS
sudo ./packetvelocity -i eth0    # Linux

# Capture with verbose output
sudo ./packetvelocity -i en0 -v

# Enable promiscuous and immediate mode
sudo ./packetvelocity -i en0 -p -I

# With pre-compiled VFM filter
sudo ./packetvelocity -i en0 -f myfilter.bin
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
- VFM: [VelocityFilterMachine](https://github.com/MonkeyIsNull/VelocityFilterMachine) with complete IPv6 support
- RistrettoDB: https://github.com/MonkeyIsNull/RistrettoDB (stubbed - not tested)

## IPv6 Support

PacketVelocity now includes comprehensive IPv6 support through VelocityFilterMachine:

- **Complete IPv6 field access**: src-ip6, dst-ip6, ip-version
- **IPv6 address literals**: ::1, 2001:db8::1, etc.
- **Extension header support**: Dynamic offset calculation for transport fields
- **High performance**: ARM64 JIT compilation for IPv6 operations
- **Safety verified**: Enhanced verifier prevents IPv6-related crashes

See `VelocityFilterMachine/IPv6_IMPLEMENTATION_SUMMARY.md` for complete details.

## License

MIT
