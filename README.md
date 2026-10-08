# PacketVelocity

[![CI](https://github.com/MonkeyIsNull/PacketVelocity/actions/workflows/ci.yml/badge.svg)](https://github.com/MonkeyIsNull/PacketVelocity/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/MonkeyIsNull/PacketVelocity)](https://github.com/MonkeyIsNull/PacketVelocity/releases/latest)
![tests](https://img.shields.io/badge/tests-68%20passing-brightgreen)
![language](https://img.shields.io/badge/language-C%20(C11)-blue)
![platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)
![status](https://img.shields.io/badge/status-active-brightgreen)
[![last commit](https://img.shields.io/github/last-commit/MonkeyIsNull/PacketVelocity)](https://github.com/MonkeyIsNull/PacketVelocity/commits/main)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-orange)](https://github.com/MonkeyIsNull/PacketVelocity/issues)
![RistrettoDB optional](https://img.shields.io/badge/RistrettoDB-optional-blue)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

High-performance packet capture library with platform-specific optimizations.

<img src="logo.jpg" alt="pvc_logo" width="85%" />

## Status
Please note, this is still a work in progress and very alpha.
The default build runs like tcpdump: it captures and logs packets to stdout with
**zero external output dependencies**. Everything beyond that is still rough.

- **macOS (BPF) is the primary, actively-exercised platform.**
- **Linux (raw sockets / AF_PACKET) is implemented but untested** - treat it as experimental.
- **Live capture requires root** (`sudo`) on both platforms, since it opens
  `/dev/bpf*` (macOS) or raw sockets (Linux).
- The RistrettoDB output backend is **optional and opt-in** (`make RISTRETTO=1`);
  it is NOT built by default and is not required to capture.


### What's Implemented

**Core Components:**
- Platform abstraction layer (pcv_platform.h)
- macOS BPF backend with mmap() support (primary, actively used)
- Linux raw socket backend (AF_PACKET, promiscuous mode) - untested
- Ring buffer for batch processing
- VFM (VelocityFilterMachine) with full IPv6 support
- VFLisp DSL for intuitive filter programming
- CLI tool that streams captured packets to stdout, tcpdump-style
- Optional RistrettoDB output backend (opt-in, OFF by default; see below)

**IPv6 Support (NEW):**
- Complete IPv6 field access (src-ip6, dst-ip6)
- IPv6 address literal parsing (::1, 2001:db8::1, etc.)
- IPv6 extension header support
- Dynamic offset calculation for IPv6 fields
- 128-bit operations for IPv6 addresses
- ARM64 JIT compilation for IPv6 operations
- Enhanced verifier for IPv6 safety

**Performance Features:**
- ARM64 JIT compilation with NEON 128-bit operations
- Direct VFLisp expression processing (no intermediate files)
- High-performance packet capture with filtering
- Flexible capture limits (packet count or time-based)

**Platform Support:**

**macOS Features:**
- High-performance capture using /dev/bpf devices
- Zero-copy reads via mmap() when available
- BIOCIMMEDIATE mode for low-latency capture
- Configurable buffer sizes
- Promiscuous mode support

**Linux Features:**
- Raw socket packet capture with promiscuous mode
- Standard Linux socket API (no external dependencies)
- VFM-based userspace filtering

**Note:** XDP/AF_XDP support has been removed in the current release to focus on VelocityFilterMachine-based filtering. XDP support is planned for a future release.

## Building

```bash
# Default build - hermetic, no RistrettoDB dependency, streams to stdout
make clean
make

# Platform-specific targets
make pcv-macos    # macOS only
make pcv-linux    # Linux only

# Run the offline test suite (no root, no live capture)
make test

# Build the bundled example program(s)
make examples

# Install system-wide (optional)
sudo make install  # Installs to /usr/local/bin
```

### Optional RistrettoDB output backend (opt-in)

RistrettoDB output is **off by default**. The default build has zero RistrettoDB
dependency. To build with it, enable it explicitly and point at a RistrettoDB
checkout:

```bash
make RISTRETTO=1                              # expects ../RistrettoDB
make RISTRETTO=1 RISTRETTO_ROOT=/path/to/RistrettoDB
```

The backend targets the RistrettoDB **V2** append-only, fixed-width table API
and appends **one row per captured packet**. Route capture to a table with
`--output ristretto:<path>` (writes `<path>.rdb`):

```bash
sudo ./packetvelocity -i en0 --output ristretto:/var/log/pv/capture
# -> creates /var/log/pv/capture.rdb, one row per packet
```

The fixed schema (table `packets`) is IPv6-friendly: addresses are stored as
text via `inet_ntop`, so full IPv6 / IPv4-mapped literals round-trip unchanged.

| column | type | meaning |
|--------|------|---------|
| `ts_ns` | INTEGER | packet timestamp, nanoseconds since epoch |
| `src_ip` / `dst_ip` | TEXT(46) | addresses (`inet_ntop`, AF_INET/AF_INET6) |
| `src_port` / `dst_port` | INTEGER | L4 ports (host order; 0 if none) |
| `protocol` | INTEGER | IP protocol number (6=TCP, 17=UDP, ...) |
| `addr_family` | INTEGER | 4 (IPv4) or 6 (IPv6) |
| `length` | INTEGER | original on-wire packet length |
| `caplen` | INTEGER | captured length (`<= length`) |

#### Per-flow output (`ristretto-flow:<path>`)

As a parallel mode, `--output ristretto-flow:<path>` writes **one row per flow**
(a 5-tuple conversation) to a `flows` table at `<path>.rdb`, instead of one row
per packet. Packets are aggregated with PacketVelocity's own flow tracking; a
row is emitted when a flow is evicted during capture (idle timeout or TCP FIN)
and, at shutdown, for every flow still open - so each flow produces exactly one
row, with nothing dropped or double-counted.

```bash
sudo ./packetvelocity -i en0 --output ristretto-flow:/var/log/pv/flows
# -> creates /var/log/pv/flows.rdb, one row per 5-tuple conversation
```

The fixed schema (table `flows`) is IPv6-friendly the same way:

| column | type | meaning |
|--------|------|---------|
| `src_ip` / `dst_ip` | TEXT(46) | addresses (`inet_ntop`, AF_INET/AF_INET6) |
| `src_port` / `dst_port` | INTEGER | L4 ports (host order; 0 if none) |
| `protocol` | INTEGER | IP protocol number (6=TCP, 17=UDP, ...) |
| `addr_family` | INTEGER | 4 (IPv4) or 6 (IPv6) |
| `first_ts_ns` / `last_ts_ns` | INTEGER | first / last packet timestamp (ns since epoch) |
| `packet_count` | INTEGER | packets aggregated into this flow |
| `byte_count` | INTEGER | sum of captured lengths over the flow |
| `tcp_flags` | INTEGER | union (OR) of TCP flag bytes seen (0 for non-TCP) |

Per-packet mode remains the default `ristretto:` behaviour and is unchanged.

If you pass `--output ristretto:...` or `--output ristretto-flow:...` to a binary
built **without** `RISTRETTO=1`, it fails fast with a clear message rather than
silently ignoring the flag.

## Dependencies

**Build (all platforms):** [VelocityFilterMachine](https://github.com/MonkeyIsNull/VelocityFilterMachine)
is required (provides `libvfm.a` and the VFLisp compiler). It is expected at
`../VelocityFilterMachine` for the default development build.

**Runtime:**
- **macOS:** no external runtime dependencies (uses BSD/Darwin BPF). Root required for live capture.
- **Linux:** no external runtime dependencies (uses standard raw sockets). Root required for live capture.
- **RistrettoDB:** optional, opt-in only (see above).

## Usage

### Quick Start with pcv.sh Script
The easiest way to use PacketVelocity is with the included `pcv.sh` script, which works both from source and when installed system-wide:

```bash
# Basic Usage (runs until Ctrl+C)
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

# With Limits
sudo ./pcv.sh en0 "(= proto 6)" 50                 # Capture 50 TCP packets
sudo ./pcv.sh en0 "(= ip-version 6)" t:30          # Capture IPv6 for 30 seconds
```

**Key Features:**
- **Direct VFLisp processing** - expressions are compiled and JIT-optimized internally
- **Automatic installation detection** - works from `/usr/local` or source directory
- **Flexible capture limits** - packet count, time limit, or unlimited
- **High performance** - utilizes ARM64 JIT compilation for IPv6 operations

### Direct Binary Usage
```bash
# Basic capture on interface (unlimited)
sudo ./packetvelocity -i en0     # macOS
sudo ./packetvelocity -i eth0    # Linux

# With VFLisp filter expression (enables JIT)
sudo ./packetvelocity -i en0 -l "(= proto 6)" -v

# With packet or time limits
sudo ./packetvelocity -i en0 -l "(= ip-version 6)" --packet-num 100
sudo ./packetvelocity -i en0 -l "(= dst-port 443)" --seconds-num 30

# Enable promiscuous and immediate mode
sudo ./packetvelocity -i en0 -p -I

# With pre-compiled VFM filter (bypasses JIT)
sudo ./packetvelocity -i en0 -f myfilter.bin

# Output sink: default is the tcpdump-style stdout stream ('-' / 'stdout').
# With a RISTRETTO=1 build, append one row per packet to a RistrettoDB V2 table:
sudo ./packetvelocity -i en0 -l "(= proto 6)" --output ristretto:/tmp/tcp_capture
# ...or one row per flow (5-tuple conversation) instead of per packet:
sudo ./packetvelocity -i en0 -l "(= proto 6)" --output ristretto-flow:/tmp/tcp_flows
```

### Live dashboard (`--serve`)

`--serve <port>` serves a self-contained live dashboard instead of the stdout
stream. One HTML page (no external URLs, no CDN, inline SVG charts) plus a small
JSON API (`/stats.json`, `/healthz`) with three panels: **capture health**
(packets/s, Mbit/s, and a prominent **drop-rate / buffer-health** indicator),
**protocol mix** (TCP/UDP/ICMP/ARP/IPv6/other), and a **top live-flow table**.

```bash
# Capture needs root; the HTTP server binds LOOPBACK ONLY (127.0.0.1).
sudo ./packetvelocity -i en0 --serve 8080      # then open http://127.0.0.1:8080
sudo ./packetvelocity -i en0 --serve 0 -v      # 0 = auto-pick a free loopback port
```

Notes:

- **Root is for capture, not the web server.** `--serve` still opens `/dev/bpf*`
  (macOS) / a raw socket (Linux), which needs `sudo`. The HTTP bind itself needs
  no privilege.
- **Loopback only, always.** The server binds `127.0.0.1` exclusively (validated
  before *and* after `bind()`); there is no flag to expose it on a LAN. A
  DNS-rebinding `Host` check and a zero-CORS response posture guard it further.
- **The per-packet stdout stream is suppressed** in this mode (deliberate; the
  tcpdump-style stream and the dashboard are mutually exclusive). `--serve`
  cannot be combined with `--output ristretto:`/`ristretto-flow:`.
- **The hot capture path is never slowed by serving.** The packet callback only
  does cheap work (atomic counters + the existing flow update + a wait-free,
  trylock-published ≤1 Hz snapshot); the HTTP server and a 1 Hz sampler run on
  separate threads and only read a published snapshot. A ThreadSanitizer CI leg
  proves the isolation. Without `--serve`, zero threads or sockets are created
  and the default path is unchanged.

## Performance

Real, **measured** numbers for the **offline processing pipeline** (everything
after capture: filter → flow tracking → output), produced by `make bench`
(source: [`bench/bench_pipeline.c`](bench/bench_pipeline.c)). Full methodology,
the exact packet mix, and caveats are in **[BENCHMARKS.md](BENCHMARKS.md)**.

> **Offline, post-capture numbers — not live capture off the wire.** Live
> capture needs root + a real NIC and is **out of scope** for this benchmark.

Measured on an **Apple M1** (`MacBookPro17,1`, 8 cores, macOS Darwin 24.6.0
arm64, clang 17.0.0) over **2,000,000** in-memory frames (mixed IPv4/IPv6,
TCP/UDP, 64–1514 B, mean 610 B, 20,000 distinct flows). Throughput is per input
packet; best of 7 timed runs (median in parentheses):

| stage (cumulative)         | throughput (Mpps) | ns/packet |
|----------------------------|------------------:|----------:|
| baseline (replay loop)     |    197.8 (189.3)  |  5.1 (5.3) |
| + filter (VFM/VFLisp JIT)  |     13.8 (13.4)   | 72.7 (74.7)|
| + flow tracking (v4/v6)    |      9.6 (9.4)    | 104.6 (106.8)|
| + stdout format (→/dev/null) | 0.98 (0.97)     | 1025 (1031)|
| + RistrettoDB, per-packet  |      1.09 (1.08)  | 918 (928)  |
| + RistrettoDB, per-flow    |      2.80 (2.79)  | 357 (359)  |

The last two rows require `make bench RISTRETTO=1`. The RistrettoDB sinks write
to a temp `.rdb` file so real `mmap`/disk I/O is included.

**Caveats:** (i) these are **offline processing-pipeline** numbers, not
live-capture-off-the-wire; (ii) they reflect this specific Apple M1 — treat them
as a ballpark and a **relative stage comparison**, not a guarantee for other
hardware; (iii) **live-capture + Linux-hardware numbers are still TODO** (need
sudo + a Linux box). No Docker/QEMU-emulated numbers are ever reported (they are
meaningless for throughput). See [BENCHMARKS.md](BENCHMARKS.md) to reproduce.

### Backend status (not yet benchmarked)

| Platform | Capture backend | Status |
|----------|-----------------|--------|
| macOS BPF | `/dev/bpf*` + mmap | Implemented, actively used (live-capture rate not yet benchmarked) |
| Linux Raw Sockets | AF_PACKET | Implemented, untested |

## Examples

The Makefile builds the `packetvelocity` CLI binary (not a `libpacketvelocity`
archive), so the bundled example is compiled directly against the capture
sources via the `examples` target:

```bash
# Build the example program(s)
make examples

# Run it (live capture needs root)
sudo ./examples/simple_capture en0    # macOS
sudo ./examples/simple_capture eth0   # Linux
```

### pcv.sh Script Usage
The `pcv.sh` script provides an easy interface for VFLisp filtering:

```bash
# Script syntax
sudo ./pcv.sh <interface> "<vflisp-expression>" [packet-count|time-limit]

# Examples
sudo ./pcv.sh en0 "(= proto 6)"                    # Run until Ctrl+C
sudo ./pcv.sh en0 "(= ip-version 6)" 100           # Capture 100 IPv6 packets  
sudo ./pcv.sh en0 "(= dst-port 443)" t:60          # Capture HTTPS for 60 seconds
```

## Architecture

```
PacketVelocity
├── Platform Interface (abstract)
│   ├── macOS: BPF + mmap (implemented)
│   └── Linux: Raw sockets + VFM filtering (implemented)
├── Ring Buffer Manager (implemented)
├── Filter Engine (VFM with IPv6 support)
└── Output: stdout stream (default) + optional RistrettoDB backend (opt-in)
```

## API Design

```c
// Initialize capture
pcv_handle* pcv_open(const char* interface, pcv_config* config);

// Set filter (VFM bytecode or BPF)
int pcv_set_filter(pcv_handle* h, void* filter, size_t len);

// Capture packets
int pcv_capture(pcv_handle* h, pcv_callback cb, void* user);

// Batch capture for performance
int pcv_capture_batch(pcv_handle* h, pcv_batch_callback cb, void* user);

// Get statistics
pcv_stats* pcv_get_stats(pcv_handle* h);
```

## Linux Raw Socket Features

- **Standard raw socket packet capture** using AF_PACKET
- **Promiscuous mode support** for complete packet visibility
- **VFM userspace filtering** with IPv6 support and JIT compilation
- **No external dependencies** - uses kernel-provided socket API
- **Root privileges required** for raw socket access

## Core Dependencies

- **VFM** (required): [VelocityFilterMachine](https://github.com/MonkeyIsNull/VelocityFilterMachine) with complete IPv6 support and JIT compilation
- **RistrettoDB** (optional, opt-in): https://github.com/MonkeyIsNull/RistrettoDB - only compiled in with `make RISTRETTO=1`; the default build has no RistrettoDB dependency

**Platform Dependencies:**
- macOS: No external dependencies (uses BSD/Darwin BPF)
- Linux: No external dependencies (uses standard raw sockets)

## IPv6 Support

PacketVelocity now includes comprehensive IPv6 support through VelocityFilterMachine:

- **Complete IPv6 field access**: src-ip6, dst-ip6, ip-version
- **IPv6 address literals**: ::1, 2001:db8::1, etc.
- **Extension header support**: Dynamic offset calculation for transport fields
- **High performance**: ARM64 JIT compilation for IPv6 operations
- **Safety verified**: Enhanced verifier prevents IPv6-related crashes

## Contributing

Issues and pull requests are welcome. Found a bug or have an idea? Open an issue. Want to send a change? Fork, make it, and open a PR — please build and run the offline test suite first (`make && make test`, after building the `../VelocityFilterMachine` dependency with `make libvfm.a`). CI builds and runs the offline tests on macOS and Linux, including the opt-in `RISTRETTO=1` backend.

## License

MIT
