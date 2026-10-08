/* =============================================================================
 * PacketVelocity - offline processing-pipeline benchmark
 * -----------------------------------------------------------------------------
 * Measures the throughput of PacketVelocity's PROCESSING pipeline - everything
 * that happens to a packet AFTER it has been captured: filter -> flow tracking
 * -> output. It does NOT measure live capture off a real NIC: that needs root
 * and real hardware and is deliberately out of scope here (see README /
 * BENCHMARKS.md). Instead a large, deterministic, seeded set of synthetic
 * frames is built IN MEMORY up front (generation is NOT timed) and then driven
 * through the exact same pipeline stages the live callback runs
 * (src/pcv_main.c, tests/test_replay.c), stage by stage.
 *
 * STAGES (each = the previous plus one more piece, so the cost localises):
 *   (a) baseline  - the replay loop touching every packet, no processing
 *   (b) + filter  - a compiled VFM/VFLisp program applied to every packet
 *   (c) + flow    - accepted packets fed to the IPv4/IPv6 flow aggregator
 *                   (hash insert / lookup / periodic expiry + eviction)
 *   (d) + output, three sinks measured SEPARATELY:
 *       - stdout FORMAT sink  : the tcpdump-style line is formatted and written
 *                               to a DISCARDED fd (/dev/null), so the formatting
 *                               work is measured without a real terminal
 *       - ristretto (per-pkt) : one RistrettoDB V2 row per accepted packet,
 *                               written to a TEMP .rdb file so real mmap/disk
 *                               I/O is included (file cleaned up afterwards)
 *       - ristretto-flow      : one RistrettoDB V2 row per flow (the per-flow
 *                               sink fuses flow tracking + emission), temp file
 *   The two RistrettoDB sinks require `make RISTRETTO=1`; they are #if-guarded
 *   so the DEFAULT (hermetic, no-RistrettoDB) build still compiles and runs
 *   stages (a)-(c) + the stdout sink, linking ZERO RistrettoDB symbols.
 *
 * Each stage is warmed up, then timed several times; the BEST (steady-state
 * peak) and MEDIAN are reported as packets/sec, bytes/sec (Gbps-equivalent)
 * and ns/packet. Timing is clock_gettime(CLOCK_MONOTONIC). Throughput is always
 * expressed per INPUT packet (the whole set), which is the meaningful
 * pipeline-ingest rate: a selective filter legitimately lets later stages run
 * faster because they see fewer packets.
 * =============================================================================
 */

/* Feature-test macros first (glibc hides clock_gettime/CLOCK_MONOTONIC,
 * inet_ntop, mkstemp, dup2, strdup under strict -std unless requested; macOS
 * exposes them regardless). Matches the convention used across the tree. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE          /* sys/sysctl.h needs the BSD u_int/u_char types */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/utsname.h>

#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

#include "pcv_platform.h"
#include "pcv_filter.h"
#include "pcv_flow.h"
#include "vflisp_types.h"      /* vfl_compile_string */

/* Reuse the synthetic frame builders the test-suite already uses. pcv_test.h is
 * header-only; it also defines an assertion harness we don't need here, so we
 * reference the unused bits once with (void) to keep -Wall -Wextra quiet. */
#include "pcv_test.h"

#if HAVE_RISTRETTO
#include "pcv_output.h"        /* per-packet RistrettoDB V2 sink */
#include "pcv_output_flow.h"   /* per-flow  RistrettoDB V2 sink */
#endif

/* ---- Tunables (compile-time defaults; env can override at run time) ------- */

#ifdef BENCH_QUICK
#  ifndef BENCH_PACKETS
#    define BENCH_PACKETS 5000u       /* tiny smoke: compiles + runs, no perf */
#  endif
#  ifndef BENCH_FLOWS
#    define BENCH_FLOWS   300u
#  endif
#  ifndef BENCH_WARMUP
#    define BENCH_WARMUP  0u
#  endif
#  ifndef BENCH_REPEAT
#    define BENCH_REPEAT  1u
#  endif
#else
#  ifndef BENCH_PACKETS
#    define BENCH_PACKETS 2000000u     /* ~2M packets held in memory */
#  endif
#  ifndef BENCH_FLOWS
#    define BENCH_FLOWS   20000u        /* distinct 5-tuples (thousands+) */
#  endif
#  ifndef BENCH_WARMUP
#    define BENCH_WARMUP  2u
#  endif
#  ifndef BENCH_REPEAT
#    define BENCH_REPEAT  7u
#  endif
#endif

/* Representative compiled VFM/VFLisp filter: IPv4 TCP OR any IPv6 traffic - a
 * dual-stack capture rule. It is a compound program (an IP-protocol byte load +
 * compare OR'd with the VFM_IP_VER opcode), fully supported by VFM's JIT, and
 * crucially it routes BOTH IPv4 and IPv6 packets downstream so flow tracking and
 * the sinks exercise the v4 AND v6 paths across thousands of flows (~77% of the
 * set is accepted).
 *
 * NOTE (finding): layer-4 PORT filters such as "(= dst-port 443)" are avoided
 * on purpose. VFLisp compiles src-port/dst-port to the VFM_IPV6_EXT opcode,
 * which VFM's arm64 JIT does NOT implement: its default case emits a stub that
 * returns -1 (DROP) rather than falling back to the interpreter, so a port-based
 * filter matches ZERO packets under the (default) JIT on Apple Silicon. The
 * `proto` field is also IPv4-only (it reads a fixed offset, so "(= proto 6)"
 * never matches IPv6). `proto`, `ip-version` and IP-address fields are JIT-safe.
 * See BENCHMARKS.md. */
#define BENCH_FILTER_EXPR "(or (= proto 6) (= ip-version 6))"

/* Flow-table sizing. max_flows must exceed the distinct-flow count because
 * pcv_flow's expiry MARKS flows (fires the eviction hook) but keeps them in the
 * table, so the array only grows. Buckets are kept well above max_flows so the
 * linear-probe hash stays sparse. */
#define BENCH_MAX_FLOWS     (BENCH_FLOWS * 4u)
#define BENCH_HASH_BUCKETS  (BENCH_FLOWS * 8u)
#define BENCH_FLOW_TIMEOUT_MS 2000u    /* short, so mid-run evictions happen */
#define BENCH_CLEANUP_IVAL    8192u    /* run an expiry sweep every N packets */

/* ---- Deterministic PRNG (xorshift64) ----------------------------------- */

static uint64_t g_rng;
static inline uint64_t xrng(void) {
    uint64_t x = g_rng;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    g_rng = x;
    return x;
}
static inline uint32_t xrng_mod(uint32_t m) { return (uint32_t)(xrng() % m); }

/* ---- Keep the optimiser honest ----------------------------------------- */
static volatile uint64_t g_sink;

/* ---- Monotonic clock ---------------------------------------------------- */
static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ---- Synthetic packet set ---------------------------------------------- */

typedef struct {
    uint8_t  af;        /* 4 or 6 */
    uint8_t  proto;     /* 6 (TCP) or 17 (UDP) */
    uint16_t sport;
    uint16_t dport;
    uint32_t sip4, dip4;      /* host order (builder applies htonl) */
    uint8_t  sip6[16], dip6[16];
} flow_tmpl;

typedef struct {
    pcv_packet*  pkts;        /* N descriptors (data set after arena built) */
    uint8_t*     arena;       /* contiguous frame bytes */
    size_t       n;
    uint64_t     total_bytes; /* sum of captured_length over all N */
    uint64_t     accepted;    /* packets passing BENCH_FILTER_EXPR */
    uint64_t     accepted_bytes;
    uint32_t     distinct_flows;
} bench_set;

/* Build one flow template deterministically. ~30% are TCP/443 so the selective
 * filter still accepts a healthy, many-flow fraction. */
static void make_flow(flow_tmpl* f) {
    uint32_t r = xrng_mod(100);
    f->af = (r < 25) ? 6 : 4;                 /* ~25% IPv6 */

    r = xrng_mod(100);
    f->proto = (r < 70) ? 6 : 17;             /* ~70% TCP */

    f->sport = (uint16_t)(1024 + xrng_mod(64000));
    if (f->proto == 6) {
        r = xrng_mod(100);
        if (r < 43)      f->dport = 443;      /* HTTPS (the filter target) */
        else if (r < 68) f->dport = 80;
        else if (r < 78) f->dport = 22;
        else if (r < 88) f->dport = 8080;
        else             f->dport = (uint16_t)(1024 + xrng_mod(64000));
    } else {
        r = xrng_mod(100);
        if (r < 50)      f->dport = 53;        /* DNS */
        else if (r < 75) f->dport = 123;       /* NTP */
        else             f->dport = 443;       /* QUIC-ish */
    }

    if (f->af == 4) {
        f->sip4 = 0x0A000000u | (xrng_mod(254) << 8) | (1 + xrng_mod(254));
        f->dip4 = 0x5DB80000u | (uint32_t)xrng_mod(0xFFFF);  /* 93.184.x.x-ish */
    } else {
        /* 2001:db8::/32 with random low 64 bits, distinct per endpoint. */
        static const uint8_t pfx[8] = {0x20,0x01,0x0d,0xb8,0,0,0,0};
        memcpy(f->sip6, pfx, 8);
        memcpy(f->dip6, pfx, 8);
        for (int i = 8; i < 16; i++) f->sip6[i] = (uint8_t)xrng_mod(256);
        for (int i = 8; i < 16; i++) f->dip6[i] = (uint8_t)xrng_mod(256);
    }
}

/* Pick a target on-wire frame size from a bimodal distribution (small acks,
 * some mid, bulk) within 64..1514. Returns the L4 payload length to request for
 * the given header overhead. */
static size_t pick_payload(size_t header_overhead) {
    uint32_t r = xrng_mod(100);
    size_t target;
    if (r < 50)       target = 64 + xrng_mod(37);     /* 64..100 */
    else if (r < 65)  target = 200 + xrng_mod(401);   /* 200..600 */
    else              target = 1400 + xrng_mod(115);  /* 1400..1514 */
    if (target <= header_overhead) return 0;
    return target - header_overhead;
}

/* Generate the whole set. NOT timed. Returns 0 on success. */
static int build_set(bench_set* s, size_t n, uint32_t nflows) {
    memset(s, 0, sizeof(*s));
    s->n = n;

    flow_tmpl* flows = malloc((size_t)nflows * sizeof(*flows));
    s->pkts = calloc(n, sizeof(pcv_packet));
    size_t* offs = malloc(n * sizeof(size_t));
    uint16_t* flens = malloc(n * sizeof(uint16_t));
    if (!flows || !s->pkts || !offs || !flens) {
        free(flows); free(offs); free(flens);
        free(s->pkts); s->pkts = NULL;
        return -1;
    }

    for (uint32_t i = 0; i < nflows; i++) make_flow(&flows[i]);
    s->distinct_flows = nflows;

    /* Growable arena; keep offsets during build, bind data pointers after. */
    size_t cap = n * 128;           /* rough first guess */
    uint8_t* arena = malloc(cap);
    if (!arena) { free(flows); free(offs); free(flens); free(s->pkts); return -1; }
    size_t used = 0;

    uint8_t tmp[1600];
    uint64_t ts = 1600000000ULL * 1000000000ULL;   /* fixed epoch base (ns) */

    for (size_t i = 0; i < n; i++) {
        const flow_tmpl* f = &flows[xrng_mod(nflows)];
        size_t hdr = 14 + (f->af == 4 ? 20u : 40u) + (f->proto == 6 ? 20u : 8u);
        size_t payload = pick_payload(hdr);

        size_t len;
        if (f->af == 4) {
            len = pcv_build_ipv4_frame(tmp, sizeof(tmp), f->proto,
                                       f->sip4, f->dip4, f->sport, f->dport,
                                       0x10 /* ACK */, payload);
        } else {
            len = pcv_build_ipv6_frame(tmp, sizeof(tmp), f->proto,
                                       f->sip6, f->dip6, f->sport, f->dport,
                                       0x10 /* ACK */, payload);
        }
        if (len == 0) { free(flows); free(offs); free(flens); free(arena);
                        free(s->pkts); return -1; }

        if (used + len > cap) {
            while (used + len > cap) cap *= 2;
            uint8_t* na = realloc(arena, cap);
            if (!na) { free(flows); free(offs); free(flens); free(arena);
                       free(s->pkts); return -1; }
            arena = na;
        }
        memcpy(arena + used, tmp, len);
        offs[i] = used;
        flens[i] = (uint16_t)len;
        used += len;

        s->pkts[i].length = (uint32_t)len;
        s->pkts[i].captured_length = (uint32_t)len;
        ts += (uint64_t)(1 + xrng_mod(300)) * 1000ULL;   /* +1..300 us */
        s->pkts[i].timestamp_ns = ts;
        s->total_bytes += len;
    }

    /* Bind data pointers now the arena is final. */
    for (size_t i = 0; i < n; i++) s->pkts[i].data = arena + offs[i];
    s->arena = arena;

    free(flows);
    free(offs);
    free(flens);
    return 0;
}

static void free_set(bench_set* s) {
    if (!s) return;
    free(s->arena);
    free(s->pkts);
    s->arena = NULL;
    s->pkts = NULL;
}

/* ---- Compiled filter ---------------------------------------------------- */

static pcv_filter* build_filter(const char* expr) {
    uint8_t* bc = NULL;
    uint32_t sz = 0;
    char err[256];
    int rc = vfl_compile_string(expr, &bc, &sz, err, sizeof(err));
    if (rc < 0 || !bc || sz == 0) {
        fprintf(stderr, "bench: VFLisp compile failed for '%s': %s\n", expr, err);
        return NULL;
    }
    pcv_filter* f = pcv_filter_create(PCV_FILTER_VFM, bc, sz);
    free(bc);
    return f;
}

static pcv_flow_table* make_flow_table(void) {
    pcv_flow_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.max_flows        = BENCH_MAX_FLOWS;
    cfg.hash_buckets     = BENCH_HASH_BUCKETS;
    cfg.flow_timeout_ms  = BENCH_FLOW_TIMEOUT_MS;
    cfg.cleanup_interval = BENCH_CLEANUP_IVAL;
    cfg.enable_tcp_state = true;
    return pcv_flow_table_create(&cfg);
}

/* ---- stdout FORMAT sink (to a discarded fd) ----------------------------- */
/* Mirrors the core of src/pcv_main.c's format_packet_info + format_timestamp:
 * extract the 5-tuple, inet_ntop both addresses, build the tcpdump-style line,
 * and write it to a /dev/null FILE*. The per-packet getifaddrs() direction
 * lookup the live path does is intentionally omitted (there is no real NIC in
 * an offline bench), so this isolates the FORMATTING + stdio cost. */
static FILE* g_devnull;

static void format_and_write(const pcv_packet* p) {
    pcv_flow_key_v6 key;
    char line[256], tbuf[32], src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];

    if (pcv_flow_extract_key_v6(p, &key) != 0) {
        g_sink += (unsigned)fprintf(g_devnull, "[unparseable %u]\n",
                                    p->captured_length);
        return;
    }

    /* timestamp: HH:MM:SS.uuuuuu (same as format_timestamp) */
    time_t secs = (time_t)(p->timestamp_ns / 1000000000ULL);
    uint32_t us = (uint32_t)((p->timestamp_ns % 1000000000ULL) / 1000ULL);
    struct tm tmv;
#if defined(__APPLE__) || defined(_POSIX_C_SOURCE)
    localtime_r(&secs, &tmv);
#else
    tmv = *localtime(&secs);
#endif
    size_t tl = strftime(tbuf, sizeof(tbuf), "%H:%M:%S", &tmv);
    snprintf(tbuf + tl, sizeof(tbuf) - tl, ".%06u", us);

    if (key.addr_family == PCV_ADDR_IPV6) {
        inet_ntop(AF_INET6, key.src_ip.ipv6, src, sizeof(src));
        inet_ntop(AF_INET6, key.dst_ip.ipv6, dst, sizeof(dst));
    } else {
        inet_ntop(AF_INET, &key.src_ip.ipv4, src, sizeof(src));
        inet_ntop(AF_INET, &key.dst_ip.ipv4, dst, sizeof(dst));
    }

    const char* pname = (key.protocol == 6) ? "TCP" :
                        (key.protocol == 17) ? "UDP" : "proto";
    if (key.protocol == 6 || key.protocol == 17) {
        if (key.addr_family == PCV_ADDR_IPV6) {
            snprintf(line, sizeof(line), "%s [%s].%u > [%s].%u: %s %u",
                     (key.addr_family == 6 ? "IPv6" : "IPv4"),
                     src, key.src_port, dst, key.dst_port, pname,
                     p->captured_length);
        } else {
            snprintf(line, sizeof(line), "IPv4 %s.%u > %s.%u: %s %u",
                     src, key.src_port, dst, key.dst_port, pname,
                     p->captured_length);
        }
    } else {
        snprintf(line, sizeof(line), "%s > %s: %s %u",
                 src, dst, pname, p->captured_length);
    }

    g_sink += (unsigned)fprintf(g_devnull, "%s %s\n", tbuf, line);
}

/* ---- stderr suppression (around noisy RistrettoDB create/close logs) ---- */
#if HAVE_RISTRETTO
static int g_saved_err = -1;
static void stderr_off(void) {
    fflush(stderr);
    g_saved_err = dup(STDERR_FILENO);
    int d = open("/dev/null", O_WRONLY);
    if (d >= 0) { dup2(d, STDERR_FILENO); close(d); }
}
static void stderr_on(void) {
    fflush(stderr);
    if (g_saved_err >= 0) { dup2(g_saved_err, STDERR_FILENO); close(g_saved_err);
                            g_saved_err = -1; }
}
#endif

/* ---- Stage functions: each returns the elapsed nanoseconds of its TIMED
 *      region. Any per-run setup/teardown that is NOT the work under test
 *      (allocating a fresh flow table, creating/closing a table file) is done
 *      OUTSIDE the clock. ----------------------------------------------- */

typedef struct { const bench_set* set; pcv_filter* filter; const char* target; }
    stage_ctx;

/* (a) baseline: touch every packet. */
static uint64_t stage_baseline(const stage_ctx* c) {
    const bench_set* s = c->set;
    uint64_t acc = 0;
    uint64_t t0 = now_ns();
    for (size_t i = 0; i < s->n; i++) {
        const pcv_packet* p = &s->pkts[i];
        acc += p->data[0] + p->captured_length;   /* force a memory touch */
    }
    uint64_t t1 = now_ns();
    g_sink += acc;
    return t1 - t0;
}

/* (b) + filter. */
static uint64_t stage_filter(const stage_ctx* c) {
    const bench_set* s = c->set;
    uint64_t acc = 0;
    uint64_t t0 = now_ns();
    for (size_t i = 0; i < s->n; i++) {
        const pcv_packet* p = &s->pkts[i];
        if (pcv_filter_apply(c->filter, p->data, p->captured_length)
                == PCV_FILTER_ACCEPT)
            acc++;
    }
    uint64_t t1 = now_ns();
    g_sink += acc;
    return t1 - t0;
}

/* (c) + flow tracking (accepted packets only). Fresh table per run (untimed). */
static uint64_t stage_flow(const stage_ctx* c) {
    const bench_set* s = c->set;
    pcv_flow_table* ft = make_flow_table();
    if (!ft) return 0;
    uint64_t t0 = now_ns();
    for (size_t i = 0; i < s->n; i++) {
        const pcv_packet* p = &s->pkts[i];
        if (pcv_filter_apply(c->filter, p->data, p->captured_length)
                == PCV_FILTER_ACCEPT)
            pcv_flow_update_v6(ft, p);
    }
    uint64_t t1 = now_ns();
    g_sink += ft->total_flows + ft->expired_flows;
    pcv_flow_table_destroy(ft);
    return t1 - t0;
}

/* (d) + stdout FORMAT sink -> /dev/null (cumulative on filter + flow). */
static uint64_t stage_stdout(const stage_ctx* c) {
    const bench_set* s = c->set;
    pcv_flow_table* ft = make_flow_table();
    if (!ft) return 0;
    uint64_t t0 = now_ns();
    for (size_t i = 0; i < s->n; i++) {
        const pcv_packet* p = &s->pkts[i];
        if (pcv_filter_apply(c->filter, p->data, p->captured_length)
                == PCV_FILTER_ACCEPT) {
            pcv_flow_update_v6(ft, p);
            format_and_write(p);
        }
    }
    fflush(g_devnull);
    uint64_t t1 = now_ns();
    pcv_flow_table_destroy(ft);
    return t1 - t0;
}

#if HAVE_RISTRETTO
/* (d) + RistrettoDB per-packet sink (cumulative on filter + flow). The create
 * (schema parse + mmap) is one-time setup, excluded. The timed region is the
 * per-packet append loop PLUS the final durable flush + close, so real
 * mmap/disk I/O is honestly included. */
static uint64_t stage_ristretto_packet(const stage_ctx* c) {
    const bench_set* s = c->set;
    pcv_flow_table* ft = make_flow_table();
    stderr_off();
    pcv_output* out = pcv_output_create(PCV_OUTPUT_RISTRETTO, c->target);
    stderr_on();
    if (!out || !ft) {
        if (out) { stderr_off(); pcv_output_destroy(out); stderr_on(); }
        if (ft) pcv_flow_table_destroy(ft);
        return 0;
    }

    stderr_off();
    uint64_t t0 = now_ns();
    for (size_t i = 0; i < s->n; i++) {
        const pcv_packet* p = &s->pkts[i];
        if (pcv_filter_apply(c->filter, p->data, p->captured_length)
                == PCV_FILTER_ACCEPT) {
            pcv_flow_update_v6(ft, p);
            pcv_output_packet(out, p);
        }
    }
    pcv_output_destroy(out);     /* durable flush + close = part of output cost */
    uint64_t t1 = now_ns();
    stderr_on();

    pcv_flow_table_destroy(ft);
    return t1 - t0;
}

/* (d) + RistrettoDB per-FLOW sink. The per-flow sink fuses flow tracking and
 * row emission, so it is measured as filter -> flow_output_update (no separate
 * flow table). Rows are emitted on eviction and, mostly, at shutdown, so the
 * destroy (which flushes every open flow + durable sync) MUST be inside the
 * timed region. create is one-time setup, excluded. */
static uint64_t stage_ristretto_flow(const stage_ctx* c) {
    const bench_set* s = c->set;
    stderr_off();
    pcv_flow_output* out = pcv_flow_output_create_ex(c->target,
                               BENCH_FLOW_TIMEOUT_MS, BENCH_CLEANUP_IVAL,
                               BENCH_MAX_FLOWS, BENCH_HASH_BUCKETS);
    stderr_on();
    if (!out) return 0;

    stderr_off();
    uint64_t t0 = now_ns();
    for (size_t i = 0; i < s->n; i++) {
        const pcv_packet* p = &s->pkts[i];
        if (pcv_filter_apply(c->filter, p->data, p->captured_length)
                == PCV_FILTER_ACCEPT)
            pcv_flow_output_update(out, p);
    }
    pcv_flow_output_destroy(out);   /* emit open flows + durable flush + close */
    uint64_t t1 = now_ns();
    stderr_on();
    return t1 - t0;
}
#endif /* HAVE_RISTRETTO */

/* ---- Measurement driver ------------------------------------------------- */

static int cmp_u64(const void* a, const void* b) {
    uint64_t x = *(const uint64_t*)a, y = *(const uint64_t*)b;
    return (x > y) - (x < y);
}

/* Run a stage warmup+repeat times; print one table row.
 * `pps_basis` is the packet count the throughput is normalised over (always the
 * full input set) and `bytes_basis` the matching byte count. */
static void run_stage(const char* name, const char* includes,
                      uint64_t (*fn)(const stage_ctx*), const stage_ctx* c,
                      uint64_t pps_basis, uint64_t bytes_basis) {
#if BENCH_WARMUP > 0
    for (unsigned w = 0; w < (unsigned)BENCH_WARMUP; w++) (void)fn(c);
#endif

    uint64_t times[BENCH_REPEAT];
    for (unsigned r = 0; r < (unsigned)BENCH_REPEAT; r++) times[r] = fn(c);
    qsort(times, BENCH_REPEAT, sizeof(times[0]), cmp_u64);

    uint64_t best = times[0];
    uint64_t med  = times[BENCH_REPEAT / 2];
    if (best == 0) best = 1;
    if (med == 0)  med = 1;

    double best_s = (double)best / 1e9, med_s = (double)med / 1e9;
    double best_pps = (double)pps_basis / best_s;
    double med_pps  = (double)pps_basis / med_s;
    double best_gbps = (double)bytes_basis * 8.0 / best_s / 1e9;
    double med_gbps  = (double)bytes_basis * 8.0 / med_s / 1e9;
    double best_nspp = (double)best / (double)pps_basis;
    double med_nspp  = (double)med  / (double)pps_basis;

    /* name | best Mpps | median Mpps | best Gbps | median Gbps | best ns/pkt | median ns/pkt */
    printf("| %-22s | %9.2f | %9.2f | %8.2f | %8.2f | %8.2f | %8.2f |\n",
           name,
           best_pps / 1e6, med_pps / 1e6,
           best_gbps, med_gbps,
           best_nspp, med_nspp);
    (void)includes;
}

/* ---- Machine / build context ------------------------------------------- */

static void print_context(const bench_set* s) {
    struct utsname u;
    char cpu[256] = "unknown", model[128] = "";
    int ncpu = 0;

#if defined(__APPLE__)
    size_t len = sizeof(cpu);
    if (sysctlbyname("machdep.cpu.brand_string", cpu, &len, NULL, 0) != 0)
        snprintf(cpu, sizeof(cpu), "unknown");
    len = sizeof(model);
    if (sysctlbyname("hw.model", model, &len, NULL, 0) != 0) model[0] = '\0';
    len = sizeof(ncpu);
    sysctlbyname("hw.logicalcpu", &ncpu, &len, NULL, 0);
#else
    /* Linux: pull the model name out of /proc/cpuinfo. */
    FILE* f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char ln[256];
        while (fgets(ln, sizeof(ln), f)) {
            if (strncmp(ln, "model name", 10) == 0) {
                char* colon = strchr(ln, ':');
                if (colon) {
                    char* v = colon + 1;
                    while (*v == ' ') v++;
                    v[strcspn(v, "\n")] = '\0';
                    snprintf(cpu, sizeof(cpu), "%s", v);
                }
            }
            if (strncmp(ln, "processor", 9) == 0) ncpu++;
        }
        fclose(f);
    }
#endif

    uname(&u);

    printf("PacketVelocity offline processing-pipeline benchmark\n");
    printf("====================================================\n");
    printf("  CPU            : %s%s%s\n", cpu,
           model[0] ? " / " : "", model);
    printf("  Cores (logical): %d\n", ncpu);
    printf("  OS / kernel    : %s %s (%s)\n", u.sysname, u.release, u.machine);
#if defined(__clang__)
    printf("  Compiler       : clang %d.%d.%d\n", __clang_major__,
           __clang_minor__, __clang_patchlevel__);
#elif defined(__GNUC__)
    printf("  Compiler       : gcc %d.%d.%d\n", __GNUC__, __GNUC_MINOR__,
           __GNUC_PATCHLEVEL__);
#else
    printf("  Compiler       : unknown\n");
#endif
    printf("  RistrettoDB    : %s\n",
#if HAVE_RISTRETTO
           "linked (RISTRETTO=1) - all stages measured"
#else
           "NOT linked (hermetic default build) - stages a-c + stdout only"
#endif
          );
    printf("  Packets        : %zu (held in memory; generation NOT timed)\n", s->n);
    printf("  Total bytes    : %" PRIu64 " (%.2f MiB), mean %.1f B/pkt\n",
           s->total_bytes, (double)s->total_bytes / (1024.0 * 1024.0),
           (double)s->total_bytes / (double)s->n);
    printf("  Distinct flows : %u (5-tuples)\n", s->distinct_flows);
    printf("  Filter         : %s\n", BENCH_FILTER_EXPR);
    printf("  Filter accepts : %" PRIu64 " pkts (%.1f%%), %" PRIu64 " bytes\n",
           s->accepted, 100.0 * (double)s->accepted / (double)s->n,
           s->accepted_bytes);
    printf("  Warmup/repeat  : %u warmup, %u timed runs (best + median)\n",
           (unsigned)BENCH_WARMUP, (unsigned)BENCH_REPEAT);
    printf("\n");
    printf("Throughput is per INPUT packet (whole set). Mpps = million pkts/s.\n");
    printf("Gbps counts on-wire bytes of the whole set (8 bits/byte).\n\n");
}

int main(void) {
    /* Silence the unused test-harness symbols pulled in via pcv_test.h. */
    (void)g_checks_run; (void)g_checks_failed; (void)pcv_test_summary;

    const char* env;
    unsigned long npk = BENCH_PACKETS, nfl = BENCH_FLOWS;
    if ((env = getenv("PCV_BENCH_PACKETS")) && *env) npk = strtoul(env, NULL, 10);
    if ((env = getenv("PCV_BENCH_FLOWS"))   && *env) nfl = strtoul(env, NULL, 10);
    if (npk < 16) npk = 16;
    if (nfl < 4)  nfl = 4;

    g_rng = 0x9E3779B97F4A7C15ULL ^ 0xC0FFEEULL;   /* fixed seed -> reproducible */

    bench_set set;
    fprintf(stderr, "bench: generating %lu packets across %lu flows...\n", npk, nfl);
    if (build_set(&set, (size_t)npk, (uint32_t)nfl) != 0) {
        fprintf(stderr, "bench: out of memory building packet set\n");
        return 1;
    }

    pcv_filter* filter = build_filter(BENCH_FILTER_EXPR);
    if (!filter) { free_set(&set); return 1; }

    /* Measure accept rate once (not timed) for the self-describing header. */
    for (size_t i = 0; i < set.n; i++) {
        const pcv_packet* p = &set.pkts[i];
        if (pcv_filter_apply(filter, p->data, p->captured_length)
                == PCV_FILTER_ACCEPT) {
            set.accepted++;
            set.accepted_bytes += p->captured_length;
        }
    }

    g_devnull = fopen("/dev/null", "w");
    if (!g_devnull) { fprintf(stderr, "bench: cannot open /dev/null\n");
                      pcv_filter_destroy(filter); free_set(&set); return 1; }

    print_context(&set);

    printf("| %-22s | %9s | %9s | %8s | %8s | %8s | %8s |\n",
           "stage", "best Mpps", "med Mpps", "best", "med", "best", "med");
    printf("| %-22s | %9s | %9s | %8s | %8s | %8s | %8s |\n",
           "", "", "", "Gbps", "Gbps", "ns/pkt", "ns/pkt");
    printf("|%s|%s|%s|%s|%s|%s|%s|\n",
           "------------------------", "-----------", "-----------",
           "----------", "----------", "----------", "----------");

    char tgt_pkt[128], tgt_flow[128];
    snprintf(tgt_pkt,  sizeof(tgt_pkt),  "/tmp/pcv_bench_pkt_%ld",  (long)getpid());
    snprintf(tgt_flow, sizeof(tgt_flow), "/tmp/pcv_bench_flow_%ld", (long)getpid());

    stage_ctx c = { .set = &set, .filter = filter, .target = NULL };

    run_stage("a. baseline (touch)",    "loop + 1 byte read",
              stage_baseline, &c, set.n, set.total_bytes);
    run_stage("b. + filter",            "+ VFM apply",
              stage_filter,   &c, set.n, set.total_bytes);
    run_stage("c. + flow tracking",     "+ flow_update_v6 (accepted)",
              stage_flow,     &c, set.n, set.total_bytes);
    run_stage("d. + stdout (format)",   "+ format -> /dev/null",
              stage_stdout,   &c, set.n, set.total_bytes);

#if HAVE_RISTRETTO
    c.target = tgt_pkt;
    run_stage("d. + ristretto (pkt)",   "+ one row/packet (temp .rdb)",
              stage_ristretto_packet, &c, set.n, set.total_bytes);
    c.target = tgt_flow;
    run_stage("d. + ristretto (flow)",  "+ one row/flow (temp .rdb)",
              stage_ristretto_flow,   &c, set.n, set.total_bytes);
#else
    printf("| %-22s | %9s | %9s | %8s | %8s | %8s | %8s |\n",
           "d. + ristretto (pkt)",  "skipped", "-", "-", "-", "-", "-");
    printf("| %-22s | %9s | %9s | %8s | %8s | %8s | %8s |\n",
           "d. + ristretto (flow)", "skipped", "-", "-", "-", "-", "-");
    printf("\n(RistrettoDB sinks require `make bench RISTRETTO=1`.)\n");
#endif

    fclose(g_devnull);
    pcv_filter_destroy(filter);
    free_set(&set);

    /* Clean up any temp .rdb files the sinks created. */
    {
        char p[160];
        snprintf(p, sizeof(p), "%s.rdb", tgt_pkt);  unlink(p);
        snprintf(p, sizeof(p), "%s.rdb", tgt_flow); unlink(p);
    }

    printf("\nNote: OFFLINE processing-pipeline numbers (post-capture). NOT a\n");
    printf("live-capture-off-the-wire measurement. See BENCHMARKS.md.\n");
    return 0;
}
