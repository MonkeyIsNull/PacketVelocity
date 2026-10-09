/* Drop-safety test - the committee's raison d'etre.
 *
 * (a) STRUCTURAL SOURCE GUARD: the hot-path translation unit (src/pcv_dash_hot.c)
 *     must contain NONE of printf/fprintf/write/malloc/calloc/realloc/free/
 *     socket/pcv_get_stats or a BLOCKING pthread_mutex_lock. A reintroduced
 *     allocation / I/O / ioctl / blocking lock on the per-packet path fails CI.
 *     (The wait-free pthread_mutex_trylock publish is permitted and expected.)
 *     Comments are stripped before scanning, and tokens are matched as CALLS
 *     ("name(") so prose mentioning them does not false-positive.
 *
 * (b) THREADSANITIZER: thread A hammers pcv_dash_on_packet + force_snapshot +
 *     sample_with_stats (the capture-side writers) while thread B calls
 *     pcv_dash_snapshot_json (the HTTP-side reader). Built with
 *     -fsanitize=thread; any data race flips the process exit code (TSan
 *     default exitcode 66) and fails `make test`.
 */
#ifdef __linux__
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>

#include "pcv_platform.h"
#include "pcv_flow.h"
#include "pcv_dashboard.h"
#include "pcv_resolve.h"
#include "pcv_test.h"

/* ---- (a) structural source guard ---------------------------------------- */

/* Read a file into a malloc'd NUL-terminated buffer (NULL on failure). */
static char* read_file(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return NULL; }
    char* buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    buf[rd] = '\0';
    fclose(f);
    return buf;
}

/* Strip C block and line comments in place so prose can't false-positive. */
static void strip_comments(char* s) {
    char* w = s;
    for (char* r = s; *r; ) {
        if (r[0] == '/' && r[1] == '*') {
            r += 2;
            while (*r && !(r[0] == '*' && r[1] == '/')) r++;
            if (*r) r += 2;
            *w++ = ' ';
        } else if (r[0] == '/' && r[1] == '/') {
            r += 2;
            while (*r && *r != '\n') r++;
            *w++ = ' ';
        } else {
            *w++ = *r++;
        }
    }
    *w = '\0';
}

static void test_source_guard(const char* path) {
    fprintf(stdout, "hot-path source guard (%s)\n", path);
    char* src = read_file(path);
    CHECK(src != NULL, "read hot-path source file");
    if (!src) return;
    strip_comments(src);

    const char* banned[] = {
        "printf(", "fprintf(", "write(",
        "malloc(", "calloc(", "realloc(", "free(",
        "socket(", "pcv_get_stats",
        "pthread_mutex_lock(",   /* BLOCKING lock; trylock is allowed */
        "getnameinfo(", "getaddrinfo(",  /* blocking resolver: resolver thread only */
    };
    for (size_t i = 0; i < sizeof(banned)/sizeof(banned[0]); i++) {
        char msg[96];
        snprintf(msg, sizeof(msg), "hot path free of %s", banned[i]);
        CHECK(strstr(src, banned[i]) == NULL, msg);
    }
    /* Positive: the wait-free publish IS present (so the guard is meaningful). */
    CHECK(strstr(src, "pthread_mutex_trylock(") != NULL,
          "hot path uses the wait-free trylock publish");
    free(src);
}

/* ---- (b) ThreadSanitizer stress ----------------------------------------- */

static pcv_dash_agg*  g_agg;
static _Atomic int    g_writer_done;

static uint8_t g_frame[128];
static uint32_t g_flen;

static void* writer_thread(void* arg) {
    (void)arg;
    const uint64_t base = 1000000000ULL;
    for (int i = 0; i < 200000; i++) {
        pcv_packet p;
        memset(&p, 0, sizeof(p));
        p.data = g_frame;
        p.captured_length = g_flen;
        p.length = g_flen;
        /* Advancing timestamp so the per-packet 1 Hz gate fires periodically. */
        p.timestamp_ns = base + (uint64_t)i * 1000000ULL; /* +1ms each */
        pcv_dash_on_packet(g_agg, &p);
        if ((i % 1000) == 0) {
            pcv_dash_force_snapshot(g_agg);
        }
        if ((i % 500) == 0) {
            pcv_dash_sample_with_stats(g_agg, (uint64_t)i, (uint64_t)(i / 100),
                                       p.timestamp_ns);
        }
    }
    atomic_store(&g_writer_done, 1);
    return NULL;
}

static void* reader_thread(void* arg) {
    (void)arg;
    static char buf[65536];
    uint64_t reads = 0;
    while (!atomic_load(&g_writer_done)) {
        pcv_dash_snapshot_json(g_agg, buf, sizeof(buf));
        reads++;
    }
    /* A few more after the writer finishes. */
    for (int i = 0; i < 100; i++) {
        pcv_dash_snapshot_json(g_agg, buf, sizeof(buf));
    }
    return (void*)(uintptr_t)reads;
}

static void test_tsan_stress(void) {
    fprintf(stdout, "ThreadSanitizer stress (writer vs reader)\n");
    g_agg = pcv_dash_create(0, 0, 0);
    CHECK(g_agg != NULL, "create agg for TSan stress");
    if (!g_agg) return;

    g_flen = (uint32_t)pcv_build_ipv4_frame(g_frame, sizeof(g_frame), 6,
                                            0x0A000001, 0x0A000002, 1234, 80, 0x10, 40);
    CHECK(g_flen > 0, "build stress frame");
    atomic_store(&g_writer_done, 0);

    pthread_t wt, rt;
    pthread_create(&rt, NULL, reader_thread, NULL);
    pthread_create(&wt, NULL, writer_thread, NULL);
    pthread_join(wt, NULL);
    pthread_join(rt, NULL);

    CHECK(1, "no data race reported by ThreadSanitizer (else exit code != 0)");
    pcv_dash_destroy(g_agg);
}

/* ---- (c) ThreadSanitizer: capture ring enqueue vs resolver drain vs lookup -
 * One thread enqueues DNS/mDNS + flow packets via pcv_dash_on_packet (writing
 * the SPSC ring with wait-free atomics); the resolver thread drains+parses the
 * ring and inserts to the map; a third thread does pcv_resolve_lookup +
 * snapshot_json. Any race on the ring release/acquire or names_mtx copy-out
 * flips TSan's exit code. The PTR seam is a no-op STUB (never live DNS). */

static pcv_resolver* gr_resolver;
static pcv_dash_agg* gr_agg;
static _Atomic int gr_writer_done;
static uint8_t gr_dns[512];
static uint32_t gr_dnslen;
static uint8_t gr_flow[128];
static uint32_t gr_flowlen;
static uint8_t gr_tls[512];
static uint32_t gr_tlslen;

static int gr_stub(const pcv_resolve_key* k, char* out, size_t n, void* c) {
    (void)k; (void)c;
    strncpy(out, "stub.example", n - 1);
    out[n - 1] = '\0';
    return 0;
}

static void* gr_writer(void* arg) {
    (void)arg;
    const uint64_t base = 1000000000ULL;
    for (int i = 0; i < 100000; i++) {
        pcv_packet p;
        memset(&p, 0, sizeof(p));
        p.timestamp_ns = base + (uint64_t)i * 1000000ULL;
        /* Interleave DNS, TLS and plain-flow packets through the SAME ring so
         * the kind-dispatch + slot->flow producer/consumer handoff is raced. */
        switch (i % 3) {
        case 0:  p.data = gr_flow; p.captured_length = gr_flowlen; p.length = gr_flowlen; break;
        case 1:  p.data = gr_dns;  p.captured_length = gr_dnslen;  p.length = gr_dnslen;  break;
        default: p.data = gr_tls;  p.captured_length = gr_tlslen;  p.length = gr_tlslen;  break;
        }
        pcv_dash_on_packet(gr_agg, &p);
        if ((i % 1000) == 0) pcv_dash_force_snapshot(gr_agg);
    }
    atomic_store(&gr_writer_done, 1);
    return NULL;
}

static void* gr_reader(void* arg) {
    (void)arg;
    static char buf[65536];
    while (!atomic_load(&gr_writer_done)) {
        pcv_dash_snapshot_json(gr_agg, buf, sizeof(buf));
        pcv_resolve_key k;
        uint8_t nb[4] = {8, 8, 8, 8};
        pcv_resolve_key_make(PCV_ADDR_IPV4, nb, &k);
        char nm[256];
        pcv_resolve_lookup(gr_resolver, &k, nm, sizeof(nm));
        /* Race pcv_resolve_flow_sni (side-map copy-out) against the resolver
         * thread inserting TLS slots into that same side map. */
        pcv_flow_key_v6 fk;
        memset(&fk, 0, sizeof(fk));
        fk.addr_family = PCV_ADDR_IPV4;
        fk.src_ip.ipv4 = htonl(0x0A000001u);
        fk.dst_ip.ipv4 = htonl(0x08080808u);
        fk.src_port = 50000; fk.dst_port = 443; fk.protocol = 6;
        char sni[256]; int sis = 0;
        pcv_resolve_flow_sni(gr_resolver, &fk, sni, sizeof(sni), &sis);
    }
    return NULL;
}

static void test_tsan_resolver(void) {
    fprintf(stdout, "ThreadSanitizer stress (ring enqueue vs resolver drain vs lookup)\n");
    gr_agg = pcv_dash_create(0, 0, 0);
    CHECK(gr_agg != NULL, "create agg for resolver TSan stress");
    if (!gr_agg) return;
    gr_resolver = pcv_resolver_create(gr_agg, gr_stub, NULL);
    CHECK(gr_resolver != NULL, "create resolver for TSan stress");
    if (!gr_resolver) { pcv_dash_destroy(gr_agg); return; }
    pcv_dash_set_resolver(gr_agg, gr_resolver);

    uint8_t a1[4] = {8, 8, 8, 8};
    pcv_dns_answer an = { 1, 0, a1 };
    gr_dnslen = (uint32_t)pcv_build_dns_ipv4(gr_dns, sizeof(gr_dns),
                                             0x08080808u, 0x0A000001u, 53, 33333,
                                             "example.com", 1, 1, 0, 1, &an, 1);
    CHECK(gr_dnslen > 0, "build DNS :53 stress frame");
    gr_flowlen = (uint32_t)pcv_build_ipv4_frame(gr_flow, sizeof(gr_flow), 6,
                                                0x0A000001u, 0x08080808u,
                                                1234, 443, 0x10, 20);
    CHECK(gr_flowlen > 0, "build flow stress frame");
    gr_tlslen = (uint32_t)pcv_build_tls_clienthello_ipv4(gr_tls, sizeof(gr_tls),
                                                         0x0A000001u, 0x08080808u,
                                                         50000, 443, "stress.example");
    CHECK(gr_tlslen > 0, "build TLS ClientHello stress frame");
    atomic_store(&gr_writer_done, 0);

    pthread_t rt, wt, res;
    pthread_create(&res, NULL, pcv_resolver_thread, gr_resolver);
    pthread_create(&rt, NULL, gr_reader, NULL);
    pthread_create(&wt, NULL, gr_writer, NULL);
    pthread_join(wt, NULL);
    pthread_join(rt, NULL);
    pcv_resolver_stop(gr_resolver);
    pthread_join(res, NULL);

    CHECK(1, "no data race across ring enqueue / drain / lookup (TSan)");
    pcv_dash_set_resolver(gr_agg, NULL);
    pcv_resolver_destroy(gr_resolver);
    pcv_dash_destroy(gr_agg);
}

int main(int argc, char** argv) {
    const char* src = (argc > 1) ? argv[1] : "src/pcv_dash_hot.c";
    test_source_guard(src);
    test_tsan_stress();
    test_tsan_resolver();
    return pcv_test_summary("test_dashboard_safety");
}
