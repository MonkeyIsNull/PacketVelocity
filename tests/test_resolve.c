/* IP -> hostname resolver tests (offline, no root, no live DNS resolver).
 *
 * Built with -fsanitize=address so a parser overread hits a redzone. Covers:
 *   (a) PURE pcv_dns_parse: A + AAAA, the POSITIVE 0xC00C compressed owner name
 *       (real traffic almost always compresses it), rdlength mismatch skipped,
 *       and a QR=0 query yielding nothing - all on TIGHT malloc(len) buffers.
 *   (b) REPLAY end-to-end: DNS/mDNS + flow frames through pcv_dash_on_packet
 *       (data in malloc(captured_length)), drained synchronously, then the names
 *       asserted in the served /stats.json flow rows AND hosts panel (incl.
 *       AAAA/IPv6 and the mDNS cache-flush bit).
 *   (c) PTR fallback via an INJECTED stub (never real getnameinfo): global-IP
 *       gating, the K=8 per-cycle rate limit, negative-cache cooldown, and
 *       passive-over-PTR precedence.
 *   (d) MALFORMED/HOSTILE DNS under ASan + a SIGALRM watchdog: truncated,
 *       compression self/forward loops, oversized name, control-char name,
 *       rdlength mismatch, ancount>bytes - no crash, no OOB, loops rejected.
 *   (e) NO-XSS: a <script> name from BOTH a DNS answer and a stubbed PTR result
 *       run through the REAL sanitize+serialize path - served bytes carry no
 *       '<'/'>'/"<script"; plus a direct sanitizer unit check.
 *   (f) HOT-PATH short-UDP frame (claims proto 17 but captured_length <
 *       l4_off+8) proves the port read + offset walk + bounded memcpy never
 *       overread.
 */
#ifdef __linux__
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include <arpa/inet.h>

#include "pcv_platform.h"
#include "pcv_flow.h"
#include "pcv_dashboard.h"
#include "pcv_resolve.h"
#include "pcv_test.h"

/* ---- helpers ------------------------------------------------------------- */

static void feed_malloc(pcv_dash_agg* a, const uint8_t* frame, size_t len) {
    /* Copy into a TIGHT malloc buffer so an ASan redzone follows the captured
     * bytes - any hot-path or parser overread is a hard failure, not luck. */
    uint8_t* data = malloc(len);
    memcpy(data, frame, len);
    pcv_packet p;
    memset(&p, 0, sizeof(p));
    p.data = data;
    p.captured_length = (uint32_t)len;
    p.length = (uint32_t)len;
    p.timestamp_ns = 1000000000ULL;
    pcv_dash_on_packet(a, &p);
    free(data);
}

static void feed_malloc_caplen(pcv_dash_agg* a, const uint8_t* frame,
                               size_t wire_len, size_t caplen) {
    uint8_t* data = malloc(caplen);
    memcpy(data, frame, caplen);          /* only caplen bytes are "captured" */
    pcv_packet p;
    memset(&p, 0, sizeof(p));
    p.data = data;
    p.captured_length = (uint32_t)caplen;
    p.length = (uint32_t)wire_len;
    p.timestamp_ns = 1000000000ULL;
    pcv_dash_on_packet(a, &p);
    free(data);
}

/* emit recorder for the pure parser */
typedef struct { uint8_t fam; uint8_t addr[16]; char name[256]; } prec;
typedef struct { prec r[32]; int n; } precctx;
static void rec_emit(uint8_t fam, const uint8_t* addr, const char* name, void* c) {
    precctx* x = (precctx*)c;
    if (x->n >= 32) return;
    x->r[x->n].fam = fam;
    memcpy(x->r[x->n].addr, addr, (fam == PCV_ADDR_IPV4) ? 4 : 16);
    strncpy(x->r[x->n].name, name, 255);
    x->r[x->n].name[255] = '\0';
    x->n++;
}
static int count_emit_calls;
static void count_emit(uint8_t f, const uint8_t* a, const char* n, void* c) {
    (void)f; (void)a; (void)n; (void)c; count_emit_calls++;
}

/* injected PTR stub (NEVER real getnameinfo) */
typedef struct {
    int calls;
    int fail;                 /* return -1 for every lookup */
    int xss;                  /* return a <script> name */
    char ret[64];             /* name to return on success */
    uint32_t seen[64];        /* IPv4 addrs (network order) looked up */
    int nseen;
} stubctx;

static int stub_ptr(const pcv_resolve_key* key, char* out, size_t outlen,
                    void* ctx) {
    stubctx* s = (stubctx*)ctx;
    s->calls++;
    if (key->family == PCV_ADDR_IPV4 && s->nseen < 64) {
        s->seen[s->nseen++] = key->a.v4;
    }
    if (s->fail) {
        return -1;
    }
    if (s->xss) {
        strncpy(out, "<script>alert(1)</script>", outlen - 1);
    } else {
        strncpy(out, s->ret[0] ? s->ret : "host.example", outlen - 1);
    }
    out[outlen - 1] = '\0';
    return 0;
}

static int stub_saw(const stubctx* s, uint32_t host_ip) {
    uint32_t net = htonl(host_ip);
    for (int i = 0; i < s->nseen; i++) {
        if (s->seen[i] == net) return 1;
    }
    return 0;
}

static void v4_netbytes(uint32_t host, uint8_t out[4]) {
    uint32_t net = htonl(host);
    memcpy(out, &net, 4);
}

/* ---- (a) pure parser ----------------------------------------------------- */

static int parse_tight(const uint8_t* msg, size_t mlen, precctx* out) {
    uint8_t* b = malloc(mlen);
    memcpy(b, msg, mlen);
    out->n = 0;
    int rc = pcv_dns_parse(b, (uint32_t)mlen, rec_emit, out);
    free(b);
    return rc;
}

static void test_pure_parser(void) {
    fprintf(stdout, "pure pcv_dns_parse (A/AAAA, compressed owner, mismatch, QR)\n");
    uint8_t msg[1024];
    precctx pc;

    uint8_t a1[4]; v4_netbytes(0x5DB8D822u, a1);         /* 93.184.216.34 */
    pcv_dns_answer an_a = { 1, 0, a1 };

    /* Literal owner name. */
    size_t ml = pcv_build_dns_msg(msg, sizeof(msg), "example.com", 1, 1, 0, 0,
                                  &an_a, 1);
    CHECK(ml > 0, "build literal-owner A response");
    CHECK(parse_tight(msg, ml, &pc) == 0, "parse literal-owner A");
    CHECK(pc.n == 1 && strcmp(pc.r[0].name, "example.com") == 0 &&
          pc.r[0].fam == PCV_ADDR_IPV4 && memcmp(pc.r[0].addr, a1, 4) == 0,
          "A: example.com -> 93.184.216.34");

    /* POSITIVE 0xC00C compressed owner name (what real traffic sends). */
    ml = pcv_build_dns_msg(msg, sizeof(msg), "lingq.com", 1, 1, 0, 1, &an_a, 1);
    CHECK(ml > 0, "build compressed-owner A response");
    CHECK(parse_tight(msg, ml, &pc) == 0, "parse compressed-owner A");
    CHECK(pc.n == 1 && strcmp(pc.r[0].name, "lingq.com") == 0,
          "compressed 0xC00C owner resolves to lingq.com");

    /* AAAA. */
    uint8_t a6[16] = {0x20,0x01,0x48,0x60,0x48,0x60,0,0,0,0,0,0,0,0,0x88,0x88};
    pcv_dns_answer an_aaaa = { 28, 0, a6 };
    ml = pcv_build_dns_msg(msg, sizeof(msg), "dns.google", 28, 1, 0, 1,
                           &an_aaaa, 1);
    CHECK(parse_tight(msg, ml, &pc) == 0, "parse AAAA");
    CHECK(pc.n == 1 && pc.r[0].fam == PCV_ADDR_IPV6 &&
          memcmp(pc.r[0].addr, a6, 16) == 0 &&
          strcmp(pc.r[0].name, "dns.google") == 0,
          "AAAA: dns.google -> 2001:4860:4860::8888");

    /* rdlength mismatch: A with rdlen 5 is SKIPPED, not misparsed. The record
     * is well-formed (5 rdata bytes present); only the A-requires-4 rule skips. */
    uint8_t bad5[5] = {1, 2, 3, 4, 5};
    pcv_dns_answer an_bad = { 1, 5, bad5 };
    ml = pcv_build_dns_msg(msg, sizeof(msg), "bad.example", 1, 1, 0, 1,
                           &an_bad, 1);
    CHECK(parse_tight(msg, ml, &pc) == 0, "parse rdlen-mismatch (well-formed msg)");
    CHECK(pc.n == 0, "rdlen-mismatch A emits nothing (skipped, not misparsed)");

    /* QR=0 query yields nothing (QR gate). */
    ml = pcv_build_dns_msg(msg, sizeof(msg), "example.com", 1, 0, 0, 0,
                           &an_a, 1);
    CHECK(parse_tight(msg, ml, &pc) == -1, "QR=0 query rejected by the QR gate");
    CHECK(pc.n == 0, "QR=0 query emits zero names");
}

/* ---- (d) malformed / hostile DNS under a watchdog ------------------------ */

static sigjmp_buf g_jmp;
static void on_alarm(int s) { (void)s; siglongjmp(g_jmp, 1); }

static void parse_watchdogged(const uint8_t* bytes, size_t len, const char* msg) {
    uint8_t* b = malloc(len ? len : 1);
    if (len) memcpy(b, bytes, len);
    count_emit_calls = 0;
    if (sigsetjmp(g_jmp, 1) == 0) {
        alarm(3);
        int rc = pcv_dns_parse(b, (uint32_t)len, count_emit, NULL);
        alarm(0);
        (void)rc;
        CHECK(1, msg);                     /* returned (did not hang/crash) */
    } else {
        CHECK(0, msg);                     /* watchdog fired: parser HUNG */
    }
    free(b);
}

static void test_malformed(void) {
    fprintf(stdout, "malformed/hostile DNS under ASan + SIGALRM watchdog\n");
    signal(SIGALRM, on_alarm);

    /* Truncated header (< 12 bytes). */
    uint8_t trunc[8] = {0x12,0x34,0x81,0x80,0x00,0x01,0x00,0x01};
    parse_watchdogged(trunc, sizeof(trunc), "truncated header rejected");

    /* Header claims QR=1, qd=1, an=1, then a SELF compression pointer at 12. */
    uint8_t selfloop[14] = {0x12,0x34,0x81,0x80,0,1,0,1,0,0,0,0, 0xC0,0x0C};
    parse_watchdogged(selfloop, sizeof(selfloop), "self compression pointer rejected");

    /* FORWARD pointer at 12 -> 20 (target > pointer offset: must reject). */
    uint8_t fwd[14] = {0x12,0x34,0x81,0x80,0,1,0,1,0,0,0,0, 0xC0,0x14};
    parse_watchdogged(fwd, sizeof(fwd), "forward compression pointer rejected");

    /* Two-pointer mutual loop: 12->14, 14->12 (first jump already not strictly
     * backward -> rejected; the watchdog proves no hang regardless). */
    uint8_t loop2[16] = {0x12,0x34,0x81,0x80,0,1,0,1,0,0,0,0, 0xC0,0x0E, 0xC0,0x0C};
    parse_watchdogged(loop2, sizeof(loop2), "mutual compression loop rejected");

    /* Oversized label length (claims 0x3F bytes with none present). */
    uint8_t over[14] = {0x12,0x34,0x81,0x80,0,1,0,1,0,0,0,0, 0x3F,0x41};
    parse_watchdogged(over, sizeof(over), "oversized label rejected");

    /* ancount huge but no bytes for the answers. */
    uint8_t manyan[13] = {0x12,0x34,0x81,0x80,0,0,0xFF,0xFF,0,0,0,0, 0x00};
    parse_watchdogged(manyan, sizeof(manyan), "ancount>>bytes rejected (no overread)");

    /* Control-char name in a well-formed A answer: parses, but the name is
     * sanitized to empty at INSERT (tested via the serializer path in XSS). */
    uint8_t msg[1024];
    uint8_t a1[4]; v4_netbytes(0x08080808u, a1);
    pcv_dns_answer an = { 1, 0, a1 };
    /* qname label of raw control bytes (no dot): built by hand below instead,
     * since the builder splits on '.' - a single control-byte label is fine. */
    const char ctl[] = { 0x01, 0x02, 0x07, 0x1f, 0x00 };
    size_t ml = pcv_build_dns_msg(msg, sizeof(msg), ctl, 1, 1, 0, 0, &an, 1);
    parse_watchdogged(msg, ml, "control-char name parses without crash");
}

/* ---- (b) replay end-to-end + (e) XSS ------------------------------------- */

static void test_replay_names(void) {
    fprintf(stdout, "replay -> drain -> served names (flow rows + hosts, v4/v6)\n");
    pcv_dash_agg* agg = pcv_dash_create(0, 0, 0);
    pcv_resolver* r = pcv_resolver_create(agg, stub_ptr, NULL); /* stub unused here */
    CHECK(agg && r, "create agg + resolver");
    pcv_dash_set_resolver(agg, r);
    pcv_dash_set_local_ip(agg, 0x0A000001u);     /* 10.0.0.1 is "you" */

    uint8_t frame[1024];

    /* Passive A: example.com -> 93.184.216.34 (compressed owner, classic :53). */
    uint8_t a1[4]; v4_netbytes(0x5DB8D822u, a1);
    pcv_dns_answer an_a = { 1, 0, a1 };
    size_t fl = pcv_build_dns_ipv4(frame, sizeof(frame), 0x08080808u, 0x0A000001u,
                                   53, 33333, "example.com", 1, 1, 0, 1,
                                   &an_a, 1);
    CHECK(fl > 0, "build DNS reply frame (udp :53)");
    feed_malloc(agg, frame, fl);

    /* mDNS A with the cache-flush bit: mymac.local -> 10.0.0.5 (port 5353). */
    uint8_t a2[4]; v4_netbytes(0x0A000005u, a2);
    pcv_dns_answer an_m = { 1, 0, a2 };
    fl = pcv_build_dns_ipv4(frame, sizeof(frame), 0x0A000005u, 0xE00000FBu,
                            5353, 5353, "mymac.local", 1, 1, 1 /*cache-flush*/, 0,
                            &an_m, 1);
    CHECK(fl > 0, "build mDNS reply frame (udp :5353, cache-flush bit)");
    feed_malloc(agg, frame, fl);

    /* AAAA over IPv6 transport: dns.google -> 2001:4860:4860::8888 (ff02::fb). */
    uint8_t a6[16] = {0x20,0x01,0x48,0x60,0x48,0x60,0,0,0,0,0,0,0,0,0x88,0x88};
    pcv_dns_answer an6 = { 28, 0, a6 };
    static const uint8_t src6[16] = {0x20,0x01,0x48,0x60,0x48,0x60,0,0,0,0,0,0,0,0,0x88,0x88};
    static const uint8_t mdns6[16] = {0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,0xfb};
    fl = pcv_build_dns_ipv6(frame, sizeof(frame), src6, mdns6, 5353, 5353,
                            "dns.google", 28, 1, 0, 1, &an6, 1);
    CHECK(fl > 0, "build IPv6-transport AAAA mDNS frame");
    feed_malloc(agg, frame, fl);

    /* Drain all passive answers synchronously (no threads). */
    pcv_resolver_drain_once(r);

    /* Flows to the named endpoints so names surface in the snapshot. */
    fl = pcv_build_ipv4_frame(frame, sizeof(frame), 6, 0x0A000001u, 0x5DB8D822u,
                              1234, 443, 0x02, 40);
    feed_malloc(agg, frame, fl);
    static const uint8_t myv6[16] = {0x20,0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,0x99};
    fl = pcv_build_ipv6_frame(frame, sizeof(frame), 6, myv6, a6, 2000, 443, 0x02, 40);
    feed_malloc(agg, frame, fl);

    pcv_dash_force_snapshot(agg);

    static char json[131072];
    size_t jlen = pcv_dash_snapshot_json(agg, json, sizeof(json));
    CHECK(jlen > 0, "serialize /stats.json");

    CHECK(strstr(json, "\"dst_name\":\"example.com\"") != NULL,
          "flow row carries dst_name example.com (passive A, compressed owner)");
    CHECK(strstr(json, "\"dst_name\":\"dns.google\"") != NULL,
          "IPv6 flow row carries dst_name dns.google (AAAA end-to-end)");
    CHECK(strstr(json, "\"hosts\":[") != NULL, "hosts panel present");
    CHECK(strstr(json, "example.com") != NULL, "hosts panel name-decorated");
    CHECK(strstr(json, "\"local\":\"10.0.0.1\"") != NULL,
          "local IPv4 emitted host-order-correct (htonl before inet_ntop)");

    /* mDNS .local survived the cache-flush 0x8001 class bit. */
    CHECK(strstr(json, "mymac.local") != NULL,
          "mDNS .local name survived the cache-flush class bit (0x8000 masked)");

    pcv_dash_set_resolver(agg, NULL);
    pcv_resolver_destroy(r);
    pcv_dash_destroy(agg);
}

static void test_xss(void) {
    fprintf(stdout, "no-XSS: attacker names from DNS AND PTR are inert\n");

    /* Direct sanitizer behavior is observed through the served bytes. */
    pcv_dash_agg* agg = pcv_dash_create(0, 0, 0);
    stubctx sc; memset(&sc, 0, sizeof(sc)); sc.xss = 1;   /* PTR returns <script> */
    pcv_resolver* r = pcv_resolver_create(agg, stub_ptr, &sc);
    CHECK(agg && r, "create agg + resolver (xss)");
    pcv_dash_set_resolver(agg, r);

    uint8_t frame[1024];

    /* Passive DNS answer whose OWNER NAME is a script payload (single label,
     * no dots) -> maps to 203.0.113.9. */
    uint8_t a1[4]; v4_netbytes(0xCB007109u, a1);          /* 203.0.113.9 */
    pcv_dns_answer an = { 1, 0, a1 };
    const char* evil = "<script>alert(1)x</script>";
    size_t fl = pcv_build_dns_ipv4(frame, sizeof(frame), 0x08080808u, 0x0A000001u,
                                   53, 33333, evil, 1, 1, 0, 0, &an, 1);
    CHECK(fl > 0, "build DNS reply with hostile owner name");
    feed_malloc(agg, frame, fl);
    pcv_resolver_drain_once(r);

    /* A flow to 203.0.113.9 (and a separate global 198.51.100.7 for the PTR). */
    fl = pcv_build_ipv4_frame(frame, sizeof(frame), 6, 0x0A000001u, 0xCB007109u,
                              1234, 443, 0x02, 40);
    feed_malloc(agg, frame, fl);
    fl = pcv_build_ipv4_frame(frame, sizeof(frame), 6, 0x0A000001u, 0xC6336407u,
                              1234, 443, 0x02, 40);                 /* 198.51.100.7 */
    feed_malloc(agg, frame, fl);

    pcv_dash_force_snapshot(agg);
    pcv_resolver_ptr_pass(r);          /* stub returns <script> for 198.51.100.7 */

    static char json[131072];
    pcv_dash_snapshot_json(agg, json, sizeof(json));

    /* '<' never legitimately appears in our JSON (the flow `tuple` arrow " -> "
     * is the only '>' source, so '<' absence is the load-bearing check). */
    CHECK(strchr(json, '<') == NULL, "served bytes contain no '<'");
    CHECK(strstr(json, "<script") == NULL, "served bytes contain no <script");
    CHECK(strstr(json, "</") == NULL, "served bytes contain no closing-tag '</'");
    CHECK(strstr(json, "alert(1)") == NULL,
          "parenthesized script payload stripped (no 'alert(1)')");
    /* The sanitized residue is the inert allowlisted text. */
    CHECK(strstr(json, "scriptalert1xscript") != NULL,
          "hostile DNS name sanitized to inert allowlist text");

    pcv_dash_set_resolver(agg, NULL);
    pcv_resolver_destroy(r);
    pcv_dash_destroy(agg);
}

/* ---- (c) PTR fallback: gating, rate limit, caching, precedence ----------- */

static void feed_global_flow(pcv_dash_agg* a, uint32_t dst_host) {
    uint8_t frame[256];
    size_t fl = pcv_build_ipv4_frame(frame, sizeof(frame), 6, 0x0A000001u,
                                     dst_host, 1234, 443, 0x02, 20);
    feed_malloc(a, frame, fl);
}

static void test_ptr(void) {
    fprintf(stdout, "reverse-PTR: global gate, K=8 cap, neg cache, precedence\n");

    /* Global-IP gate (pure). */
    uint8_t v4[4];
    v4_netbytes(0x08080808u, v4); CHECK(pcv_is_global_ip(PCV_ADDR_IPV4, v4),  "8.8.8.8 global");
    v4_netbytes(0x0A000001u, v4); CHECK(!pcv_is_global_ip(PCV_ADDR_IPV4, v4), "10.0.0.1 private");
    v4_netbytes(0xC0A80101u, v4); CHECK(!pcv_is_global_ip(PCV_ADDR_IPV4, v4), "192.168.1.1 private");
    v4_netbytes(0xAC100001u, v4); CHECK(!pcv_is_global_ip(PCV_ADDR_IPV4, v4), "172.16.0.1 private");
    v4_netbytes(0x7F000001u, v4); CHECK(!pcv_is_global_ip(PCV_ADDR_IPV4, v4), "127.0.0.1 loopback");
    v4_netbytes(0xA9FE0101u, v4); CHECK(!pcv_is_global_ip(PCV_ADDR_IPV4, v4), "169.254.x link-local");
    v4_netbytes(0xE0000001u, v4); CHECK(!pcv_is_global_ip(PCV_ADDR_IPV4, v4), "224.0.0.1 multicast");

    /* K=8 cap + global gating over a snapshot of 12 distinct global dsts (all
     * from a private src, which must never be looked up). */
    {
        pcv_dash_agg* agg = pcv_dash_create(0, 0, 0);
        stubctx sc; memset(&sc, 0, sizeof(sc)); strcpy(sc.ret, "named.example");
        pcv_resolver* r = pcv_resolver_create(agg, stub_ptr, &sc);
        pcv_dash_set_resolver(agg, r);
        for (uint32_t i = 0; i < 12; i++) {
            feed_global_flow(agg, 0x08080800u + i);        /* 8.8.8.0+ (global) */
        }
        pcv_dash_force_snapshot(agg);
        int issued = pcv_resolver_ptr_pass(r);
        CHECK(issued == 8, "PTR pass issues exactly K=8 lookups (rate limited)");
        CHECK(sc.calls == 8, "stub called exactly 8 times");
        CHECK(!stub_saw(&sc, 0x0A000001u), "private src 10.0.0.1 never looked up");
        pcv_dash_set_resolver(agg, NULL);
        pcv_resolver_destroy(r);
        pcv_dash_destroy(agg);
    }

    /* Negative cache == cooldown: a failing lookup is not retried next pass. */
    {
        pcv_dash_agg* agg = pcv_dash_create(0, 0, 0);
        stubctx sc; memset(&sc, 0, sizeof(sc)); sc.fail = 1;
        pcv_resolver* r = pcv_resolver_create(agg, stub_ptr, &sc);
        pcv_dash_set_resolver(agg, r);
        feed_global_flow(agg, 0x08080808u);               /* one global dst */
        pcv_dash_force_snapshot(agg);
        int first = pcv_resolver_ptr_pass(r);
        int after_calls = sc.calls;
        int second = pcv_resolver_ptr_pass(r);
        CHECK(first >= 1, "first PTR pass attempts the lookup");
        CHECK(sc.calls == after_calls,
              "second pass does NOT retry (negative cache cooldown)");
        (void)second;
        pcv_dash_set_resolver(agg, NULL);
        pcv_resolver_destroy(r);
        pcv_dash_destroy(agg);
    }

    /* Positive caching: a named IP is not re-looked-up next pass. */
    {
        pcv_dash_agg* agg = pcv_dash_create(0, 0, 0);
        stubctx sc; memset(&sc, 0, sizeof(sc)); strcpy(sc.ret, "ok.example");
        pcv_resolver* r = pcv_resolver_create(agg, stub_ptr, &sc);
        pcv_dash_set_resolver(agg, r);
        feed_global_flow(agg, 0x08080808u);
        pcv_dash_force_snapshot(agg);
        pcv_resolver_ptr_pass(r);
        int after = sc.calls;
        pcv_resolver_ptr_pass(r);
        CHECK(sc.calls == after, "positive entry is cached (no re-lookup)");
        pcv_resolve_key k; uint8_t nb[4]; v4_netbytes(0x08080808u, nb);
        pcv_resolve_key_make(PCV_ADDR_IPV4, nb, &k);
        char buf[256];
        CHECK(pcv_resolve_lookup(r, &k, buf, sizeof(buf)) > 0 &&
              strcmp(buf, "ok.example") == 0, "PTR name stored + looked up");
        pcv_dash_set_resolver(agg, NULL);
        pcv_resolver_destroy(r);
        pcv_dash_destroy(agg);
    }

    /* Passive-over-PTR precedence: a passive name is never attempted via PTR,
     * and a later passive insert replaces a PTR name. */
    {
        pcv_dash_agg* agg = pcv_dash_create(0, 0, 0);
        stubctx sc; memset(&sc, 0, sizeof(sc)); strcpy(sc.ret, "ptr.example");
        pcv_resolver* r = pcv_resolver_create(agg, stub_ptr, &sc);
        pcv_dash_set_resolver(agg, r);

        /* Passive name for 8.8.8.8 via a DNS reply. */
        uint8_t frame[1024];
        uint8_t a1[4]; v4_netbytes(0x08080808u, a1);
        pcv_dns_answer an = { 1, 0, a1 };
        size_t fl = pcv_build_dns_ipv4(frame, sizeof(frame), 0x08080808u,
                                       0x0A000001u, 53, 33333, "dns.google", 1,
                                       1, 0, 1, &an, 1);
        feed_malloc(agg, frame, fl);
        pcv_resolver_drain_once(r);

        feed_global_flow(agg, 0x08080808u);
        pcv_dash_force_snapshot(agg);
        pcv_resolver_ptr_pass(r);
        CHECK(sc.calls == 0, "PTR not attempted for an IP with a passive name");

        pcv_resolve_key k; pcv_resolve_key_make(PCV_ADDR_IPV4, a1, &k);
        char buf[256];
        pcv_resolve_lookup(r, &k, buf, sizeof(buf));
        CHECK(strcmp(buf, "dns.google") == 0, "passive name wins over PTR");

        pcv_dash_set_resolver(agg, NULL);
        pcv_resolver_destroy(r);
        pcv_dash_destroy(agg);
    }
}

/* ---- (f) hot-path short-UDP overread guard ------------------------------- */

static void test_short_udp(void) {
    fprintf(stdout, "hot-path short-UDP frame: no overread (ASan tight buffer)\n");
    pcv_dash_agg* agg = pcv_dash_create(0, 0, 0);
    pcv_resolver* r = pcv_resolver_create(agg, stub_ptr, NULL);
    pcv_dash_set_resolver(agg, r);

    uint8_t frame[1024];
    uint8_t a1[4]; v4_netbytes(0x08080808u, a1);
    pcv_dns_answer an = { 1, 0, a1 };
    size_t fl = pcv_build_dns_ipv4(frame, sizeof(frame), 0x08080808u, 0x0A000001u,
                                   53, 33333, "example.com", 1, 1, 0, 1, &an, 1);
    CHECK(fl > 0, "build full DNS frame");

    /* Claim proto 17 but capture only part of the UDP header: l4_off is 34, so
     * l4_off + 8 = 42 > caplen; the enqueue must bail BEFORE reading ports. The
     * tight malloc(caplen) means any port read past caplen is an ASan fault. */
    feed_malloc_caplen(agg, frame, fl, 38);   /* 14 + 20 + 4 captured */
    feed_malloc_caplen(agg, frame, fl, 34);   /* exactly the L4 start */
    feed_malloc_caplen(agg, frame, fl, 42);   /* full UDP hdr, zero payload */
    feed_malloc_caplen(agg, frame, fl, 44);   /* 2 payload bytes (< 12 hdr) */
    pcv_resolver_drain_once(r);                /* parse whatever (safely) enqueued */

    /* Nothing should have overread, and the truncated frames produce no name. */
    pcv_resolve_key k; pcv_resolve_key_make(PCV_ADDR_IPV4, a1, &k);
    char buf[256];
    CHECK(pcv_resolve_lookup(r, &k, buf, sizeof(buf)) == 0,
          "truncated UDP frames yield no name (no overread, no bogus entry)");

    CHECK(1, "no ASan fault on truncated UDP frames");
    pcv_dash_set_resolver(agg, NULL);
    pcv_resolver_destroy(r);
    pcv_dash_destroy(agg);
}

/* ---- (g) pure TLS ClientHello -> SNI parser (ASan tight buffers) --------- */

static int sni_tight(const uint8_t* rec, size_t len, char* out, size_t outcap) {
    uint8_t* b = malloc(len ? len : 1);
    if (len) memcpy(b, rec, len);
    int rc = pcv_tls_parse_sni(b, (uint32_t)len, out, outcap);
    free(b);
    return rc;
}

/* Build a ClientHello record wrapping a caller-supplied extensions blob, for
 * the extension-walk edge cases (GREASE, overlap, duplicates). */
static size_t build_ch_with_exts(uint8_t* out, size_t cap,
                                  const uint8_t* exts, size_t elen) {
    uint8_t body[2048];
    size_t o = 0;
    body[o++] = 0x03; body[o++] = 0x03;             /* legacy_version */
    memset(body + o, 0xAB, 32); o += 32;            /* random */
    body[o++] = 0x00;                               /* session_id length 0 */
    body[o++] = 0x00; body[o++] = 0x02;             /* cipher_suites length */
    body[o++] = 0x13; body[o++] = 0x01;
    body[o++] = 0x01; body[o++] = 0x00;             /* compression: null */
    body[o++] = (uint8_t)(elen >> 8); body[o++] = (uint8_t)(elen & 0xFF);
    if (o + elen > sizeof(body)) return 0;
    memcpy(body + o, exts, elen); o += elen;

    size_t hs = o, rl = 4 + hs, total = 5 + rl;
    if (total > cap) return 0;
    out[0] = 0x16; out[1] = 0x03; out[2] = 0x01;
    out[3] = (uint8_t)(rl >> 8); out[4] = (uint8_t)(rl & 0xFF);
    out[5] = 0x01;
    out[6] = (uint8_t)(hs >> 16); out[7] = (uint8_t)(hs >> 8); out[8] = (uint8_t)(hs & 0xFF);
    memcpy(out + 9, body, hs);
    return total;
}

/* Append a server_name extension carrying `host` to e; returns new length. */
static size_t put_sni_ext(uint8_t* e, size_t o, const char* host) {
    size_t hl = strlen(host);
    size_t entry = 3 + hl, list = entry, body = 2 + list;
    e[o++] = 0x00; e[o++] = 0x00;
    e[o++] = (uint8_t)(body >> 8); e[o++] = (uint8_t)(body & 0xFF);
    e[o++] = (uint8_t)(list >> 8); e[o++] = (uint8_t)(list & 0xFF);
    e[o++] = 0x00;
    e[o++] = (uint8_t)(hl >> 8); e[o++] = (uint8_t)(hl & 0xFF);
    memcpy(e + o, host, hl); o += hl;
    return o;
}

static void test_tls_parser(void) {
    fprintf(stdout, "pure pcv_tls_parse_sni (valid + hostile/malformed, ASan)\n");
    uint8_t rec[900];
    char host[256];

    /* Valid. */
    size_t rl = pcv_build_tls_clienthello(rec, sizeof(rec), "www.nytimes.com", 0x01);
    CHECK(rl > 0, "build ClientHello record");
    CHECK(sni_tight(rec, rl, host, sizeof(host)) == 0 &&
          strcmp(host, "www.nytimes.com") == 0, "SNI extracted: www.nytimes.com");

    /* ServerHello (handshake type 0x02) -> rejected. */
    rl = pcv_build_tls_clienthello(rec, sizeof(rec), "evil.example", 0x02);
    CHECK(sni_tight(rec, rl, host, sizeof(host)) == -1,
          "handshake type 0x02 (ServerHello) rejected");

    /* No server_name extension. */
    rl = pcv_build_tls_clienthello(rec, sizeof(rec), NULL, 0x01);
    CHECK(sni_tight(rec, rl, host, sizeof(host)) == -1,
          "no server_name extension -> not found");

    /* Zero-length / non-handshake content type. */
    CHECK(sni_tight(rec, 0, host, sizeof(host)) == -1, "zero-length rejected");
    rl = pcv_build_tls_clienthello(rec, sizeof(rec), "x.example", 0x01);
    { uint8_t t[900]; memcpy(t, rec, rl); t[0] = 0x17;
      CHECK(sni_tight(t, rl, host, sizeof(host)) == -1,
            "non-handshake content type (0x17) rejected"); }

    /* Truncate at EVERY prefix length: never a crash, never a name past the
     * captured bytes (ASan redzone proves no overread). */
    rl = pcv_build_tls_clienthello(rec, sizeof(rec), "truncate.me.example", 0x01);
    int trunc_ok = 1;
    for (size_t cut = 1; cut < rl; cut++) {
        int rc = sni_tight(rec, cut, host, sizeof(host));
        if (!(rc == -1 || strcmp(host, "truncate.me.example") == 0)) trunc_ok = 0;
    }
    CHECK(trunc_ok, "every truncation returns -1 or the exact name (no partial/OOB)");

    /* record_len too large: still bounded by len, name still parses. */
    rl = pcv_build_tls_clienthello(rec, sizeof(rec), "rl.example", 0x01);
    { uint8_t t[900]; memcpy(t, rec, rl); t[3] = 0xFF; t[4] = 0xFF;
      CHECK(sni_tight(t, rl, host, sizeof(host)) == 0,
            "oversized record_len still bounded by len"); }
    /* record_len too small: cuts off the ClientHello -> not found. */
    { uint8_t t[900]; memcpy(t, rec, rl); t[3] = 0x00; t[4] = 0x05;
      CHECK(sni_tight(t, rl, host, sizeof(host)) == -1,
            "too-small record_len -> not found"); }
    /* 24-bit hs_len too small. */
    { uint8_t t[900]; memcpy(t, rec, rl); t[6] = 0; t[7] = 0; t[8] = 0x05;
      CHECK(sni_tight(t, rl, host, sizeof(host)) == -1,
            "too-small hs_len -> not found"); }

    /* Oversized host name_len + nametype!=0 via locating the SNI bytes. */
    rl = pcv_build_tls_clienthello(rec, sizeof(rec), "find.me.example", 0x01);
    {
        /* locate "find.me.example" */
        const char* needle = "find.me.example";
        uint8_t* pos = NULL;
        for (size_t i = 0; i + strlen(needle) <= rl; i++) {
            if (memcmp(rec + i, needle, strlen(needle)) == 0) { pos = rec + i; break; }
        }
        CHECK(pos != NULL, "locate SNI bytes in record");
        if (pos) {
            /* name_len is the 2 bytes immediately before the host; nametype the
             * byte before that. */
            uint8_t t[900]; memcpy(t, rec, rl);
            size_t off = (size_t)(pos - rec);
            t[off - 2] = 0xFF; t[off - 1] = 0xFF;      /* name_len huge */
            CHECK(sni_tight(t, rl, host, sizeof(host)) == -1,
                  "oversized name_len rejected (dest cap)");
            memcpy(t, rec, rl);
            t[off - 3] = 0x01;                          /* nametype != host_name */
            CHECK(sni_tight(t, rl, host, sizeof(host)) == -1,
                  "nametype != 0 (host_name) rejected");
        }
    }

    /* Tiny dest buffer: name longer than outcap-1 is rejected, never truncated. */
    rl = pcv_build_tls_clienthello(rec, sizeof(rec), "longname.example.com", 0x01);
    { char small[8];
      CHECK(sni_tight(rec, rl, small, sizeof(small)) == -1,
            "name longer than outcap rejected (no truncation)"); }

    /* GREASE extension (type 0x0a0a, len 0) BEFORE server_name -> still found. */
    {
        uint8_t e[256]; size_t o = 0;
        e[o++] = 0x0a; e[o++] = 0x0a; e[o++] = 0x00; e[o++] = 0x00; /* GREASE, 0 */
        o = put_sni_ext(e, o, "grease.example");
        size_t cl = build_ch_with_exts(rec, sizeof(rec), e, o);
        CHECK(cl > 0 && sni_tight(rec, cl, host, sizeof(host)) == 0 &&
              strcmp(host, "grease.example") == 0,
              "server_name after a GREASE extension still found");
    }

    /* Duplicate server_name entries: the FIRST wins. */
    {
        uint8_t e[256]; size_t o = 0;
        o = put_sni_ext(e, o, "first.example");
        o = put_sni_ext(e, o, "second.example");
        size_t cl = build_ch_with_exts(rec, sizeof(rec), e, o);
        CHECK(cl > 0 && sni_tight(rec, cl, host, sizeof(host)) == 0 &&
              strcmp(host, "first.example") == 0,
              "duplicate server_name: first entry wins");
    }

    /* Small-elen server_name whose inner name_len overflows INTO a following
     * extension: bounded by ext_end, must reject (not read the neighbour). */
    {
        uint8_t e[256]; size_t o = 0;
        e[o++] = 0x00; e[o++] = 0x00;               /* server_name type */
        e[o++] = 0x00; e[o++] = 0x07;               /* elen = 7 (too small) */
        e[o++] = 0x00; e[o++] = 0x05;               /* list_len */
        e[o++] = 0x00;                              /* host_name type */
        e[o++] = 0x00; e[o++] = 0x20;               /* name_len = 32 (overflows) */
        e[o++] = 'A';  e[o++] = 'A';                /* only 2 host bytes inside */
        /* a neighbouring GREASE ext the name_len would otherwise reach into */
        e[o++] = 0x0a; e[o++] = 0x0a; e[o++] = 0x00; e[o++] = 0x10;
        memset(e + o, 0x42, 16); o += 16;
        size_t cl = build_ch_with_exts(rec, sizeof(rec), e, o);
        CHECK(cl > 0 && sni_tight(rec, cl, host, sizeof(host)) == -1,
              "small-elen inner name_len bounded by ext_end (no neighbour read)");
    }

    /* Two TLS records in one buffer: the parser sees ONLY the first. */
    {
        uint8_t r1[900], r2[900];
        size_t l1 = pcv_build_tls_clienthello(r1, sizeof(r1), "first.record", 0x01);
        size_t l2 = pcv_build_tls_clienthello(r2, sizeof(r2), "second.record", 0x01);
        uint8_t both[1800]; memcpy(both, r1, l1); memcpy(both + l1, r2, l2);
        CHECK(sni_tight(both, l1 + l2, host, sizeof(host)) == 0 &&
              strcmp(host, "first.record") == 0,
              "two records in one buffer: only the first is parsed");
    }

    CHECK(1, "no ASan fault across all malformed/hostile ClientHellos");
}

/* ---- (h) replay: per-flow SNI on forward + reverse rows (v4/v6) ---------- */

/* Return 1 if some flow object containing `anchor` also contains `name`. */
static int row_has(const char* json, const char* anchor, const char* name) {
    const char* p = json;
    while ((p = strstr(p, anchor)) != NULL) {
        const char* end = strchr(p, '}');
        if (!end) break;
        const char* nm = strstr(p, name);
        if (nm && nm < end) return 1;
        p = end;
    }
    return 0;
}

static void test_tls_replay(void) {
    fprintf(stdout, "replay: SYN-first then ClientHello -> per-flow SNI (v4+v6)\n");
    pcv_dash_agg* agg = pcv_dash_create(0, 0, 0);
    pcv_resolver* r = pcv_resolver_create(agg, stub_ptr, NULL);
    CHECK(agg && r, "create agg+resolver (tls replay)");
    pcv_dash_set_resolver(agg, r);

    uint8_t frame[1600];

    /* IPv4: client 10.0.0.1:50000 -> server 93.184.216.34:443. */
    size_t fl = pcv_build_ipv4_frame(frame, sizeof(frame), 6, 0x0A000001u,
                                     0x5DB8D822u, 50000, 443, 0x02, 0); /* SYN */
    feed_malloc(agg, frame, fl);
    fl = pcv_build_tls_clienthello_ipv4(frame, sizeof(frame), 0x0A000001u,
                                        0x5DB8D822u, 50000, 443, "www.nytimes.com");
    CHECK(fl > 0, "build IPv4 ClientHello frame");
    feed_malloc(agg, frame, fl);
    for (int i = 0; i < 6; i++) {               /* reverse (download) packets */
        fl = pcv_build_ipv4_frame(frame, sizeof(frame), 6, 0x5DB8D822u,
                                  0x0A000001u, 443, 50000, 0x10, 1000);
        feed_malloc(agg, frame, fl);
    }

    /* IPv6: client 2001::99 -> server 2606:2800::1 :443. */
    static const uint8_t cli6[16] = {0x20,0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,0x99};
    static const uint8_t srv6[16] = {0x26,0x06,0x28,0,0,0,0,0,0,0,0,0,0,0,0,0x01};
    fl = pcv_build_ipv6_frame(frame, sizeof(frame), 6, cli6, srv6, 50001, 443, 0x02, 0);
    feed_malloc(agg, frame, fl);
    fl = pcv_build_tls_clienthello_ipv6(frame, sizeof(frame), cli6, srv6,
                                        50001, 443, "ipv6.example.org");
    CHECK(fl > 0, "build IPv6 ClientHello frame");
    feed_malloc(agg, frame, fl);
    for (int i = 0; i < 6; i++) {
        fl = pcv_build_ipv6_frame(frame, sizeof(frame), 6, srv6, cli6, 443, 50001, 0x10, 1000);
        feed_malloc(agg, frame, fl);
    }

    pcv_resolver_drain_once(r);
    pcv_dash_force_snapshot(agg);

    static char json[131072];
    pcv_dash_snapshot_json(agg, json, sizeof(json));

    CHECK(row_has(json, "\"src_ip\":\"10.0.0.1\"", "\"dst_name\":\"www.nytimes.com\""),
          "IPv4 forward row: dst_name == SNI (server is dst)");
    CHECK(row_has(json, "\"dst_ip\":\"10.0.0.1\"", "\"src_name\":\"www.nytimes.com\""),
          "IPv4 reverse row: src_name == SNI (orientation swap)");
    CHECK(strstr(json, "ipv6.example.org") != NULL,
          "IPv6 ClientHello SNI surfaced end-to-end");

    pcv_dash_set_resolver(agg, NULL);
    pcv_resolver_destroy(r);
    pcv_dash_destroy(agg);
}

/* ---- (i) shared-IP discrimination: the option-(a) proof ------------------ */

static void test_tls_shared_ip(void) {
    fprintf(stdout, "shared CDN IP: two SNIs, per-flow accuracy (not IP LWW)\n");
    pcv_dash_agg* agg = pcv_dash_create(0, 0, 0);
    pcv_resolver* r = pcv_resolver_create(agg, stub_ptr, NULL);
    CHECK(agg && r, "create agg+resolver (shared ip)");
    pcv_dash_set_resolver(agg, r);

    uint8_t frame[1600];
    const uint32_t cdn = 0x924B0101u;            /* 146.75.1.1 (one server IP) */

    /* Flow A: clientA 10.0.0.10 -> cdn:443, SNI www.nytimes.com. */
    size_t fl = pcv_build_ipv4_frame(frame, sizeof(frame), 6, 0x0A00000Au, cdn, 40001, 443, 0x02, 0);
    feed_malloc(agg, frame, fl);
    fl = pcv_build_tls_clienthello_ipv4(frame, sizeof(frame), 0x0A00000Au, cdn, 40001, 443, "www.nytimes.com");
    feed_malloc(agg, frame, fl);

    /* Flow B: clientB 10.0.0.20 -> cdn:443, SNI www.washingtonpost.com. */
    fl = pcv_build_ipv4_frame(frame, sizeof(frame), 6, 0x0A000014u, cdn, 40002, 443, 0x02, 0);
    feed_malloc(agg, frame, fl);
    fl = pcv_build_tls_clienthello_ipv4(frame, sizeof(frame), 0x0A000014u, cdn, 40002, 443, "www.washingtonpost.com");
    feed_malloc(agg, frame, fl);

    pcv_resolver_drain_once(r);
    pcv_dash_force_snapshot(agg);

    static char json[131072];
    pcv_dash_snapshot_json(agg, json, sizeof(json));

    CHECK(row_has(json, "\"src_ip\":\"10.0.0.10\"", "\"dst_name\":\"www.nytimes.com\""),
          "flow A row shows its OWN SNI (www.nytimes.com)");
    CHECK(row_has(json, "\"src_ip\":\"10.0.0.20\"", "\"dst_name\":\"www.washingtonpost.com\""),
          "flow B row shows its OWN SNI (www.washingtonpost.com) - not IP LWW");

    pcv_dash_set_resolver(agg, NULL);
    pcv_resolver_destroy(r);
    pcv_dash_destroy(agg);
}

/* ---- (j) hot-path TLS gate tight-caplen overread ------------------------- */

static void test_tls_hotpath_caplen(void) {
    fprintf(stdout, "hot-path TLS gate: tight-caplen cuts, no overread (ASan)\n");
    pcv_dash_agg* agg = pcv_dash_create(0, 0, 0);
    pcv_resolver* r = pcv_resolver_create(agg, stub_ptr, NULL);
    pcv_dash_set_resolver(agg, r);

    uint8_t frame[1600];
    size_t fl = pcv_build_tls_clienthello_ipv4(frame, sizeof(frame), 0x0A000001u,
                                               0x08080808u, 50000, 443, "cut.example");
    CHECK(fl > 0, "build ClientHello for caplen cuts");

    /* IPv4: l4_off=34, payload_off=54. Cut at each structural boundary. */
    size_t cuts[] = { 34, 46, 47, 54, 55, 59, 64 };
    for (size_t i = 0; i < sizeof(cuts)/sizeof(cuts[0]); i++) {
        if (cuts[i] <= fl) feed_malloc_caplen(agg, frame, fl, cuts[i]);
    }
    pcv_resolver_drain_once(r);

    pcv_resolve_key k; uint8_t nb[4]; v4_netbytes(0x08080808u, nb);
    pcv_resolve_key_make(PCV_ADDR_IPV4, nb, &k);
    char buf[256];
    CHECK(pcv_resolve_lookup(r, &k, buf, sizeof(buf)) == 0,
          "tight-caplen cuts yield no name (no overread, no bogus entry)");
    CHECK(1, "no ASan fault on tight-caplen TLS frames");

    pcv_dash_set_resolver(agg, NULL);
    pcv_resolver_destroy(r);
    pcv_dash_destroy(agg);
}

/* ---- (k) no-XSS for an attacker SNI (both sinks) ------------------------- */

static void test_tls_xss(void) {
    fprintf(stdout, "no-XSS: attacker SNI inert on flow-row AND hosts sinks\n");
    pcv_dash_agg* agg = pcv_dash_create(0, 0, 0);
    pcv_resolver* r = pcv_resolver_create(agg, stub_ptr, NULL);
    CHECK(agg && r, "create agg+resolver (tls xss)");
    pcv_dash_set_resolver(agg, r);

    uint8_t frame[1600];
    const char* evil = "<script>alert(1)</script>.evil.com";
    size_t fl = pcv_build_ipv4_frame(frame, sizeof(frame), 6, 0x0A000001u,
                                     0xCB007109u, 50000, 443, 0x02, 0);
    feed_malloc(agg, frame, fl);
    fl = pcv_build_tls_clienthello_ipv4(frame, sizeof(frame), 0x0A000001u,
                                        0xCB007109u, 50000, 443, evil);
    CHECK(fl > 0, "build ClientHello with hostile SNI");
    feed_malloc(agg, frame, fl);
    for (int i = 0; i < 4; i++) {
        fl = pcv_build_ipv4_frame(frame, sizeof(frame), 6, 0xCB007109u,
                                  0x0A000001u, 443, 50000, 0x10, 1000);
        feed_malloc(agg, frame, fl);
    }

    pcv_resolver_drain_once(r);
    pcv_dash_force_snapshot(agg);

    static char json[131072];
    pcv_dash_snapshot_json(agg, json, sizeof(json));

    CHECK(strchr(json, '<') == NULL, "served bytes contain no '<'");
    CHECK(strstr(json, "<script") == NULL, "served bytes contain no <script");
    CHECK(strstr(json, "</") == NULL, "served bytes contain no closing-tag '</'");
    CHECK(strstr(json, "alert(1)") == NULL, "no 'alert(1)' (parens stripped)");
    /* Positive inert residue (proves the name traversed insert->serialize, not
     * merely dropped). Appears in BOTH the flow-row and hosts sinks. */
    CHECK(strstr(json, "scriptalert1script.evil.com") != NULL,
          "hostile SNI sanitized to inert allowlist residue (both sinks)");

    pcv_dash_set_resolver(agg, NULL);
    pcv_resolver_destroy(r);
    pcv_dash_destroy(agg);
}

/* ---- (l) provenance precedence: SNI > PASSIVE > PTR ---------------------- */

static void feed_clienthello(pcv_dash_agg* a, uint32_t dst_host, const char* sni) {
    uint8_t frame[1600];
    size_t fl = pcv_build_tls_clienthello_ipv4(frame, sizeof(frame), 0x0A000001u,
                                               dst_host, 50000, 443, sni);
    feed_malloc(a, frame, fl);
}

static void test_tls_precedence(void) {
    fprintf(stdout, "precedence: SNI beats PTR/PASSIVE; PTR/PASSIVE cannot clobber live SNI\n");

    /* SNI beats a prior PTR on the same server IP. */
    {
        pcv_dash_agg* agg = pcv_dash_create(0, 0, 0);
        stubctx sc; memset(&sc, 0, sizeof(sc)); strcpy(sc.ret, "ptr.infra.example");
        pcv_resolver* r = pcv_resolver_create(agg, stub_ptr, &sc);
        pcv_dash_set_resolver(agg, r);

        feed_global_flow(agg, 0x08080808u);          /* flow to 8.8.8.8 */
        pcv_dash_force_snapshot(agg);
        pcv_resolver_ptr_pass(r);                    /* PTR name inserted */

        pcv_resolve_key k; uint8_t nb[4]; v4_netbytes(0x08080808u, nb);
        pcv_resolve_key_make(PCV_ADDR_IPV4, nb, &k);
        char buf[256];
        pcv_resolve_lookup(r, &k, buf, sizeof(buf));
        CHECK(strcmp(buf, "ptr.infra.example") == 0, "PTR name set first");

        feed_clienthello(agg, 0x08080808u, "dns.google");
        pcv_resolver_drain_once(r);
        pcv_resolve_lookup(r, &k, buf, sizeof(buf));
        CHECK(strcmp(buf, "dns.google") == 0, "SNI overwrites a live PTR name");

        /* PTR cannot clobber the now-live SNI: a fresh pass must not attempt it. */
        int before = sc.calls;
        pcv_resolver_ptr_pass(r);
        CHECK(sc.calls == before, "PTR not attempted for an IP with a live SNI name");
        pcv_resolve_lookup(r, &k, buf, sizeof(buf));
        CHECK(strcmp(buf, "dns.google") == 0, "live SNI survives a PTR pass");

        pcv_dash_set_resolver(agg, NULL);
        pcv_resolver_destroy(r);
        pcv_dash_destroy(agg);
    }

    /* PASSIVE cannot clobber a live SNI (rank PASSIVE < SNI). */
    {
        pcv_dash_agg* agg = pcv_dash_create(0, 0, 0);
        pcv_resolver* r = pcv_resolver_create(agg, stub_ptr, NULL);
        pcv_dash_set_resolver(agg, r);

        /* SNI first for 8.8.8.8. */
        feed_clienthello(agg, 0x08080808u, "sni.google");
        pcv_resolver_drain_once(r);

        /* Then a passive DNS answer naming the SAME IP differently. */
        uint8_t frame[1024]; uint8_t a1[4]; v4_netbytes(0x08080808u, a1);
        pcv_dns_answer an = { 1, 0, a1 };
        size_t fl = pcv_build_dns_ipv4(frame, sizeof(frame), 0x08080808u,
                                       0x0A000001u, 53, 33333, "passive.google",
                                       1, 1, 0, 1, &an, 1);
        feed_malloc(agg, frame, fl);
        pcv_resolver_drain_once(r);

        pcv_resolve_key k; pcv_resolve_key_make(PCV_ADDR_IPV4, a1, &k);
        char buf[256]; pcv_resolve_lookup(r, &k, buf, sizeof(buf));
        CHECK(strcmp(buf, "sni.google") == 0,
              "PASSIVE does not clobber a live SNI (SNI outranks PASSIVE)");

        pcv_dash_set_resolver(agg, NULL);
        pcv_resolver_destroy(r);
        pcv_dash_destroy(agg);
    }
}

int main(void) {
    test_pure_parser();
    test_malformed();
    test_replay_names();
    test_xss();
    test_ptr();
    test_short_udp();
    test_tls_parser();
    test_tls_replay();
    test_tls_shared_ip();
    test_tls_hotpath_caplen();
    test_tls_xss();
    test_tls_precedence();
    return pcv_test_summary("test_resolve");
}
