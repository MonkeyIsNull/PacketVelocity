/* Offline dashboard-aggregation test (no root, no NIC, no RistrettoDB).
 *
 * Drives the SAME pcv_dash_on_packet() the live capture callback calls, fed by
 * the pcap replay harness and by direct synthetic packets, then asserts the
 * published snapshot and the /stats.json bytes:
 *   - exact per-protocol counts AND the invariant sum(proto[]) == packets
 *     classified (every packet in exactly one bucket, incl. a <14-byte frame);
 *   - the top-N ACTIVE flows (tuple + packet count), via force_snapshot;
 *   - rate / drop math: pps, Mbit/s, per-interval drop-rate and cumulative
 *     ratio from injected recv/dropped, plus the first-sample=0, 32-bit-wrap,
 *     and idle-zero-pps guards.
 */
#ifdef __linux__
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L   /* glibc hides mkstemp under strict -std=c11 */
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pcv_platform.h"
#include "pcv_dashboard.h"
#include "pcap_replay.h"
#include "pcv_test.h"

/* ---- tiny JSON probes (sufficient for our flat, known payload) ---------- */

static int jget_u64(const char* j, const char* key, uint64_t* out) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char* p = strstr(j, pat);
    if (!p) return 0;
    p += strlen(pat);
    *out = strtoull(p, NULL, 10);
    return 1;
}

static int jget_double(const char* j, const char* key, double* out) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char* p = strstr(j, pat);
    if (!p) return 0;
    p += strlen(pat);
    *out = strtod(p, NULL);
    return 1;
}

static int count_occurrences(const char* hay, const char* needle) {
    int c = 0;
    const char* p = hay;
    while ((p = strstr(p, needle)) != NULL) { c++; p += strlen(needle); }
    return c;
}

/* Replay callback: the ONLY difference from live mode is the packet source. */
static void dash_replay_cb(const pcv_packet* pkt, void* user) {
    pcv_dash_on_packet((pcv_dash_agg*)user, pkt);
}

static void feed(pcv_dash_agg* a, const uint8_t* buf, uint32_t caplen,
                 uint32_t wire, uint64_t ts) {
    pcv_packet p;
    memset(&p, 0, sizeof(p));
    p.data = buf;
    p.captured_length = caplen;
    p.length = wire;
    p.timestamp_ns = ts;
    pcv_dash_on_packet(a, &p);
}

/* ---- 1. protocol + flow aggregation over a known replay ----------------- */

static void test_aggregation(void) {
    fprintf(stdout, "aggregation over known replay\n");

    static uint8_t f_tcp1[256], f_tcp2[256], f_tcp3[256];
    static uint8_t f_udp1[256], f_udp2[256], f_icmp[256];
    static uint8_t f_arp[64], f_v6[256];
    static uint8_t f_short[10] = {0};

    size_t l_tcp1 = pcv_build_ipv4_frame(f_tcp1, 256, 6, 0x0A000001, 0x0A000002, 1234, 80, 0x02, 0);
    size_t l_tcp2 = pcv_build_ipv4_frame(f_tcp2, 256, 6, 0x0A000001, 0x0A000002, 1234, 80, 0x10, 60);
    size_t l_tcp3 = pcv_build_ipv4_frame(f_tcp3, 256, 6, 0x0A000001, 0x0A000002, 1235, 443, 0x02, 0);
    size_t l_udp1 = pcv_build_ipv4_frame(f_udp1, 256, 17, 0x0A000001, 0x08080808, 5000, 53, 0, 20);
    size_t l_udp2 = pcv_build_ipv4_frame(f_udp2, 256, 17, 0x0A000001, 0x08080808, 5001, 53, 0, 24);
    size_t l_icmp = pcv_build_ipv4_frame(f_icmp, 256, 1, 0x0A000001, 0x0A000009, 0, 0, 0, 0);
    static const uint8_t smac[6] = {0x02,0,0,0,0,0x02};
    size_t l_arp  = pcv_build_arp_frame(f_arp, 64, 1, 0x0A000001, 0x0A0000FE, smac, NULL);
    static const uint8_t s6[16] = {0x20,0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    static const uint8_t d6[16] = {0x20,0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,2};
    size_t l_v6   = pcv_build_ipv6_frame(f_v6, 256, 6, s6, d6, 2000, 443, 0x02, 0);

    pcap_replay_packet pkts[9];
    const uint8_t* bufs[9] = {f_tcp1,f_tcp2,f_tcp3,f_udp1,f_udp2,f_icmp,f_arp,f_v6,f_short};
    size_t lens[9] = {l_tcp1,l_tcp2,l_tcp3,l_udp1,l_udp2,l_icmp,l_arp,l_v6,10};
    for (int i = 0; i < 9; i++) {
        CHECK(lens[i] > 0, "build frame");
        pkts[i].data = bufs[i];
        pkts[i].length = (uint32_t)lens[i];
        pkts[i].timestamp_ns = (uint64_t)(i + 1) * 1000000000ULL;
    }

    char path[] = "/tmp/pcv_dash_XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0, "temp pcap path");
    if (fd >= 0) close(fd);
    CHECK(pcap_replay_write(path, pkts, 9) == 0, "write pcap savefile");

    pcv_dash_agg* agg = pcv_dash_create(0, 0, 0);
    CHECK(agg != NULL, "create aggregator");

    int n = pcap_replay_file(path, dash_replay_cb, agg);
    CHECK_EQ_U64(n, 9, "replayed 9 packets through pcv_dash_on_packet");
    unlink(path);

    pcv_dash_force_snapshot(agg);  /* deterministic top-N publish */

    static char json[65536];
    size_t jlen = pcv_dash_snapshot_json(agg, json, sizeof(json));
    CHECK(jlen > 0, "serialize /stats.json");

    uint64_t pkts_total = 0, proto_total = 0;
    uint64_t tcp=0, udp=0, icmp=0, arp=0, ipv6=0, other=0;
    jget_u64(json, "pkts", &pkts_total);
    jget_u64(json, "proto_total", &proto_total);
    jget_u64(json, "tcp", &tcp);
    jget_u64(json, "udp", &udp);
    jget_u64(json, "icmp", &icmp);
    jget_u64(json, "arp", &arp);
    jget_u64(json, "ipv6", &ipv6);
    jget_u64(json, "other", &other);

    CHECK_EQ_U64(pkts_total, 9, "total packets");
    CHECK_EQ_U64(tcp, 3, "TCP bucket (IPv4 TCP only)");
    CHECK_EQ_U64(udp, 2, "UDP bucket");
    CHECK_EQ_U64(icmp, 1, "ICMP bucket");
    CHECK_EQ_U64(arp, 1, "ARP bucket");
    CHECK_EQ_U64(ipv6, 1, "IPv6 bucket (single bucket for the MVP)");
    CHECK_EQ_U64(other, 1, "OTHER bucket (the <14-byte frame)");
    CHECK_EQ_U64(proto_total, 9, "sum(proto[]) == packets classified (TOTAL classifier)");
    CHECK_EQ_U64(tcp+udp+icmp+arp+ipv6+other, pkts_total, "buckets re-sum to total");

    /* Flows: ARP + the short frame create no flow; the rest yield 6 ACTIVE
     * flows, topped by the 2-packet TCP conversation. */
    int nflows = count_occurrences(json, "\"tuple\":");
    CHECK_EQ_U64(nflows, 6, "6 active flows in the snapshot (below saturation)");
    CHECK(strstr(json, "10.0.0.1:1234 -> 10.0.0.2:80 (6)") != NULL,
          "top flow 5-tuple present");

    const char* flows = strstr(json, "\"flows\":[");
    CHECK(flows != NULL, "flows array present");
    if (flows) {
        uint64_t top_pkts = 0;
        jget_u64(flows, "packets", &top_pkts);
        CHECK_EQ_U64(top_pkts, 2, "top flow ranked first has 2 packets");
    }

    pcv_dash_destroy(agg);
}

/* ---- 2. rate + drop math (injected recv/dropped) ------------------------ */

static void test_rates(void) {
    fprintf(stdout, "rate + drop math (injected stats)\n");

    uint8_t frame[256];
    size_t flen = pcv_build_ipv4_frame(frame, 256, 6, 0x0A000001, 0x0A000002, 1111, 80, 0x10, 60);
    CHECK(flen > 0, "build rate-test frame");

    const uint64_t t0 = 10ULL * 1000000000ULL;
    static char json[65536];

    /* (a) steady interval: 50 accepted packets over exactly 1s. */
    {
        pcv_dash_agg* a = pcv_dash_create(0, 0, 0);
        pcv_dash_sample_with_stats(a, 1000, 0, t0);           /* first sample */
        for (int i = 0; i < 50; i++) feed(a, frame, (uint32_t)flen, 100, t0);
        pcv_dash_sample_with_stats(a, 1100, 10, t0 + 1000000000ULL);
        pcv_dash_snapshot_json(a, json, sizeof(json));

        double pps = 0, mbit = 0, drate = 0, dratio = 0;
        uint64_t recv = 0, dropped = 0;
        jget_double(json, "pps", &pps);
        jget_double(json, "mbit", &mbit);
        jget_double(json, "drop_rate", &drate);
        jget_double(json, "drop_ratio", &dratio);
        jget_u64(json, "recv", &recv);
        jget_u64(json, "dropped", &dropped);

        CHECK(pps > 49.9 && pps < 50.1, "pps = 50 over a 1s interval");
        CHECK(mbit > 0.0399 && mbit < 0.0401, "Mbit/s = 50*100*8 / 1e6");
        CHECK(drate > 0.0908 && drate < 0.0910, "interval drop-rate = 10/110");
        CHECK(dratio > 0.0090 && dratio < 0.0091, "cumulative drop ratio = 10/1110");
        CHECK_EQ_U64(recv, 1100, "cumulative recv surfaced");
        CHECK_EQ_U64(dropped, 10, "cumulative dropped surfaced");
        pcv_dash_destroy(a);
    }

    /* (b) half-second interval: rate must divide by ACTUAL dt, not an assumed 1s. */
    {
        pcv_dash_agg* a = pcv_dash_create(0, 0, 0);
        pcv_dash_sample_with_stats(a, 0, 0, t0);
        for (int i = 0; i < 50; i++) feed(a, frame, (uint32_t)flen, 100, t0);
        pcv_dash_sample_with_stats(a, 0, 0, t0 + 500000000ULL);  /* 0.5s */
        pcv_dash_snapshot_json(a, json, sizeof(json));
        double pps = 0;
        jget_double(json, "pps", &pps);
        CHECK(pps > 99.9 && pps < 100.1, "pps = 100 over a 0.5s interval (dt-based)");
        pcv_dash_destroy(a);
    }

    /* (c) FIRST sample yields 0, never a spike from the large absolute recv. */
    {
        pcv_dash_agg* a = pcv_dash_create(0, 0, 0);
        pcv_dash_sample_with_stats(a, 5000, 100, t0);  /* only sample */
        pcv_dash_snapshot_json(a, json, sizeof(json));
        double pps = 0, drate = 0;
        jget_double(json, "pps", &pps);
        jget_double(json, "drop_rate", &drate);
        CHECK(pps == 0.0, "first sample pps = 0 (no previous reading)");
        CHECK(drate == 0.0, "first sample interval drop-rate = 0");
        pcv_dash_destroy(a);
    }

    /* (d) 32-bit recv WRAP yields a sane delta, not a bogus spike. */
    {
        pcv_dash_agg* a = pcv_dash_create(0, 0, 0);
        pcv_dash_sample_with_stats(a, 4294967290ULL, 0, t0);          /* near 2^32 */
        pcv_dash_sample_with_stats(a, 10, 5, t0 + 1000000000ULL);     /* wrapped */
        pcv_dash_snapshot_json(a, json, sizeof(json));
        /* recv_delta == (uint32)(10 - 4294967290) == 16; drop_delta == 5;
         * interval drop-rate == 5/21 ~= 0.238 - a bogus huge recv_delta would
         * instead drive this toward 0. */
        double drate = 0;
        jget_double(json, "drop_rate", &drate);
        CHECK(drate > 0.22 && drate < 0.25, "wrap -> sane delta -> drop-rate 5/21");
        pcv_dash_destroy(a);
    }

    /* (e) idle tick reports 0 pps AND advances prev_* (no stale / double-count). */
    {
        pcv_dash_agg* a = pcv_dash_create(0, 0, 0);
        for (int i = 0; i < 10; i++) feed(a, frame, (uint32_t)flen, 100, t0);
        pcv_dash_sample_with_stats(a, 100, 0, t0);                    /* first */
        pcv_dash_sample_with_stats(a, 100, 0, t0 + 1000000000ULL);    /* idle */
        pcv_dash_snapshot_json(a, json, sizeof(json));
        double idle_pps = 0;
        jget_double(json, "pps", &idle_pps);
        CHECK(idle_pps == 0.0, "idle tick reports 0 pps");

        for (int i = 0; i < 20; i++) feed(a, frame, (uint32_t)flen, 100, t0);
        pcv_dash_sample_with_stats(a, 100, 0, t0 + 2000000000ULL);
        pcv_dash_snapshot_json(a, json, sizeof(json));
        double next_pps = 0;
        jget_double(json, "pps", &next_pps);
        /* 20, not 30: the idle tick advanced prev_pkts, so no double count. */
        CHECK(next_pps > 19.9 && next_pps < 20.1,
              "next interval = 20 pps (idle tick advanced prev_*, no double count)");
        pcv_dash_destroy(a);
    }
}

int main(void) {
    test_aggregation();
    test_rates();
    return pcv_test_summary("test_dashboard");
}
