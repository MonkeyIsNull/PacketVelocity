/* Unit tests for flow aggregation (src/pcv_flow.c). */
#include "pcv_flow.h"
#include "pcv_platform.h"
#include "pcv_test.h"

/* Wrap a synthetic frame in a pcv_packet. */
static pcv_packet make_packet(const uint8_t* data, uint32_t len, uint64_t ts) {
    pcv_packet p;
    memset(&p, 0, sizeof(p));
    p.data = data;
    p.length = len;
    p.captured_length = len;
    p.timestamp_ns = ts;
    return p;
}

/* Iteration callback: count flows and flag any that are expired. */
typedef struct {
    int total;
    int expired;
} iter_ctx;

static void count_cb(const pcv_flow_stats* flow, void* user) {
    iter_ctx* c = (iter_ctx*)user;
    c->total++;
    if (flow->flow_state & PCV_FLOW_TIMEOUT) c->expired++;
}

int main(void) {
    fprintf(stdout, "flow aggregation tests\n");

    uint8_t buf[256];

    /* ---- key extraction --------------------------------------------- */
    {
        size_t n = pcv_build_ipv4_frame(buf, sizeof(buf), 6,
                                        0x0A000001 /*10.0.0.1*/,
                                        0x0A000002 /*10.0.0.2*/,
                                        1234, 80, 0x02 /*SYN*/, 0);
        CHECK(n > 0, "build TCP frame");
        pcv_packet pkt = make_packet(buf, (uint32_t)n, 1000000000ULL);

        pcv_flow_key key;
        CHECK(pcv_flow_extract_key(&pkt, &key) == 0, "extract key from TCP frame");
        CHECK_EQ_U64(key.protocol, 6, "extracted protocol is TCP");
        CHECK_EQ_U64(key.src_port, 1234, "extracted src port");
        CHECK_EQ_U64(key.dst_port, 80, "extracted dst port");
        CHECK(key.src_ip == htonl(0x0A000001), "extracted src ip");
        CHECK(key.dst_ip == htonl(0x0A000002), "extracted dst ip");
    }

    /* A too-short frame must be rejected by extraction. */
    {
        pcv_packet pkt = make_packet(buf, 20, 0);
        pcv_flow_key key;
        CHECK(pcv_flow_extract_key(&pkt, &key) != 0, "short frame rejected");
    }

    /* ---- flow table aggregation ------------------------------------- */
    pcv_flow_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.max_flows = 1024;
    cfg.hash_buckets = 4096;
    cfg.flow_timeout_ms = 1000;        /* 1 second */
    cfg.cleanup_interval = 1000000;    /* effectively disable auto-expire */
    cfg.enable_tcp_state = true;

    pcv_flow_table* table = pcv_flow_table_create(&cfg);
    CHECK(table != NULL, "create flow table");

    /* Flow 1: two TCP packets, same 5-tuple. */
    size_t n1 = pcv_build_ipv4_frame(buf, sizeof(buf), 6,
                                     0x0A000001, 0x0A000002, 1234, 80, 0x10, 10);
    pcv_packet f1a = make_packet(buf, (uint32_t)n1, 1000ULL * 1000000ULL);
    CHECK(pcv_flow_update(table, &f1a) == 0, "update flow 1 (packet a)");

    uint8_t buf2[256];
    size_t n1b = pcv_build_ipv4_frame(buf2, sizeof(buf2), 6,
                                      0x0A000001, 0x0A000002, 1234, 80, 0x18, 40);
    pcv_packet f1b = make_packet(buf2, (uint32_t)n1b, 2000ULL * 1000000ULL);
    CHECK(pcv_flow_update(table, &f1b) == 0, "update flow 1 (packet b)");

    /* Flow 2: different destination port. */
    uint8_t buf3[256];
    size_t n2 = pcv_build_ipv4_frame(buf3, sizeof(buf3), 6,
                                     0x0A000001, 0x0A000002, 1234, 443, 0x02, 0);
    pcv_packet f2 = make_packet(buf3, (uint32_t)n2, 2500ULL * 1000000ULL);
    CHECK(pcv_flow_update(table, &f2) == 0, "update flow 2");

    /* Flow 3: a UDP flow. */
    uint8_t buf4[256];
    size_t n3 = pcv_build_ipv4_frame(buf4, sizeof(buf4), 17,
                                     0x0A000001, 0x08080808, 5000, 53, 0, 20);
    pcv_packet f3 = make_packet(buf4, (uint32_t)n3, 2600ULL * 1000000ULL);
    CHECK(pcv_flow_update(table, &f3) == 0, "update flow 3 (UDP)");

    /* Look up flow 1 and verify aggregated counters. */
    pcv_flow_key k1;
    CHECK(pcv_flow_extract_key(&f1a, &k1) == 0, "re-extract flow 1 key");
    pcv_flow_stats* s1 = pcv_flow_lookup(table, &k1);
    CHECK(s1 != NULL, "lookup flow 1");
    if (s1) {
        CHECK_EQ_U64(s1->packet_count, 2, "flow 1 packet count");
        CHECK_EQ_U64(s1->byte_count, f1a.captured_length + f1b.captured_length,
                     "flow 1 byte count");
        CHECK(s1->first_seen_ns == f1a.timestamp_ns, "flow 1 first_seen");
        CHECK(s1->last_seen_ns == f1b.timestamp_ns, "flow 1 last_seen");
    }

    /* Three distinct flows should exist. */
    {
        iter_ctx ic = {0, 0};
        int it = pcv_flow_iterate(table, count_cb, &ic);
        CHECK_EQ_U64(it, 3, "iterate reports 3 flows");
        CHECK_EQ_U64(ic.total, 3, "callback visited 3 flows");
        CHECK_EQ_U64(ic.expired, 0, "no flows expired yet");
    }

    /* Expire with a timestamp far in the future -> all active flows time out. */
    {
        uint64_t future = 10000ULL * 1000000000ULL;  /* 10000s in ns */
        int expired = pcv_flow_expire_old(table, future);
        CHECK(expired == 3, "expire_old marked all 3 flows");

        iter_ctx ic = {0, 0};
        pcv_flow_iterate(table, count_cb, &ic);
        CHECK_EQ_U64(ic.expired, 3, "all flows now flagged TIMEOUT");
    }

    pcv_flow_table_destroy(table);

    return pcv_test_summary("test_flow");
}
