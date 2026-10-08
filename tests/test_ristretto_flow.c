/* Offline RistrettoDB V2 per-FLOW sink test (opt-in, built only under
 * RISTRETTO=1).
 *
 * Replays multiple packets across 3 distinct flows - an IPv4 TCP flow (2
 * packets), an IPv4 UDP flow (1 packet) and an IPv6 TCP flow (2 packets) -
 * through the per-flow RistrettoDB sink, with a short flow timeout and
 * per-packet expiry sweep so that:
 *   - the two IPv4 flows are EVICTED (and emitted) DURING capture, once the
 *     later IPv6 packets advance the clock past the timeout, and
 *   - the IPv6 flow is still open at EOF and emitted by the shutdown flush.
 *
 * It then reads the "flows" rows back with the V2 read API and asserts:
 *   - exactly one row per flow (3 rows, no dupes, nothing dropped),
 *   - packet_count / byte_count are the exact per-flow sums,
 *   - first_ts_ns / last_ts_ns are correct,
 *   - the IPv6 5-tuple round-trips EXACTLY as text,
 *   - the tcp_flags union is accumulated.
 *
 * Runs WITHOUT root and WITHOUT live capture.
 */
/* Feature-test macros first (strict -std=c11; glibc hides
 * mkstemp/inet_pton/getpid/unlink/close behind these). */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define RISTRETTO_NO_COMPATIBILITY_LAYER   /* only the prefixed ristretto_* API */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "pcv_output_flow.h"
#include "pcv_flow.h"
#include "pcv_platform.h"
#include "pcap_replay.h"
#include "pcv_test.h"

#include "ristretto.h"

/* ---- Row collection for read-back verification ------------------------- */

typedef struct {
    char    src_ip[64];
    char    dst_ip[64];
    int64_t src_port;
    int64_t dst_port;
    int64_t protocol;
    int64_t addr_family;
    int64_t first_ts_ns;
    int64_t last_ts_ns;
    int64_t packet_count;
    int64_t byte_count;
    int64_t tcp_flags;
} collected_flow;

typedef struct {
    collected_flow rows[32];
    int count;
} collected_flows;

static void collect_cb(void *ctx, const RistrettoValue *row) {
    collected_flows *c = (collected_flows *)ctx;
    if (c->count >= (int)(sizeof(c->rows) / sizeof(c->rows[0]))) return;

    collected_flow *r = &c->rows[c->count++];
    snprintf(r->src_ip, sizeof(r->src_ip), "%s",
             row[0].is_null ? "" : row[0].value.text.data);
    snprintf(r->dst_ip, sizeof(r->dst_ip), "%s",
             row[1].is_null ? "" : row[1].value.text.data);
    r->src_port     = row[2].value.integer;
    r->dst_port     = row[3].value.integer;
    r->protocol     = row[4].value.integer;
    r->addr_family  = row[5].value.integer;
    r->first_ts_ns  = row[6].value.integer;
    r->last_ts_ns   = row[7].value.integer;
    r->packet_count = row[8].value.integer;
    r->byte_count   = row[9].value.integer;
    r->tcp_flags    = row[10].value.integer;
}

/* Find the nth (0-based) collected row matching a 5-tuple; NULL if absent. */
static const collected_flow *find_flow_n(const collected_flows *c, int n,
                                         const char *src_ip, const char *dst_ip,
                                         int64_t src_port, int64_t dst_port,
                                         int64_t protocol) {
    int seen = 0;
    for (int i = 0; i < c->count; i++) {
        const collected_flow *r = &c->rows[i];
        if (strcmp(r->src_ip, src_ip) == 0 && strcmp(r->dst_ip, dst_ip) == 0 &&
            r->src_port == src_port && r->dst_port == dst_port &&
            r->protocol == protocol) {
            if (seen++ == n) return r;
        }
    }
    return NULL;
}

/* First row matching a 5-tuple. */
static const collected_flow *find_flow(const collected_flows *c,
                                       const char *src_ip, const char *dst_ip,
                                       int64_t src_port, int64_t dst_port,
                                       int64_t protocol) {
    return find_flow_n(c, 0, src_ip, dst_ip, src_port, dst_port, protocol);
}

/* Count rows matching a 5-tuple. */
static int count_flow(const collected_flows *c,
                      const char *src_ip, const char *dst_ip,
                      int64_t src_port, int64_t dst_port, int64_t protocol) {
    int n = 0;
    for (int i = 0; i < c->count; i++) {
        const collected_flow *r = &c->rows[i];
        if (strcmp(r->src_ip, src_ip) == 0 && strcmp(r->dst_ip, dst_ip) == 0 &&
            r->src_port == src_port && r->dst_port == dst_port &&
            r->protocol == protocol) {
            n++;
        }
    }
    return n;
}

/* ---- Replay pipeline: feed each replayed packet to the flow sink -------- */

static void sink_cb(const pcv_packet *packet, void *user) {
    pcv_flow_output *out = (pcv_flow_output *)user;
    pcv_flow_output_update(out, packet);
}

int main(void) {
    fprintf(stdout, "RistrettoDB V2 per-flow sink test\n");

    /* 6 frames. Flows A/B/C are the 3 required distinct flows; the 6th packet
     * REUSES flow B's 5-tuple after B has already been evicted, to prove the
     * sink neither drops those packets silently nor double-counts them (it
     * starts a fresh B epoch that gets its own row). tcp_flags are chosen so
     * the TCP flows exercise the flag union (SYN|ACK = 0x12) without a FIN
     * (which would expire the flow early). */
    static uint8_t frames[6][256];
    size_t lens[6];

    /* Flow A: IPv4 TCP 10.0.0.1:1234 -> 10.0.0.2:80, two packets. */
    lens[0] = pcv_build_ipv4_frame(frames[0], 256, 6,
                                   0x0A000001, 0x0A000002, 1234, 80, 0x02, 10);
    lens[1] = pcv_build_ipv4_frame(frames[1], 256, 6,
                                   0x0A000001, 0x0A000002, 1234, 80, 0x10, 40);

    /* Flow B: IPv4 UDP 10.0.0.1:5000 -> 8.8.8.8:53, one packet. */
    lens[2] = pcv_build_ipv4_frame(frames[2], 256, 17,
                                   0x0A000001, 0x08080808, 5000, 53, 0, 20);

    /* Flow C: IPv6 TCP 2001:db8::1 -> 2001:db8::2, 443 -> 51000, two packets. */
    uint8_t src6[16], dst6[16];
    CHECK(inet_pton(AF_INET6, "2001:db8::1", src6) == 1, "parse IPv6 src literal");
    CHECK(inet_pton(AF_INET6, "2001:db8::2", dst6) == 1, "parse IPv6 dst literal");
    lens[3] = pcv_build_ipv6_frame(frames[3], 256, 6,
                                   src6, dst6, 443, 51000, 0x02, 30);
    lens[4] = pcv_build_ipv6_frame(frames[4], 256, 6,
                                   src6, dst6, 443, 51000, 0x10, 60);

    /* Flow B, second epoch: same 5-tuple as B, but a distinct payload size so
     * its byte_count differs from the first epoch's. */
    lens[5] = pcv_build_ipv4_frame(frames[5], 256, 17,
                                   0x0A000001, 0x08080808, 5000, 53, 0, 100);

    /* Timestamps (ns). The jump from 2s to 10s crosses the 2s flow timeout, so
     * the IPv4 flows expire when the first IPv6 packet advances the clock. The
     * 6th packet arrives after that eviction, reusing B's tuple. */
    uint64_t ts[6] = {
        1000000000ULL,   /* A pkt1 @ 1.0s */
        1100000000ULL,   /* A pkt2 @ 1.1s */
        2000000000ULL,   /* B pkt1 @ 2.0s */
        10000000000ULL,  /* C pkt1 @ 10.0s -> cleanup evicts A and B here */
        10100000000ULL,  /* C pkt2 @ 10.1s */
        10200000000ULL,  /* B-reuse @ 10.2s -> starts a fresh B epoch */
    };

    pcap_replay_packet pkts[6];
    for (int i = 0; i < 6; i++) {
        CHECK(lens[i] > 0, "build synthetic frame");
        pkts[i].data = frames[i];
        pkts[i].length = (uint32_t)lens[i];
        pkts[i].timestamp_ns = ts[i];
    }

    /* Temp pcap savefile. */
    char pcap_path[] = "/tmp/pcv_flow_pcap_XXXXXX";
    int fd = mkstemp(pcap_path);
    CHECK(fd >= 0, "create temp pcap path");
    if (fd >= 0) close(fd);
    CHECK(pcap_replay_write(pcap_path, pkts, 6) == 0, "write pcap savefile");

    /* Temp table target; split like the backend does for read-back. */
    char table_name[64];
    snprintf(table_name, sizeof(table_name), "pcv_flow_tbl_%ld", (long)getpid());
    char target[128];
    snprintf(target, sizeof(target), "/tmp/%s", table_name);
    char rdb_path[160];
    snprintf(rdb_path, sizeof(rdb_path), "%s.rdb", target);

    /* Create the flow sink with a short 2s timeout and a per-packet expiry
     * sweep (cleanup_interval = 1) so mid-capture eviction is deterministic. */
    pcv_flow_output *out =
        pcv_flow_output_create_ex(target, 2000 /*ms*/, 1 /*cleanup*/, 0, 0);
    CHECK(out != NULL, "create RistrettoDB flow sink");

    uint64_t expect_bytes_a  = (uint64_t)lens[0] + lens[1];
    uint64_t expect_bytes_b1 = (uint64_t)lens[2];   /* B epoch 1 */
    uint64_t expect_bytes_b2 = (uint64_t)lens[5];   /* B epoch 2 (reuse) */
    uint64_t expect_bytes_c  = (uint64_t)lens[3] + lens[4];

    if (out) {
        int n = pcap_replay_file(pcap_path, sink_cb, out);
        CHECK_EQ_U64(n, 6, "replayed packet count");

        uint64_t rows = 0, pkts_stat = 0, bytes = 0;
        pcv_flow_output_get_stats(out, &rows, &pkts_stat, &bytes);
        CHECK_EQ_U64(pkts_stat, 6, "sink aggregated 6 packets");
        CHECK_EQ_U64(bytes,
                     expect_bytes_a + expect_bytes_b1 + expect_bytes_b2 + expect_bytes_c,
                     "sink aggregated total bytes");
        /* A and B(epoch 1) were evicted during capture; C and B(epoch 2) are
         * still open here and emitted at shutdown. */
        CHECK_EQ_U64(rows, 2, "2 flow rows emitted via expiry during capture");

        pcv_flow_output_destroy(out);   /* shutdown flush emits C + B epoch2 */
    }

    /* Read the rows back with the V2 read API. */
    RistrettoTable *t = ristretto_table_open_ex(table_name, "/tmp");
    CHECK(t != NULL, "reopen flows table for read-back");

    if (t) {
        CHECK_EQ_U64(ristretto_table_get_row_count(t), 4,
                     "table holds exactly 4 flow rows (A, B-epoch1, C, B-epoch2)");

        collected_flows c;
        memset(&c, 0, sizeof(c));
        CHECK(ristretto_table_select(t, collect_cb, &c), "scan flow rows");
        CHECK_EQ_U64(c.count, 4, "scanned 4 flow rows");

        /* Flow A: IPv4 TCP, 2 packets, present exactly once (no dupes). */
        CHECK_EQ_U64(count_flow(&c, "10.0.0.1", "10.0.0.2", 1234, 80, 6), 1,
                     "flow A has exactly one row");
        const collected_flow *a =
            find_flow(&c, "10.0.0.1", "10.0.0.2", 1234, 80, 6);
        CHECK(a != NULL, "flow A present");
        if (a) {
            CHECK_EQ_U64(a->addr_family, 4, "flow A addr family IPv4");
            CHECK_EQ_U64(a->packet_count, 2, "flow A packet_count = 2");
            CHECK_EQ_U64(a->byte_count, expect_bytes_a, "flow A byte_count sum");
            CHECK_EQ_U64(a->first_ts_ns, ts[0], "flow A first_ts_ns");
            CHECK_EQ_U64(a->last_ts_ns, ts[1], "flow A last_ts_ns");
            CHECK_EQ_U64(a->tcp_flags, 0x12, "flow A tcp_flags union (SYN|ACK)");
        }

        /* Flow C: IPv6 TCP, 2 packets - exact 5-tuple round-trip, one row. */
        CHECK_EQ_U64(count_flow(&c, "2001:db8::1", "2001:db8::2", 443, 51000, 6), 1,
                     "flow C has exactly one row");
        const collected_flow *cc =
            find_flow(&c, "2001:db8::1", "2001:db8::2", 443, 51000, 6);
        CHECK(cc != NULL, "flow C (IPv6) present, 5-tuple round-trips");
        if (cc) {
            CHECK_EQ_U64(cc->addr_family, 6, "flow C addr family IPv6");
            CHECK_EQ_U64(cc->packet_count, 2, "flow C packet_count = 2");
            CHECK_EQ_U64(cc->byte_count, expect_bytes_c, "flow C byte_count sum");
            CHECK_EQ_U64(cc->first_ts_ns, ts[3], "flow C first_ts_ns");
            CHECK_EQ_U64(cc->last_ts_ns, ts[4], "flow C last_ts_ns");
            CHECK_EQ_U64(cc->tcp_flags, 0x12, "flow C tcp_flags union (SYN|ACK)");
        }

        /* Flow B: the reused 5-tuple must produce exactly TWO rows (one per
         * epoch) - no silent drop of the reuse, no merge/double-count. */
        CHECK_EQ_U64(count_flow(&c, "10.0.0.1", "8.8.8.8", 5000, 53, 17), 2,
                     "flow B tuple has exactly two rows (two epochs)");

        /* Identify the epochs by timestamp rather than row order. */
        const collected_flow *b0 =
            find_flow_n(&c, 0, "10.0.0.1", "8.8.8.8", 5000, 53, 17);
        const collected_flow *b1 =
            find_flow_n(&c, 1, "10.0.0.1", "8.8.8.8", 5000, 53, 17);
        const collected_flow *b_e1 = NULL, *b_e2 = NULL;
        if (b0 && b1) {
            b_e1 = (b0->first_ts_ns == (int64_t)ts[2]) ? b0 : b1;
            b_e2 = (b0->first_ts_ns == (int64_t)ts[5]) ? b0 : b1;
        }
        CHECK(b_e1 != NULL, "flow B epoch 1 present");
        if (b_e1) {
            CHECK_EQ_U64(b_e1->packet_count, 1, "flow B epoch1 packet_count = 1");
            CHECK_EQ_U64(b_e1->byte_count, expect_bytes_b1, "flow B epoch1 byte_count");
            CHECK_EQ_U64(b_e1->first_ts_ns, ts[2], "flow B epoch1 first_ts_ns");
            CHECK_EQ_U64(b_e1->last_ts_ns, ts[2], "flow B epoch1 last_ts_ns");
        }
        CHECK(b_e2 != NULL, "flow B epoch 2 (reuse) present");
        if (b_e2) {
            CHECK_EQ_U64(b_e2->packet_count, 1, "flow B epoch2 packet_count = 1");
            CHECK_EQ_U64(b_e2->byte_count, expect_bytes_b2, "flow B epoch2 byte_count");
            CHECK_EQ_U64(b_e2->first_ts_ns, ts[5], "flow B epoch2 first_ts_ns");
            CHECK_EQ_U64(b_e2->last_ts_ns, ts[5], "flow B epoch2 last_ts_ns");
        }

        ristretto_table_close(t);
    }

    unlink(pcap_path);
    unlink(rdb_path);

    return pcv_test_summary("test_ristretto_flow");
}
