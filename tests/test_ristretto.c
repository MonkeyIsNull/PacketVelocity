/* Offline RistrettoDB V2 sink test (opt-in, built only under RISTRETTO=1).
 *
 * Replays synthetic packets - including at least one IPv6 flow - through the
 * RistrettoDB output backend (pcv_output_packet) into a temporary V2 table
 * file, then reads the rows back with the V2 read API (table_open + select)
 * and asserts:
 *   - the row count matches the number of IP packets replayed,
 *   - the IPv6 source/destination addresses round-trip EXACTLY as text,
 *   - ports, protocol, address family and length are stored correctly.
 *
 * Like the rest of the suite this runs WITHOUT root and WITHOUT live capture.
 */
/* Feature-test macros first: this file is compiled with strict -std=c11, and
 * glibc hides mkstemp/inet_pton/inet_ntop/getpid/unlink/close behind these
 * unless they are requested (macOS exposes them regardless). */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define RISTRETTO_NO_COMPATIBILITY_LAYER   /* only the prefixed ristretto_* API */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "pcv_output.h"
#include "pcv_flow.h"
#include "pcv_platform.h"
#include "pcap_replay.h"
#include "pcv_test.h"

#include "ristretto.h"

/* ---- Row collection for read-back verification ------------------------- */

typedef struct {
    int64_t ts_ns;
    char    src_ip[64];
    char    dst_ip[64];
    int64_t src_port;
    int64_t dst_port;
    int64_t protocol;
    int64_t addr_family;
    int64_t length;
    int64_t caplen;
} collected_row;

typedef struct {
    collected_row rows[32];
    int count;
} collected_rows;

/* table_select callback: copy each row out (select frees its TEXT values after
 * we return, so the strings must be copied, not aliased). */
static void collect_cb(void *ctx, const RistrettoValue *row) {
    collected_rows *c = (collected_rows *)ctx;
    if (c->count >= (int)(sizeof(c->rows) / sizeof(c->rows[0]))) return;

    collected_row *r = &c->rows[c->count++];
    r->ts_ns = row[0].value.integer;
    snprintf(r->src_ip, sizeof(r->src_ip), "%s",
             row[1].is_null ? "" : row[1].value.text.data);
    snprintf(r->dst_ip, sizeof(r->dst_ip), "%s",
             row[2].is_null ? "" : row[2].value.text.data);
    r->src_port    = row[3].value.integer;
    r->dst_port    = row[4].value.integer;
    r->protocol    = row[5].value.integer;
    r->addr_family = row[6].value.integer;
    r->length      = row[7].value.integer;
    r->caplen      = row[8].value.integer;
}

/* ---- Replay pipeline: feed each replayed packet to the sink ------------- */

static void sink_cb(const pcv_packet *packet, void *user) {
    pcv_output *out = (pcv_output *)user;
    pcv_output_packet(out, packet);
}

int main(void) {
    fprintf(stdout, "RistrettoDB V2 sink test\n");

    /* Build 3 synthetic frames: IPv4 TCP, IPv4 UDP, and an IPv6 TCP flow. */
    static uint8_t frames[3][256];
    size_t lens[3];

    lens[0] = pcv_build_ipv4_frame(frames[0], 256, 6,
                                   0x0A000001, 0x0A000002, 1234, 80, 0x02, 10);
    lens[1] = pcv_build_ipv4_frame(frames[1], 256, 17,
                                   0x0A000001, 0x08080808, 5000, 53, 0, 20);

    /* IPv6 flow: 2001:db8::1 -> 2001:db8::2, TCP 443 -> 51000. */
    uint8_t src6[16], dst6[16];
    CHECK(inet_pton(AF_INET6, "2001:db8::1", src6) == 1, "parse IPv6 src literal");
    CHECK(inet_pton(AF_INET6, "2001:db8::2", dst6) == 1, "parse IPv6 dst literal");
    lens[2] = pcv_build_ipv6_frame(frames[2], 256, 6,
                                   src6, dst6, 443, 51000, 0x02, 30);

    pcap_replay_packet pkts[3];
    for (int i = 0; i < 3; i++) {
        CHECK(lens[i] > 0, "build synthetic frame");
        pkts[i].data = frames[i];
        pkts[i].length = (uint32_t)lens[i];
        pkts[i].timestamp_ns = (uint64_t)(i + 1) * 1000000000ULL;
    }

    /* Temp pcap savefile. */
    char pcap_path[] = "/tmp/pcv_rist_pcap_XXXXXX";
    int fd = mkstemp(pcap_path);
    CHECK(fd >= 0, "create temp pcap path");
    if (fd >= 0) close(fd);
    CHECK(pcap_replay_write(pcap_path, pkts, 3) == 0, "write pcap savefile");

    /* Temp table target. The sink writes <base_dir>/<name>.rdb, so split the
     * known path the same way the backend does for read-back. */
    char table_name[64];
    snprintf(table_name, sizeof(table_name), "pcv_rist_tbl_%ld", (long)getpid());
    char target[128];
    snprintf(target, sizeof(target), "/tmp/%s", table_name);
    char rdb_path[160];
    snprintf(rdb_path, sizeof(rdb_path), "%s.rdb", target);

    /* Create the sink and replay packets through it. */
    pcv_output *out = pcv_output_create(PCV_OUTPUT_RISTRETTO, target);
    CHECK(out != NULL, "create RistrettoDB sink");

    if (out) {
        int n = pcap_replay_file(pcap_path, sink_cb, out);
        CHECK_EQ_U64(n, 3, "replayed packet count");

        uint64_t rows = 0, pkts_stat = 0, bytes = 0;
        pcv_output_get_stats(out, &rows, &pkts_stat, &bytes);
        CHECK_EQ_U64(rows, 3, "sink reports 3 rows written");

        pcv_output_destroy(out);   /* durable flush + close */
    }

    /* Read the rows back with the V2 read API. */
    RistrettoTable *t = ristretto_table_open_ex(table_name, "/tmp");
    CHECK(t != NULL, "reopen table for read-back");

    if (t) {
        CHECK_EQ_U64(ristretto_table_get_row_count(t), 3, "table holds 3 rows");

        collected_rows c;
        memset(&c, 0, sizeof(c));
        CHECK(ristretto_table_select(t, collect_cb, &c), "scan rows");
        CHECK_EQ_U64(c.count, 3, "scanned 3 rows");

        /* Row 0: IPv4 TCP 10.0.0.1:1234 -> 10.0.0.2:80 */
        if (c.count >= 1) {
            collected_row *r = &c.rows[0];
            CHECK(strcmp(r->src_ip, "10.0.0.1") == 0, "row0 IPv4 src round-trips");
            CHECK(strcmp(r->dst_ip, "10.0.0.2") == 0, "row0 IPv4 dst round-trips");
            CHECK_EQ_U64(r->src_port, 1234, "row0 src port");
            CHECK_EQ_U64(r->dst_port, 80, "row0 dst port");
            CHECK_EQ_U64(r->protocol, 6, "row0 protocol TCP");
            CHECK_EQ_U64(r->addr_family, 4, "row0 addr family IPv4");
            CHECK_EQ_U64(r->length, lens[0], "row0 length");
            CHECK_EQ_U64(r->ts_ns, 1000000000ULL, "row0 timestamp");
        }

        /* Row 1: IPv4 UDP 10.0.0.1:5000 -> 8.8.8.8:53 */
        if (c.count >= 2) {
            collected_row *r = &c.rows[1];
            CHECK(strcmp(r->dst_ip, "8.8.8.8") == 0, "row1 IPv4 dst round-trips");
            CHECK_EQ_U64(r->dst_port, 53, "row1 dst port");
            CHECK_EQ_U64(r->protocol, 17, "row1 protocol UDP");
            CHECK_EQ_U64(r->length, lens[1], "row1 length");
        }

        /* Row 2: IPv6 TCP - the exact round-trip the task requires. */
        if (c.count >= 3) {
            collected_row *r = &c.rows[2];
            CHECK(strcmp(r->src_ip, "2001:db8::1") == 0,
                  "row2 IPv6 src round-trips EXACTLY");
            CHECK(strcmp(r->dst_ip, "2001:db8::2") == 0,
                  "row2 IPv6 dst round-trips EXACTLY");
            CHECK_EQ_U64(r->src_port, 443, "row2 src port");
            CHECK_EQ_U64(r->dst_port, 51000, "row2 dst port");
            CHECK_EQ_U64(r->protocol, 6, "row2 protocol TCP");
            CHECK_EQ_U64(r->addr_family, 6, "row2 addr family IPv6");
            CHECK_EQ_U64(r->length, lens[2], "row2 length");
        }

        ristretto_table_close(t);
    }

    /* Cleanup temp files. */
    unlink(pcap_path);
    unlink(rdb_path);

    return pcv_test_summary("test_ristretto");
}
