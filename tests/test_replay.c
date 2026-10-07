/* Offline capture-pipeline test.
 *
 * Drives the capture -> filter -> flow pipeline WITHOUT root and WITHOUT live
 * sniffing: synthetic Ethernet/IPv4 frames are written to a pcap savefile, then
 * replayed through a VFM/VFLisp filter and the flow aggregator - exactly the
 * work the live callback does, minus the OS capture.
 *
 * If a pcap path is given on the command line, that file is replayed and its
 * packet/accept/drop counts are printed (a genuine replay harness usable with
 * captured sample traffic); with no argument a synthetic trace is generated and
 * self-checked.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pcv_filter.h"
#include "pcv_flow.h"
#include "pcv_platform.h"
#include "pcap_replay.h"
#include "pcv_test.h"
#include "vflisp_types.h"

/* Downstream pipeline state (mirrors the live callback_context). */
typedef struct {
    pcv_filter* filter;
    pcv_flow_table* flows;
    uint64_t seen;
    uint64_t accepted;
    uint64_t dropped;
} pipeline_ctx;

/* Same shape and logic as pcv_main.c's packet_callback: filter, then account. */
static void pipeline_cb(const pcv_packet* packet, void* user) {
    pipeline_ctx* ctx = (pipeline_ctx*)user;
    ctx->seen++;

    pcv_filter_decision decision = PCV_FILTER_ACCEPT;
    if (ctx->filter) {
        decision = pcv_filter_apply(ctx->filter, packet->data,
                                    packet->captured_length);
    }

    if (decision == PCV_FILTER_ACCEPT) {
        ctx->accepted++;
        if (ctx->flows) {
            pcv_flow_update(ctx->flows, packet);
        }
    } else {
        ctx->dropped++;
    }
}

/* Build the VFLisp filter expression into a VFM filter. */
static pcv_filter* build_filter(const char* expr) {
    uint8_t* bytecode = NULL;
    uint32_t size = 0;
    char err[256];

    int rc = vfl_compile_string(expr, &bytecode, &size, err, sizeof(err));
    if (rc < 0 || !bytecode || size == 0) {
        fprintf(stderr, "  VFLisp compile failed for '%s': %s\n", expr, err);
        return NULL;
    }

    pcv_filter* f = pcv_filter_create(PCV_FILTER_VFM, bytecode, size);
    free(bytecode);
    return f;
}

static int run_synthetic(void) {
    fprintf(stdout, "offline replay pipeline tests\n");

    /* Build a synthetic trace: 3 TCP packets across 2 flows, 2 UDP packets. */
    static uint8_t frames[5][256];
    size_t lens[5];

    lens[0] = pcv_build_ipv4_frame(frames[0], 256, 6,
                                   0x0A000001, 0x0A000002, 1234, 80, 0x02, 0);
    lens[1] = pcv_build_ipv4_frame(frames[1], 256, 6,
                                   0x0A000001, 0x0A000002, 1234, 80, 0x10, 60);
    lens[2] = pcv_build_ipv4_frame(frames[2], 256, 6,
                                   0x0A000001, 0x0A000002, 1235, 443, 0x02, 0);
    lens[3] = pcv_build_ipv4_frame(frames[3], 256, 17,
                                   0x0A000001, 0x08080808, 5000, 53, 0, 20);
    lens[4] = pcv_build_ipv4_frame(frames[4], 256, 17,
                                   0x0A000001, 0x08080808, 5001, 53, 0, 24);

    pcap_replay_packet pkts[5];
    for (int i = 0; i < 5; i++) {
        CHECK(lens[i] > 0, "build synthetic frame");
        pkts[i].data = frames[i];
        pkts[i].length = (uint32_t)lens[i];
        pkts[i].timestamp_ns = (uint64_t)(i + 1) * 1000000000ULL;
    }

    /* Write to a temporary pcap savefile. */
    char path[] = "/tmp/pcv_replay_XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0, "create temp pcap path");
    if (fd >= 0) close(fd);

    CHECK(pcap_replay_write(path, pkts, 5) == 0, "write pcap savefile");

    /* Sanity: replay with NO filter sees all 5 packets. */
    {
        pipeline_ctx ctx;
        memset(&ctx, 0, sizeof(ctx));
        int n = pcap_replay_file(path, pipeline_cb, &ctx);
        CHECK_EQ_U64(n, 5, "replayed packet count (no filter)");
        CHECK_EQ_U64(ctx.seen, 5, "pipeline saw all packets");
        CHECK_EQ_U64(ctx.accepted, 5, "all accepted without a filter");
    }

    /* Replay through a "(= proto 6)" filter: only TCP should pass. */
    pcv_filter* tcp_filter = build_filter("(= proto 6)");
    CHECK(tcp_filter != NULL, "compile VFLisp filter (= proto 6)");

    if (tcp_filter) {
        pcv_flow_config cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.max_flows = 256;
        cfg.hash_buckets = 1024;
        cfg.flow_timeout_ms = 1000;
        cfg.cleanup_interval = 1000000;
        cfg.enable_tcp_state = true;

        pcv_flow_table* flows = pcv_flow_table_create(&cfg);
        CHECK(flows != NULL, "create flow table for pipeline");

        pipeline_ctx ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.filter = tcp_filter;
        ctx.flows = flows;

        int n = pcap_replay_file(path, pipeline_cb, &ctx);
        CHECK_EQ_U64(n, 5, "replayed packet count (TCP filter)");
        CHECK_EQ_U64(ctx.seen, 5, "pipeline saw all packets (TCP filter)");
        CHECK_EQ_U64(ctx.accepted, 3, "3 TCP packets accepted");
        CHECK_EQ_U64(ctx.dropped, 2, "2 UDP packets dropped");

        uint64_t processed = 0, accepted = 0, dropped = 0;
        pcv_filter_get_stats(tcp_filter, &processed, &accepted, &dropped);
        CHECK_EQ_U64(processed, 5, "filter processed all packets");
        CHECK_EQ_U64(accepted, 3, "filter accepted stat");

        /* Accepted TCP packets fall into 2 distinct 5-tuples -> 2 flows. */
        if (flows) {
            CHECK_EQ_U64(flows->flow_count, 2, "2 distinct TCP flows aggregated");
            pcv_flow_table_destroy(flows);
        }

        pcv_filter_destroy(tcp_filter);
    }

    unlink(path);
    return pcv_test_summary("test_replay");
}

static int run_file(const char* path) {
    pcv_filter* tcp_filter = build_filter("(= proto 6)");
    pipeline_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.filter = tcp_filter;

    int n = pcap_replay_file(path, pipeline_cb, &ctx);
    if (n < 0) {
        fprintf(stderr, "failed to replay pcap: %s\n", path);
        if (tcp_filter) pcv_filter_destroy(tcp_filter);
        return 1;
    }

    fprintf(stdout, "replayed %s: %d packets, %llu accepted (TCP), %llu dropped\n",
            path, n, (unsigned long long)ctx.accepted,
            (unsigned long long)ctx.dropped);

    if (tcp_filter) pcv_filter_destroy(tcp_filter);
    return 0;
}

int main(int argc, char** argv) {
    if (argc > 1) {
        return run_file(argv[1]);
    }
    return run_synthetic();
}
