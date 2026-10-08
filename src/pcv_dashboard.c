/* PacketVelocity live dashboard - control, sampling, and serialization.
 *
 * Everything here runs OFF the per-packet hot path: creation/teardown, the
 * sampler's rate math, and the pure JSON serializer. The hot path lives in
 * src/pcv_dash_hot.c. These functions may allocate and may take the BLOCKING
 * agg->mtx (they run on the sampler / HTTP / main threads, never on capture's
 * per-packet path, so waiting here never causes drops).
 *
 * agg->mtx discipline: the capture thread publishes the flow snapshot with a
 * non-blocking trylock (src/pcv_dash_hot.c). The sampler (ring writer) and the
 * HTTP thread (reader) take the blocking lock, but HOLD it only for a bounded
 * in-memory copy - the HTTP thread copies the ring + published snapshot into a
 * local buffer, RELEASES the lock, and ONLY THEN formats JSON, so a slow socket
 * client can never hold the lock across a send().
 */

#ifdef __linux__
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif

#include "pcv_dashboard_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

/* ---- Create / destroy ---------------------------------------------------- */

pcv_dash_agg* pcv_dash_create(uint32_t serve_max_flows,
                              uint32_t serve_hash_buckets,
                              uint32_t topn) {
    pcv_dash_agg* agg = calloc(1, sizeof(*agg));
    if (!agg) {
        return NULL;
    }

    if (pthread_mutex_init(&agg->mtx, NULL) != 0) {
        free(agg);
        return NULL;
    }

    pcv_flow_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.max_flows        = serve_max_flows   ? serve_max_flows   : PCV_DASH_DEFAULT_MAX_FLOWS;
    cfg.hash_buckets     = serve_hash_buckets ? serve_hash_buckets : PCV_DASH_DEFAULT_HASH_BUCKETS;
    cfg.flow_timeout_ms  = 30000;   /* 30s active-flow timeout */
    cfg.cleanup_interval = 100000;  /* periodic expiry sweep */
    cfg.enable_tcp_state = true;

    agg->flows = pcv_flow_table_create(&cfg);
    if (!agg->flows) {
        pthread_mutex_destroy(&agg->mtx);
        free(agg);
        return NULL;
    }

    agg->topn = (topn == 0 || topn > PCV_DASH_TOPN) ? PCV_DASH_TOPN : topn;
    agg->last_snap_ns = 0;
    agg->have_prev = 0;
    return agg;
}

void pcv_dash_destroy(pcv_dash_agg* agg) {
    if (!agg) {
        return;
    }
    if (agg->flows) {
        pcv_flow_table_destroy(agg->flows);
    }
    pthread_mutex_destroy(&agg->mtx);
    free(agg);
}

/* ---- Test / shutdown seam: deterministic snapshot ------------------------
 * Runs on the capture (or test) thread. Builds into scratch via the hot-path
 * builder, then publishes under a BLOCKING lock so the publish is guaranteed
 * (unlike the per-packet trylock, which may skip under contention). This is NOT
 * the per-packet path, so a blocking lock here is fine. */
void pcv_dash_force_snapshot(pcv_dash_agg* agg) {
    if (!agg) {
        return;
    }
    pcv_dash_build_topn(agg);
    pthread_mutex_lock(&agg->mtx);
    agg->published = agg->scratch;
    pthread_mutex_unlock(&agg->mtx);
}

/* ---- Sampler: dt-based rate + 32-bit-wrap drop math ---------------------- */

void pcv_dash_sample_with_stats(pcv_dash_agg* agg,
                                uint64_t recv, uint64_t dropped,
                                uint64_t now_ns) {
    if (!agg) {
        return;
    }

    /* Read the capture-thread atomics (relaxed; a poll-late value is harmless).*/
    uint64_t pkts  = atomic_load_explicit(&agg->pkts, memory_order_relaxed);
    uint64_t bytes = atomic_load_explicit(&agg->bytes, memory_order_relaxed);

    pcv_dash_sample smp;
    memset(&smp, 0, sizeof(smp));
    smp.t_ns = now_ns;

    if (!agg->have_prev) {
        /* FIRST sample: no previous reading, so emit zeros - never a spike. */
        smp.pps = 0.0;
        smp.mbit = 0.0;
        smp.recv_delta = 0;
        smp.drop_delta = 0;
        smp.drop_rate = 0.0;
    } else {
        uint64_t dt = now_ns - agg->prev_ns;
        if (dt == 0) {
            /* Zero-dt tick: do not divide; report 0 and re-anchor below. */
            smp.pps = 0.0;
            smp.mbit = 0.0;
        } else {
            uint64_t pkts_delta  = pkts - agg->prev_pkts;   /* uint64, monotonic */
            uint64_t bytes_delta = bytes - agg->prev_bytes;
            /* pps = pkts_delta / (dt seconds); Mbit/s = bytes*8 / (dt * 1e6). */
            smp.pps  = (double)pkts_delta * 1e9 / (double)dt;
            smp.mbit = (double)bytes_delta * 8.0 * 1000.0 / (double)dt;
        }
        /* recv/drop deltas modulo 2^32: the kernel's bs_recv/bs_drop are u_int,
         * widened to uint64 AFTER wrapping, so a mask subtraction recovers the
         * true per-interval delta across a single 32-bit wrap. */
        smp.recv_delta = (uint32_t)((uint32_t)recv - (uint32_t)agg->prev_recv);
        smp.drop_delta = (uint32_t)((uint32_t)dropped - (uint32_t)agg->prev_dropped);
        uint64_t denom = (uint64_t)smp.recv_delta + (uint64_t)smp.drop_delta;
        smp.drop_rate = denom ? (double)smp.drop_delta / (double)denom : 0.0;
    }

    /* Publish the sample into the ring and update cumulative stats (under mtx:
     * the HTTP reader may be snapshotting concurrently). */
    pthread_mutex_lock(&agg->mtx);
    agg->ring[agg->ring_head] = smp;
    agg->ring_head = (agg->ring_head + 1u) % PCV_DASH_RING_CAP;
    if (agg->ring_len < PCV_DASH_RING_CAP) {
        agg->ring_len++;
    }
    agg->cum_recv = recv;
    agg->cum_dropped = dropped;
    pthread_mutex_unlock(&agg->mtx);

    /* Advance the previous reading (sampler-thread-only; no lock). Done even on
     * an idle / zero-dt tick so the next tick reports a true rate, never a
     * stale rate or a double-count spike. */
    agg->prev_pkts    = pkts;
    agg->prev_bytes   = bytes;
    agg->prev_ns      = now_ns;
    agg->prev_recv    = recv;
    agg->prev_dropped = dropped;
    agg->have_prev    = 1;
}

/* ---- Pure JSON serializer ------------------------------------------------ */

/* Append a JSON string value with the few escapes our content can produce. The
 * flow 5-tuple strings come from pcv_flow_key_v6_to_string (IPs, ports, "->",
 * brackets) - no control chars, but we escape '"' and '\\' defensively. */
static size_t json_escape(const char* in, char* out, size_t out_size) {
    size_t o = 0;
    for (size_t i = 0; in[i] != '\0'; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') {
            if (o + 2 >= out_size) break;
            out[o++] = '\\';
            out[o++] = (char)c;
        } else if (c < 0x20) {
            if (o + 1 >= out_size) break;
            out[o++] = ' ';
        } else {
            if (o + 1 >= out_size) break;
            out[o++] = (char)c;
        }
    }
    if (o < out_size) {
        out[o] = '\0';
    } else if (out_size > 0) {
        out[out_size - 1] = '\0';
    }
    return o;
}

size_t pcv_dash_snapshot_json(pcv_dash_agg* agg, char* buf, size_t size) {
    if (!agg || !buf || size == 0) {
        return 0;
    }

    /* Read the atomics (relaxed). */
    uint64_t pkts  = atomic_load_explicit(&agg->pkts, memory_order_relaxed);
    uint64_t bytes = atomic_load_explicit(&agg->bytes, memory_order_relaxed);
    uint64_t proto[PCV_PROTO_COUNT];
    uint64_t proto_total = 0;
    for (int i = 0; i < PCV_PROTO_COUNT; i++) {
        proto[i] = atomic_load_explicit(&agg->proto[i], memory_order_relaxed);
        proto_total += proto[i];
    }

    /* Copy the ring + published flow snapshot + cumulative stats into locals
     * under the lock, then RELEASE before any formatting (netdebug Snapshot()
     * pattern). The lock is held only for fixed-size struct copies. */
    static _Thread_local pcv_dash_flow_snap flows_local;
    static _Thread_local pcv_dash_sample ring_local[PCV_DASH_RING_CAP];
    uint32_t ring_n;
    uint32_t ring_start;
    uint64_t cum_recv, cum_dropped;

    pthread_mutex_lock(&agg->mtx);
    flows_local = agg->published;
    ring_n = agg->ring_len;
    ring_start = (agg->ring_head + PCV_DASH_RING_CAP - agg->ring_len) % PCV_DASH_RING_CAP;
    for (uint32_t i = 0; i < ring_n; i++) {
        ring_local[i] = agg->ring[(ring_start + i) % PCV_DASH_RING_CAP];
    }
    cum_recv = agg->cum_recv;
    cum_dropped = agg->cum_dropped;
    pthread_mutex_unlock(&agg->mtx);

    /* Latest sample drives the headline capture-health numbers. */
    double last_pps = 0.0, last_mbit = 0.0, last_drop_rate = 0.0;
    if (ring_n > 0) {
        last_pps = ring_local[ring_n - 1].pps;
        last_mbit = ring_local[ring_n - 1].mbit;
        last_drop_rate = ring_local[ring_n - 1].drop_rate;
    }
    double cum_drop_ratio = (cum_recv + cum_dropped)
        ? (double)cum_dropped / (double)(cum_recv + cum_dropped) : 0.0;

    size_t o = 0;
    int n;

#define EMIT(...)                                                        \
    do {                                                                 \
        if (o >= size) goto done;                                        \
        n = snprintf(buf + o, size - o, __VA_ARGS__);                    \
        if (n < 0) goto done;                                            \
        o += (size_t)n;                                                  \
        if (o >= size) { o = size - 1; goto done; }                      \
    } while (0)

    EMIT("{\"pkts\":%" PRIu64 ",\"bytes\":%" PRIu64 ",", pkts, bytes);
    EMIT("\"proto\":{\"tcp\":%" PRIu64 ",\"udp\":%" PRIu64 ",\"icmp\":%" PRIu64
         ",\"arp\":%" PRIu64 ",\"ipv6\":%" PRIu64 ",\"other\":%" PRIu64 "},",
         proto[PCV_PROTO_TCP], proto[PCV_PROTO_UDP], proto[PCV_PROTO_ICMP],
         proto[PCV_PROTO_ARP], proto[PCV_PROTO_IPV6], proto[PCV_PROTO_OTHER]);
    EMIT("\"proto_total\":%" PRIu64 ",", proto_total);

    EMIT("\"capture\":{\"recv\":%" PRIu64 ",\"dropped\":%" PRIu64
         ",\"drop_ratio\":%.6f,\"pps\":%.2f,\"mbit\":%.4f,\"drop_rate\":%.6f},",
         cum_recv, cum_dropped, cum_drop_ratio, last_pps, last_mbit, last_drop_rate);

    /* Rolling history for the sparkline. */
    EMIT("\"history\":[");
    for (uint32_t i = 0; i < ring_n; i++) {
        const pcv_dash_sample* s = &ring_local[i];
        EMIT("%s{\"t\":%" PRIu64 ",\"pps\":%.2f,\"mbit\":%.4f,\"drop_rate\":%.6f,"
             "\"recv_delta\":%u,\"drop_delta\":%u}",
             (i == 0) ? "" : ",", s->t_ns, s->pps, s->mbit, s->drop_rate,
             s->recv_delta, s->drop_delta);
    }
    EMIT("],");

    /* Top-N live flows ([] never null). */
    EMIT("\"flows\":[");
    uint32_t fcount = flows_local.count;
    if (fcount > agg->topn) {
        fcount = agg->topn;
    }
    for (uint32_t i = 0; i < fcount; i++) {
        const pcv_dash_flow_row* r = &flows_local.rows[i];
        char tuple[128];
        char esc[160];
        pcv_flow_key_v6_to_string(&r->key, tuple, sizeof(tuple));
        json_escape(tuple, esc, sizeof(esc));
        EMIT("%s{\"tuple\":\"%s\",\"packets\":%" PRIu64 ",\"bytes\":%" PRIu64
             ",\"tcp_flags\":%u,\"duration_ms\":%.3f}",
             (i == 0) ? "" : ",", esc, r->packet_count, r->byte_count,
             (unsigned)r->tcp_flags, (double)r->duration_ns / 1e6);
    }
    EMIT("]}");

#undef EMIT
done:
    if (o >= size) {
        o = size - 1;
    }
    buf[o] = '\0';
    return o;
}
