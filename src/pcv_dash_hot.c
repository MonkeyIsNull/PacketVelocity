/* PacketVelocity live dashboard - THE HOT PATH.
 *
 * This translation unit holds ONLY work that runs on the capture thread, once
 * per accepted packet. It is deliberately isolated so the drop-safety structural
 * guard (tests/test_dashboard_safety.c) can scan the WHOLE file and prove the
 * hot path contains none of: printf / fprintf / write / malloc / calloc /
 * realloc / free / socket / pcv_get_stats / a BLOCKING pthread_mutex_lock.
 *
 * The ONLY synchronization primitive used here is a NON-BLOCKING
 * pthread_mutex_trylock when publishing the <=1 Hz flow snapshot: the capture
 * thread never waits on it. If the HTTP/sampler thread momentarily holds the
 * lock, the capture thread simply keeps the previous published snapshot and
 * moves on - it is wait-free, so serving can never slow capture or cause drops.
 *
 * Per-packet cost: a bounds-checked protocol classify (~4 byte reads), three
 * relaxed atomic adds, one flow-table update, and ONE 64-bit integer compare
 * (the time gate). The top-N build + publish runs at most ~1/sec, between
 * read()s, on the capture thread.
 */

#include "pcv_dashboard_internal.h"

#include <string.h>

/* ---- TOTAL, bounds-checked L3/L4 protocol classifier ---------------------
 * Every packet lands in EXACTLY ONE bucket, so sum(proto[]) == total packets.
 * Standalone (not the flow parser) because ARP / non-IP frames are rejected by
 * pcv_flow_update_v6 anyway, and this is just a few byte reads - cheaper than
 * refactoring the flow API to also return a protocol. */
static pcv_proto_bucket dash_classify(const pcv_packet* p) {
    uint32_t caplen = p->captured_length;
    const uint8_t* d = p->data;

    if (caplen < 14u || d == NULL) {
        return PCV_PROTO_OTHER;               /* too short for an Ethernet header */
    }

    uint16_t ethertype = (uint16_t)((d[12] << 8) | d[13]);
    switch (ethertype) {
    case 0x0806:
        return PCV_PROTO_ARP;
    case 0x0800:
        /* IPv4: protocol byte is at Ethernet(14) + IPv4 offset 9 = index 23. */
        if (caplen < 24u) {
            return PCV_PROTO_OTHER;            /* short IPv4 -> OTHER (still counted) */
        }
        switch (d[23]) {
        case 6:  return PCV_PROTO_TCP;
        case 17: return PCV_PROTO_UDP;
        case 1:  return PCV_PROTO_ICMP;
        default: return PCV_PROTO_OTHER;
        }
    case 0x86DD:
        return PCV_PROTO_IPV6;                 /* single bucket for the MVP */
    default:
        /* Includes 0x8100 VLAN and everything else. */
        return PCV_PROTO_OTHER;
    }
}

/* ---- Top-N ACTIVE-flow selection into agg->scratch (capture thread only) --
 * Bounded insertion into a fixed-size array ranked by packet_count (ties by
 * byte_count). SKIPS non-ACTIVE slots so the "top ACTIVE flows" panel never
 * ranks long-dead heavy hitters (pcv_flow_expire_old retains historical counts
 * without compacting flows[]). Examines at most PCV_DASH_MAX_SCAN entries. No
 * allocation (scratch is pre-sized); no lock. */
void pcv_dash_build_topn(struct pcv_dash_agg* agg) {
    pcv_dash_flow_snap* s = &agg->scratch;
    s->count = 0;

    pcv_flow_table* t = agg->flows;
    if (t == NULL) {
        return;
    }

    uint32_t topn = agg->topn;
    if (topn > PCV_DASH_TOPN) {
        topn = PCV_DASH_TOPN;
    }

    uint32_t scanned = 0;
    uint32_t total = t->flow_count;
    for (uint32_t i = 0; i < total && scanned < PCV_DASH_MAX_SCAN; i++) {
        const pcv_flow_stats* f = &t->flows[i];
        scanned++;

        if (!(f->flow_state & PCV_FLOW_ACTIVE)) {
            continue;                          /* only live flows */
        }

        /* Find the insertion point (array is kept sorted, high -> low). */
        uint32_t n = s->count;
        if (n == topn) {
            /* Full: skip anything that cannot beat the current tail. */
            const pcv_dash_flow_row* tail = &s->rows[n - 1];
            if (f->packet_count < tail->packet_count ||
                (f->packet_count == tail->packet_count &&
                 f->byte_count <= tail->byte_count)) {
                continue;
            }
        }

        uint32_t pos = n;
        while (pos > 0) {
            const pcv_dash_flow_row* prev = &s->rows[pos - 1];
            if (f->packet_count > prev->packet_count ||
                (f->packet_count == prev->packet_count &&
                 f->byte_count > prev->byte_count)) {
                pos--;
            } else {
                break;
            }
        }

        /* Make room (shift down), bounded by topn. */
        uint32_t last = (n < topn) ? n : (topn - 1);
        for (uint32_t j = last; j > pos; j--) {
            s->rows[j] = s->rows[j - 1];
        }

        if (pos < topn) {
            pcv_dash_flow_row* dst = &s->rows[pos];
            dst->key          = f->key6;
            dst->packet_count = f->packet_count;
            dst->byte_count   = f->byte_count;
            dst->duration_ns  = f->duration_ns;
            dst->tcp_flags    = f->tcp_flags;
            if (n < topn) {
                s->count = n + 1;
            }
        }
    }
}

/* Publish agg->scratch to agg->published WITHOUT ever blocking the caller.
 * A non-blocking trylock: if the HTTP/sampler thread holds the lock right now,
 * we keep the previous published snapshot and return - capture is wait-free. */
static void dash_try_publish(struct pcv_dash_agg* agg) {
    if (pthread_mutex_trylock(&agg->mtx) == 0) {
        agg->published = agg->scratch;         /* fixed-size struct copy */
        pthread_mutex_unlock(&agg->mtx);
    }
}

/* THE per-packet hot hook. */
void pcv_dash_on_packet(pcv_dash_agg* agg, const pcv_packet* packet) {
    if (agg == NULL || packet == NULL) {
        return;
    }

    /* 1. TOTAL protocol classification -> exactly one bucket. */
    pcv_proto_bucket k = dash_classify(packet);

    /* 2. Three relaxed atomic adds (independent scalars; 64-bit aligned, cannot
     *    tear; a one-poll-late value is harmless, so no stronger ordering). */
    atomic_fetch_add_explicit(&agg->pkts, 1u, memory_order_relaxed);
    atomic_fetch_add_explicit(&agg->bytes, (uint64_t)packet->length,
                              memory_order_relaxed);
    atomic_fetch_add_explicit(&agg->proto[k], 1u, memory_order_relaxed);

    /* 3. Feed the existing flow tracker (capture owns the table). */
    pcv_flow_update_v6(agg->flows, packet);

    /* 4. Time-gated self-snapshot: ONE 64-bit integer compare per packet. The
     *    build + publish run at most ~1/sec, piggybacking the periodic slot the
     *    flow table's own cleanup already uses. Uses the free packet timestamp -
     *    no clock syscall on the hot path. */
    uint64_t now = packet->timestamp_ns;
    if (now - agg->last_snap_ns >= PCV_DASH_SNAP_INTERVAL_NS) {
        agg->last_snap_ns = now;
        pcv_dash_build_topn(agg);
        dash_try_publish(agg);
    }
}
