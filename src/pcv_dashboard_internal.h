#ifndef PCV_DASHBOARD_INTERNAL_H
#define PCV_DASHBOARD_INTERNAL_H

/* Internal layout of pcv_dash_agg, shared ONLY between the dashboard
 * translation units (src/pcv_dashboard.c and the hot-path src/pcv_dash_hot.c).
 * It is intentionally NOT in the public header so callers keep the opaque type.
 */

#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include "pcv_dashboard.h"
#include "pcv_flow.h"

/* Maximum flows the live table reports and the publish buffers are sized for. */
#define PCV_DASH_TOPN       64u
/* Hard cap on flow-table entries examined per 1 Hz top-N build, so the scan can
 * never open a drop-inducing gap between capture read()s even on a full table. */
#define PCV_DASH_MAX_SCAN   16384u
/* Rate-ring capacity (samples of rolling pps/Mbit/drop history, ~1 Hz). */
#define PCV_DASH_RING_CAP   120u
/* Snapshot cadence on the capture thread (nanoseconds), gated by packet->timestamp_ns. */
#define PCV_DASH_SNAP_INTERVAL_NS 1000000000ULL

/* Modest defaults for the serve flow table (NOT the 65536 the ristretto-flow
 * sink uses): a smaller table bounds the once-per-second top-N scan. */
#define PCV_DASH_DEFAULT_MAX_FLOWS    8192u
#define PCV_DASH_DEFAULT_HASH_BUCKETS 16384u

/* One flow row in a published snapshot. The 5-tuple is kept as the raw key and
 * formatted to a string at serialize time (HTTP thread), NOT on the hot path. */
typedef struct {
    pcv_flow_key_v6 key;
    uint64_t packet_count;
    uint64_t byte_count;
    uint64_t duration_ns;
    uint8_t  tcp_flags;
} pcv_dash_flow_row;

/* A complete top-N snapshot (count + rows). Published as a unit under agg->mtx. */
typedef struct {
    uint32_t count;
    pcv_dash_flow_row rows[PCV_DASH_TOPN];
} pcv_dash_flow_snap;

/* One time-series sample pushed by the sampler, read by the HTTP serializer. */
typedef struct {
    uint64_t t_ns;
    double   pps;        /* accepted packets/sec over the interval */
    double   mbit;       /* wire megabits/sec over the interval */
    uint32_t recv_delta; /* interface packets received over the interval */
    uint32_t drop_delta; /* interface packets dropped over the interval */
    double   drop_rate;  /* drop_delta / (recv_delta + drop_delta), interval */
} pcv_dash_sample;

struct pcv_dash_agg {
    /* ---- Scalars: capture writes relaxed; sampler + HTTP read relaxed. ---- */
    _Atomic uint64_t pkts;                    /* accepted packets */
    _Atomic uint64_t bytes;                   /* wire bytes (packet->length) */
    _Atomic uint64_t proto[PCV_PROTO_COUNT];  /* per-protocol counts */

    /* ---- Flow tracking: the capture thread owns this table EXCLUSIVELY. ---- */
    pcv_flow_table* flows;
    uint32_t topn;                 /* rows reported (<= PCV_DASH_TOPN) */
    uint64_t last_snap_ns;         /* capture-thread only (time gate) */
    pcv_dash_flow_snap scratch;    /* capture-thread only build buffer */

    /* ---- Published state guarded by mtx. The capture thread publishes with a
     * NON-BLOCKING trylock (it never waits); the sampler and HTTP thread take a
     * blocking lock (they may wait, which never causes capture drops). ---- */
    pthread_mutex_t mtx;
    pcv_dash_flow_snap published;  /* last published top-N (under mtx) */

    /* Rate ring (under mtx): written by sampler, read by HTTP, NEVER by capture. */
    pcv_dash_sample ring[PCV_DASH_RING_CAP];
    uint32_t ring_head;            /* next write slot */
    uint32_t ring_len;             /* number of valid samples (<= cap) */
    uint64_t cum_recv;             /* latest cumulative interface recv */
    uint64_t cum_dropped;          /* latest cumulative interface drops */

    /* ---- Sampler-thread-only previous reading (no lock needed). ---- */
    uint64_t prev_pkts, prev_bytes, prev_ns;
    uint64_t prev_recv, prev_dropped;
    int      have_prev;
};

/* Build the top-N ACTIVE-flow snapshot into agg->scratch. Reads the
 * capture-owned flow table, so it MUST run on the capture thread (or the test
 * thread that drives on_packet). No lock, no allocation. Defined in
 * src/pcv_dash_hot.c; shared with force_snapshot in src/pcv_dashboard.c. */
void pcv_dash_build_topn(struct pcv_dash_agg* agg);

#endif /* PCV_DASHBOARD_INTERNAL_H */
