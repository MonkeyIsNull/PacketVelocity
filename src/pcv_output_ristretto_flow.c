/* =============================================================================
 * PacketVelocity per-FLOW RistrettoDB output backend (OPTIONAL, opt-in)
 * -----------------------------------------------------------------------------
 * Compiled ONLY when the tree is built with `make RISTRETTO=1`. The DEFAULT
 * build is hermetic and does NOT compile or link this file or any RistrettoDB
 * code. This is the per-FLOW counterpart to the per-PACKET sink in
 * src/pcv_output_ristretto.c; that file and the per-packet path are untouched.
 *
 * Where the per-packet sink appends one row per captured packet, this sink
 * writes ONE ROW PER NETWORK FLOW (a 5-tuple conversation). Aggregation reuses
 * PacketVelocity's existing flow tracking (src/pcv_flow.c): packets are fed to
 * one pcv_flow_table via pcv_flow_update_v6, and a row is emitted through the
 * table's expiry hook. No second, parallel flow table is built.
 *
 * LIFECYCLE (one row per flow, no drops, no double-counting):
 *   (1) During capture, pcv_flow_update_v6 runs pcv_flow's periodic cleanup,
 *       which marks timed-out / FIN'd flows and fires on_expire once per flow.
 *       emit_flow_cb appends that flow's row.
 *   (2) At shutdown (pcv_flow_output_destroy) we call pcv_flow_expire_old with a
 *       future timestamp, forcing every still-open flow through the same hook,
 *       so each is emitted exactly once before the table is closed.
 *
 * -----------------------------------------------------------------------------
 * SCHEMA (fixed-width; IPv6-friendly). V2 offers only INTEGER (8 bytes),
 * REAL (8 bytes) and TEXT(n) (n<=255, up to n-1 chars + NUL). Table name:
 * "flows". Every column is justified below.
 *
 *   -- 5-tuple key (identifies the conversation) --
 *   src_ip        TEXT(46)  source address, inet_ntop (AF_INET / AF_INET6).
 *                           TEXT so IPv6 / IPv4-mapped literals round-trip
 *                           exactly; 46 = INET6_ADDRSTRLEN.
 *   dst_ip        TEXT(46)  destination address, inet_ntop.
 *   src_port      INTEGER   L4 source port, host order (0 if no L4 ports).
 *   dst_port      INTEGER   L4 destination port, host order.
 *   protocol      INTEGER   IP protocol number (6=TCP, 17=UDP, ...).
 *   addr_family   INTEGER   4 (IPv4) or 6 (IPv6); disambiguates the address text.
 *   -- aggregates over the packets of this flow --
 *   first_ts_ns   INTEGER   timestamp (ns since epoch) of the first packet.
 *   last_ts_ns    INTEGER   timestamp (ns since epoch) of the last packet.
 *   packet_count  INTEGER   number of packets aggregated into this flow.
 *   byte_count    INTEGER   sum of captured_length over this flow's packets.
 *   tcp_flags     INTEGER   union (OR) of TCP flag bytes seen; pcv_flow already
 *                           tracks this, so it is surfaced rather than invented
 *                           (0 for non-TCP flows).
 * =============================================================================
 */
#define _POSIX_C_SOURCE 200809L           /* strdup, inet_ntop prototypes */
#define _DEFAULT_SOURCE                   /* glibc: inet_ntop under -std=c11 */
#define RISTRETTO_NO_COMPATIBILITY_LAYER  /* only the prefixed ristretto_* API */

#include "pcv_output_flow.h"
#include "pcv_flow.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include "ristretto.h"

/* Number of columns; must match PCV_FLOW_SCHEMA below. */
#define PCV_FLOW_NUM_COLS 11

/* Live-capture defaults (overridable via pcv_flow_output_create_ex). */
#define PCV_FLOW_DEFAULT_TIMEOUT_MS   60000u   /* evict a flow idle for 60s */
#define PCV_FLOW_DEFAULT_CLEANUP      256u     /* run expiry sweep every N pkts */
#define PCV_FLOW_DEFAULT_MAX_FLOWS    65536u
#define PCV_FLOW_DEFAULT_HASH_BUCKETS 131072u  /* > max_flows for linear probing */

/* INET6_ADDRSTRLEN is 46 on every supported platform; the schema string must
 * use a literal, so assert the assumption instead of silently diverging. */
#if INET6_ADDRSTRLEN > 46
#error "INET6_ADDRSTRLEN exceeds the src_ip/dst_ip TEXT(46) column width"
#endif

#define PCV_FLOW_SCHEMA \
    "CREATE TABLE flows (" \
    "src_ip TEXT(46), " \
    "dst_ip TEXT(46), " \
    "src_port INTEGER, " \
    "dst_port INTEGER, " \
    "protocol INTEGER, " \
    "addr_family INTEGER, " \
    "first_ts_ns INTEGER, " \
    "last_ts_ns INTEGER, " \
    "packet_count INTEGER, " \
    "byte_count INTEGER, " \
    "tcp_flags INTEGER)"

struct pcv_flow_output {
    RistrettoTable* table;    /* V2 "flows" table */
    pcv_flow_table* flows;    /* reused PV flow tracking (aggregation) */
    char* base_dir;           /* directory the .rdb file lives in */
    char* name;               /* table name (basename, no .rdb suffix) */
    uint64_t flows_written;   /* rows emitted */
    uint64_t insert_errors;   /* append failures */
    uint64_t seen_packets;    /* packets aggregated */
    uint64_t seen_bytes;      /* bytes aggregated */
};

/* Split a user target into (base_dir, name) the V2 library expects; it stores
 * the table at "<base_dir>/<name>.rdb". Mirrors the per-packet sink. A missing
 * directory becomes ".", and a trailing ".rdb" is stripped. Returns 0 on ok. */
static int split_target(const char* target, char** out_dir, char** out_name) {
    const char* slash = strrchr(target, '/');
    const char* base  = slash ? slash + 1 : target;
    size_t dirlen = slash ? (size_t)(slash - target) : 0;

    char* dir = malloc(dirlen ? dirlen + 1 : 2);
    if (!dir) return -1;
    if (dirlen) {
        memcpy(dir, target, dirlen);
        dir[dirlen] = '\0';
    } else {
        dir[0] = '.';
        dir[1] = '\0';
    }

    size_t namelen = strlen(base);
    const size_t extlen = 4;  /* ".rdb" */
    if (namelen > extlen && strcmp(base + namelen - extlen, ".rdb") == 0) {
        namelen -= extlen;
    }
    if (namelen == 0) {
        free(dir);
        return -1;
    }

    char* name = malloc(namelen + 1);
    if (!name) {
        free(dir);
        return -1;
    }
    memcpy(name, base, namelen);
    name[namelen] = '\0';

    *out_dir = dir;
    *out_name = name;
    return 0;
}

/* Expiry hook: append one row for an evicted flow. pcv_flow guarantees this
 * fires exactly once per flow (the ACTIVE bit is cleared before the call), so
 * rows are neither dropped nor double-counted. */
static void emit_flow_cb(const pcv_flow_stats* flow, void* user) {
    pcv_flow_output* out = (pcv_flow_output*)user;
    if (!out || !out->table) {
        return;
    }

    const pcv_flow_key_v6* key = &flow->key6;

    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    if (key->addr_family == PCV_ADDR_IPV6) {
        inet_ntop(AF_INET6, key->src_ip.ipv6, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET6, key->dst_ip.ipv6, dst_ip, sizeof(dst_ip));
    } else {
        inet_ntop(AF_INET, &key->src_ip.ipv4, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &key->dst_ip.ipv4, dst_ip, sizeof(dst_ip));
    }

    RistrettoValue v[PCV_FLOW_NUM_COLS];
    v[0]  = ristretto_value_text(src_ip);
    v[1]  = ristretto_value_text(dst_ip);
    v[2]  = ristretto_value_integer((int64_t)key->src_port);
    v[3]  = ristretto_value_integer((int64_t)key->dst_port);
    v[4]  = ristretto_value_integer((int64_t)key->protocol);
    v[5]  = ristretto_value_integer((int64_t)key->addr_family);
    v[6]  = ristretto_value_integer((int64_t)flow->first_seen_ns);
    v[7]  = ristretto_value_integer((int64_t)flow->last_seen_ns);
    v[8]  = ristretto_value_integer((int64_t)flow->packet_count);
    v[9]  = ristretto_value_integer((int64_t)flow->byte_count);
    v[10] = ristretto_value_integer((int64_t)flow->tcp_flags);

    bool ok = ristretto_table_append_row_n(out->table, v, PCV_FLOW_NUM_COLS);

    /* Only the TEXT values own heap memory. */
    ristretto_value_destroy(&v[0]);
    ristretto_value_destroy(&v[1]);

    if (!ok) {
        out->insert_errors++;
        fprintf(stderr, "pcv_output: failed to append flow row\n");
        return;
    }
    out->flows_written++;
}

pcv_flow_output* pcv_flow_output_create_ex(const char* target,
                                           uint64_t flow_timeout_ms,
                                           uint32_t cleanup_interval,
                                           uint32_t max_flows,
                                           uint32_t hash_buckets) {
    if (!target || !*target) {
        target = "flows";
    }

    pcv_flow_output* out = calloc(1, sizeof(pcv_flow_output));
    if (!out) {
        return NULL;
    }

    if (split_target(target, &out->base_dir, &out->name) != 0) {
        fprintf(stderr, "pcv_output: invalid RistrettoDB flow target '%s'\n", target);
        free(out);
        return NULL;
    }

    /* Flow tracking table (reused pcv_flow.c aggregation). */
    pcv_flow_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.max_flows        = max_flows      ? max_flows      : PCV_FLOW_DEFAULT_MAX_FLOWS;
    cfg.hash_buckets     = hash_buckets   ? hash_buckets   : PCV_FLOW_DEFAULT_HASH_BUCKETS;
    cfg.flow_timeout_ms  = flow_timeout_ms? flow_timeout_ms: PCV_FLOW_DEFAULT_TIMEOUT_MS;
    cfg.cleanup_interval = cleanup_interval ? cleanup_interval : PCV_FLOW_DEFAULT_CLEANUP;
    cfg.enable_tcp_state = true;

    out->flows = pcv_flow_table_create(&cfg);
    if (!out->flows) {
        fprintf(stderr, "pcv_output: failed to create flow tracking table\n");
        free(out->base_dir);
        free(out->name);
        free(out);
        return NULL;
    }
    pcv_flow_table_set_expire_cb(out->flows, emit_flow_cb, out);

    out->table = ristretto_table_create_ex(out->name, PCV_FLOW_SCHEMA,
                                           out->base_dir,
                                           RISTRETTO_CREATE_OR_TRUNCATE);
    if (!out->table) {
        fprintf(stderr,
                "pcv_output: failed to create RistrettoDB table '%s/%s.rdb'\n",
                out->base_dir, out->name);
        pcv_flow_table_destroy(out->flows);
        free(out->base_dir);
        free(out->name);
        free(out);
        return NULL;
    }

    fprintf(stderr, "pcv_output: writing flows to RistrettoDB table %s/%s.rdb\n",
            out->base_dir, out->name);
    return out;
}

pcv_flow_output* pcv_flow_output_create(const char* target) {
    return pcv_flow_output_create_ex(target, 0, 0, 0, 0);
}

int pcv_flow_output_update(pcv_flow_output* out, const pcv_packet* packet) {
    if (!out || !packet) {
        return -1;
    }
    /* Non-IP / unparseable packets are skipped without erroring. */
    if (pcv_flow_update_v6(out->flows, packet) != 0) {
        return 0;
    }
    out->seen_packets++;
    out->seen_bytes += packet->captured_length;
    return 0;
}

void pcv_flow_output_destroy(pcv_flow_output* out) {
    if (!out) {
        return;
    }

    /* Final flush: force every still-open flow through the expiry hook so it is
     * emitted exactly once. Must happen BEFORE the table is closed. */
    if (out->flows) {
        pcv_flow_expire_old(out->flows, UINT64_MAX);
        pcv_flow_table_destroy(out->flows);
        out->flows = NULL;
    }

    if (out->table) {
        ristretto_table_flush_durable(out->table);
        ristretto_table_close(out->table);
        out->table = NULL;
    }

    fprintf(stderr,
            "pcv_output: wrote %" PRIu64 " flow rows (%" PRIu64 " errors) to %s/%s.rdb\n",
            out->flows_written, out->insert_errors,
            out->base_dir ? out->base_dir : "?",
            out->name ? out->name : "?");

    free(out->base_dir);
    free(out->name);
    free(out);
}

void pcv_flow_output_get_stats(const pcv_flow_output* out, uint64_t* flows,
                               uint64_t* packets, uint64_t* bytes) {
    if (!out) {
        return;
    }
    if (flows)   *flows   = out->flows_written;
    if (packets) *packets = out->seen_packets;
    if (bytes)   *bytes   = out->seen_bytes;
}
