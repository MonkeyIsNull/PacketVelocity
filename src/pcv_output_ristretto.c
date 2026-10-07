/* =============================================================================
 * PacketVelocity RistrettoDB output backend (OPTIONAL, opt-in)
 * -----------------------------------------------------------------------------
 * This file is compiled ONLY when the tree is built with `make RISTRETTO=1`.
 * The DEFAULT build is hermetic (terminal/stdout stream, like tcpdump) and does
 * NOT compile or link this file or any RistrettoDB code.
 *
 * This backend targets the RistrettoDB *V2* append-only, fixed-width table API
 * (ristretto_table_* / ristretto_value_*, see <RistrettoDB>/embed/ristretto.h).
 * There is no SQL, no UPDATE/DELETE, and exactly one writer: we create a table,
 * append ONE ROW PER CAPTURED PACKET, and close it. Per-packet (rather than
 * per-flow) rows keep the mapping between captured packets and stored rows
 * exact and deterministic, which the append-only model is built for.
 *
 * -----------------------------------------------------------------------------
 * SCHEMA (fixed-width; IPv6-friendly). Column types are the only ones V2
 * offers: INTEGER (8 bytes), REAL (8 bytes), TEXT(n) (n<=255 bytes, stores
 * up to n-1 chars + NUL). Table name: "packets".
 *
 *   ts_ns        INTEGER   packet timestamp, nanoseconds since the epoch
 *   src_ip       TEXT(46)  source address, inet_ntop (AF_INET / AF_INET6)
 *   dst_ip       TEXT(46)  destination address, inet_ntop
 *   src_port     INTEGER   L4 source port in host order (0 if no L4 ports)
 *   dst_port     INTEGER   L4 destination port in host order
 *   protocol     INTEGER   IP protocol number (6=TCP, 17=UDP, ...)
 *   addr_family  INTEGER   4 (IPv4) or 6 (IPv6)
 *   length       INTEGER   original on-wire packet length
 *   caplen       INTEGER   captured length (<= length)
 *
 * IPv6 storage: addresses are kept as TEXT formatted with inet_ntop, so a full
 * IPv6 or IPv4-mapped literal round-trips unchanged. INET6_ADDRSTRLEN (46) is
 * the width: the longest textual address is 45 chars, and the V2 packer keeps
 * up to (width-1) chars + NUL, i.e. 45 usable chars in a TEXT(46) column.
 * =============================================================================
 */
#define _POSIX_C_SOURCE 200809L           /* strdup, inet_ntop prototypes */
#define RISTRETTO_NO_COMPATIBILITY_LAYER  /* only the prefixed ristretto_* API */

#include "pcv_output.h"
#include "pcv_flow.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include "ristretto.h"

/* Number of columns; must match PCV_RISTRETTO_SCHEMA below. */
#define PCV_RISTRETTO_NUM_COLS 9

/* INET6_ADDRSTRLEN is 46 on every supported platform; the schema string must
 * use a literal, so assert the assumption instead of silently diverging. */
#if INET6_ADDRSTRLEN > 46
#error "INET6_ADDRSTRLEN exceeds the src_ip/dst_ip TEXT(46) column width"
#endif

#define PCV_RISTRETTO_SCHEMA \
    "CREATE TABLE packets (" \
    "ts_ns INTEGER, " \
    "src_ip TEXT(46), " \
    "dst_ip TEXT(46), " \
    "src_port INTEGER, " \
    "dst_port INTEGER, " \
    "protocol INTEGER, " \
    "addr_family INTEGER, " \
    "length INTEGER, " \
    "caplen INTEGER)"

typedef struct pcv_ristretto_context {
    RistrettoTable* table;
    char* base_dir;   /* directory the .rdb file lives in */
    char* name;       /* table name (basename, no .rdb suffix) */
    uint64_t insert_errors;
} pcv_ristretto_context;

/* Split a user target ("ristretto:<target>") into the (base_dir, name) pair the
 * V2 library expects; it stores the table at "<base_dir>/<name>.rdb". A missing
 * directory becomes ".", and a trailing ".rdb" on the target is stripped so
 * "pkts" and "pkts.rdb" resolve to the same file. Returns 0 on success. */
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

/* Create output handler: create (or truncate) the V2 table. */
pcv_output* pcv_output_create(pcv_output_type type, const char* target) {
    if (type != PCV_OUTPUT_RISTRETTO) {
        return NULL;
    }
    if (!target || !*target) {
        target = "packets";
    }

    pcv_output* output = calloc(1, sizeof(pcv_output));
    if (!output) {
        return NULL;
    }

    pcv_ristretto_context* ctx = calloc(1, sizeof(pcv_ristretto_context));
    if (!ctx) {
        free(output);
        return NULL;
    }

    if (split_target(target, &ctx->base_dir, &ctx->name) != 0) {
        fprintf(stderr, "pcv_output: invalid RistrettoDB target '%s'\n", target);
        free(ctx);
        free(output);
        return NULL;
    }

    ctx->table = ristretto_table_create_ex(ctx->name, PCV_RISTRETTO_SCHEMA,
                                           ctx->base_dir,
                                           RISTRETTO_CREATE_OR_TRUNCATE);
    if (!ctx->table) {
        fprintf(stderr,
                "pcv_output: failed to create RistrettoDB table '%s/%s.rdb'\n",
                ctx->base_dir, ctx->name);
        free(ctx->base_dir);
        free(ctx->name);
        free(ctx);
        free(output);
        return NULL;
    }

    output->type = type;
    output->context = ctx;
    output->flush_interval_ms = 1000;

    fprintf(stderr, "pcv_output: writing packets to RistrettoDB table %s/%s.rdb\n",
            ctx->base_dir, ctx->name);
    return output;
}

/* Destroy output handler: durably flush and close the table. */
void pcv_output_destroy(pcv_output* output) {
    if (!output) {
        return;
    }

    pcv_ristretto_context* ctx = (pcv_ristretto_context*)output->context;
    if (ctx) {
        if (ctx->table) {
            ristretto_table_flush_durable(ctx->table);
            ristretto_table_close(ctx->table);
        }
        fprintf(stderr,
                "pcv_output: wrote %" PRIu64 " rows (%" PRIu64 " errors) to %s/%s.rdb\n",
                output->total_flows, ctx->insert_errors,
                ctx->base_dir ? ctx->base_dir : "?",
                ctx->name ? ctx->name : "?");
        free(ctx->base_dir);
        free(ctx->name);
        free(ctx);
    }

    free(output);
}

/* Append one row for a captured packet. Never aborts the capture loop: parse
 * failures are skipped and append failures are counted and reported via the
 * return code. */
int pcv_output_packet(pcv_output* output, const pcv_packet* packet) {
    if (!output || !packet) {
        return -1;
    }

    pcv_ristretto_context* ctx = (pcv_ristretto_context*)output->context;
    if (!ctx || !ctx->table) {
        return -1;
    }

    pcv_flow_key_v6 key;
    if (pcv_flow_extract_key_v6(packet, &key) != 0) {
        /* Not an IP packet we can parse - skip it without erroring. */
        return 0;
    }

    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    if (key.addr_family == PCV_ADDR_IPV6) {
        inet_ntop(AF_INET6, key.src_ip.ipv6, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET6, key.dst_ip.ipv6, dst_ip, sizeof(dst_ip));
    } else {
        inet_ntop(AF_INET, &key.src_ip.ipv4, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &key.dst_ip.ipv4, dst_ip, sizeof(dst_ip));
    }

    RistrettoValue v[PCV_RISTRETTO_NUM_COLS];
    v[0] = ristretto_value_integer((int64_t)packet->timestamp_ns);
    v[1] = ristretto_value_text(src_ip);
    v[2] = ristretto_value_text(dst_ip);
    v[3] = ristretto_value_integer((int64_t)key.src_port);
    v[4] = ristretto_value_integer((int64_t)key.dst_port);
    v[5] = ristretto_value_integer((int64_t)key.protocol);
    v[6] = ristretto_value_integer((int64_t)key.addr_family);
    v[7] = ristretto_value_integer((int64_t)packet->length);
    v[8] = ristretto_value_integer((int64_t)packet->captured_length);

    bool ok = ristretto_table_append_row_n(ctx->table, v, PCV_RISTRETTO_NUM_COLS);

    /* Only the TEXT values own heap memory. */
    ristretto_value_destroy(&v[1]);
    ristretto_value_destroy(&v[2]);

    output->total_packets++;
    output->total_bytes += packet->captured_length;

    if (!ok) {
        ctx->insert_errors++;
        fprintf(stderr, "pcv_output: failed to append packet row\n");
        return -1;
    }

    output->total_flows++;  /* reused as "rows written" */
    return 0;
}

/* Flush buffered data to disk (fast, async). */
int pcv_output_flush(pcv_output* output) {
    if (!output) {
        return 0;
    }
    pcv_ristretto_context* ctx = (pcv_ristretto_context*)output->context;
    if (ctx && ctx->table) {
        ristretto_table_flush(ctx->table);
    }
    return 0;
}

/* Get output statistics */
void pcv_output_get_stats(const pcv_output* output, uint64_t* flows,
                          uint64_t* packets, uint64_t* bytes) {
    if (!output) {
        return;
    }
    if (flows)   *flows   = output->total_flows;
    if (packets) *packets = output->total_packets;
    if (bytes)   *bytes   = output->total_bytes;
}
