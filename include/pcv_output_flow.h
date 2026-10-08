#ifndef PCV_OUTPUT_FLOW_H
#define PCV_OUTPUT_FLOW_H

#include <stdint.h>
#include "pcv_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/* PacketVelocity per-FLOW RistrettoDB output sink (OPTIONAL, opt-in).
 *
 * This is the per-flow counterpart to the per-packet sink in
 * pcv_output_ristretto.c: instead of one row per captured packet, it writes
 * ONE ROW PER NETWORK FLOW (a 5-tuple conversation) to a RistrettoDB V2
 * "flows" table. Packets are aggregated with PacketVelocity's own flow
 * tracking (pcv_flow.c); a row is emitted when a flow is evicted during capture
 * (timeout / TCP FIN) and, at shutdown, for every flow still open.
 *
 * Compiled ONLY when the tree is built with `make RISTRETTO=1`. The default
 * build never references this header or any RistrettoDB code.
 */
typedef struct pcv_flow_output pcv_flow_output;

/* Create a per-flow sink writing <target>.rdb. Uses live-capture defaults for
 * flow timeout / table sizing. Returns NULL on error. */
pcv_flow_output* pcv_flow_output_create(const char* target);

/* Create a per-flow sink with explicit flow-tracking parameters. Used by tests
 * to force deterministic mid-capture expiry; pcv_flow_output_create wraps this
 * with sensible defaults. A zero argument falls back to its default. */
pcv_flow_output* pcv_flow_output_create_ex(const char* target,
                                           uint64_t flow_timeout_ms,
                                           uint32_t cleanup_interval,
                                           uint32_t max_flows,
                                           uint32_t hash_buckets);

/* Aggregate one captured packet into its flow. Never aborts the capture loop:
 * unparseable (non-IP) packets are skipped. Returns 0 on success, -1 on error. */
int pcv_flow_output_update(pcv_flow_output* out, const pcv_packet* packet);

/* Emit every still-open flow, durably flush and close the table, then free the
 * sink. Safe on NULL. */
void pcv_flow_output_destroy(pcv_flow_output* out);

/* Statistics: flows = rows written so far, packets = packets aggregated,
 * bytes = bytes aggregated. Any pointer may be NULL. */
void pcv_flow_output_get_stats(const pcv_flow_output* out, uint64_t* flows,
                               uint64_t* packets, uint64_t* bytes);

#ifdef __cplusplus
}
#endif

#endif /* PCV_OUTPUT_FLOW_H */
