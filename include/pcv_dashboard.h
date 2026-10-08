#ifndef PCV_DASHBOARD_H
#define PCV_DASHBOARD_H

#include <stdint.h>
#include <stddef.h>
#include "pcv_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/* PacketVelocity live-dashboard aggregation.
 *
 * This module owns the hot-path-safe aggregated state behind `--serve`. It is
 * deliberately decoupled from live capture: the SAME pcv_dash_on_packet() hook
 * that the live capture callback calls is driven, byte-for-byte, by the offline
 * pcap replay harness in tests (no root, no NIC). Live mode only swaps the
 * packet source (BPF) and the recv/dropped source (the kernel, via the sampler).
 *
 * Threading contract (see src/pcv_dash_hot.c and src/pcv_http.c):
 *   - pcv_dash_on_packet runs ONLY on the capture thread. It does cheap work:
 *     a bounds-checked protocol classify, three relaxed atomic adds, one flow
 *     update, and a time-gated (<=1 Hz) top-N snapshot published WAIT-FREE (a
 *     non-blocking trylock; the capture thread never blocks on a lock the HTTP
 *     thread can hold). No I/O, no malloc, no blocking lock on this path.
 *   - pcv_dash_sample_with_stats runs ONLY on the sampler thread.
 *   - pcv_dash_snapshot_json runs ONLY on the HTTP thread.
 */

/* Protocol-mix buckets. The classifier is TOTAL: every packet increments
 * EXACTLY ONE bucket, so sum(proto[]) == total packets classified. */
typedef enum {
    PCV_PROTO_TCP = 0,
    PCV_PROTO_UDP,
    PCV_PROTO_ICMP,
    PCV_PROTO_ARP,
    PCV_PROTO_IPV6,
    PCV_PROTO_OTHER,
    PCV_PROTO_COUNT
} pcv_proto_bucket;

/* Opaque aggregated state. */
typedef struct pcv_dash_agg pcv_dash_agg;

/* Create / destroy the aggregator.
 *   serve_max_flows / serve_hash_buckets size the private flow table that the
 *     capture thread feeds (a MODEST default is used when 0 is passed, so the
 *     1 Hz on-capture-thread top-N scan stays bounded - see src/pcv_dash_hot.c).
 *   topn is the number of flows the live flow table reports (clamped to the
 *     built-in maximum; 0 => the maximum).
 * Returns NULL on allocation failure. */
pcv_dash_agg* pcv_dash_create(uint32_t serve_max_flows,
                              uint32_t serve_hash_buckets,
                              uint32_t topn);
void pcv_dash_destroy(pcv_dash_agg* agg);

/* HOT PATH. Called from the capture callback (or the replay callback in tests)
 * once per accepted packet. Cheap + allocation/lock/IO-free (trylock publish is
 * wait-free for the caller). Safe to call with agg == NULL (no-op). */
void pcv_dash_on_packet(pcv_dash_agg* agg, const pcv_packet* packet);

/* TEST / SHUTDOWN SEAM. Build + publish the top-N flow snapshot immediately,
 * independent of the per-packet 1 Hz time gate, so a sub-second synthetic trace
 * (and the final <1s of a live run) is observable. Must be called from the same
 * thread that calls pcv_dash_on_packet (it reads the capture-owned flow table).*/
void pcv_dash_force_snapshot(pcv_dash_agg* agg);

/* SAMPLER. Push one time-series sample. recv/dropped are PASSED IN (not read
 * here) so the live sampler sources them from the kernel (BIOCGSTATS) while
 * tests inject synthetic values - the "swap the source" testability seam.
 * Rates divide by the ACTUAL elapsed dt (now_ns - previous now_ns), never an
 * assumed 1.0s. recv/dropped deltas are computed modulo 2^32 (the kernel's
 * bs_recv/bs_drop are 32-bit), so a counter wrap yields a sane delta. The first
 * sample (no previous) and a zero-dt tick emit 0, never a spike. */
void pcv_dash_sample_with_stats(pcv_dash_agg* agg,
                                uint64_t recv, uint64_t dropped,
                                uint64_t now_ns);

/* HTTP THREAD. Pure serializer: builds the three-panel /stats.json payload from
 * the atomics + the published flow snapshot + the rate ring into buf. Does no
 * agg mutation and no socket I/O (the caller writes the socket AFTER this
 * returns, holding no lock). Returns the number of bytes written (excluding the
 * NUL), or 0 on error / NULL agg. */
size_t pcv_dash_snapshot_json(pcv_dash_agg* agg, char* buf, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* PCV_DASHBOARD_H */
