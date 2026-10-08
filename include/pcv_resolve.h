#ifndef PCV_RESOLVE_H
#define PCV_RESOLVE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PacketVelocity IP -> hostname resolver (the --serve "names" engine).
 *
 * TWO sources, both surfaced through ONE bounded IP->name map:
 *   (a) PASSIVE DNS (primary): DNS/mDNS RESPONSE packets already on the wire are
 *       copied - on the capture hot path - into a wait-free SPSC ring that lives
 *       inline in the dashboard aggregator. This resolver thread DRAINS and
 *       PARSES them with a hardened, fully bounds-checked in-house parser,
 *       mapping each A/AAAA answer's OWNER NAME to its RDATA IP. NO extra network
 *       traffic; these are the good names apps actually resolved.
 *   (b) REVERSE PTR (fallback): for GLOBAL IPs seen in the published flow
 *       snapshot that have no passive name, an ASYNC, bounded, rate-limited
 *       reverse lookup via an INJECTABLE fn pointer (defaulting to libc
 *       getnameinfo). NEVER on the capture hot path or the HTTP response path.
 *
 * THREADING (mirrors the dashboard's capture-never-blocks discipline):
 *   - The capture thread ONLY writes the SPSC ring (wait-free atomics) and NEVER
 *     takes names_mtx - it structurally cannot, since names_mtx lives HERE, in
 *     the resolver, not in the aggregator the capture thread holds.
 *   - This resolver thread owns the map: it drains+parses (passive) and runs the
 *     PTR pass. It MAY take blocking locks (it is not the capture thread).
 *   - The HTTP thread reads names ONLY via pcv_resolve_lookup, which takes
 *     names_mtx for a bounded copy-out into a request-local buffer and releases
 *     it before any JSON formatting or socket I/O.
 *
 * SECURITY: DNS/mDNS/PTR names are ATTACKER-INFLUENCED. The parser is fully
 * bounds-checked (255-byte name cap, hard compression-pointer jump cap, a
 * strictly-decreasing pointer-target invariant that guarantees termination) and
 * names are sanitized to a strict allowlist ([A-Za-z0-9.-*_]) AT INSERT, for
 * BOTH passive and PTR names, so a hostile name cannot carry markup or control
 * bytes into the dashboard.
 */

/* Address family tags: reuse pcv_flow.h's PCV_ADDR_IPV4(4)/PCV_ADDR_IPV6(6). */

struct pcv_dash_agg;                 /* the dashboard aggregator (opaque here) */
typedef struct pcv_resolver pcv_resolver;

/* A tagged IP key, derived the SAME way flow keys are (never confusing a raw
 * IPv4 with an IPv4-mapped IPv6). v4 is network byte order (as pcv_ip_addr_t);
 * v6 is 16 network-order bytes. */
typedef struct {
    uint8_t family;        /* 4 (IPv4) or 6 (IPv6) */
    uint8_t _pad[3];
    union {
        uint32_t v4;
        uint8_t  v6[16];
    } a;
} pcv_resolve_key;

/* Name-source provenance stored per map entry. */
typedef enum {
    PCV_NAME_NONE    = 0,
    PCV_NAME_PASSIVE = 1,   /* from a DNS/mDNS answer (authoritative-ish, best) */
    PCV_NAME_PTR     = 2    /* from a reverse-PTR fallback lookup */
} pcv_name_source;

/* Reverse-PTR seam ("swap the source", mirroring netdebug lookupAddrFunc). Must
 * write a NUL-terminated name into out (<= outlen) and return 0 on success, or
 * non-zero on failure / NXDOMAIN. outlen must be >= 1 (room for the NUL). The
 * default wrapper calls getnameinfo with NI_NAMEREQD. Tests inject a stub so no
 * suite ever hits a live resolver. */
typedef int (*pcv_ptr_fn)(const pcv_resolve_key* key, char* out, size_t outlen,
                          void* ctx);

/* Pure DNS/mDNS parser emit callback: one call per extracted A/AAAA answer.
 * family is 4 or 6; addr points at 4 (IPv4) or 16 (IPv6) network-order bytes
 * INSIDE the caller's payload buffer (copy immediately, do not retain); name is
 * the assembled, bounds-capped owner name (NOT yet sanitized). */
typedef void (*pcv_dns_emit_fn)(uint8_t family, const uint8_t* addr,
                                const char* name, void* ctx);

/* ---- Lifecycle ----------------------------------------------------------- */

/* Create a resolver bound to the dashboard aggregator (whose inline SPSC ring it
 * drains and whose published flow snapshot it reads). fn==NULL installs the
 * default getnameinfo-based PTR wrapper; ctx is passed to fn. Returns NULL on
 * allocation failure. */
pcv_resolver* pcv_resolver_create(struct pcv_dash_agg* agg, pcv_ptr_fn fn,
                                  void* ctx);

/* Free the map + caches. The caller MUST have cleared running and JOINED both
 * the resolver thread AND the HTTP thread first (both touch the map). */
void pcv_resolver_destroy(pcv_resolver* r);

/* Clear the _Atomic running flag so the resolver thread exits promptly. */
void pcv_resolver_stop(pcv_resolver* r);

/* pthread entry point; arg is a pcv_resolver*. Drains the ring continuously and
 * runs a bounded PTR pass every few seconds, sleeping in short slices that
 * re-check running (so a join is prompt). Returns NULL. */
void* pcv_resolver_thread(void* arg);

/* ---- HTTP-thread read path ---------------------------------------------- */

/* Copy the name for key into buf under names_mtx, then release BEFORE the caller
 * formats/sends. Returns the name length (0 and buf[0]='\0' when r==NULL, no
 * entry, or an expired entry). buf must be non-NULL with len>=1. */
size_t pcv_resolve_lookup(pcv_resolver* r, const pcv_resolve_key* key,
                          char* buf, size_t len);

/* ---- Pure helpers + test seams ------------------------------------------ */

/* Build a tagged key from a family tag (4/6) and a pointer to 4 or 16
 * network-order address bytes. */
void pcv_resolve_key_make(uint8_t family, const void* addr, pcv_resolve_key* out);

/* GLOBAL-IP gate: false for RFC1918 / loopback / link-local / CGNAT /
 * multicast / unspecified (mirrors netdebug isGlobalIP). addr is 4 or 16
 * network-order bytes per family. Only global IPs are eligible for a PTR. */
bool pcv_is_global_ip(uint8_t family, const void* addr);

/* The hardened, pure DNS/mDNS message parser over ONLY payload[0..len). Requires
 * QR=1 and ancount>0; skips the question section and walks exactly ancount
 * answers, emitting A(type 1, rdlen 4)->IPv4 and AAAA(type 28, rdlen 16)->IPv6.
 * Never reads past len; rejects compression loops. Returns 0 on a well-formed
 * parse (even if it emitted nothing), -1 on a structural error. */
int pcv_dns_parse(const uint8_t* payload, uint32_t len, pcv_dns_emit_fn emit,
                  void* ctx);

/* TEST/thread seam: drain + parse everything currently in the SPSC ring once,
 * inserting passive names. Safe to call from the resolver thread or a test. */
void pcv_resolver_drain_once(pcv_resolver* r);

/* TEST/thread seam: run ONE bounded reverse-PTR pass over the published flow
 * snapshot (at most PCV_RESOLVE_PTR_PER_CYCLE lookups, running re-checked
 * between each). Returns the number of PTR lookups actually issued. */
int pcv_resolver_ptr_pass(pcv_resolver* r);

#ifdef __cplusplus
}
#endif

#endif /* PCV_RESOLVE_H */
