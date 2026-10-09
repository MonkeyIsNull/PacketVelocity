/* PacketVelocity IP -> hostname resolver. See include/pcv_resolve.h.
 *
 * Runs ENTIRELY off the capture hot path (on its own resolver thread, or driven
 * synchronously by tests). It owns the bounded IP->name map and the names_mtx
 * that guards it; the capture thread cannot reach either (it sees only the
 * aggregator and the inline SPSC ring). The HTTP thread reads names only through
 * pcv_resolve_lookup (a bounded copy-out under names_mtx).
 *
 * Two name sources funnel into one map:
 *   - PASSIVE DNS: pcv_resolver_drain_once pulls each copied UDP payload off the
 *     ring and runs the hardened in-house pcv_dns_parse, inserting PASSIVE names.
 *   - REVERSE PTR: pcv_resolver_ptr_pass walks the published flow snapshot and
 *     issues at most PCV_RESOLVE_PTR_PER_CYCLE bounded lookups for GLOBAL IPs
 *     that have no name and are not in the negative cache.
 *
 * All names (passive AND PTR) are sanitized to a strict allowlist at insert, so
 * an attacker-influenced name cannot carry markup or control bytes onward.
 */

#ifdef __linux__
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#endif

#include "pcv_resolve.h"
#include "pcv_dashboard_internal.h"
#include "pcv_flow.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

/* ---- Tunables ------------------------------------------------------------ */

#define PCV_NAME_MAX            256u   /* name buffer incl. NUL (255-byte cap) */
#define PCV_RESOLVE_MAP_CAP     4096u  /* fixed open-addressed IP->name table */
#define PCV_RESOLVE_NEG_CAP     1024u  /* fixed open-addressed negative cache */
#define PCV_RESOLVE_SNI_CAP     2048u  /* fixed open-addressed flow->SNI map */
#define PCV_DNS_MAX_JUMPS       16     /* hard compression-pointer indirection cap */
#define PCV_RESOLVE_PTR_PER_CYCLE 8    /* K: max reverse lookups per PTR pass */

/* TTLs (nanoseconds, CLOCK_MONOTONIC domain). */
#define PCV_NAME_POS_TTL_NS     (30ULL * 60ULL * 1000000000ULL)  /* ~30 min */
#define PCV_NAME_NEG_TTL_NS     (5ULL  * 60ULL * 1000000000ULL)  /* ~5 min  */

/* ---- Entry layouts ------------------------------------------------------- */

typedef struct {
    uint8_t  used;                 /* 0 empty, 1 occupied */
    uint8_t  family;               /* 4 or 6 */
    uint8_t  source;               /* pcv_name_source */
    uint8_t  _pad;
    union { uint32_t v4; uint8_t v6[16]; } a;
    uint64_t insert_ns;            /* for TTL + LRU reclaim */
    char     name[PCV_NAME_MAX];
} name_entry;

typedef struct {
    uint8_t  used;
    uint8_t  family;
    uint8_t  _pad[2];
    union { uint32_t v4; uint8_t v6[16]; } a;
    uint64_t insert_ns;            /* TTL (== cooldown) + LRU reclaim */
} neg_entry;

/* Per-flow SNI side map entry: keyed by the EXACT 5-tuple the ClientHello was
 * captured on (client->server:443), carrying the sanitized server_name. */
typedef struct {
    uint8_t         used;          /* 0 empty, 1 occupied */
    uint8_t         _pad[7];
    pcv_flow_key_v6 key;           /* the ClientHello's forward 5-tuple */
    uint64_t        insert_ns;     /* TTL + LRU reclaim (refreshed on read) */
    char            name[PCV_NAME_MAX];
} sni_entry;

struct pcv_resolver {
    struct pcv_dash_agg* agg;      /* ring source + flow-snapshot source */

    pthread_mutex_t names_mtx;     /* guards map[], neg[] AND sni[] */
    name_entry* map;               /* PCV_RESOLVE_MAP_CAP entries */
    neg_entry*  neg;               /* PCV_RESOLVE_NEG_CAP entries */
    sni_entry*  sni;               /* PCV_RESOLVE_SNI_CAP entries (flow->SNI) */

    pcv_ptr_fn ptr_fn;             /* injectable reverse-PTR seam */
    void*      ptr_ctx;

    _Atomic int running;           /* resolver thread loop flag */
};

/* ---- Time ---------------------------------------------------------------- */

static uint64_t res_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ---- Key helpers --------------------------------------------------------- */

void pcv_resolve_key_make(uint8_t family, const void* addr, pcv_resolve_key* out) {
    memset(out, 0, sizeof(*out));
    out->family = family;
    if (family == PCV_ADDR_IPV4) {
        memcpy(&out->a.v4, addr, 4);
    } else if (family == PCV_ADDR_IPV6) {
        memcpy(out->a.v6, addr, 16);
    }
}

/* FNV-1a over family + address bytes. */
static uint32_t key_hash(uint8_t family, const void* addr) {
    uint32_t h = 0x811c9dc5u;
    h ^= family; h *= 0x01000193u;
    size_t n = (family == PCV_ADDR_IPV4) ? 4u : 16u;
    const uint8_t* b = (const uint8_t*)addr;
    for (size_t i = 0; i < n; i++) {
        h ^= b[i]; h *= 0x01000193u;
    }
    return h;
}

/* ---- Global-IP gate (mirrors netdebug isGlobalIP) ------------------------ */

bool pcv_is_global_ip(uint8_t family, const void* addr) {
    if (family == PCV_ADDR_IPV4) {
        uint32_t net; /* network byte order */
        memcpy(&net, addr, 4);
        uint32_t h = ntohl(net);
        uint8_t a = (uint8_t)(h >> 24);
        uint8_t b = (uint8_t)(h >> 16);
        if (a == 10u) return false;                       /* 10/8 */
        if (a == 127u) return false;                      /* 127/8 loopback */
        if (a == 172u && b >= 16u && b <= 31u) return false; /* 172.16/12 */
        if (a == 192u && b == 168u) return false;         /* 192.168/16 */
        if (a == 169u && b == 254u) return false;         /* 169.254/16 link-local */
        if (a == 100u && b >= 64u && b <= 127u) return false; /* 100.64/10 CGNAT */
        if (a >= 224u) return false;                      /* 224/4 multicast + 240/4 */
        if (h == 0u) return false;                        /* 0.0.0.0 */
        return true;
    }
    if (family == PCV_ADDR_IPV6) {
        const uint8_t* p = (const uint8_t*)addr;
        /* ::1 loopback */
        static const uint8_t loop[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        if (memcmp(p, loop, 16) == 0) return false;
        /* :: unspecified */
        int all_zero = 1;
        for (int i = 0; i < 16; i++) { if (p[i]) { all_zero = 0; break; } }
        if (all_zero) return false;
        if (p[0] == 0xff) return false;                   /* ff00::/8 multicast */
        if (p[0] == 0xfe && (p[1] & 0xc0) == 0x80) return false; /* fe80::/10 */
        if ((p[0] & 0xfe) == 0xfc) return false;          /* fc00::/7 ULA */
        return true;
    }
    return false;
}

/* ---- Allowlist sanitizer ------------------------------------------------- */

/* Keep only [A-Za-z0-9.-] plus '*' (wildcard) and '_' (odd mDNS/service
 * labels); drop everything else; enforce the 255-byte cap. Returns the output
 * length (0 => the name sanitized to empty and MUST be rejected). */
static size_t sanitize_name(const char* in, char* out, size_t outcap) {
    size_t o = 0;
    for (size_t i = 0; in[i] != '\0' && o + 1u < outcap && o < 255u; i++) {
        char c = in[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '.' || c == '-' || c == '*' || c == '_') {
            out[o++] = c;
        }
    }
    out[o] = '\0';
    return o;
}

/* ---- Provenance precedence ----------------------------------------------- */

/* Map a name source to its precedence rank. The enum's RAW values are not in
 * rank order (PTR=2 > PASSIVE=1), so ordering MUST go through this helper.
 * Strongest to weakest: SNI(3) > PASSIVE(2) > PTR(1) > NONE(0). */
static int name_rank(uint8_t source) {
    switch (source) {
    case PCV_NAME_SNI:     return 3;
    case PCV_NAME_PASSIVE: return 2;
    case PCV_NAME_PTR:     return 1;
    default:               return 0;
    }
}

/* ---- Map operations (caller holds names_mtx) ----------------------------- */

static name_entry* map_find(pcv_resolver* r, uint8_t family, const void* addr,
                            uint64_t now) {
    uint32_t start = key_hash(family, addr) % PCV_RESOLVE_MAP_CAP;
    for (uint32_t i = 0; i < PCV_RESOLVE_MAP_CAP; i++) {
        uint32_t idx = (start + i) % PCV_RESOLVE_MAP_CAP;
        name_entry* e = &r->map[idx];
        if (!e->used) {
            return NULL;                       /* open slot ends the probe run */
        }
        if (e->family == family &&
            ((family == PCV_ADDR_IPV4) ? (memcmp(&e->a.v4, addr, 4) == 0)
                                       : (memcmp(e->a.v6, addr, 16) == 0))) {
            if (now - e->insert_ns > PCV_NAME_POS_TTL_NS) {
                return NULL;                   /* expired: treat as absent */
            }
            return e;
        }
    }
    return NULL;
}

/* Insert/update a sanitized name with provenance. PTR never overwrites PASSIVE;
 * PASSIVE may replace PTR. On a full table, reclaim the oldest (LRU) slot. */
static void map_insert(pcv_resolver* r, uint8_t family, const void* addr,
                       const char* sani, uint8_t source, uint64_t now) {
    uint32_t start = key_hash(family, addr) % PCV_RESOLVE_MAP_CAP;
    uint32_t first_free = UINT32_MAX;
    uint32_t oldest_idx = 0;
    uint64_t oldest_ns = UINT64_MAX;

    for (uint32_t i = 0; i < PCV_RESOLVE_MAP_CAP; i++) {
        uint32_t idx = (start + i) % PCV_RESOLVE_MAP_CAP;
        name_entry* e = &r->map[idx];

        if (e->used && e->insert_ns < oldest_ns) {
            oldest_ns = e->insert_ns;
            oldest_idx = idx;
        }

        if (!e->used) {
            if (first_free == UINT32_MAX) {
                first_free = idx;
            }
            break;                             /* open slot ends this key's run */
        }
        if (e->family == family &&
            ((family == PCV_ADDR_IPV4) ? (memcmp(&e->a.v4, addr, 4) == 0)
                                       : (memcmp(e->a.v6, addr, 16) == 0))) {
            int expired = (now - e->insert_ns > PCV_NAME_POS_TTL_NS);
            /* Provenance precedence SNI > PASSIVE > PTR: replace a LIVE entry
             * only when the new source ranks >= the existing (same-rank is
             * last-writer-wins refresh). So PTR never clobbers live SNI/PASSIVE,
             * PASSIVE never clobbers live SNI, and SNI overwrites anything. An
             * EXPIRED entry of any rank stays replaceable (the !expired escape),
             * so a stale SNI/PASSIVE cannot forever block a fresh PTR. */
            if (!expired && name_rank(source) < name_rank(e->source)) {
                return;
            }
            e->source = source;
            e->insert_ns = now;
            strncpy(e->name, sani, PCV_NAME_MAX - 1);
            e->name[PCV_NAME_MAX - 1] = '\0';
            return;
        }
    }

    uint32_t dst;
    if (first_free != UINT32_MAX) {
        dst = first_free;
    } else {
        /* No free slot found along the probe run: scan the whole table for the
         * globally-oldest entry to reclaim (strictly bounded, never grows). */
        oldest_ns = UINT64_MAX;
        for (uint32_t i = 0; i < PCV_RESOLVE_MAP_CAP; i++) {
            if (r->map[i].insert_ns < oldest_ns) {
                oldest_ns = r->map[i].insert_ns;
                oldest_idx = i;
            }
        }
        dst = oldest_idx;
    }

    name_entry* e = &r->map[dst];
    memset(e, 0, sizeof(*e));
    e->used = 1;
    e->family = family;
    e->source = source;
    e->insert_ns = now;
    if (family == PCV_ADDR_IPV4) {
        memcpy(&e->a.v4, addr, 4);
    } else {
        memcpy(e->a.v6, addr, 16);
    }
    strncpy(e->name, sani, PCV_NAME_MAX - 1);
    e->name[PCV_NAME_MAX - 1] = '\0';
}

/* ---- Negative cache (== reverse-PTR cooldown; caller holds names_mtx) ---- */

static int neg_present(pcv_resolver* r, uint8_t family, const void* addr,
                       uint64_t now) {
    uint32_t start = key_hash(family, addr) % PCV_RESOLVE_NEG_CAP;
    for (uint32_t i = 0; i < PCV_RESOLVE_NEG_CAP; i++) {
        uint32_t idx = (start + i) % PCV_RESOLVE_NEG_CAP;
        neg_entry* e = &r->neg[idx];
        if (!e->used) {
            return 0;
        }
        if (e->family == family &&
            ((family == PCV_ADDR_IPV4) ? (memcmp(&e->a.v4, addr, 4) == 0)
                                       : (memcmp(e->a.v6, addr, 16) == 0))) {
            if (now - e->insert_ns > PCV_NAME_NEG_TTL_NS) {
                return 0;                      /* cooldown expired */
            }
            return 1;
        }
    }
    return 0;
}

static void neg_insert(pcv_resolver* r, uint8_t family, const void* addr,
                       uint64_t now) {
    uint32_t start = key_hash(family, addr) % PCV_RESOLVE_NEG_CAP;
    uint32_t dst = UINT32_MAX;
    uint32_t oldest_idx = start;
    uint64_t oldest_ns = UINT64_MAX;

    for (uint32_t i = 0; i < PCV_RESOLVE_NEG_CAP; i++) {
        uint32_t idx = (start + i) % PCV_RESOLVE_NEG_CAP;
        neg_entry* e = &r->neg[idx];
        if (e->used && e->insert_ns < oldest_ns) {
            oldest_ns = e->insert_ns;
            oldest_idx = idx;
        }
        if (!e->used) {
            dst = idx;
            break;
        }
        if (e->family == family &&
            ((family == PCV_ADDR_IPV4) ? (memcmp(&e->a.v4, addr, 4) == 0)
                                       : (memcmp(e->a.v6, addr, 16) == 0))) {
            e->insert_ns = now;                /* refresh cooldown */
            return;
        }
        /* Reclaim an expired entry in the run. */
        if (now - e->insert_ns > PCV_NAME_NEG_TTL_NS) {
            dst = idx;
            break;
        }
    }
    if (dst == UINT32_MAX) {
        dst = oldest_idx;                      /* full run: LRU reclaim */
    }

    neg_entry* e = &r->neg[dst];
    memset(e, 0, sizeof(*e));
    e->used = 1;
    e->family = family;
    e->insert_ns = now;
    if (family == PCV_ADDR_IPV4) {
        memcpy(&e->a.v4, addr, 4);
    } else {
        memcpy(e->a.v6, addr, 16);
    }
}

/* ---- Flow->SNI side map (caller holds names_mtx) -------------------------
 * A bounded open-addressed table keyed by the EXACT 5-tuple a ClientHello was
 * captured on, hashed/compared with the SAME directional functions the flow
 * table uses (pcv_flow_hash_key_v6 + pcv_flow_key_v6_compare, no
 * canonicalization), so a side-map key matches a flow row's key6 byte-for-byte.
 * TTL + whole-table-LRU reclaim mirror map_insert, so memory is strictly
 * bounded (PCV_RESOLVE_SNI_CAP entries, never grows). */

static sni_entry* sni_find(pcv_resolver* r, const pcv_flow_key_v6* key,
                           uint64_t now) {
    uint32_t start = pcv_flow_hash_key_v6(key) % PCV_RESOLVE_SNI_CAP;
    for (uint32_t i = 0; i < PCV_RESOLVE_SNI_CAP; i++) {
        uint32_t idx = (start + i) % PCV_RESOLVE_SNI_CAP;
        sni_entry* e = &r->sni[idx];
        if (!e->used) {
            return NULL;                       /* open slot ends the probe run */
        }
        if (pcv_flow_key_v6_compare(&e->key, key) == 0) {
            if (now - e->insert_ns > PCV_NAME_POS_TTL_NS) {
                return NULL;                   /* expired: treat as absent */
            }
            return e;
        }
    }
    return NULL;
}

static void sni_insert(pcv_resolver* r, const pcv_flow_key_v6* key,
                       const char* sani, uint64_t now) {
    uint32_t start = pcv_flow_hash_key_v6(key) % PCV_RESOLVE_SNI_CAP;
    uint32_t first_free = UINT32_MAX;

    for (uint32_t i = 0; i < PCV_RESOLVE_SNI_CAP; i++) {
        uint32_t idx = (start + i) % PCV_RESOLVE_SNI_CAP;
        sni_entry* e = &r->sni[idx];
        if (!e->used) {
            if (first_free == UINT32_MAX) {
                first_free = idx;
            }
            break;                             /* open slot ends this key's run */
        }
        if (pcv_flow_key_v6_compare(&e->key, key) == 0) {
            e->insert_ns = now;
            strncpy(e->name, sani, PCV_NAME_MAX - 1);
            e->name[PCV_NAME_MAX - 1] = '\0';
            return;
        }
    }

    uint32_t dst;
    if (first_free != UINT32_MAX) {
        dst = first_free;
    } else {
        /* No free slot: reclaim the globally-oldest entry (bounded, no growth).*/
        uint64_t oldest_ns = UINT64_MAX;
        uint32_t oldest_idx = 0;
        for (uint32_t i = 0; i < PCV_RESOLVE_SNI_CAP; i++) {
            if (r->sni[i].insert_ns < oldest_ns) {
                oldest_ns = r->sni[i].insert_ns;
                oldest_idx = i;
            }
        }
        dst = oldest_idx;
    }

    sni_entry* e = &r->sni[dst];
    memset(e, 0, sizeof(*e));
    e->used = 1;
    e->key = *key;
    e->insert_ns = now;
    strncpy(e->name, sani, PCV_NAME_MAX - 1);
    e->name[PCV_NAME_MAX - 1] = '\0';
}

size_t pcv_resolve_flow_sni(pcv_resolver* r, const struct pcv_flow_key_v6* rowkey,
                            char* buf, size_t len, int* server_is_src) {
    if (server_is_src) {
        *server_is_src = 0;
    }
    if (!buf || len == 0) {
        return 0;
    }
    buf[0] = '\0';
    if (!r || !rowkey) {
        return 0;
    }
    const pcv_flow_key_v6* key = (const pcv_flow_key_v6*)rowkey;
    uint64_t now = res_now_ns();

    size_t out = 0;
    pthread_mutex_lock(&r->names_mtx);

    int src_side = 0;
    sni_entry* e = sni_find(r, key, now);    /* DIRECT: SNI names rowkey.dst */
    if (!e) {
        /* Build the src/dst + port swapped twin (the reverse-direction row's
         * forward tuple) and try that: a hit means the SNI names rowkey.src. */
        pcv_flow_key_v6 twin = *key;
        twin.src_ip   = key->dst_ip;
        twin.dst_ip   = key->src_ip;
        twin.src_port = key->dst_port;
        twin.dst_port = key->src_port;
        e = sni_find(r, &twin, now);
        if (e) {
            src_side = 1;
        }
    }
    if (e) {
        e->insert_ns = now;                  /* refresh-on-read (resolver owns) */
        size_t nl = strlen(e->name);
        if (nl >= len) {
            nl = len - 1;
        }
        memcpy(buf, e->name, nl);
        buf[nl] = '\0';
        out = nl;
        if (server_is_src) {
            *server_is_src = src_side;
        }
    }
    pthread_mutex_unlock(&r->names_mtx);
    return out;
}

/* ---- HTTP-thread read path ----------------------------------------------- */

size_t pcv_resolve_lookup(pcv_resolver* r, const pcv_resolve_key* key,
                          char* buf, size_t len) {
    if (!buf || len == 0) {
        return 0;
    }
    buf[0] = '\0';
    if (!r || (key->family != PCV_ADDR_IPV4 && key->family != PCV_ADDR_IPV6)) {
        return 0;
    }
    const void* addr = (key->family == PCV_ADDR_IPV4)
                     ? (const void*)&key->a.v4 : (const void*)key->a.v6;
    uint64_t now = res_now_ns();

    size_t out = 0;
    pthread_mutex_lock(&r->names_mtx);
    name_entry* e = map_find(r, key->family, addr, now);
    if (e) {
        size_t nl = strlen(e->name);
        if (nl >= len) {
            nl = len - 1;
        }
        memcpy(buf, e->name, nl);
        buf[nl] = '\0';
        out = nl;
    }
    pthread_mutex_unlock(&r->names_mtx);       /* released before caller formats */
    return out;
}

/* ---- Hardened DNS/mDNS parser -------------------------------------------- */

/* Read a (possibly compressed) DNS name starting at pos into out. On success
 * returns 0 and *advance = the offset JUST PAST the name in the record stream
 * (after the first pointer, or after the terminating zero). Fully bounds-checked
 * against len; caps the assembled name to 255 bytes; rejects a compression
 * pointer whose target is NOT strictly less than the pointer byte's own offset
 * (guarantees termination), with a hard jump cap as belt-and-suspenders. */
static int dns_read_name(const uint8_t* msg, uint32_t len, uint32_t pos,
                         char* out, size_t outcap, uint32_t* advance) {
    size_t o = 0;
    int jumps = 0;
    int advanced = 0;
    uint32_t adv = 0;
    uint32_t cur = pos;

    for (;;) {
        if (cur >= len) {
            return -1;
        }
        uint8_t b = msg[cur];
        uint8_t top = (uint8_t)(b & 0xC0u);

        if (top == 0xC0u) {                    /* compression pointer */
            if ((uint64_t)cur + 1u >= (uint64_t)len) {
                return -1;
            }
            uint32_t target = ((uint32_t)(b & 0x3Fu) << 8) | msg[cur + 1u];
            if (!advanced) {
                adv = cur + 2u;                /* record continues after the ptr */
                advanced = 1;
            }
            if (target >= cur) {
                return -1;                     /* not strictly backward: reject */
            }
            if (++jumps > PCV_DNS_MAX_JUMPS) {
                return -1;
            }
            cur = target;
            continue;
        } else if (top == 0x00u) {             /* literal label (len <= 63) */
            uint32_t llen = b;
            if (llen == 0u) {                  /* root: end of name */
                if (!advanced) {
                    adv = cur + 1u;
                }
                break;
            }
            cur += 1u;
            if ((uint64_t)cur + llen > (uint64_t)len) {
                return -1;
            }
            if (o != 0) {
                if (o + 1u >= outcap) return -1;
                out[o++] = '.';
            }
            for (uint32_t i = 0; i < llen; i++) {
                if (o + 1u >= outcap) return -1;
                out[o++] = (char)msg[cur + i];
            }
            cur += llen;
            if (o > 255u) {
                return -1;                     /* hard total-name cap */
            }
        } else {
            return -1;                         /* 0x40/0x80 reserved: reject */
        }
    }

    out[o] = '\0';
    if (advance) {
        *advance = adv;
    }
    return 0;
}

int pcv_dns_parse(const uint8_t* msg, uint32_t len, pcv_dns_emit_fn emit,
                  void* ctx) {
    if (!msg || len < 12u) {
        return -1;
    }
    uint16_t flags   = (uint16_t)((msg[2] << 8) | msg[3]);
    uint16_t qdcount = (uint16_t)((msg[4] << 8) | msg[5]);
    uint16_t ancount = (uint16_t)((msg[6] << 8) | msg[7]);

    if (!(flags & 0x8000u)) {
        return -1;                             /* QR must be 1 (a response) */
    }
    if (ancount == 0u) {
        return -1;
    }

    uint32_t pos = 12u;
    char name[PCV_NAME_MAX];

    /* Skip the question section with the SAME bounded, compression-aware walk. */
    for (uint16_t i = 0; i < qdcount; i++) {
        uint32_t adv = 0;
        if (dns_read_name(msg, len, pos, name, sizeof(name), &adv) != 0) {
            return -1;
        }
        pos = adv;
        if ((uint64_t)pos + 4u > (uint64_t)len) {   /* qtype(2) + qclass(2) */
            return -1;
        }
        pos += 4u;
    }

    /* Walk EXACTLY ancount answers; parse ONLY the answer section. */
    for (uint16_t i = 0; i < ancount; i++) {
        uint32_t adv = 0;
        if (dns_read_name(msg, len, pos, name, sizeof(name), &adv) != 0) {
            return -1;
        }
        pos = adv;
        if ((uint64_t)pos + 10u > (uint64_t)len) {  /* type/class/ttl/rdlength */
            return -1;
        }
        uint16_t type   = (uint16_t)((msg[pos] << 8) | msg[pos + 1]);
        /* class at pos+2 (mDNS sets the 0x8000 cache-flush bit); we do NOT
         * filter on class, so .local answers survive regardless. */
        uint16_t rdlen  = (uint16_t)((msg[pos + 8] << 8) | msg[pos + 9]);
        pos += 10u;
        if ((uint64_t)pos + rdlen > (uint64_t)len) {
            return -1;
        }
        if (type == 1u && rdlen == 4u) {            /* A -> IPv4 */
            if (emit) emit(PCV_ADDR_IPV4, &msg[pos], name, ctx);
        } else if (type == 28u && rdlen == 16u) {   /* AAAA -> IPv6 */
            if (emit) emit(PCV_ADDR_IPV6, &msg[pos], name, ctx);
        }
        /* Non-A/AAAA (and rdlen-mismatched A/AAAA): advance past rdata without
         * parsing it - never mis-map an OPT/CNAME/etc. to an IP. */
        pos += rdlen;
    }
    return 0;
}

/* ---- Hardened TLS ClientHello -> SNI parser ------------------------------
 * Self-contained and memory-safe for ANY len (tests drive it over tight
 * malloc(len) buffers under ASan, so it MUST NOT rely on any drain-time clamp).
 * A single cursor p and a bound `end` are advanced; end starts at the captured
 * length and is only ever CLAMPED DOWN (record_len, then hs_len, then
 * ext_total), never past len. The invariant p <= end is maintained at every
 * advance, so the subtraction-form need check (end - p) >= n never underflows.
 * server_name is additionally bounded by the extension's own ext_end, so a
 * hostile small elen cannot read a neighbouring extension. Any shortfall at any
 * step returns -1 (not found); never overreads, never blocks. */
int pcv_tls_parse_sni(const uint8_t* b, uint32_t len, char* out, size_t outcap) {
    if (!b || !out || outcap == 0) {
        return -1;
    }
    out[0] = '\0';

    /* (1) TLS record header. Re-assert the content type even though the hot
     * gate checked it (the SPSC ring is a trust boundary). */
    if (len < 5u || b[0] != 0x16) {
        return -1;
    }
    uint32_t record_len = ((uint32_t)b[3] << 8) | (uint32_t)b[4];
    uint32_t end = len;
    if ((uint64_t)5u + (uint64_t)record_len < (uint64_t)end) {
        end = 5u + record_len;
    }
    uint32_t p = 5u;

/* Needed-bytes check in subtraction form; valid ONLY while (pp) <= end holds. */
#define NEED(pp, nn) (((uint32_t)((end) - (pp))) >= (uint32_t)(nn))

    /* (2) ClientHello header: type(1) + 24-bit length(3). */
    if (!NEED(p, 4)) {
        return -1;
    }
    if (b[5] != 0x01) {                        /* re-assert ClientHello */
        return -1;
    }
    uint32_t hs_len = ((uint32_t)b[6] << 16) | ((uint32_t)b[7] << 8) | (uint32_t)b[8];
    if ((uint64_t)9u + (uint64_t)hs_len < (uint64_t)end) {
        end = 9u + hs_len;
    }
    p = 9u;

    /* (3) legacy_version(2) + random(32) = 34 bytes. */
    if (!NEED(p, 34)) {
        return -1;
    }
    p += 34u;

    /* (4) session_id (1-byte length prefix). */
    if (!NEED(p, 1)) {
        return -1;
    }
    uint32_t sid = b[p];
    p += 1u;
    if (!NEED(p, sid)) {
        return -1;
    }
    p += sid;

    /* (5) cipher_suites (2-byte length prefix). */
    if (!NEED(p, 2)) {
        return -1;
    }
    uint32_t cs = ((uint32_t)b[p] << 8) | (uint32_t)b[p + 1];
    p += 2u;
    if (!NEED(p, cs)) {
        return -1;
    }
    p += cs;

    /* (6) compression_methods (1-byte length prefix). */
    if (!NEED(p, 1)) {
        return -1;
    }
    uint32_t cm = b[p];
    p += 1u;
    if (!NEED(p, cm)) {
        return -1;
    }
    p += cm;

    /* (7) extensions block (2-byte total length); clamp end down to its span. */
    if (!NEED(p, 2)) {
        return -1;
    }
    uint32_t ext_total = ((uint32_t)b[p] << 8) | (uint32_t)b[p + 1];
    p += 2u;
    if ((uint64_t)p + (uint64_t)ext_total < (uint64_t)end) {
        end = p + ext_total;
    }

    /* (8) walk extensions; advance p by 4 UNCONDITIONALLY so progress is
     * guaranteed (elen==0 is legal). */
    while (NEED(p, 4)) {
        uint32_t etype = ((uint32_t)b[p] << 8) | (uint32_t)b[p + 1];
        uint32_t elen  = ((uint32_t)b[p + 2] << 8) | (uint32_t)b[p + 3];
        p += 4u;
        if (!NEED(p, elen)) {
            return -1;                         /* elen past end: reject */
        }
        uint32_t ext_end = p + elen;           /* bound for THIS extension body */

        if (etype != 0x0000u) {
            p = ext_end;                        /* skip non-server_name ext */
            continue;
        }

        /* (9) server_name extension, bounded strictly by ext_end (NOT end). */
        if ((uint32_t)(ext_end - p) < 2u) {    /* server_name_list length(2) */
            return -1;
        }
        p += 2u;                                /* list length; value unused */
        if ((uint32_t)(ext_end - p) < 3u) {    /* entry: type(1)+name_len(2) */
            return -1;
        }
        uint32_t nametype = b[p];
        uint32_t name_len = ((uint32_t)b[p + 1] << 8) | (uint32_t)b[p + 2];
        p += 3u;
        if (nametype != 0u) {                   /* host_name only */
            return -1;
        }
        /* TWO independent bounds: source (within the extension) AND dest. */
        if ((uint32_t)(ext_end - p) < name_len) {
            return -1;
        }
        if (!(name_len <= outcap - 1u && name_len <= 255u)) {
            return -1;                          /* never truncate: reject */
        }
        memcpy(out, b + p, name_len);
        out[name_len] = '\0';
        return 0;
    }

#undef NEED
    return -1;                                  /* no server_name found */
}

/* ---- Passive-DNS drain --------------------------------------------------- */

/* emit context: the resolver + a timestamp, so the emit callback can sanitize
 * and insert PASSIVE names under names_mtx. */
typedef struct {
    pcv_resolver* r;
    uint64_t now;
} passive_ctx;

static void passive_emit(uint8_t family, const uint8_t* addr, const char* name,
                         void* ctxp) {
    passive_ctx* c = (passive_ctx*)ctxp;
    char sani[PCV_NAME_MAX];
    if (sanitize_name(name, sani, sizeof(sani)) == 0) {
        return;                                /* sanitized to empty: reject */
    }
    /* names_mtx is held across a drain batch by the caller. */
    map_insert(c->r, family, addr, sani, PCV_NAME_PASSIVE, c->now);
}

void pcv_resolver_drain_once(pcv_resolver* r) {
    if (!r || !r->agg) {
        return;
    }
    struct pcv_dash_agg* agg = r->agg;

    uint32_t head = atomic_load_explicit(&agg->dns_head, memory_order_relaxed);
    uint32_t tail = atomic_load_explicit(&agg->dns_tail, memory_order_acquire);
    if (head == tail) {
        return;                                /* nothing to drain */
    }

    passive_ctx c;
    c.r = r;
    c.now = res_now_ns();

    pthread_mutex_lock(&r->names_mtx);
    while (head != tail) {
        pcv_dns_slot* slot = &agg->dns_ring[head];
        uint32_t slen = slot->len;
        if (slen > PCV_DNS_SLOT_BYTES) {
            slen = PCV_DNS_SLOT_BYTES;         /* defensive clamp */
        }
        /* Dispatch STRICTLY on the producer's kind tag so a slot reused across
         * DNS/TLS enqueues never misfeeds a payload into the wrong parser. Each
         * parser reads ONLY slot->bytes[0..slen); the DNS path never touches
         * slot->flow. */
        if (slot->kind == PCV_SLOT_TLS) {
            char host[PCV_NAME_MAX];
            if (pcv_tls_parse_sni(slot->bytes, slen, host, sizeof(host)) == 0) {
                char sani[PCV_NAME_MAX];
                if (sanitize_name(host, sani, sizeof(sani)) > 0) {
                    /* (a) PRIMARY: the per-flow side map, keyed by the EXACT
                     * captured 5-tuple (exact even on a shared CDN IP). */
                    sni_insert(r, &slot->flow, sani, c.now);
                    /* (b) FOLD: the IP->name map for the server IP (flow.dst),
                     * source SNI, so the per-IP hosts panel + cross-flow reuse
                     * get a name. Lossy on shared IPs (last-writer-wins) by
                     * design; the flow row stays exact via the side map. */
                    uint8_t fam = slot->flow.addr_family;
                    if (fam == PCV_ADDR_IPV4) {
                        map_insert(r, PCV_ADDR_IPV4, &slot->flow.dst_ip.ipv4,
                                   sani, PCV_NAME_SNI, c.now);
                    } else if (fam == PCV_ADDR_IPV6) {
                        map_insert(r, PCV_ADDR_IPV6, slot->flow.dst_ip.ipv6,
                                   sani, PCV_NAME_SNI, c.now);
                    }
                }
            }
        } else {
            pcv_dns_parse(slot->bytes, slen, passive_emit, &c);
        }
        head = (head + 1u) & PCV_DNS_RING_MASK;
    }
    pthread_mutex_unlock(&r->names_mtx);

    /* Publish the consumed head so the producer can reuse those slots. */
    atomic_store_explicit(&agg->dns_head, head, memory_order_release);
}

/* ---- Reverse-PTR fallback ------------------------------------------------ */

/* Default PTR seam: libc getnameinfo(NI_NAMEREQD) - hermetic, resolver-thread
 * only. Blocking (no per-call timeout on macOS); the running flag re-checked
 * between lookups bounds a wedged call to a single in-flight lookup. */
static int default_ptr_fn(const pcv_resolve_key* key, char* out, size_t outlen,
                          void* ctx) {
    (void)ctx;
    if (outlen == 0) {
        return -1;                 /* no room even for the NUL terminator */
    }
    char host[NI_MAXHOST];
    if (key->family == PCV_ADDR_IPV4) {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        memcpy(&sa.sin_addr, &key->a.v4, 4);
        if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host),
                        NULL, 0, NI_NAMEREQD) != 0) {
            return -1;
        }
    } else if (key->family == PCV_ADDR_IPV6) {
        struct sockaddr_in6 sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin6_family = AF_INET6;
        memcpy(&sa.sin6_addr, key->a.v6, 16);
        if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host),
                        NULL, 0, NI_NAMEREQD) != 0) {
            return -1;
        }
    } else {
        return -1;
    }
    strncpy(out, host, outlen - 1);
    out[outlen - 1] = '\0';
    return 0;
}

/* Collect the distinct endpoint IPs of the published flow snapshot, then run a
 * bounded, rate-limited reverse-PTR pass over the GLOBAL ones with no name and
 * no live negative-cache entry. running is re-checked between EVERY lookup. */
int pcv_resolver_ptr_pass(pcv_resolver* r) {
    if (!r || !r->agg || !r->ptr_fn) {
        return 0;
    }
    struct pcv_dash_agg* agg = r->agg;

    /* Copy the published snapshot under agg->mtx (we are NOT the capture thread,
     * so a blocking lock is fine - same rule the sampler/HTTP threads follow),
     * then release before any lookup. */
    static _Thread_local pcv_dash_flow_snap snap; /* resolver-thread-only scratch */
    pthread_mutex_lock(&agg->mtx);
    snap = agg->published;
    pthread_mutex_unlock(&agg->mtx);

    uint32_t n = snap.count;
    if (n > PCV_DASH_TOPN) {
        n = PCV_DASH_TOPN;
    }

    int issued = 0;
    uint64_t now = res_now_ns();

    for (uint32_t i = 0; i < n && issued < PCV_RESOLVE_PTR_PER_CYCLE; i++) {
        const pcv_flow_key_v6* k = &snap.rows[i].key;
        uint8_t family = k->addr_family;
        if (family != PCV_ADDR_IPV4 && family != PCV_ADDR_IPV6) {
            continue;
        }
        /* Both endpoints are candidates. */
        for (int side = 0; side < 2 && issued < PCV_RESOLVE_PTR_PER_CYCLE; side++) {
            if (!atomic_load_explicit(&r->running, memory_order_relaxed)) {
                return issued;                 /* prompt shutdown */
            }
            const void* addr = (side == 0)
                ? ((family == PCV_ADDR_IPV4) ? (const void*)&k->src_ip.ipv4
                                             : (const void*)k->src_ip.ipv6)
                : ((family == PCV_ADDR_IPV4) ? (const void*)&k->dst_ip.ipv4
                                             : (const void*)k->dst_ip.ipv6);

            if (!pcv_is_global_ip(family, addr)) {
                continue;
            }

            /* Eligibility gates under names_mtx: already named? cooling down? */
            int skip = 0;
            pthread_mutex_lock(&r->names_mtx);
            if (map_find(r, family, addr, now) != NULL) {
                skip = 1;
            } else if (neg_present(r, family, addr, now)) {
                skip = 1;
            }
            pthread_mutex_unlock(&r->names_mtx);
            if (skip) {
                continue;
            }

            pcv_resolve_key key;
            pcv_resolve_key_make(family, addr, &key);

            char raw[PCV_NAME_MAX];
            raw[0] = '\0';
            int rc = r->ptr_fn(&key, raw, sizeof(raw), r->ptr_ctx);
            issued++;
            uint64_t t = res_now_ns();

            if (rc == 0 && raw[0] != '\0') {
                char sani[PCV_NAME_MAX];
                if (sanitize_name(raw, sani, sizeof(sani)) > 0) {
                    pthread_mutex_lock(&r->names_mtx);
                    map_insert(r, family, addr, sani, PCV_NAME_PTR, t);
                    pthread_mutex_unlock(&r->names_mtx);
                } else {
                    pthread_mutex_lock(&r->names_mtx);
                    neg_insert(r, family, addr, t);   /* unusable name */
                    pthread_mutex_unlock(&r->names_mtx);
                }
            } else {
                pthread_mutex_lock(&r->names_mtx);
                neg_insert(r, family, addr, t);       /* NXDOMAIN / failure */
                pthread_mutex_unlock(&r->names_mtx);
            }
        }
    }
    return issued;
}

/* ---- Lifecycle + thread -------------------------------------------------- */

pcv_resolver* pcv_resolver_create(struct pcv_dash_agg* agg, pcv_ptr_fn fn,
                                  void* ctx) {
    pcv_resolver* r = calloc(1, sizeof(*r));
    if (!r) {
        return NULL;
    }
    r->agg = agg;
    r->ptr_fn = fn ? fn : default_ptr_fn;
    r->ptr_ctx = ctx;
    atomic_store_explicit(&r->running, 1, memory_order_relaxed);

    if (pthread_mutex_init(&r->names_mtx, NULL) != 0) {
        free(r);
        return NULL;
    }
    r->map = calloc(PCV_RESOLVE_MAP_CAP, sizeof(name_entry));
    r->neg = calloc(PCV_RESOLVE_NEG_CAP, sizeof(neg_entry));
    r->sni = calloc(PCV_RESOLVE_SNI_CAP, sizeof(sni_entry));
    if (!r->map || !r->neg || !r->sni) {
        free(r->map);
        free(r->neg);
        free(r->sni);
        pthread_mutex_destroy(&r->names_mtx);
        free(r);
        return NULL;
    }
    return r;
}

void pcv_resolver_stop(pcv_resolver* r) {
    if (r) {
        atomic_store_explicit(&r->running, 0, memory_order_relaxed);
    }
}

void pcv_resolver_destroy(pcv_resolver* r) {
    if (!r) {
        return;
    }
    free(r->map);
    free(r->neg);
    free(r->sni);
    pthread_mutex_destroy(&r->names_mtx);
    free(r);
}

void* pcv_resolver_thread(void* arg) {
    pcv_resolver* r = (pcv_resolver*)arg;
    if (!r) {
        return NULL;
    }

    /* PTR cadence: run a pass roughly every ~3s; drain the ring far more often
     * so passive names appear promptly. Sleep in short slices re-checking
     * running so a join is bounded (to one in-flight PTR lookup at most). */
    const int drain_slices_per_ptr = 30;       /* 30 * 100ms ~= 3s */
    int slice = 0;

    while (atomic_load_explicit(&r->running, memory_order_relaxed)) {
        pcv_resolver_drain_once(r);

        if (++slice >= drain_slices_per_ptr) {
            slice = 0;
            if (atomic_load_explicit(&r->running, memory_order_relaxed)) {
                pcv_resolver_ptr_pass(r);
            }
        }

        if (!atomic_load_explicit(&r->running, memory_order_relaxed)) {
            break;
        }
        struct timespec ts = { 0, 100 * 1000 * 1000 };  /* 100ms */
        nanosleep(&ts, NULL);
    }

    /* Final drain so names captured just before shutdown are not lost if a test
     * or caller serializes after join. */
    pcv_resolver_drain_once(r);
    return NULL;
}
