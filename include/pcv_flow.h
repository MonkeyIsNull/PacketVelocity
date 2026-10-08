#ifndef PCV_FLOW_H
#define PCV_FLOW_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "pcv_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/* PacketVelocity Flow Aggregation System */

/* Address family types */
typedef enum {
    PCV_ADDR_IPV4 = 4,
    PCV_ADDR_IPV6 = 6
} pcv_addr_family_t;

/* IP address union for IPv4/IPv6 support */
typedef union {
    uint32_t ipv4;          /* IPv4 address (network byte order) */
    uint8_t ipv6[16];       /* IPv6 address (network byte order) */
} pcv_ip_addr_t;

/* Enhanced flow key with IPv4/IPv6 support */
typedef struct pcv_flow_key_v6 {
    pcv_ip_addr_t src_ip;   /* Source IP address */
    pcv_ip_addr_t dst_ip;   /* Destination IP address */
    uint16_t src_port;      /* Source port */
    uint16_t dst_port;      /* Destination port */
    uint8_t protocol;       /* IP protocol */
    uint8_t addr_family;    /* PCV_ADDR_IPV4 or PCV_ADDR_IPV6 */
    uint16_t reserved;      /* Padding for alignment */
} pcv_flow_key_v6;

/* IPv6 extension header parsing information */
typedef struct pcv_ipv6_ext_headers {
    uint8_t has_ext_headers;     /* 1 if extension headers are present */
    uint8_t ext_header_count;    /* Number of extension headers */
    uint16_t total_ext_length;   /* Total length of all extension headers */
    uint8_t final_protocol;      /* Final protocol after all extension headers */
    
    /* Fragment header information (if present) */
    uint32_t fragment_id;        /* Fragment identification */
    uint16_t fragment_offset;    /* Fragment offset (in 8-byte units) */
    uint8_t fragment_flags;      /* Fragment flags (more fragments bit) */
    
    uint8_t reserved;            /* Padding for alignment */
} pcv_ipv6_ext_headers;

/* Legacy IPv4-only flow key for backward compatibility */
typedef struct pcv_flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint8_t reserved[3];  /* Padding for alignment */
} pcv_flow_key;

/* Flow statistics */
typedef struct pcv_flow_stats {
    pcv_flow_key key;

    /* IPv4/IPv6 5-tuple key. Populated by the IPv6-capable aggregation path
     * (pcv_flow_update_v6); the legacy IPv4 path (pcv_flow_update) leaves it
     * zeroed and uses `key` above. Kept additive so neither path disturbs the
     * other and the existing IPv4 API/tests are unchanged. */
    pcv_flow_key_v6 key6;

    /* Timing */
    uint64_t first_seen_ns;
    uint64_t last_seen_ns;
    uint64_t duration_ns;
    
    /* Counters */
    uint64_t packet_count;
    uint64_t byte_count;
    
    /* TCP flags (if applicable) */
    uint8_t tcp_flags;
    uint8_t flow_state;
    uint16_t reserved;
    
    /* Additional metadata */
    uint32_t hash;           /* Precomputed hash for quick lookups */
    uint32_t flow_id;        /* Unique flow identifier */
} pcv_flow_stats;

/* Flow states */
#define PCV_FLOW_ACTIVE     0x01
#define PCV_FLOW_TIMEOUT    0x02
#define PCV_FLOW_FINISHED   0x04

/* Hash table for flow tracking */
typedef struct pcv_flow_table {
    pcv_flow_stats* flows;
    uint32_t* buckets;       /* Hash table buckets */
    uint32_t bucket_count;   /* Number of hash buckets */
    uint32_t flow_count;     /* Current number of flows */
    uint32_t max_flows;      /* Maximum flows capacity */
    uint32_t next_flow_id;   /* Next flow ID to assign */
    
    /* Configuration */
    uint64_t timeout_ns;     /* Flow timeout in nanoseconds */
    uint32_t cleanup_interval; /* Cleanup every N packets */
    uint32_t packet_counter; /* Packet counter for cleanup */
    
    /* Statistics */
    uint64_t total_flows;
    uint64_t expired_flows;
    uint64_t hash_collisions;

    /* Optional expiry hook. When set, pcv_flow_expire_old invokes it EXACTLY
     * ONCE per flow - at the moment the flow transitions out of PCV_FLOW_ACTIVE
     * (timeout or TCP FIN). NULL by default, so existing callers see unchanged
     * behaviour. The per-flow RistrettoDB sink uses this to emit one row per
     * flow on eviction, then flushes the still-open flows at shutdown by calling
     * pcv_flow_expire_old with a future timestamp. */
    void (*on_expire)(const struct pcv_flow_stats* flow, void* user);
    void* expire_ctx;
} pcv_flow_table;

/* Flow aggregation configuration */
typedef struct pcv_flow_config {
    uint32_t max_flows;           /* Maximum concurrent flows */
    uint32_t hash_buckets;        /* Number of hash buckets */
    uint64_t flow_timeout_ms;     /* Flow timeout in milliseconds */
    uint32_t cleanup_interval;    /* Cleanup interval in packets */
    bool enable_tcp_state;        /* Track TCP connection state */
} pcv_flow_config;

/* Flow table functions */
pcv_flow_table* pcv_flow_table_create(const pcv_flow_config* config);
void pcv_flow_table_destroy(pcv_flow_table* table);

/* Flow operations - Legacy IPv4 API (keys by pcv_flow_key) */
int pcv_flow_update(pcv_flow_table* table, const pcv_packet* packet);
pcv_flow_stats* pcv_flow_lookup(pcv_flow_table* table, const pcv_flow_key* key);
int pcv_flow_expire_old(pcv_flow_table* table, uint64_t current_time_ns);

/* Flow operations - IPv4/IPv6 API (keys by pcv_flow_key_v6). Aggregates the
 * same pcv_flow_stats into the same table, but tracks the full IPv4/IPv6
 * 5-tuple so IPv6 flows are supported. A given table must be driven by only one
 * of the two update APIs. */
int pcv_flow_update_v6(pcv_flow_table* table, const pcv_packet* packet);
pcv_flow_stats* pcv_flow_lookup_v6(pcv_flow_table* table, const pcv_flow_key_v6* key);

/* Register an optional expiry hook (see pcv_flow_table.on_expire). Passing NULL
 * clears it. Returns 0 on success, -1 on a NULL table. */
int pcv_flow_table_set_expire_cb(pcv_flow_table* table,
                                 void (*cb)(const pcv_flow_stats* flow, void* user),
                                 void* user);

/* Flow key extraction - Legacy IPv4 API */
int pcv_flow_extract_key(const pcv_packet* packet, pcv_flow_key* key);
uint32_t pcv_flow_hash_key(const pcv_flow_key* key);

/* Flow key extraction - Enhanced IPv4/IPv6 API */
int pcv_flow_extract_key_v6(const pcv_packet* packet, pcv_flow_key_v6* key);
uint32_t pcv_flow_hash_key_v6(const pcv_flow_key_v6* key);

/* IPv6 extension header parsing */
int pcv_parse_ipv6_ext_headers(const pcv_packet* packet, pcv_ipv6_ext_headers* ext_info);

/* Key conversion utilities */
int pcv_flow_key_v4_to_v6(const pcv_flow_key* v4_key, pcv_flow_key_v6* v6_key);
int pcv_flow_key_v6_to_v4(const pcv_flow_key_v6* v6_key, pcv_flow_key* v4_key);

/* Utility functions - Legacy IPv4 */
void pcv_flow_key_to_string(const pcv_flow_key* key, char* buffer, size_t size);
int pcv_flow_key_compare(const pcv_flow_key* a, const pcv_flow_key* b);

/* Utility functions - Enhanced IPv4/IPv6 */
void pcv_flow_key_v6_to_string(const pcv_flow_key_v6* key, char* buffer, size_t size);
int pcv_flow_key_v6_compare(const pcv_flow_key_v6* a, const pcv_flow_key_v6* b);

/* Render a SINGLE endpoint address (no port/brackets) into buf. */
void pcv_flow_addr_to_string(uint8_t addr_family, const pcv_ip_addr_t* addr,
                             char* buf, size_t size);

/* L4-header byte offset (from the Ethernet frame start) + resolved L4 protocol,
 * fully bounds-checked against the CAPTURED length (returns false rather than an
 * out-of-range offset). Promoted from the flow TU for the hot-path passive-DNS
 * enqueue; callers still re-check that their specific L4 fields fit. */
bool pcv_l4_header_offset(const pcv_packet* packet, uint32_t* out_off,
                          uint8_t* out_proto);

/* Flow iteration for bulk operations */
typedef void (*pcv_flow_iterator)(const pcv_flow_stats* flow, void* user_data);
int pcv_flow_iterate(pcv_flow_table* table, pcv_flow_iterator callback, void* user_data);

#ifdef __cplusplus
}
#endif

#endif /* PCV_FLOW_H */
