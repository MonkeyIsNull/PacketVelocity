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

/* Flow key for 5-tuple identification */
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

/* Flow operations */
int pcv_flow_update(pcv_flow_table* table, const pcv_packet* packet);
pcv_flow_stats* pcv_flow_lookup(pcv_flow_table* table, const pcv_flow_key* key);
int pcv_flow_expire_old(pcv_flow_table* table, uint64_t current_time_ns);

/* Flow key extraction */
int pcv_flow_extract_key(const pcv_packet* packet, pcv_flow_key* key);
uint32_t pcv_flow_hash_key(const pcv_flow_key* key);

/* Utility functions */
void pcv_flow_key_to_string(const pcv_flow_key* key, char* buffer, size_t size);
int pcv_flow_key_compare(const pcv_flow_key* a, const pcv_flow_key* b);

/* Flow iteration for bulk operations */
typedef void (*pcv_flow_iterator)(const pcv_flow_stats* flow, void* user_data);
int pcv_flow_iterate(pcv_flow_table* table, pcv_flow_iterator callback, void* user_data);

#ifdef __cplusplus
}
#endif

#endif /* PCV_FLOW_H */
