#include "pcv_flow.h"
#include "pcv_platform.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

/* FNV-1a hash function for flow keys */
#define FNV_PRIME_32 0x01000193
#define FNV_OFFSET_32 0x811c9dc5

static uint32_t fnv1a_hash(const void* data, size_t len) {
    const uint8_t* bytes = (const uint8_t*)data;
    uint32_t hash = FNV_OFFSET_32;
    
    for (size_t i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= FNV_PRIME_32;
    }
    
    return hash;
}

/* Hash flow key */
uint32_t pcv_flow_hash_key(const pcv_flow_key* key) {
    return fnv1a_hash(key, sizeof(pcv_flow_key));
}

/* Compare flow keys */
int pcv_flow_key_compare(const pcv_flow_key* a, const pcv_flow_key* b) {
    return memcmp(a, b, sizeof(pcv_flow_key));
}

/* Extract flow key from packet */
int pcv_flow_extract_key(const pcv_packet* packet, pcv_flow_key* key) {
    const uint8_t* data = packet->data;
    uint32_t len = packet->captured_length;
    
    /* Clear key */
    memset(key, 0, sizeof(pcv_flow_key));
    
    /* Need at least Ethernet + IP headers */
    if (len < 34) {
        return -1;
    }
    
    /* Skip Ethernet header (14 bytes) */
    const uint8_t* ip_header = data + 14;
    
    /* Check IP version */
    uint8_t version = (ip_header[0] >> 4) & 0x0F;
    if (version != 4) {
        return -1;  /* Only IPv4 for now */
    }
    
    /* Extract IP addresses */
    memcpy(&key->src_ip, ip_header + 12, 4);
    memcpy(&key->dst_ip, ip_header + 16, 4);
    
    /* Extract protocol */
    key->protocol = ip_header[9];
    
    /* Extract ports for TCP/UDP */
    if (key->protocol == 6 || key->protocol == 17) {  /* TCP or UDP */
        uint8_t ip_header_len = (ip_header[0] & 0x0F) * 4;
        if (len >= 14 + ip_header_len + 4) {
            const uint8_t* transport_header = ip_header + ip_header_len;
            memcpy(&key->src_port, transport_header, 2);
            memcpy(&key->dst_port, transport_header + 2, 2);
            key->src_port = ntohs(key->src_port);
            key->dst_port = ntohs(key->dst_port);
        }
    }
    
    return 0;
}

/* Create flow table */
pcv_flow_table* pcv_flow_table_create(const pcv_flow_config* config) {
    pcv_flow_table* table;
    
    if (!config || config->max_flows == 0) {
        return NULL;
    }
    
    table = calloc(1, sizeof(pcv_flow_table));
    if (!table) {
        return NULL;
    }
    
    /* Allocate flows array */
    table->flows = calloc(config->max_flows, sizeof(pcv_flow_stats));
    if (!table->flows) {
        free(table);
        return NULL;
    }
    
    /* Allocate hash buckets */
    table->bucket_count = config->hash_buckets;
    table->buckets = malloc(table->bucket_count * sizeof(uint32_t));
    if (!table->buckets) {
        free(table->flows);
        free(table);
        return NULL;
    }
    
    /* Initialize buckets to empty */
    for (uint32_t i = 0; i < table->bucket_count; i++) {
        table->buckets[i] = UINT32_MAX;  /* Empty bucket marker */
    }
    
    /* Set configuration */
    table->max_flows = config->max_flows;
    table->timeout_ns = config->flow_timeout_ms * 1000000ULL;
    table->cleanup_interval = config->cleanup_interval;
    table->next_flow_id = 1;
    
    return table;
}

/* Destroy flow table */
void pcv_flow_table_destroy(pcv_flow_table* table) {
    if (!table) return;
    
    free(table->flows);
    free(table->buckets);
    free(table);
}

/* Find flow in hash table */
static pcv_flow_stats* flow_table_find(pcv_flow_table* table, const pcv_flow_key* key) {
    uint32_t hash = pcv_flow_hash_key(key);
    uint32_t bucket = hash % table->bucket_count;
    uint32_t flow_idx = table->buckets[bucket];
    
    while (flow_idx != UINT32_MAX) {
        pcv_flow_stats* flow = &table->flows[flow_idx];
        if (pcv_flow_key_compare(&flow->key, key) == 0) {
            return flow;
        }
        
        /* Linear probing for collision resolution */
        bucket = (bucket + 1) % table->bucket_count;
        flow_idx = table->buckets[bucket];
        
        /* Avoid infinite loop */
        if (bucket == (hash % table->bucket_count)) {
            break;
        }
    }
    
    return NULL;
}

/* Insert new flow into hash table */
static pcv_flow_stats* flow_table_insert(pcv_flow_table* table, const pcv_flow_key* key) {
    if (table->flow_count >= table->max_flows) {
        return NULL;  /* Table full */
    }
    
    uint32_t hash = pcv_flow_hash_key(key);
    uint32_t bucket = hash % table->bucket_count;
    uint32_t flow_idx = table->flow_count;
    
    /* Find empty bucket using linear probing */
    while (table->buckets[bucket] != UINT32_MAX) {
        bucket = (bucket + 1) % table->bucket_count;
        table->hash_collisions++;
        
        /* Avoid infinite loop */
        if (bucket == (hash % table->bucket_count)) {
            return NULL;  /* No empty buckets */
        }
    }
    
    /* Initialize new flow */
    pcv_flow_stats* flow = &table->flows[flow_idx];
    memset(flow, 0, sizeof(pcv_flow_stats));
    flow->key = *key;
    flow->hash = hash;
    flow->flow_id = table->next_flow_id++;
    flow->flow_state = PCV_FLOW_ACTIVE;
    
    /* Insert into hash table */
    table->buckets[bucket] = flow_idx;
    table->flow_count++;
    table->total_flows++;
    
    return flow;
}

/* Look up flow by key */
pcv_flow_stats* pcv_flow_lookup(pcv_flow_table* table, const pcv_flow_key* key) {
    if (!table || !key) {
        return NULL;
    }
    
    return flow_table_find(table, key);
}

/* Update flow with new packet */
int pcv_flow_update(pcv_flow_table* table, const pcv_packet* packet) {
    pcv_flow_key key;
    pcv_flow_stats* flow;
    
    if (!table || !packet) {
        return -1;
    }
    
    /* Extract flow key from packet */
    if (pcv_flow_extract_key(packet, &key) < 0) {
        return -1;
    }
    
    /* Find existing flow or create new one */
    flow = flow_table_find(table, &key);
    if (!flow) {
        flow = flow_table_insert(table, &key);
        if (!flow) {
            return -1;  /* Failed to create flow */
        }
        
        /* Initialize flow timing */
        flow->first_seen_ns = packet->timestamp_ns;
    }
    
    /* Update flow statistics */
    flow->last_seen_ns = packet->timestamp_ns;
    flow->duration_ns = flow->last_seen_ns - flow->first_seen_ns;
    flow->packet_count++;
    flow->byte_count += packet->captured_length;
    
    /* Update TCP flags if applicable */
    if (key.protocol == 6 && packet->captured_length >= 34) {  /* TCP */
        const uint8_t* ip_header = packet->data + 14;
        uint8_t ip_header_len = (ip_header[0] & 0x0F) * 4;
        if (packet->captured_length >= 14 + ip_header_len + 14) {
            const uint8_t* tcp_header = ip_header + ip_header_len;
            uint8_t tcp_flags = tcp_header[13];
            flow->tcp_flags |= tcp_flags;
            
            /* Update flow state based on TCP flags */
            if (tcp_flags & 0x01) {  /* FIN */
                flow->flow_state |= PCV_FLOW_FINISHED;
            }
        }
    }
    
    /* Periodic cleanup */
    table->packet_counter++;
    if (table->packet_counter >= table->cleanup_interval) {
        pcv_flow_expire_old(table, packet->timestamp_ns);
        table->packet_counter = 0;
    }
    
    return 0;
}

/* Expire old flows */
int pcv_flow_expire_old(pcv_flow_table* table, uint64_t current_time_ns) {
    uint32_t expired = 0;
    
    if (!table) {
        return -1;
    }
    
    for (uint32_t i = 0; i < table->flow_count; i++) {
        pcv_flow_stats* flow = &table->flows[i];
        
        /* Check if flow has timed out */
        if (flow->flow_state & PCV_FLOW_ACTIVE) {
            uint64_t age_ns = current_time_ns - flow->last_seen_ns;
            if (age_ns > table->timeout_ns || (flow->flow_state & PCV_FLOW_FINISHED)) {
                flow->flow_state |= PCV_FLOW_TIMEOUT;
                flow->flow_state &= ~PCV_FLOW_ACTIVE;
                expired++;
            }
        }
    }
    
    table->expired_flows += expired;
    return expired;
}

/* Convert flow key to string */
void pcv_flow_key_to_string(const pcv_flow_key* key, char* buffer, size_t size) {
    char src_ip[16], dst_ip[16];
    
    /* Convert IP addresses to string */
    inet_ntop(AF_INET, &key->src_ip, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &key->dst_ip, dst_ip, sizeof(dst_ip));
    
    snprintf(buffer, size, "%s:%u -> %s:%u (%u)",
             src_ip, key->src_port,
             dst_ip, key->dst_port,
             key->protocol);
}

/* Iterate over all flows */
int pcv_flow_iterate(pcv_flow_table* table, pcv_flow_iterator callback, void* user_data) {
    if (!table || !callback) {
        return -1;
    }
    
    for (uint32_t i = 0; i < table->flow_count; i++) {
        callback(&table->flows[i], user_data);
    }
    
    return table->flow_count;
}
