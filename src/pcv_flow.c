#ifdef __linux__
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L  /* For strdup and other POSIX functions */
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE  /* For additional system functions */
#endif
#endif

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

/* =============================================================================
 * IPv6 Support Functions
 * ============================================================================= */

/* Check if protocol is an IPv6 extension header */
static bool is_ipv6_extension_header(uint8_t protocol) {
    switch (protocol) {
        case 0:   /* Hop-by-Hop Options Header */
        case 43:  /* Routing Header */
        case 44:  /* Fragment Header */
        case 51:  /* Authentication Header */
        case 60:  /* Destination Options Header */
        case 135: /* Mobility Header */
            return true;
        default:
            return false;
    }
}

/* Get length of IPv6 extension header */
static uint16_t get_ipv6_extension_header_length(uint8_t protocol, const uint8_t* header) {
    switch (protocol) {
        case 0:   /* Hop-by-Hop Options Header */
        case 60:  /* Destination Options Header */
            /* Length is in 8-byte units, excluding first 8 bytes */
            return (header[1] + 1) * 8;
            
        case 43:  /* Routing Header */
            /* Length is in 8-byte units, excluding first 8 bytes */
            return (header[1] + 1) * 8;
            
        case 44:  /* Fragment Header */
            /* Fixed length of 8 bytes */
            return 8;
            
        case 51:  /* Authentication Header */
            /* Length is in 4-byte units, excluding first 2 units (8 bytes) */
            return (header[1] + 2) * 4;
            
        case 135: /* Mobility Header */
            /* Length field is total header length minus 8 bytes */
            return header[1] + 8;
            
        default:
            return 0;  /* Unknown extension header */
    }
}

/* Parse IPv6 extension headers and extract detailed information */
int pcv_parse_ipv6_ext_headers(const pcv_packet* packet, pcv_ipv6_ext_headers* ext_info) {
    const uint8_t* data = packet->data;
    uint32_t len = packet->captured_length;
    
    /* Clear extension header info */
    memset(ext_info, 0, sizeof(pcv_ipv6_ext_headers));
    
    /* Need at least Ethernet + IPv6 header */
    if (len < 54) {
        return -1;
    }
    
    /* Skip Ethernet header (14 bytes) */
    const uint8_t* ip_header = data + 14;
    
    /* Check IP version - must be IPv6 */
    uint8_t version = (ip_header[0] >> 4) & 0x0F;
    if (version != 6) {
        return -1;  /* Not IPv6 */
    }
    
    /* Start parsing from IPv6 next header field */
    uint8_t next_header = ip_header[6];
    uint16_t offset = 40;  /* IPv6 header is fixed 40 bytes */
    
    ext_info->final_protocol = next_header;
    
    /* Parse extension headers */
    while (is_ipv6_extension_header(next_header) && (14 + offset) < len) {
        if ((14 + offset + 2) > len) {
            break;  /* Not enough data for extension header */
        }
        
        const uint8_t* ext_header = ip_header + offset;
        uint16_t ext_len = get_ipv6_extension_header_length(next_header, ext_header);
        
        if (ext_len == 0 || (offset + ext_len) > (len - 14)) {
            break;  /* Invalid extension header */
        }
        
        ext_info->has_ext_headers = 1;
        ext_info->ext_header_count++;
        ext_info->total_ext_length += ext_len;
        
        /* Handle specific extension header types */
        switch (next_header) {
            case 44: /* Fragment Header */
                /* Extract fragment information */
                if (ext_len >= 8) {
                    /* Fragment header format:
                     * 0: Next Header
                     * 1: Reserved
                     * 2-3: Fragment Offset and Flags (network byte order)
                     * 4-7: Identification (network byte order)
                     */
                    uint16_t frag_info = ntohs(*(uint16_t*)(ext_header + 2));
                    ext_info->fragment_offset = (frag_info >> 3) & 0x1FFF;  /* 13 bits */
                    ext_info->fragment_flags = frag_info & 0x0007;          /* 3 bits */
                    ext_info->fragment_id = ntohl(*(uint32_t*)(ext_header + 4));
                }
                break;
                
            case 51: /* Authentication Header */
                /* AH has variable length based on authentication data */
                break;
                
            case 0:   /* Hop-by-Hop Options */
            case 60:  /* Destination Options */
                /* Options headers contain variable TLV options */
                break;
                
            case 43:  /* Routing Header */
                /* Routing header contains routing information */
                break;
                
            case 135: /* Mobility Header */
                /* Mobile IPv6 header */
                break;
        }
        
        /* Move to next header */
        next_header = ext_header[0];
        offset += ext_len;
        ext_info->final_protocol = next_header;
    }
    
    return 0;
}

/* Extract flow key from packet with IPv4/IPv6 support */
int pcv_flow_extract_key_v6(const pcv_packet* packet, pcv_flow_key_v6* key) {
    const uint8_t* data = packet->data;
    uint32_t len = packet->captured_length;
    
    /* Clear key */
    memset(key, 0, sizeof(pcv_flow_key_v6));
    
    /* Need at least Ethernet + minimum IP headers */
    if (len < 34) {
        return -1;
    }
    
    /* Skip Ethernet header (14 bytes) */
    const uint8_t* ip_header = data + 14;
    
    /* Check IP version */
    uint8_t version = (ip_header[0] >> 4) & 0x0F;
    
    if (version == 4) {
        /* IPv4 packet processing */
        key->addr_family = PCV_ADDR_IPV4;
        
        /* Extract IPv4 addresses (network byte order) */
        memcpy(&key->src_ip.ipv4, ip_header + 12, 4);
        memcpy(&key->dst_ip.ipv4, ip_header + 16, 4);
        
        /* Extract protocol */
        key->protocol = ip_header[9];
        
        /* Extract ports for TCP/UDP */
        if (key->protocol == 6 || key->protocol == 17) {  /* TCP or UDP */
            uint8_t ip_header_len = (ip_header[0] & 0x0F) * 4;
            if (len >= 14 + ip_header_len + 4) {
                const uint8_t* transport_header = ip_header + ip_header_len;
                key->src_port = ntohs(*(uint16_t*)transport_header);
                key->dst_port = ntohs(*(uint16_t*)(transport_header + 2));
            }
        }
        
    } else if (version == 6) {
        /* IPv6 packet processing */
        if (len < 54) {  /* Ethernet + IPv6 header + ports = 54 bytes minimum */
            return -1;
        }
        
        key->addr_family = PCV_ADDR_IPV6;
        
        /* Extract IPv6 addresses (network byte order) */
        memcpy(key->src_ip.ipv6, ip_header + 8, 16);   /* IPv6 source at offset 8 */
        memcpy(key->dst_ip.ipv6, ip_header + 24, 16);  /* IPv6 dest at offset 24 */
        
        /* Start with next header field */
        uint8_t next_header = ip_header[6];
        uint16_t offset = 40;  /* IPv6 header is fixed 40 bytes */
        
        /* Skip extension headers to find final protocol */
        while (is_ipv6_extension_header(next_header) && (14 + offset) < len) {
            if ((14 + offset + 2) > len) {
                break;  /* Not enough data for extension header */
            }
            
            const uint8_t* ext_header = ip_header + offset;
            uint16_t ext_len = get_ipv6_extension_header_length(next_header, ext_header);
            
            if (ext_len == 0 || (offset + ext_len) > len) {
                break;  /* Invalid extension header */
            }
            
            next_header = ext_header[0];  /* Next header field */
            offset += ext_len;
        }
        
        key->protocol = next_header;
        
        /* Extract ports for TCP/UDP */
        if ((next_header == 6 || next_header == 17) && (14 + offset + 4) <= len) {
            const uint8_t* transport_header = ip_header + offset;
            key->src_port = ntohs(*(uint16_t*)transport_header);
            key->dst_port = ntohs(*(uint16_t*)(transport_header + 2));
        }
        
    } else {
        return -1;  /* Unsupported IP version */
    }
    
    return 0;
}

/* Hash flow key with IPv6 support */
uint32_t pcv_flow_hash_key_v6(const pcv_flow_key_v6* key) {
    uint32_t hash = FNV_OFFSET_32;
    
    /* Hash IP addresses based on family */
    if (key->addr_family == PCV_ADDR_IPV4) {
        /* Hash IPv4 addresses */
        hash ^= (key->src_ip.ipv4 >> 24) & 0xFF; hash *= FNV_PRIME_32;
        hash ^= (key->src_ip.ipv4 >> 16) & 0xFF; hash *= FNV_PRIME_32;
        hash ^= (key->src_ip.ipv4 >> 8) & 0xFF;  hash *= FNV_PRIME_32;
        hash ^= key->src_ip.ipv4 & 0xFF;         hash *= FNV_PRIME_32;
        
        hash ^= (key->dst_ip.ipv4 >> 24) & 0xFF; hash *= FNV_PRIME_32;
        hash ^= (key->dst_ip.ipv4 >> 16) & 0xFF; hash *= FNV_PRIME_32;
        hash ^= (key->dst_ip.ipv4 >> 8) & 0xFF;  hash *= FNV_PRIME_32;
        hash ^= key->dst_ip.ipv4 & 0xFF;         hash *= FNV_PRIME_32;
    } else if (key->addr_family == PCV_ADDR_IPV6) {
        /* Hash IPv6 addresses */
        for (int i = 0; i < 16; i++) {
            hash ^= key->src_ip.ipv6[i]; hash *= FNV_PRIME_32;
        }
        for (int i = 0; i < 16; i++) {
            hash ^= key->dst_ip.ipv6[i]; hash *= FNV_PRIME_32;
        }
    }
    
    /* Hash ports and protocol */
    hash ^= (key->src_port >> 8) & 0xFF; hash *= FNV_PRIME_32;
    hash ^= key->src_port & 0xFF;        hash *= FNV_PRIME_32;
    hash ^= (key->dst_port >> 8) & 0xFF; hash *= FNV_PRIME_32;
    hash ^= key->dst_port & 0xFF;        hash *= FNV_PRIME_32;
    hash ^= key->protocol;               hash *= FNV_PRIME_32;
    hash ^= key->addr_family;            hash *= FNV_PRIME_32;
    
    return hash;
}

/* Compare flow keys with IPv6 support */
int pcv_flow_key_v6_compare(const pcv_flow_key_v6* a, const pcv_flow_key_v6* b) {
    /* First check address family */
    if (a->addr_family != b->addr_family) {
        return a->addr_family - b->addr_family;
    }
    
    /* Compare IP addresses based on family */
    int ip_cmp;
    if (a->addr_family == PCV_ADDR_IPV4) {
        ip_cmp = memcmp(&a->src_ip.ipv4, &b->src_ip.ipv4, 4);
        if (ip_cmp != 0) return ip_cmp;
        ip_cmp = memcmp(&a->dst_ip.ipv4, &b->dst_ip.ipv4, 4);
        if (ip_cmp != 0) return ip_cmp;
    } else if (a->addr_family == PCV_ADDR_IPV6) {
        ip_cmp = memcmp(a->src_ip.ipv6, b->src_ip.ipv6, 16);
        if (ip_cmp != 0) return ip_cmp;
        ip_cmp = memcmp(a->dst_ip.ipv6, b->dst_ip.ipv6, 16);
        if (ip_cmp != 0) return ip_cmp;
    }
    
    /* Compare ports and protocol */
    if (a->src_port != b->src_port) return a->src_port - b->src_port;
    if (a->dst_port != b->dst_port) return a->dst_port - b->dst_port;
    if (a->protocol != b->protocol) return a->protocol - b->protocol;
    
    return 0;
}

/* Convert IPv6 flow key to string */
void pcv_flow_key_v6_to_string(const pcv_flow_key_v6* key, char* buffer, size_t size) {
    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
    
    if (key->addr_family == PCV_ADDR_IPV4) {
        /* Format IPv4 addresses */
        inet_ntop(AF_INET, &key->src_ip.ipv4, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &key->dst_ip.ipv4, dst_ip, sizeof(dst_ip));
        
        snprintf(buffer, size, "%s:%u -> %s:%u (%u)",
                 src_ip, key->src_port,
                 dst_ip, key->dst_port,
                 key->protocol);
    } else if (key->addr_family == PCV_ADDR_IPV6) {
        /* Format IPv6 addresses */
        inet_ntop(AF_INET6, key->src_ip.ipv6, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET6, key->dst_ip.ipv6, dst_ip, sizeof(dst_ip));
        
        snprintf(buffer, size, "[%s]:%u -> [%s]:%u (%u)",
                 src_ip, key->src_port,
                 dst_ip, key->dst_port,
                 key->protocol);
    } else {
        snprintf(buffer, size, "unknown address family");
    }
}

/* Convert IPv4 key to IPv6 key format */
int pcv_flow_key_v4_to_v6(const pcv_flow_key* v4_key, pcv_flow_key_v6* v6_key) {
    if (!v4_key || !v6_key) {
        return -1;
    }
    
    memset(v6_key, 0, sizeof(pcv_flow_key_v6));
    
    v6_key->addr_family = PCV_ADDR_IPV4;
    v6_key->src_ip.ipv4 = v4_key->src_ip;
    v6_key->dst_ip.ipv4 = v4_key->dst_ip;
    v6_key->src_port = v4_key->src_port;
    v6_key->dst_port = v4_key->dst_port;
    v6_key->protocol = v4_key->protocol;
    
    return 0;
}

/* Convert IPv6 key to IPv4 key format (only works for IPv4 addresses) */
int pcv_flow_key_v6_to_v4(const pcv_flow_key_v6* v6_key, pcv_flow_key* v4_key) {
    if (!v6_key || !v4_key) {
        return -1;
    }
    
    /* Only convert if it's actually an IPv4 address */
    if (v6_key->addr_family != PCV_ADDR_IPV4) {
        return -1;
    }
    
    memset(v4_key, 0, sizeof(pcv_flow_key));
    
    v4_key->src_ip = v6_key->src_ip.ipv4;
    v4_key->dst_ip = v6_key->dst_ip.ipv4;
    v4_key->src_port = v6_key->src_port;
    v4_key->dst_port = v6_key->dst_port;
    v4_key->protocol = v6_key->protocol;
    
    return 0;
}
