#ifndef PCV_OUTPUT_H
#define PCV_OUTPUT_H

#include <stdint.h>
#include <stdbool.h>
#include "pcv_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/* PacketVelocity Output Interface */

/* Output types */
typedef enum pcv_output_type {
    PCV_OUTPUT_RISTRETTO,
    PCV_OUTPUT_PCAP,
    PCV_OUTPUT_JSON,
    PCV_OUTPUT_BINARY,
    PCV_OUTPUT_CUSTOM
} pcv_output_type;

/* Flow tuple for aggregation */
typedef struct pcv_flow_tuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} pcv_flow_tuple;

/* Flow statistics */
typedef struct pcv_flow_stats {
    pcv_flow_tuple tuple;
    uint64_t first_seen_ns;
    uint64_t last_seen_ns;
    uint64_t packet_count;
    uint64_t byte_count;
    uint32_t flags;
} pcv_flow_stats;

/* Output context */
typedef struct pcv_output {
    pcv_output_type type;
    void* context;
    
    /* Buffering */
    pcv_flow_stats* flow_buffer;
    size_t flow_buffer_size;
    size_t flow_count;
    
    /* Configuration */
    uint32_t flush_interval_ms;
    uint32_t max_flows;
    
    /* Statistics */
    uint64_t total_flows;
    uint64_t total_packets;
    uint64_t total_bytes;
} pcv_output;

/* Output functions */

/* Create output handler */
pcv_output* pcv_output_create(pcv_output_type type, const char* target);

/* Destroy output handler */
void pcv_output_destroy(pcv_output* output);

/* Process packet */
int pcv_output_packet(pcv_output* output, const pcv_packet* packet);

/* Flush buffered data */
int pcv_output_flush(pcv_output* output);

/* Get output statistics */
void pcv_output_get_stats(const pcv_output* output, uint64_t* flows,
                          uint64_t* packets, uint64_t* bytes);

/* RistrettoDB specific */
int pcv_output_ristretto_init(const char* connection_string);
void pcv_output_ristretto_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* PCV_OUTPUT_H */
