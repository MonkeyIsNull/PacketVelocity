#include "pcv_output.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* RistrettoDB output stub implementation
 * This is a placeholder for actual RistrettoDB integration
 * Replace with real implementation using:
 * https://github.com/MonkeyIsNull/RistrettoDB
 */

typedef struct pcv_ristretto_context {
    char* connection_string;
    FILE* log_file;  /* For now, just log to file */
    time_t last_flush;
} pcv_ristretto_context;

/* Hash function for flow tuple */
static uint32_t flow_hash(const pcv_flow_tuple* tuple) {
    uint32_t hash = tuple->src_ip;
    hash ^= tuple->dst_ip << 16;
    hash ^= tuple->src_port;
    hash ^= tuple->dst_port << 16;
    hash ^= tuple->protocol << 24;
    return hash;
}

/* Compare flow tuples */
static int flow_compare(const pcv_flow_tuple* a, const pcv_flow_tuple* b) {
    if (a->src_ip != b->src_ip) return a->src_ip - b->src_ip;
    if (a->dst_ip != b->dst_ip) return a->dst_ip - b->dst_ip;
    if (a->src_port != b->src_port) return a->src_port - b->src_port;
    if (a->dst_port != b->dst_port) return a->dst_port - b->dst_port;
    return a->protocol - b->protocol;
}

/* Extract flow tuple from packet (simplified) */
static int extract_flow_tuple(const pcv_packet* packet, pcv_flow_tuple* tuple) {
    /* This is a simplified extraction - real implementation would parse headers */
    if (packet->captured_length < 34) {  /* Min Ethernet + IP headers */
        return -1;
    }
    
    /* Skip Ethernet header (14 bytes) */
    const uint8_t* ip_header = packet->data + 14;
    
    /* Extract IP addresses (assuming IPv4) */
    tuple->src_ip = *(uint32_t*)(ip_header + 12);
    tuple->dst_ip = *(uint32_t*)(ip_header + 16);
    
    /* Extract protocol */
    tuple->protocol = ip_header[9];
    
    /* Extract ports if TCP/UDP */
    if (tuple->protocol == 6 || tuple->protocol == 17) {
        uint8_t ip_header_len = (ip_header[0] & 0x0F) * 4;
        const uint8_t* transport_header = ip_header + ip_header_len;
        tuple->src_port = ntohs(*(uint16_t*)transport_header);
        tuple->dst_port = ntohs(*(uint16_t*)(transport_header + 2));
    } else {
        tuple->src_port = 0;
        tuple->dst_port = 0;
    }
    
    return 0;
}

/* Find or create flow in buffer */
static pcv_flow_stats* find_or_create_flow(pcv_output* output, const pcv_flow_tuple* tuple) {
    /* Simple linear search - real implementation would use hash table */
    for (size_t i = 0; i < output->flow_count; i++) {
        if (flow_compare(&output->flow_buffer[i].tuple, tuple) == 0) {
            return &output->flow_buffer[i];
        }
    }
    
    /* Create new flow if space available */
    if (output->flow_count < output->flow_buffer_size) {
        pcv_flow_stats* flow = &output->flow_buffer[output->flow_count++];
        memset(flow, 0, sizeof(*flow));
        flow->tuple = *tuple;
        return flow;
    }
    
    return NULL;
}

/* Create output handler */
pcv_output* pcv_output_create(pcv_output_type type, const char* target) {
    pcv_output* output;
    pcv_ristretto_context* ctx;
    
    if (type != PCV_OUTPUT_RISTRETTO) {
        return NULL;
    }
    
    output = calloc(1, sizeof(pcv_output));
    if (!output) {
        return NULL;
    }
    
    ctx = calloc(1, sizeof(pcv_ristretto_context));
    if (!ctx) {
        free(output);
        return NULL;
    }
    
    /* Initialize output */
    output->type = type;
    output->context = ctx;
    output->flush_interval_ms = 100;  /* 100ms default */
    output->max_flows = 10000;
    
    /* Allocate flow buffer */
    output->flow_buffer_size = 1000;
    output->flow_buffer = calloc(output->flow_buffer_size, sizeof(pcv_flow_stats));
    if (!output->flow_buffer) {
        free(ctx);
        free(output);
        return NULL;
    }
    
    /* Save connection string */
    ctx->connection_string = strdup(target ? target : "ristretto.log");
    
    /* Open log file (stub implementation) */
    ctx->log_file = fopen(ctx->connection_string, "a");
    if (!ctx->log_file) {
        ctx->log_file = stdout;  /* Fallback to stdout */
    }
    
    ctx->last_flush = time(NULL);
    
    /* Log header */
    fprintf(ctx->log_file, "# RistrettoDB Output Stub - PacketVelocity\n");
    fprintf(ctx->log_file, "# timestamp,src_ip,dst_ip,src_port,dst_port,protocol,packets,bytes\n");
    
    return output;
}

/* Destroy output handler */
void pcv_output_destroy(pcv_output* output) {
    if (!output) return;
    
    /* Flush any remaining data */
    pcv_output_flush(output);
    
    if (output->type == PCV_OUTPUT_RISTRETTO && output->context) {
        pcv_ristretto_context* ctx = output->context;
        
        if (ctx->log_file && ctx->log_file != stdout) {
            fclose(ctx->log_file);
        }
        
        free(ctx->connection_string);
        free(ctx);
    }
    
    free(output->flow_buffer);
    free(output);
}

/* Process packet */
int pcv_output_packet(pcv_output* output, const pcv_packet* packet) {
    pcv_flow_tuple tuple;
    pcv_flow_stats* flow;
    pcv_ristretto_context* ctx;
    time_t now;
    
    if (!output || !packet) {
        return -1;
    }
    
    /* Extract flow tuple */
    if (extract_flow_tuple(packet, &tuple) < 0) {
        return -1;
    }
    
    /* Find or create flow */
    flow = find_or_create_flow(output, &tuple);
    if (!flow) {
        /* Buffer full, flush and retry */
        pcv_output_flush(output);
        flow = find_or_create_flow(output, &tuple);
        if (!flow) {
            return -1;
        }
    }
    
    /* Update flow statistics */
    if (flow->packet_count == 0) {
        flow->first_seen_ns = packet->timestamp_ns;
    }
    flow->last_seen_ns = packet->timestamp_ns;
    flow->packet_count++;
    flow->byte_count += packet->captured_length;
    
    /* Update totals */
    output->total_packets++;
    output->total_bytes += packet->captured_length;
    
    /* Check if flush needed */
    ctx = output->context;
    now = time(NULL);
    if ((now - ctx->last_flush) * 1000 >= output->flush_interval_ms) {
        pcv_output_flush(output);
        ctx->last_flush = now;
    }
    
    return 0;
}

/* Flush buffered data */
int pcv_output_flush(pcv_output* output) {
    pcv_ristretto_context* ctx;
    char src_ip[16], dst_ip[16];
    
    if (!output || output->flow_count == 0) {
        return 0;
    }
    
    ctx = output->context;
    
    /* Write flows to log (stub implementation) */
    for (size_t i = 0; i < output->flow_count; i++) {
        pcv_flow_stats* flow = &output->flow_buffer[i];
        
        /* Format IP addresses */
        snprintf(src_ip, sizeof(src_ip), "%d.%d.%d.%d",
                 (flow->tuple.src_ip >> 0) & 0xFF,
                 (flow->tuple.src_ip >> 8) & 0xFF,
                 (flow->tuple.src_ip >> 16) & 0xFF,
                 (flow->tuple.src_ip >> 24) & 0xFF);
        
        snprintf(dst_ip, sizeof(dst_ip), "%d.%d.%d.%d",
                 (flow->tuple.dst_ip >> 0) & 0xFF,
                 (flow->tuple.dst_ip >> 8) & 0xFF,
                 (flow->tuple.dst_ip >> 16) & 0xFF,
                 (flow->tuple.dst_ip >> 24) & 0xFF);
        
        /* Write CSV line */
        fprintf(ctx->log_file, "%llu,%s,%s,%u,%u,%u,%llu,%llu\n",
                flow->last_seen_ns / 1000000000,  /* Convert to seconds */
                src_ip, dst_ip,
                flow->tuple.src_port, flow->tuple.dst_port,
                flow->tuple.protocol,
                flow->packet_count, flow->byte_count);
    }
    
    fflush(ctx->log_file);
    
    /* Update statistics */
    output->total_flows += output->flow_count;
    
    /* Clear buffer */
    output->flow_count = 0;
    
    return 0;
}

/* Get output statistics */
void pcv_output_get_stats(const pcv_output* output, uint64_t* flows,
                          uint64_t* packets, uint64_t* bytes) {
    if (!output) return;
    
    if (flows) *flows = output->total_flows;
    if (packets) *packets = output->total_packets;
    if (bytes) *bytes = output->total_bytes;
}

/* RistrettoDB specific initialization */
int pcv_output_ristretto_init(const char* connection_string) {
    /* TODO: Initialize RistrettoDB connection */
    (void)connection_string;
    printf("RistrettoDB stub: Would connect to %s\n", 
           connection_string ? connection_string : "default");
    return 0;
}

void pcv_output_ristretto_cleanup(void) {
    /* TODO: Cleanup RistrettoDB connection */
    printf("RistrettoDB stub: Cleanup\n");
}
