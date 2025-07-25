#include "pcv_output.h"
#include "pcv_flow.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#if HAVE_RISTRETTO
#include "ristretto.h"
#endif

/* RistrettoDB output stub implementation
 * This is a placeholder for actual RistrettoDB integration
 * Replace with real implementation using:
 * https://github.com/MonkeyIsNull/RistrettoDB
 */

typedef struct pcv_ristretto_context {
    char* database_file;
#if HAVE_RISTRETTO
    RistrettoDB* db;
#else
    void* db;  /* Placeholder when RistrettoDB is not available */
#endif
    
    /* Flow aggregation */
    pcv_flow_table* flow_table;
    pcv_flow_config flow_config;
    
    /* Bulk insert configuration */
    uint32_t batch_size;
    uint32_t current_batch_count;
    
    /* Timing */
    time_t last_flush;
    uint64_t flush_interval_ns;
    
    /* Statistics */
    uint64_t total_inserts;
    uint64_t total_flushes;
    uint64_t insert_errors;
    
    /* Fallback logging */
    FILE* log_file;
} pcv_ristretto_context;

/* Initialize RistrettoDB database and table */
static int init_ristretto_database(pcv_ristretto_context* ctx) {
#if HAVE_RISTRETTO
    const char* schema_sql = 
        "CREATE TABLE IF NOT EXISTS packet_flows ("
        "flow_id INTEGER PRIMARY KEY, "
        "src_ip TEXT, "
        "dst_ip TEXT, "
        "src_port INTEGER, "
        "dst_port INTEGER, "
        "protocol INTEGER, "
        "first_seen INTEGER, "
        "last_seen INTEGER, "
        "duration_ms INTEGER, "
        "packet_count INTEGER, "
        "byte_count INTEGER, "
        "tcp_flags INTEGER, "
        "flow_state INTEGER"
        ")";
    
    /* Open the database */
    ctx->db = ristretto_open(ctx->database_file);
    if (!ctx->db) {
        fprintf(stderr, "Failed to open RistrettoDB database: %s\n", ctx->database_file);
        return -1;
    }
    
    /* Create the table */
    RistrettoResult result = ristretto_exec(ctx->db, schema_sql);
    if (result != RISTRETTO_OK) {
        fprintf(stderr, "Failed to create packet_flows table: %s\n", ristretto_error_string(result));
        ristretto_close(ctx->db);
        ctx->db = NULL;
        return -1;
    }
    
    printf("RistrettoDB database initialized successfully: %s\n", ctx->database_file);
    return 0;
#else
    printf("RistrettoDB support not compiled in - using stub implementation\n");
    ctx->db = NULL;
    return 0;
#endif
}

/* Convert IP address to string */
static void ip_to_string(uint32_t ip, char* buffer, size_t size) {
    inet_ntop(AF_INET, &ip, buffer, size);
}

/* Insert flow into RistrettoDB table using SQL */
static int insert_flow_to_database(pcv_ristretto_context* ctx, const pcv_flow_stats* flow) {
    char src_ip_str[16], dst_ip_str[16];
    char sql_buffer[1024];
    
    /* Convert IP addresses to strings */
    ip_to_string(flow->key.src_ip, src_ip_str, sizeof(src_ip_str));
    ip_to_string(flow->key.dst_ip, dst_ip_str, sizeof(dst_ip_str));
    
    /* Build INSERT statement */
    snprintf(sql_buffer, sizeof(sql_buffer),
        "INSERT INTO packet_flows ("
        "flow_id, src_ip, dst_ip, src_port, dst_port, protocol, "
        "first_seen, last_seen, duration_ms, packet_count, byte_count, tcp_flags, flow_state"
        ") VALUES ("
        "%u, '%s', '%s', %u, %u, %u, "
        "%llu, %llu, %llu, %llu, %llu, %u, %u"
        ")",
        flow->flow_id, src_ip_str, dst_ip_str,
        flow->key.src_port, flow->key.dst_port, flow->key.protocol,
        flow->first_seen_ns / 1000000000,  /* Unix timestamp */
        flow->last_seen_ns / 1000000000,
        flow->duration_ns / 1000000,       /* Milliseconds */
        flow->packet_count, flow->byte_count,
        flow->tcp_flags, flow->flow_state
    );
    
    /* Execute the insert */
#if HAVE_RISTRETTO
    RistrettoResult result = ristretto_exec(ctx->db, sql_buffer);
    if (result == RISTRETTO_OK) {
        ctx->total_inserts++;
        ctx->current_batch_count++;
        return 0;
    } else {
        ctx->insert_errors++;
        fprintf(stderr, "Failed to insert flow: %s\n", ristretto_error_string(result));
        return -1;
    }
#else
    /* Stub implementation - just log to file if available */
    if (ctx->log_file) {
        fprintf(ctx->log_file, "%s\n", sql_buffer);
        fflush(ctx->log_file);
    }
    ctx->total_inserts++;
    ctx->current_batch_count++;
    return 0;
#endif
}

/* Bulk insert callback for flow iteration */
static void bulk_insert_callback(const pcv_flow_stats* flow, void* user_data) {
    pcv_ristretto_context* ctx = (pcv_ristretto_context*)user_data;
    
    /* Only insert completed or expired flows */
    if (!(flow->flow_state & (PCV_FLOW_TIMEOUT | PCV_FLOW_FINISHED))) {
        return;
    }
    
    insert_flow_to_database(ctx, flow);
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
    output->flush_interval_ms = 1000;  /* 1 second default */
    output->max_flows = 100000;  /* Increased capacity */
    
    /* Save database file path */
    ctx->database_file = strdup(target ? target : "packet_flows.db");
    
    /* Initialize RistrettoDB database */
    if (init_ristretto_database(ctx) < 0) {
        free(ctx->database_file);
        free(ctx);
        free(output);
        return NULL;
    }
    
    /* Configure flow aggregation */
    ctx->flow_config.max_flows = 50000;
    ctx->flow_config.hash_buckets = 65536;
    ctx->flow_config.flow_timeout_ms = 300000;  /* 5 minutes */
    ctx->flow_config.cleanup_interval = 1000;
    ctx->flow_config.enable_tcp_state = true;
    
    /* Create flow table */
    ctx->flow_table = pcv_flow_table_create(&ctx->flow_config);
    if (!ctx->flow_table) {
#if HAVE_RISTRETTO
        if (ctx->db) {
            ristretto_close(ctx->db);
        }
#endif
        free(ctx->database_file);
        free(ctx);
        free(output);
        return NULL;
    }
    
    /* Set configurable flush intervals and thresholds */
    ctx->batch_size = output->max_flows / 50;  /* Adaptive batch size based on capacity */
    if (ctx->batch_size < 100) ctx->batch_size = 100;      /* Minimum batch size */
    if (ctx->batch_size > 5000) ctx->batch_size = 5000;    /* Maximum batch size */
    
    ctx->flush_interval_ns = (uint64_t)output->flush_interval_ms * 1000000ULL;  /* Convert ms to ns */
    ctx->last_flush = time(NULL);
    
    /* Open fallback log file */
    char log_filename[256];
    snprintf(log_filename, sizeof(log_filename), "%s.log", ctx->database_file);
    ctx->log_file = fopen(log_filename, "a");
    if (!ctx->log_file) {
        ctx->log_file = stdout;
    }
    
    printf("RistrettoDB database initialized: %s\n", ctx->database_file);
    printf("Flow table capacity: %u flows, %u buckets\n", 
           ctx->flow_config.max_flows, ctx->flow_config.hash_buckets);
    printf("Flush configuration: batch_size=%u, interval=%llu ms\n",
           ctx->batch_size, ctx->flush_interval_ns / 1000000ULL);
    
    return output;
}

/* Destroy output handler */
void pcv_output_destroy(pcv_output* output) {
    if (!output) return;
    
    /* Flush any remaining data */
    pcv_output_flush(output);
    
    if (output->type == PCV_OUTPUT_RISTRETTO && output->context) {
        pcv_ristretto_context* ctx = output->context;
        
        /* Close RistrettoDB database */
        if (ctx->db) {
#if HAVE_RISTRETTO
            ristretto_close(ctx->db);
#endif
        }
        
        /* Destroy flow table */
        if (ctx->flow_table) {
            pcv_flow_table_destroy(ctx->flow_table);
        }
        
        /* Close log file */
        if (ctx->log_file && ctx->log_file != stdout) {
            fclose(ctx->log_file);
        }
        
        printf("RistrettoDB statistics:\n");
        printf("  Total inserts: %llu\n", ctx->total_inserts);
        printf("  Total flushes: %llu\n", ctx->total_flushes);
        printf("  Insert errors: %llu\n", ctx->insert_errors);
        
        free(ctx->database_file);
        free(ctx);
    }
    
    free(output);
}

/* Process packet */
int pcv_output_packet(pcv_output* output, const pcv_packet* packet) {
    pcv_ristretto_context* ctx;
    time_t now;
    
    if (!output || !packet) {
        return -1;
    }
    
    ctx = (pcv_ristretto_context*)output->context;
    
    /* Update flow table with packet */
    if (pcv_flow_update(ctx->flow_table, packet) < 0) {
        /* Flow table might be full, try flushing */
        pcv_output_flush(output);
        if (pcv_flow_update(ctx->flow_table, packet) < 0) {
            return -1;
        }
    }
    
    /* Update totals */
    output->total_packets++;
    output->total_bytes += packet->captured_length;
    
    /* Check if flush needed based on time */
    now = time(NULL);
    if ((now - ctx->last_flush) * 1000 >= output->flush_interval_ms) {
        pcv_output_flush(output);
        ctx->last_flush = now;
    }
    
    /* Check if flush needed based on batch size */
    if (ctx->current_batch_count >= ctx->batch_size) {
        pcv_output_flush(output);
    }
    
    return 0;
}

/* Flush buffered data */
int pcv_output_flush(pcv_output* output) {
    pcv_ristretto_context* ctx;
    uint64_t current_time_ns;
    
    if (!output) {
        return 0;
    }
    
    ctx = (pcv_ristretto_context*)output->context;
    current_time_ns = time(NULL) * 1000000000ULL;  /* Approximate */
    
    /* Expire old flows */
    int expired = pcv_flow_expire_old(ctx->flow_table, current_time_ns);
    
    if (expired == 0) {
        return 0;  /* Nothing to flush */
    }
    
    /* Reset batch counter for this flush */
    ctx->current_batch_count = 0;
    
    /* Iterate through flows and insert expired/finished ones */
    pcv_flow_iterate(ctx->flow_table, bulk_insert_callback, ctx);
    
    /* Update statistics */
    if (ctx->current_batch_count > 0) {
        ctx->total_flushes++;
        printf("Flushed %u flows to RistrettoDB\n", ctx->current_batch_count);
    }
    
    /* Update statistics */
    output->total_flows += expired;
    
    return expired;
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
