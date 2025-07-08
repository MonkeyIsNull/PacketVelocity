/* Simple PacketVelocity Example
 * Demonstrates basic packet capture functionality
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "pcv.h"

static volatile int running = 1;
static uint64_t packet_count = 0;

void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

void packet_callback(const pcv_packet* packet, void* user_data) {
    (void)user_data;
    
    packet_count++;
    
    printf("Packet %llu: %u bytes at %llu ns\n", 
           packet_count, packet->captured_length, packet->timestamp_ns);
    
    if (packet_count >= 10) {
        running = 0;
    }
}

int main(int argc, char* argv[]) {
    pcv_handle* handle;
    pcv_config config = {0};
    const char* interface = "en0";  /* Default interface */
    
    if (argc > 1) {
        interface = argv[1];
    }
    
    printf("PacketVelocity Simple Capture Example\n");
    printf("Platform: %s\n", pcv_platform_name());
    printf("Capturing on %s...\n", interface);
    
    signal(SIGINT, signal_handler);
    
    /* Configure capture */
    config.immediate_mode = true;
    config.buffer_size = 1024 * 1024;  /* 1MB buffer */
    
    /* Open capture */
    handle = pcv_open(interface, &config);
    if (!handle) {
        fprintf(stderr, "Failed to open interface %s\n", interface);
        return 1;
    }
    
    /* Start capture */
    while (running) {
        if (pcv_capture(handle, packet_callback, NULL) < 0) {
            break;
        }
    }
    
    /* Get final statistics */
    pcv_stats* stats = pcv_get_stats(handle);
    if (stats) {
        printf("\nFinal Statistics:\n");
        printf("  Packets received: %llu\n", stats->packets_received);
        printf("  Packets dropped:  %llu\n", stats->packets_dropped);
        printf("  Bytes received:   %llu\n", stats->bytes_received);
    }
    
    pcv_close(handle);
    printf("Capture complete.\n");
    
    return 0;
}