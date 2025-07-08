#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <errno.h>
#include "pcv.h"
#include "pcv_filter.h"

/* Global handle for signal handling */
static pcv_handle* g_handle = NULL;
static volatile int g_running = 1;

/* Packet counter */
static uint64_t g_packet_count = 0;

/* Signal handler */
static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
    if (g_handle) {
        pcv_breakloop(g_handle);
    }
}

/* Format timestamp */
static void format_timestamp(uint64_t timestamp_ns, char* buffer, size_t size) {
    time_t seconds = timestamp_ns / 1000000000;
    uint32_t nanoseconds = timestamp_ns % 1000000000;
    struct tm* tm_info = localtime(&seconds);
    
    strftime(buffer, size, "%H:%M:%S", tm_info);
    size_t len = strlen(buffer);
    snprintf(buffer + len, size - len, ".%09u", nanoseconds);
}

/* Packet callback */
static void packet_callback(const pcv_packet* packet, void* user_data) {
    pcv_filter* filter = (pcv_filter*)user_data;
    pcv_filter_decision decision = PCV_FILTER_ACCEPT;
    char timestamp[32];
    
    /* Apply filter if present */
    if (filter) {
        decision = pcv_filter_apply(filter, packet->data, packet->captured_length);
        if (decision != PCV_FILTER_ACCEPT) {
            return;
        }
    }
    
    g_packet_count++;
    
    /* Format and print packet info */
    format_timestamp(packet->timestamp_ns, timestamp, sizeof(timestamp));
    
    printf("%s %5u bytes", timestamp, packet->captured_length);
    
    /* Print first few bytes as hex */
    printf(" |");
    for (uint32_t i = 0; i < 16 && i < packet->captured_length; i++) {
        printf(" %02x", packet->data[i]);
    }
    if (packet->captured_length > 16) {
        printf(" ...");
    }
    printf("\n");
}

/* Print usage */
static void print_usage(const char* program) {
    printf("PacketVelocity %s - High-performance packet capture\n", pcv_version());
    printf("Platform: %s\n\n", pcv_platform_name());
    printf("Usage: %s [options]\n", program);
    printf("Options:\n");
    printf("  -i, --interface <name>    Network interface to capture from\n");
    printf("  -f, --filter <file>       VFM filter bytecode file\n");
    printf("  -p, --promiscuous         Enable promiscuous mode\n");
    printf("  -I, --immediate           Enable immediate mode (low latency)\n");
    printf("  -b, --buffer-size <size>  Set buffer size (default: 4MB)\n");
    printf("  -v, --verbose             Enable verbose output\n");
    printf("  -V, --version             Show version information\n");
    printf("  -h, --help                Show this help message\n");
}

/* Load filter from file */
static uint8_t* load_filter_file(const char* filename, size_t* size) {
    FILE* file;
    uint8_t* buffer;
    size_t file_size;
    
    file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error: Cannot open filter file '%s': %s\n", 
                filename, strerror(errno));
        return NULL;
    }
    
    /* Get file size */
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (file_size == 0 || file_size > 1024 * 1024) {
        fprintf(stderr, "Error: Invalid filter file size\n");
        fclose(file);
        return NULL;
    }
    
    /* Allocate buffer */
    buffer = malloc(file_size);
    if (!buffer) {
        fprintf(stderr, "Error: Cannot allocate memory for filter\n");
        fclose(file);
        return NULL;
    }
    
    /* Read file */
    if (fread(buffer, 1, file_size, file) != file_size) {
        fprintf(stderr, "Error: Cannot read filter file\n");
        free(buffer);
        fclose(file);
        return NULL;
    }
    
    fclose(file);
    *size = file_size;
    return buffer;
}

int main(int argc, char* argv[]) {
    const char* interface = NULL;
    const char* filter_file = NULL;
    bool promiscuous = false;
    bool immediate = false;
    bool verbose = false;
    uint32_t buffer_size = 0;
    
    pcv_config config = {0};
    pcv_filter* filter = NULL;
    uint8_t* filter_bytecode = NULL;
    size_t filter_size = 0;
    
    /* Command line options */
    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"filter", required_argument, 0, 'f'},
        {"promiscuous", no_argument, 0, 'p'},
        {"immediate", no_argument, 0, 'I'},
        {"buffer-size", required_argument, 0, 'b'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    /* Parse command line */
    int opt;
    while ((opt = getopt_long(argc, argv, "i:f:pIb:vVh", long_options, NULL)) != -1) {
        switch (opt) {
        case 'i':
            interface = optarg;
            break;
        case 'f':
            filter_file = optarg;
            break;
        case 'p':
            promiscuous = true;
            break;
        case 'I':
            immediate = true;
            break;
        case 'b':
            buffer_size = atoi(optarg);
            break;
        case 'v':
            verbose = true;
            break;
        case 'V':
            printf("PacketVelocity %s\n", pcv_version());
            printf("Platform: %s\n", pcv_platform_name());
            printf("VFM: %s\n", pcv_filter_vfm_version());
            return 0;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }
    
    /* Check required arguments */
    if (!interface) {
        fprintf(stderr, "Error: Interface not specified\n");
        print_usage(argv[0]);
        return 1;
    }
    
    /* Setup signal handling */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    /* Load filter if specified */
    if (filter_file) {
        filter_bytecode = load_filter_file(filter_file, &filter_size);
        if (!filter_bytecode) {
            return 1;
        }
        
        filter = pcv_filter_create(PCV_FILTER_VFM, filter_bytecode, filter_size);
        if (!filter) {
            fprintf(stderr, "Error: Cannot create filter\n");
            free(filter_bytecode);
            return 1;
        }
        
        if (verbose) {
            printf("Loaded VFM filter from %s (%zu bytes)\n", filter_file, filter_size);
        }
    }
    
    /* Configure capture */
    config.promiscuous = promiscuous;
    config.immediate_mode = immediate;
    config.buffer_size = buffer_size;
    config.timeout_ms = 100;
    
    /* Open capture device */
    if (verbose) {
        printf("Opening interface %s...\n", interface);
        uint32_t caps = pcv_get_capabilities();
        printf("Platform capabilities:");
        if (caps & PCV_CAP_ZERO_COPY) printf(" ZERO_COPY");
        if (caps & PCV_CAP_HARDWARE_TIMESTAMPS) printf(" HW_TIMESTAMPS");
        if (caps & PCV_CAP_BATCH_PROCESSING) printf(" BATCH");
        if (caps & PCV_CAP_HARDWARE_OFFLOAD) printf(" HW_OFFLOAD");
        if (caps & PCV_CAP_NUMA_AWARE) printf(" NUMA");
        printf("\n");
    }
    
    g_handle = pcv_open(interface, &config);
    if (!g_handle) {
        fprintf(stderr, "Error: Cannot open interface %s\n", interface);
        if (filter) pcv_filter_destroy(filter);
        if (filter_bytecode) free(filter_bytecode);
        return 1;
    }
    
    printf("Capturing on %s... Press Ctrl+C to stop\n", interface);
    
    /* Start capture */
    int result = pcv_capture(g_handle, packet_callback, filter);
    
    /* Cleanup */
    pcv_stats* stats = pcv_get_stats(g_handle);
    if (stats) {
        printf("\nCapture statistics:\n");
        printf("  Packets received: %llu\n", stats->packets_received);
        printf("  Packets dropped:  %llu\n", stats->packets_dropped);
        printf("  Packets filtered: %llu\n", g_packet_count);
        
        if (filter) {
            uint64_t processed, accepted, dropped;
            pcv_filter_get_stats(filter, &processed, &accepted, &dropped);
            printf("  Filter processed: %llu\n", processed);
            printf("  Filter accepted:  %llu\n", accepted);
            printf("  Filter dropped:   %llu\n", dropped);
        }
    }
    
    pcv_close(g_handle);
    
    if (filter) {
        pcv_filter_destroy(filter);
    }
    
    if (filter_bytecode) {
        free(filter_bytecode);
    }
    
    return result < 0 ? 1 : 0;
}
