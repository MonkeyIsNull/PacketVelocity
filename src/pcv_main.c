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
#include "pcv_flow.h"
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "vflisp_types.h"

/* Global handle for signal handling */
static pcv_handle* g_handle = NULL;
static volatile int g_running = 1;

/* Packet counter */
static uint64_t g_packet_count = 0;

/* Structure to pass filter and local addresses to callback */
typedef struct {
    pcv_filter* filter;
    uint32_t local_ip;
    uint8_t local_ipv6[16];
    bool has_ipv6;
} callback_context;

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
    uint32_t microseconds = (timestamp_ns % 1000000000) / 1000;
    struct tm* tm_info = localtime(&seconds);
    
    strftime(buffer, size, "%H:%M:%S", tm_info);
    size_t len = strlen(buffer);
    snprintf(buffer + len, size - len, ".%06u", microseconds);
}

/* Convert protocol number to string */
static const char* protocol_to_string(uint8_t protocol) {
    switch (protocol) {
        case 1:  return "ICMP";
        case 6:  return "TCP";
        case 17: return "UDP";
        case 2:  return "IGMP";
        case 47: return "GRE";
        case 50: return "ESP";
        case 51: return "AH";
        case 89: return "OSPF";
        default: return "proto";
    }
}

/* Get local IPv4 address of interface */
static uint32_t get_interface_ip(const char* interface_name) {
    struct ifaddrs *ifaddrs_ptr = NULL;
    struct ifaddrs *ifa = NULL;
    uint32_t local_ip = 0;
    
    if (getifaddrs(&ifaddrs_ptr) == -1) {
        return 0;
    }
    
    for (ifa = ifaddrs_ptr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        
        if (ifa->ifa_addr->sa_family == AF_INET && 
            strcmp(ifa->ifa_name, interface_name) == 0) {
            struct sockaddr_in* addr_in = (struct sockaddr_in*)ifa->ifa_addr;
            local_ip = ntohl(addr_in->sin_addr.s_addr);
            break;
        }
    }
    
    freeifaddrs(ifaddrs_ptr);
    return local_ip;
}

/* Get local IPv6 address of interface */
static bool get_interface_ipv6(const char* interface_name, uint8_t* ipv6_addr) {
    struct ifaddrs *ifaddrs_ptr = NULL;
    struct ifaddrs *ifa = NULL;
    bool found = false;
    
    if (getifaddrs(&ifaddrs_ptr) == -1) {
        return false;
    }
    
    for (ifa = ifaddrs_ptr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        
        if (ifa->ifa_addr->sa_family == AF_INET6 && 
            strcmp(ifa->ifa_name, interface_name) == 0) {
            struct sockaddr_in6* addr_in6 = (struct sockaddr_in6*)ifa->ifa_addr;
            
            /* Skip link-local addresses */
            if (!IN6_IS_ADDR_LINKLOCAL(&addr_in6->sin6_addr)) {
                memcpy(ipv6_addr, &addr_in6->sin6_addr, 16);
                found = true;
                break;
            }
        }
    }
    
    freeifaddrs(ifaddrs_ptr);
    return found;
}

/* Format packet information with directional arrows and IPv6 support */
static void format_packet_info(const pcv_packet* packet, uint32_t local_ip, const uint8_t* local_ipv6, char* buffer, size_t size) {
    pcv_flow_key_v6 key;
    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
    bool is_outgoing;
    const char* arrow;
    
    /* Extract flow key from packet using IPv6-capable parser */
    if (pcv_flow_extract_key_v6(packet, &key) != 0) {
        /* Fallback for unparseable packets */
        snprintf(buffer, size, "[unparseable packet, %u bytes]", packet->captured_length);
        return;
    }
    
    /* Format addresses and determine direction based on address family */
    if (key.addr_family == PCV_ADDR_IPV4) {
        /* IPv4 packet */
        inet_ntop(AF_INET, &key.src_ip.ipv4, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &key.dst_ip.ipv4, dst_ip, sizeof(dst_ip));
        is_outgoing = (ntohl(key.src_ip.ipv4) == local_ip);
    } else if (key.addr_family == PCV_ADDR_IPV6) {
        /* IPv6 packet */
        inet_ntop(AF_INET6, key.src_ip.ipv6, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET6, key.dst_ip.ipv6, dst_ip, sizeof(dst_ip));
        is_outgoing = (local_ipv6 && memcmp(key.src_ip.ipv6, local_ipv6, 16) == 0);
    } else {
        snprintf(buffer, size, "[unknown IP version %u, %u bytes]", key.addr_family, packet->captured_length);
        return;
    }
    
    arrow = is_outgoing ? ">" : "<";
    const char* ip_version = (key.addr_family == PCV_ADDR_IPV6) ? "6" : "";
    
    /* Format with directional arrows */
    if (key.protocol == 6 || key.protocol == 17) {
        /* TCP or UDP with ports */
        const char* direction = is_outgoing ? "OUT" : "IN ";
        if (key.addr_family == PCV_ADDR_IPV6) {
            /* IPv6 addresses need brackets for port notation */
            snprintf(buffer, size, "%s IP%s [%s].%u %s [%s].%u: %s %u",
                     direction, ip_version,
                     src_ip, key.src_port, arrow,
                     dst_ip, key.dst_port,
                     protocol_to_string(key.protocol),
                     packet->captured_length);
        } else {
            /* IPv4 standard notation */
            snprintf(buffer, size, "%s IP%s %s.%u %s %s.%u: %s %u",
                     direction, ip_version,
                     src_ip, key.src_port, arrow,
                     dst_ip, key.dst_port,
                     protocol_to_string(key.protocol),
                     packet->captured_length);
        }
    } else {
        /* Other protocols without ports */
        const char* direction = is_outgoing ? "OUT" : "IN ";
        snprintf(buffer, size, "%s IP%s %s %s %s: %s %u",
                 direction, ip_version,
                 src_ip, arrow, dst_ip,
                 protocol_to_string(key.protocol),
                 packet->captured_length);
    }
}

/* Packet callback */
static void packet_callback(const pcv_packet* packet, void* user_data) {
    callback_context* ctx = (callback_context*)user_data;
    pcv_filter_decision decision = PCV_FILTER_ACCEPT;
    char timestamp[32];
    char packet_info[256];
    
    /* Apply filter if present */
    if (ctx && ctx->filter) {
        decision = pcv_filter_apply(ctx->filter, packet->data, packet->captured_length);
        if (decision != PCV_FILTER_ACCEPT) {
            return;
        }
    }
    
    g_packet_count++;
    
    /* Format timestamp and packet info with direction */
    format_timestamp(packet->timestamp_ns, timestamp, sizeof(timestamp));
    uint32_t local_ip = ctx ? ctx->local_ip : 0;
    const uint8_t* local_ipv6 = (ctx && ctx->has_ipv6) ? ctx->local_ipv6 : NULL;
    format_packet_info(packet, local_ip, local_ipv6, packet_info, sizeof(packet_info));
    
    /* Print tcpdump-style output */
    printf("%s %s\n", timestamp, packet_info);
}

/* Print usage */
static void print_usage(const char* program) {
    printf("PacketVelocity %s - High-performance packet capture\n", pcv_version());
    printf("Platform: %s\n\n", pcv_platform_name());
    printf("Usage: %s [options]\n", program);
    printf("Options:\n");
    printf("  -i, --interface <name>    Network interface to capture from\n");
    printf("  -f, --filter <file>       VFM filter bytecode file\n");
    printf("  -l, --lisp <expr>         VFLisp expression to compile dynamically\n");
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
    const char* lisp_expr = NULL;
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
        {"lisp", required_argument, 0, 'l'},
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
    while ((opt = getopt_long(argc, argv, "i:f:l:pIb:vVh", long_options, NULL)) != -1) {
        switch (opt) {
        case 'i':
            interface = optarg;
            break;
        case 'f':
            filter_file = optarg;
            break;
        case 'l':
            lisp_expr = optarg;
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
    
    /* Check for conflicting filter options */
    if (filter_file && lisp_expr) {
        fprintf(stderr, "Error: Cannot specify both -f and -l options\n");
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
    } else if (lisp_expr) {
        /* Compile VFLisp expression */
        char error_msg[256];
        int result = vfl_compile_string(lisp_expr, &filter_bytecode, (uint32_t*)&filter_size, 
                                       error_msg, sizeof(error_msg));
        if (result < 0) {
            fprintf(stderr, "Error: VFLisp compilation failed: %s\n", error_msg);
            return 1;
        }
        
        filter = pcv_filter_create(PCV_FILTER_VFM, filter_bytecode, filter_size);
        if (!filter) {
            fprintf(stderr, "Error: Cannot create VFLisp filter\n");
            free(filter_bytecode);
            return 1;
        }
        
        if (verbose) {
            printf("Compiled VFLisp expression: %s (%zu bytes)\n", lisp_expr, filter_size);
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
    
    /* Get local addresses for directional packet display */
    uint32_t local_ip = get_interface_ip(interface);
    uint8_t local_ipv6[16];
    bool has_ipv6 = get_interface_ipv6(interface, local_ipv6);
    
    /* Create callback context with filter and local addresses */
    callback_context ctx = {
        .filter = filter,
        .local_ip = local_ip,
        .has_ipv6 = has_ipv6
    };
    
    if (has_ipv6) {
        memcpy(ctx.local_ipv6, local_ipv6, 16);
    }
    
    /* Start capture */
    int result = pcv_capture(g_handle, packet_callback, &ctx);
    
    /* Cleanup */
    pcv_stats* stats = pcv_get_stats(g_handle);
    if (stats) {
        printf("\nCapture Statistics:\n");
        printf("  Interface received: %llu (total packets seen by network interface)\n", stats->packets_received);
        printf("  Interface dropped:  %llu (packets lost due to buffer overruns)\n", stats->packets_dropped);
        printf("  Application output: %llu (packets displayed to user)\n", g_packet_count);
        
        if (ctx.filter) {
            uint64_t processed, accepted, dropped;
            pcv_filter_get_stats(ctx.filter, &processed, &accepted, &dropped);
            
            printf("\nFilter Statistics:\n");
            printf("  Total processed: %llu\n", processed);
            if (processed > 0) {
                double accept_pct = (double)accepted / processed * 100.0;
                double reject_pct = (double)dropped / processed * 100.0;
                printf("  Matched criteria: %llu (%.1f%%)\n", accepted, accept_pct);
                printf("  Rejected by filter: %llu (%.1f%%)\n", dropped, reject_pct);
            } else {
                printf("  Matched criteria: %llu\n", accepted);
                printf("  Rejected by filter: %llu\n", dropped);
            }
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
