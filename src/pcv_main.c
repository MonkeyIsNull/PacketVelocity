#ifdef __linux__
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L  /* For getopt_long and other POSIX functions */
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE  /* For additional system functions */
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE  /* For getopt_long on some systems */
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include "pcv.h"
#include "pcv_filter.h"
#include "pcv_flow.h"
#include "pcv_format.h"
#include "pcv_dashboard.h"
#include "pcv_http.h"
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "vflisp_types.h"

/* The RistrettoDB output backend is OPTIONAL and opt-in: its header and symbols
 * only exist when the tree is built with `make RISTRETTO=1`. The default build
 * stays hermetic (no RistrettoDB include, no RistrettoDB symbols). */
#if HAVE_RISTRETTO
#include "pcv_output.h"
#include "pcv_output_flow.h"
#endif

/* Global handle for signal handling */
static pcv_handle* g_handle = NULL;
static volatile int g_running = 1;

/* Packet counter and limits */
static uint64_t g_packet_count = 0;
static uint64_t g_packet_limit = 0;  /* 0 = unlimited */
static time_t g_start_time = 0;
static uint32_t g_time_limit = 0;    /* 0 = unlimited */

/* Structure to pass filter and local addresses to callback */
typedef struct {
    pcv_filter* filter;
    uint32_t local_ip;
    char interface_name[32];
    bool has_ipv6;
    pcv_dash_agg* dash;            /* non-NULL => --serve: route to the dashboard */
#if HAVE_RISTRETTO
    pcv_output* output;            /* non-NULL => per-packet RistrettoDB sink */
    pcv_flow_output* flow_output;  /* non-NULL => per-flow RistrettoDB sink */
#endif
} callback_context;

/* ---- Dashboard sampler thread (--serve) ---------------------------------
 * The UI heartbeat: on a fixed ~1 Hz cadence driven by CLOCK_MONOTONIC (NOT by
 * packet timestamps, so the capture-health panel keeps updating on a silent
 * link), it reads the kernel's recv/drop counters (BIOCGSTATS, via the
 * reentrant pcv_get_stats_r) and pushes one time-series Sample. It runs on its
 * own thread; it never touches the flow table or any lock the capture thread
 * can hold. */
typedef struct {
    pcv_handle*   handle;
    pcv_dash_agg* agg;
    _Atomic int   running;
} sampler_ctx;

static uint64_t monotonic_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void* sampler_thread(void* arg) {
    sampler_ctx* s = (sampler_ctx*)arg;
    while (atomic_load(&s->running)) {
        /* Sleep ~1s in 100ms slices so shutdown (join) is prompt. */
        for (int i = 0; i < 10 && atomic_load(&s->running); i++) {
            struct timespec slice = { 0, 100 * 1000 * 1000 };
            nanosleep(&slice, NULL);
        }
        if (!atomic_load(&s->running)) {
            break;
        }
        pcv_stats st;
        uint64_t recv = 0, dropped = 0;
        if (pcv_get_stats_r(s->handle, &st) == 0) {
            recv = st.packets_received;
            dropped = st.packets_dropped;
        }
        pcv_dash_sample_with_stats(s->agg, recv, dropped, monotonic_ns());
    }
    return NULL;
}

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
    
    /* Check packet limit */
    if (g_packet_limit > 0 && g_packet_count >= g_packet_limit) {
        g_running = 0;
        if (g_handle) {
            pcv_breakloop(g_handle);
        }
    }
    
    /* Check time limit */
    if (g_time_limit > 0 && g_start_time > 0) {
        time_t current_time = time(NULL);
        if (current_time - g_start_time >= g_time_limit) {
            g_running = 0;
            if (g_handle) {
                pcv_breakloop(g_handle);
            }
        }
    }
    
#if HAVE_RISTRETTO
    /* If an output backend is configured, route the packet there instead of
     * streaming a tcpdump-style line to stdout. A failing append is counted by
     * the sink and must not abort the capture loop. */
    if (ctx && ctx->output) {
        pcv_output_packet(ctx->output, packet);
        return;
    }
    /* Per-flow sink: aggregate into flows; rows are emitted on eviction and at
     * shutdown, not per packet. */
    if (ctx && ctx->flow_output) {
        pcv_flow_output_update(ctx->flow_output, packet);
        return;
    }
#endif

    /* Dashboard mode (--serve): feed the hot-path-safe aggregator and SUPPRESS
     * the per-packet stdout line (a deliberate, documented behavior change - the
     * tcpdump stream and the dashboard are mutually exclusive). */
    if (ctx && ctx->dash) {
        pcv_dash_on_packet(ctx->dash, packet);
        return;
    }

    /* Format timestamp and packet info with direction */
    format_timestamp(packet->timestamp_ns, timestamp, sizeof(timestamp));
    uint32_t local_ip = ctx ? ctx->local_ip : 0;
    const char* interface_name = (ctx && ctx->has_ipv6) ? ctx->interface_name : "";
    pcv_format_packet_info(packet, local_ip, interface_name, packet_info, sizeof(packet_info));
    
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
    printf("  -c, --packet-num <count>  Stop after capturing <count> packets\n");
    printf("  -t, --seconds-num <secs>  Stop after <secs> seconds\n");
    printf("  -o, --output <sink>       Output sink: '-'/'stdout' (default, tcpdump-style\n");
    printf("                            stream); 'ristretto:<path>' to append one row per\n");
    printf("                            packet to a RistrettoDB V2 table at <path>.rdb; or\n");
    printf("                            'ristretto-flow:<path>' to write one row per flow\n");
    printf("                            (5-tuple conversation) to a 'flows' table at\n");
    printf("                            <path>.rdb (both require 'make RISTRETTO=1')\n");
    printf("  -S, --serve <port>        Serve a LIVE DASHBOARD instead of the stdout\n");
    printf("                            stream: a self-contained web page + JSON API on\n");
    printf("                            http://127.0.0.1:<port> (use 0 to auto-pick a\n");
    printf("                            port). The HTTP server binds LOOPBACK ONLY and is\n");
    printf("                            never exposed on a LAN. Capture still needs root,\n");
    printf("                            so run with sudo; the per-packet stdout stream is\n");
    printf("                            suppressed in this mode. Cannot be combined with\n");
    printf("                            --output ristretto*/ristretto-flow*.\n");
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
    const char* output_spec = NULL;   /* NULL/'-'/'stdout' => tcpdump stream */
    bool serve_enabled = false;       /* --serve => live dashboard mode */
    long serve_port = -1;             /* 0 => auto-pick a loopback port */
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
        {"packet-num", required_argument, 0, 'c'},
        {"seconds-num", required_argument, 0, 't'},
        {"output", required_argument, 0, 'o'},
        {"serve", required_argument, 0, 'S'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    /* Parse command line */
    int opt;
    while ((opt = getopt_long(argc, argv, "i:f:l:pIb:c:t:o:S:vVh", long_options, NULL)) != -1) {
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
        case 'c':
            g_packet_limit = strtoull(optarg, NULL, 10);
            break;
        case 't':
            g_time_limit = atoi(optarg);
            break;
        case 'o':
            output_spec = optarg;
            break;
        case 'S': {
            char* end = NULL;
            errno = 0;
            long p = strtol(optarg, &end, 10);
            if (errno != 0 || end == optarg || *end != '\0' || p < 0 || p > 65535) {
                fprintf(stderr, "Error: --serve requires a port in [0,65535] "
                                "(0 = auto-pick)\n");
                return 1;
            }
            serve_enabled = true;
            serve_port = p;
            break;
        }
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

    /* Resolve the output sink. Default (NULL, "-", "stdout") is the tcpdump-style
     * stdout stream. "ristretto:<path>" routes packets to a RistrettoDB V2 table.
     * Validate (and fast-fail the not-compiled-in case) before touching the
     * capture device, which would otherwise need root. */
    const char* ristretto_path = NULL;       /* per-packet sink target */
    const char* ristretto_flow_path = NULL;  /* per-flow sink target */
    if (output_spec && strcmp(output_spec, "-") != 0 &&
        strcmp(output_spec, "stdout") != 0) {
        /* Check the longer, more specific prefix first. */
        if (strncmp(output_spec, "ristretto-flow:", 15) == 0) {
            ristretto_flow_path = output_spec + 15;
            if (*ristretto_flow_path == '\0') {
                fprintf(stderr, "Error: --output ristretto-flow: requires a path, "
                                "e.g. --output ristretto-flow:/tmp/flows\n");
                return 1;
            }
#if !HAVE_RISTRETTO
            fprintf(stderr, "Error: this build has no RistrettoDB support; "
                            "rebuild with make RISTRETTO=1\n");
            return 1;
#endif
        } else if (strncmp(output_spec, "ristretto:", 10) == 0) {
            ristretto_path = output_spec + 10;
            if (*ristretto_path == '\0') {
                fprintf(stderr, "Error: --output ristretto: requires a path, "
                                "e.g. --output ristretto:/tmp/capture\n");
                return 1;
            }
#if !HAVE_RISTRETTO
            fprintf(stderr, "Error: this build has no RistrettoDB support; "
                            "rebuild with make RISTRETTO=1\n");
            return 1;
#endif
        } else {
            fprintf(stderr, "Error: unknown --output sink '%s' (use '-', 'stdout', "
                            "'ristretto:<path>', or 'ristretto-flow:<path>')\n",
                    output_spec);
            return 1;
        }
    }

    /* --serve is mutually exclusive with the RistrettoDB sinks: those consume
     * packets via an early return before any flow feed, while the dashboard
     * reads the flow table, so the two sinks would fight over the callback. */
    if (serve_enabled && (ristretto_path || ristretto_flow_path)) {
        fprintf(stderr, "Error: --serve cannot be combined with "
                        "--output ristretto:/ristretto-flow:\n");
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
    
    /* Create callback context with filter and local addresses */
    callback_context ctx = {
        .filter = filter,
        .local_ip = local_ip,
        .has_ipv6 = true  // Enable IPv6 direction detection
    };
    
    /* Store interface name for IPv6 direction detection */
    strncpy(ctx.interface_name, interface, sizeof(ctx.interface_name) - 1);
    ctx.interface_name[sizeof(ctx.interface_name) - 1] = '\0';

#if HAVE_RISTRETTO
    /* Attach the RistrettoDB output backend if requested (already validated). */
    if (ristretto_path) {
        ctx.output = pcv_output_create(PCV_OUTPUT_RISTRETTO, ristretto_path);
        if (!ctx.output) {
            fprintf(stderr, "Error: Cannot open RistrettoDB output '%s'\n",
                    ristretto_path);
            pcv_close(g_handle);
            if (filter) pcv_filter_destroy(filter);
            if (filter_bytecode) free(filter_bytecode);
            return 1;
        }
    } else if (ristretto_flow_path) {
        ctx.flow_output = pcv_flow_output_create(ristretto_flow_path);
        if (!ctx.flow_output) {
            fprintf(stderr, "Error: Cannot open RistrettoDB flow output '%s'\n",
                    ristretto_flow_path);
            pcv_close(g_handle);
            if (filter) pcv_filter_destroy(filter);
            if (filter_bytecode) free(filter_bytecode);
            return 1;
        }
    }
#endif

    /* --serve: stand up the live dashboard. Threads are created ONLY here, so
     * without --serve no threads/sockets exist and the default stdout path is
     * byte-for-byte unchanged. */
    pcv_dash_agg* dash = NULL;
    pcv_http_server http_srv;
    sampler_ctx scx;
    pthread_t http_tid = 0, sampler_tid = 0;
    bool http_started = false, sampler_started = false;
    if (serve_enabled) {
        dash = pcv_dash_create(0, 0, 0);   /* modest serve flow config */
        if (!dash) {
            fprintf(stderr, "Error: Cannot create dashboard aggregator\n");
            pcv_close(g_handle);
            if (filter) pcv_filter_destroy(filter);
            if (filter_bytecode) free(filter_bytecode);
            return 1;
        }

        int listen_fd = -1;
        char bound_ip[64] = {0};
        uint16_t bound_port = 0;
        if (pcv_http_listen_local((uint16_t)serve_port, &listen_fd,
                                  bound_ip, sizeof(bound_ip), &bound_port) != 0) {
            fprintf(stderr, "Error: Cannot bind dashboard HTTP server on "
                            "127.0.0.1:%ld\n", serve_port);
            pcv_dash_destroy(dash);
            pcv_close(g_handle);
            if (filter) pcv_filter_destroy(filter);
            if (filter_bytecode) free(filter_bytecode);
            return 1;
        }

        pcv_http_server_init(&http_srv, listen_fd, dash);
        if (pthread_create(&http_tid, NULL, pcv_http_thread, &http_srv) != 0) {
            fprintf(stderr, "Error: Cannot start HTTP thread\n");
            pcv_http_stop(&http_srv);
            pcv_dash_destroy(dash);
            pcv_close(g_handle);
            if (filter) pcv_filter_destroy(filter);
            if (filter_bytecode) free(filter_bytecode);
            return 1;
        }
        http_started = true;

        scx.handle = g_handle;
        scx.agg = dash;
        atomic_store(&scx.running, 1);
        if (pthread_create(&sampler_tid, NULL, sampler_thread, &scx) != 0) {
            fprintf(stderr, "Error: Cannot start sampler thread\n");
            atomic_store(&scx.running, 0);
            pcv_http_stop(&http_srv);
            pthread_join(http_tid, NULL);
            pcv_dash_destroy(dash);
            pcv_close(g_handle);
            if (filter) pcv_filter_destroy(filter);
            if (filter_bytecode) free(filter_bytecode);
            return 1;
        }
        sampler_started = true;

        ctx.dash = dash;
        printf("Dashboard: http://%s:%u  (loopback only; capture needs sudo)\n",
               bound_ip, bound_port);
    }

    /* Initialize start time for time limit */
    g_start_time = time(NULL);

    /* Start capture */
    int result = pcv_capture(g_handle, packet_callback, &ctx);

    /* --serve shutdown ordering (MANDATORY): stop + join BOTH dashboard threads
     * BEFORE the end-of-run stats block and before destroying the aggregator.
     * (a) pcv_get_stats aliases a function-static, so a live sampler calling it
     *     concurrently with the stats print below would clobber the buffer -
     *     joining the sampler first closes that; the print uses the reentrant
     *     pcv_get_stats_r regardless.
     * (b) Freeing the aggregator/flow table while the HTTP thread still reads it
     *     is a use-after-free - joining the HTTP thread first closes that. */
    if (serve_enabled) {
        if (sampler_started) {
            atomic_store(&scx.running, 0);
        }
        if (http_started) {
            pcv_http_stop(&http_srv);
        }
        if (sampler_started) {
            pthread_join(sampler_tid, NULL);
        }
        if (http_started) {
            pthread_join(http_tid, NULL);
        }
    }

    /* Cleanup */
    pcv_stats stats_buf;
    pcv_stats* stats = (pcv_get_stats_r(g_handle, &stats_buf) == 0) ? &stats_buf : NULL;
    if (stats) {
        printf("\nCapture Statistics:\n");
        printf("  Interface received: %" PRIu64 " (total packets seen by network interface)\n", stats->packets_received);
        printf("  Interface dropped:  %" PRIu64 " (packets lost due to buffer overruns)\n", stats->packets_dropped);
        printf("  Application output: %" PRIu64 " (packets displayed to user)\n", g_packet_count);
        
        if (ctx.filter) {
            uint64_t processed, accepted, dropped;
            pcv_filter_get_stats(ctx.filter, &processed, &accepted, &dropped);
            
            printf("\nFilter Statistics:\n");
            printf("  Total processed: %" PRIu64 "\n", processed);
            if (processed > 0) {
                double accept_pct = (double)accepted / processed * 100.0;
                double reject_pct = (double)dropped / processed * 100.0;
                printf("  Matched criteria: %" PRIu64 " (%.1f%%)\n", accepted, accept_pct);
                printf("  Rejected by filter: %" PRIu64 " (%.1f%%)\n", dropped, reject_pct);
            } else {
                printf("  Matched criteria: %" PRIu64 "\n", accepted);
                printf("  Rejected by filter: %" PRIu64 "\n", dropped);
            }
        }
    }
    
#if HAVE_RISTRETTO
    /* Flush and close the output backend; prints the row count written. */
    if (ctx.output) {
        uint64_t rows = 0, pkts = 0, bytes = 0;
        pcv_output_get_stats(ctx.output, &rows, &pkts, &bytes);
        printf("  RistrettoDB rows:   %" PRIu64 " (packets written to table)\n", rows);
        pcv_output_destroy(ctx.output);
        ctx.output = NULL;
    }
    /* Per-flow sink: the final row count is only known after destroy flushes
     * every still-open flow, so report packets aggregated here and let destroy
     * print the authoritative flow-row total. */
    if (ctx.flow_output) {
        uint64_t rows = 0, pkts = 0, bytes = 0;
        pcv_flow_output_get_stats(ctx.flow_output, &rows, &pkts, &bytes);
        printf("  RistrettoDB flows:  aggregated %" PRIu64 " packets into flows "
               "(row count reported on close)\n", pkts);
        pcv_flow_output_destroy(ctx.flow_output);
        ctx.flow_output = NULL;
    }
#endif

    pcv_close(g_handle);

    /* Both dashboard threads are joined above, so the aggregator has no more
     * readers and is safe to free. */
    if (dash) {
        pcv_dash_destroy(dash);
    }

    if (filter) {
        pcv_filter_destroy(filter);
    }
    
    if (filter_bytecode) {
        free(filter_bytecode);
    }
    
    return result < 0 ? 1 : 0;
}
