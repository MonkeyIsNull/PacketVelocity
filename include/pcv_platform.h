#ifndef PCV_PLATFORM_H
#define PCV_PLATFORM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PacketVelocity Platform Abstraction Layer */

/* Platform detection */
#if defined(__APPLE__) && defined(__MACH__)
    #define PCV_PLATFORM_MACOS 1
#elif defined(__linux__)
    #define PCV_PLATFORM_LINUX 1
#elif defined(__FreeBSD__)
    #define PCV_PLATFORM_FREEBSD 1
#else
    #define PCV_PLATFORM_FALLBACK 1
#endif

/* Forward declarations */
typedef struct pcv_handle pcv_handle;
typedef struct pcv_packet pcv_packet;
typedef struct pcv_stats pcv_stats;

/* Packet metadata structure */
struct pcv_packet {
    const uint8_t* data;        /* Pointer to packet data */
    uint32_t length;            /* Packet length */
    uint32_t captured_length;   /* Captured length (may be less than full packet) */
    uint64_t timestamp_ns;      /* Timestamp in nanoseconds */
    uint32_t interface_index;   /* Interface index */
    uint16_t flags;             /* Platform-specific flags */
    uint16_t reserved;          /* Padding/alignment */
};

/* Capture statistics */
struct pcv_stats {
    uint64_t packets_received;   /* Total packets seen by interface */
    uint64_t packets_dropped;    /* Packets dropped by kernel */
    uint64_t packets_filtered;   /* Packets that passed filter */
    uint64_t bytes_received;     /* Total bytes received */
    uint64_t buffer_overruns;    /* Ring buffer overruns */
    uint64_t timestamp_ns;       /* Stats collection timestamp */
};

/* Callback types */
typedef void (*pcv_callback)(const pcv_packet* packet, void* user_data);
typedef void (*pcv_batch_callback)(const pcv_packet* packets, size_t count, void* user_data);

/* Configuration structure */
typedef struct pcv_config {
    uint32_t buffer_size;        /* Ring buffer size (0 = default) */
    uint32_t batch_size;         /* Batch processing size (0 = default) */
    uint16_t timeout_ms;         /* Read timeout in milliseconds */
    bool immediate_mode;         /* Enable immediate mode (low latency) */
    bool promiscuous;            /* Enable promiscuous mode */
    bool hardware_timestamps;    /* Use hardware timestamps if available */
} pcv_config;

/* Platform operations vtable */
typedef struct pcv_platform_ops {
    /* Lifecycle */
    pcv_handle* (*open)(const char* interface, const pcv_config* config);
    void (*close)(pcv_handle* handle);
    
    /* Capture */
    int (*capture)(pcv_handle* handle, pcv_callback callback, void* user_data);
    int (*capture_batch)(pcv_handle* handle, pcv_batch_callback callback, void* user_data);
    int (*breakloop)(pcv_handle* handle);
    
    /* Filter */
    int (*set_filter)(pcv_handle* handle, const void* filter, size_t filter_len);
    
    /* Stats */
    int (*get_stats)(pcv_handle* handle, pcv_stats* stats);
    
    /* Platform info */
    const char* (*get_platform_name)(void);
    uint32_t (*get_capabilities)(void);
} pcv_platform_ops;

/* Platform capabilities flags */
#define PCV_CAP_HARDWARE_TIMESTAMPS  0x0001
#define PCV_CAP_ZERO_COPY           0x0002
#define PCV_CAP_BATCH_PROCESSING    0x0004
#define PCV_CAP_HARDWARE_OFFLOAD    0x0008
#define PCV_CAP_NUMA_AWARE          0x0010

/* Error codes */
#define PCV_SUCCESS              0
#define PCV_ERROR_GENERIC       -1
#define PCV_ERROR_NO_DEVICE     -2
#define PCV_ERROR_PERMISSION    -3
#define PCV_ERROR_NO_MEMORY     -4
#define PCV_ERROR_INVALID_ARG   -5
#define PCV_ERROR_TIMEOUT       -6
#define PCV_ERROR_BREAK         -7

/* Platform initialization */
const pcv_platform_ops* pcv_get_platform_ops(void);

#ifdef __cplusplus
}
#endif

#endif /* PCV_PLATFORM_H */

