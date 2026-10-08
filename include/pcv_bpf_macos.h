#ifndef PCV_BPF_MACOS_H
#define PCV_BPF_MACOS_H

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <sys/types.h>
#include "pcv_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/* macOS BPF implementation specifics */

/* BPF device limits */
#define PCV_BPF_MAX_DEVICES 256
#define PCV_BPF_DEVICE_PREFIX "/dev/bpf"

/* Default buffer sizes */
#define PCV_BPF_DEFAULT_BUFFER_SIZE (4 * 1024 * 1024)  /* 4MB */
#define PCV_BPF_MIN_BUFFER_SIZE (32 * 1024)             /* 32KB */
#define PCV_BPF_MAX_BUFFER_SIZE (16 * 1024 * 1024)      /* 16MB */

/* BPF handle structure */
typedef struct pcv_bpf_handle {
    int fd;                     /* BPF device file descriptor */
    char* device_path;          /* Path to BPF device */
    char* interface_name;       /* Network interface name */
    
    /* Buffer management */
    void* buffer;               /* mmap'd buffer */
    size_t buffer_size;         /* Buffer size */
    size_t read_offset;         /* Current read position */
    
    /* Configuration */
    bool immediate_mode;        /* BIOCIMMEDIATE enabled */
    bool promiscuous;           /* Promiscuous mode */
    uint32_t timeout_ms;        /* Read timeout */
    volatile bool break_loop;   /* Signal to break capture loop */
    
    /* Statistics. packets_seen/bytes_received are _Atomic because the dashboard
     * sampler thread reads them (via macos_get_stats) concurrently with the
     * capture thread's updates; relaxed atomics are as cheap as the previous
     * plain adds and keep the read TSan-clean. */
    _Atomic uint64_t packets_seen;      /* Packets processed */
    uint64_t packets_dropped;           /* Dropped by kernel */
    _Atomic uint64_t bytes_received;    /* Total bytes */
    
    /* Error handling */
    char error_buffer[256];     /* Last error message */
} pcv_bpf_handle;

/* BPF-specific functions */
int pcv_bpf_find_device(char* path_buffer, size_t buffer_size);
int pcv_bpf_open_device(const char* device_path);
int pcv_bpf_set_interface(int fd, const char* interface);
int pcv_bpf_set_immediate(int fd, bool enable);
int pcv_bpf_set_buffer_size(int fd, uint32_t size);
int pcv_bpf_get_buffer_size(int fd, uint32_t* size);
int pcv_bpf_enable_mmap(int fd);
void* pcv_bpf_mmap_buffer(int fd, size_t size);

/* Platform operations implementation */
extern const pcv_platform_ops pcv_macos_ops;

#ifdef __cplusplus
}
#endif

#endif /* PCV_BPF_MACOS_H */
