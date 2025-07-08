#ifndef PCV_XDP_LINUX_H
#define PCV_XDP_LINUX_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include "pcv_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Linux AF_XDP implementation specifics */

/* AF_XDP configuration */
#define PCV_XDP_DEFAULT_FRAME_SIZE    2048
#define PCV_XDP_DEFAULT_RING_SIZE     2048
#define PCV_XDP_DEFAULT_UMEM_SIZE     (4 * 1024 * 1024)  /* 4MB */
#define PCV_XDP_FRAME_HEADROOM        256
#define PCV_XDP_MAX_BATCH_SIZE        64

/* XDP modes */
typedef enum pcv_xdp_mode {
    PCV_XDP_MODE_SKB = 0,      /* Generic XDP (slowest) */
    PCV_XDP_MODE_DRV,          /* Native XDP (faster) */
    PCV_XDP_MODE_HW            /* Hardware offload (fastest) */
} pcv_xdp_mode;

/* UMEM (User Memory) configuration */
typedef struct pcv_xdp_umem {
    void* buffer;              /* Memory buffer */
    size_t size;               /* Total buffer size */
    uint32_t frame_size;       /* Size of each frame */
    uint32_t frame_count;      /* Number of frames */
    uint32_t headroom;         /* Headroom per frame */
    
    /* Fill and completion rings */
    struct xsk_ring_prod fill_ring;
    struct xsk_ring_cons comp_ring;
    
    /* Memory mapping */
    bool owns_memory;          /* Whether we allocated the buffer */
    int umem_fd;               /* UMEM file descriptor */
} pcv_xdp_umem;

/* XDP socket structure */
typedef struct pcv_xdp_socket {
    int fd;                    /* Socket file descriptor */
    struct xsk_ring_prod tx_ring;
    struct xsk_ring_cons rx_ring;
    
    /* UMEM reference */
    pcv_xdp_umem* umem;
    
    /* Queue configuration */
    uint32_t queue_id;
    uint32_t prog_id;          /* XDP program ID */
    
    /* Statistics */
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t rx_dropped;
} pcv_xdp_socket;

/* XDP handle structure */
typedef struct pcv_xdp_handle {
    char* interface_name;      /* Network interface name */
    int ifindex;               /* Interface index */
    
    /* XDP configuration */
    pcv_xdp_mode mode;
    bool zero_copy;            /* Zero-copy mode enabled */
    
    /* UMEM and socket */
    pcv_xdp_umem* umem;
    pcv_xdp_socket* socket;
    
    /* Configuration */
    uint32_t frame_size;
    uint32_t ring_size;
    uint32_t batch_size;
    bool numa_aware;
    int cpu_core;              /* CPU core to pin to (-1 = no pinning) */
    
    /* Statistics */
    uint64_t packets_received;
    uint64_t packets_dropped;
    uint64_t bytes_received;
    
    /* Error handling */
    char error_buffer[256];
} pcv_xdp_handle;

/* XDP-specific functions */

/* UMEM management */
pcv_xdp_umem* pcv_xdp_umem_create(size_t size, uint32_t frame_size, 
                                  uint32_t ring_size);
void pcv_xdp_umem_destroy(pcv_xdp_umem* umem);

/* Socket management */
pcv_xdp_socket* pcv_xdp_socket_create(const char* interface, uint32_t queue_id,
                                      pcv_xdp_umem* umem, pcv_xdp_mode mode);
void pcv_xdp_socket_destroy(pcv_xdp_socket* socket);

/* Packet processing */
int pcv_xdp_receive_batch(pcv_xdp_socket* socket, pcv_packet* packets, 
                         uint32_t max_packets);
int pcv_xdp_process_rx_ring(pcv_xdp_socket* socket, pcv_callback callback, 
                           void* user_data);

/* Utility functions */
int pcv_xdp_get_ifindex(const char* interface);
int pcv_xdp_set_prog(int ifindex, pcv_xdp_mode mode);
int pcv_xdp_remove_prog(int ifindex);

/* NUMA and CPU affinity */
int pcv_xdp_get_numa_node(const char* interface);
int pcv_xdp_set_cpu_affinity(int cpu_core);
void* pcv_xdp_alloc_numa(size_t size, int numa_node);

/* Platform operations implementation */
extern const pcv_platform_ops pcv_linux_ops;

#ifdef __cplusplus
}
#endif

#endif /* PCV_XDP_LINUX_H */