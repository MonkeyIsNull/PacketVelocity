#include "pcv_xdp_linux.h"
#include "pcv_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <ifaddrs.h>

/* Note: This implementation requires libxdp and libbpf
 * On Ubuntu/Debian: apt install libxdp-dev libbpf-dev
 * For now, we'll implement core functionality with stubs for libxdp calls
 */

#ifdef HAVE_LIBXDP
#include <xdp/xsk.h>
#include <bpf/libbpf.h>
#else
/* Stub structures when libxdp is not available */
struct xsk_ring_prod {
    uint32_t cached_prod;
    uint32_t cached_cons;
    uint32_t mask;
    uint32_t size;
    uint32_t *producer;
    void *ring;
    uint32_t *consumer;
    void *map;
    int ring_size;
};

struct xsk_ring_cons {
    uint32_t cached_prod;
    uint32_t cached_cons;
    uint32_t mask;
    uint32_t size;
    uint32_t *producer;
    void *ring;
    uint32_t *consumer;
    void *map;
    int ring_size;
};

/* Stub XDP descriptor */
struct xdp_desc {
    uint64_t addr;
    uint32_t len;
    uint32_t options;
};
#endif

/* Get interface index */
int pcv_xdp_get_ifindex(const char* interface) {
    int ifindex = if_nametoindex(interface);
    if (ifindex == 0) {
        return -PCV_ERROR_NO_DEVICE;
    }
    return ifindex;
}

/* Get NUMA node for interface */
int pcv_xdp_get_numa_node(const char* interface) {
    char path[256];
    FILE* file;
    int numa_node = -1;
    
    snprintf(path, sizeof(path), "/sys/class/net/%s/device/numa_node", interface);
    
    file = fopen(path, "r");
    if (file) {
        if (fscanf(file, "%d", &numa_node) != 1) {
            numa_node = -1;
        }
        fclose(file);
    }
    
    return numa_node;
}

/* NUMA-aware memory allocation */
void* pcv_xdp_alloc_numa(size_t size, int numa_node) {
    /* For now, use regular malloc
     * Real implementation would use numa_alloc_onnode() from libnuma
     */
    (void)numa_node;
    
    /* Align to page boundary for better performance */
    void* ptr = aligned_alloc(4096, (size + 4095) & ~4095);
    if (ptr) {
        memset(ptr, 0, size);
    }
    
    return ptr;
}

/* Set CPU affinity */
int pcv_xdp_set_cpu_affinity(int cpu_core) {
    /* Stub implementation - would use sched_setaffinity() */
    (void)cpu_core;
    printf("Linux stub: Would set CPU affinity to core %d\n", cpu_core);
    return 0;
}

/* Create UMEM */
pcv_xdp_umem* pcv_xdp_umem_create(size_t size, uint32_t frame_size, 
                                  uint32_t ring_size) {
    pcv_xdp_umem* umem;
    
    umem = calloc(1, sizeof(pcv_xdp_umem));
    if (!umem) {
        return NULL;
    }
    
    /* Align frame size to page boundary */
    frame_size = (frame_size + 4095) & ~4095;
    
    /* Ensure minimum frame size */
    if (frame_size < 2048) {
        frame_size = 2048;
    }
    
    /* Allocate buffer aligned to page boundary */
    umem->buffer = pcv_xdp_alloc_numa(size, -1);
    if (!umem->buffer) {
        free(umem);
        return NULL;
    }
    
    umem->size = size;
    umem->frame_size = frame_size;
    umem->frame_count = size / frame_size;
    umem->headroom = PCV_XDP_FRAME_HEADROOM;
    umem->owns_memory = true;
    umem->umem_fd = -1;
    
    /* Initialize ring structures */
    memset(&umem->fill_ring, 0, sizeof(umem->fill_ring));
    memset(&umem->comp_ring, 0, sizeof(umem->comp_ring));
    
    /* Set up ring sizes */
    umem->fill_ring.size = ring_size;
    umem->comp_ring.size = ring_size;
    umem->fill_ring.mask = ring_size - 1;
    umem->comp_ring.mask = ring_size - 1;
    
#ifdef HAVE_LIBXDP
    /* Real implementation would use xsk_umem__create() here */
    printf("Linux: Would create UMEM with libxdp\n");
#else
    printf("Linux stub: Created UMEM with %u frames of %u bytes\n", 
           umem->frame_count, umem->frame_size);
#endif
    
    return umem;
}

/* Destroy UMEM */
void pcv_xdp_umem_destroy(pcv_xdp_umem* umem) {
    if (!umem) return;
    
    if (umem->owns_memory && umem->buffer) {
        free(umem->buffer);
    }
    
    free(umem);
}

/* Create XDP socket */
pcv_xdp_socket* pcv_xdp_socket_create(const char* interface, uint32_t queue_id,
                                      pcv_xdp_umem* umem, pcv_xdp_mode mode) {
    pcv_xdp_socket* socket;
    int ifindex;
    
    if (!interface || !umem) {
        return NULL;
    }
    
    ifindex = pcv_xdp_get_ifindex(interface);
    if (ifindex < 0) {
        return NULL;
    }
    
    socket = calloc(1, sizeof(pcv_xdp_socket));
    if (!socket) {
        return NULL;
    }
    
    socket->umem = umem;
    socket->queue_id = queue_id;
    socket->fd = -1;  /* Would create AF_XDP socket here */
    
    /* Initialize rings (stub) */
    memset(&socket->tx_ring, 0, sizeof(socket->tx_ring));
    memset(&socket->rx_ring, 0, sizeof(socket->rx_ring));
    
    printf("Linux stub: Created XDP socket for %s queue %u mode %d\n", 
           interface, queue_id, mode);
    
    return socket;
}

/* Destroy XDP socket */
void pcv_xdp_socket_destroy(pcv_xdp_socket* socket) {
    if (!socket) return;
    
    if (socket->fd >= 0) {
        close(socket->fd);
    }
    
    free(socket);
}

/* Set XDP program */
int pcv_xdp_set_prog(int ifindex, pcv_xdp_mode mode) {
    printf("Linux stub: Would attach XDP program to ifindex %d mode %d\n", 
           ifindex, mode);
    return 0;
}

/* Remove XDP program */
int pcv_xdp_remove_prog(int ifindex) {
    printf("Linux stub: Would remove XDP program from ifindex %d\n", ifindex);
    return 0;
}

/* Fill UMEM fill ring with available frames */
static int pcv_xdp_fill_ring_populate(pcv_xdp_umem* umem) {
    uint32_t idx = 0;
    uint64_t frame_addr;
    uint32_t i;
    
    if (!umem) return -1;
    
#ifdef HAVE_LIBXDP
    /* Real implementation would use xsk_ring_prod__reserve() */
    return 0;
#else
    /* Stub: populate fill ring with frame addresses */
    for (i = 0; i < umem->frame_count && i < umem->fill_ring.size; i++) {
        frame_addr = i * umem->frame_size;
        /* In real implementation, would write to fill ring */
        (void)frame_addr;
        (void)idx;
    }
    
    printf("Linux stub: Populated fill ring with %u frames\n", i);
    return i;
#endif
}

/* Receive batch of packets */
int pcv_xdp_receive_batch(pcv_xdp_socket* socket, pcv_packet* packets, 
                         uint32_t max_packets) {
    uint32_t received = 0;
    
    if (!socket || !packets || max_packets == 0) {
        return -1;
    }
    
#ifdef HAVE_LIBXDP
    /* Real implementation would use xsk_ring_cons__peek() */
    struct xdp_desc* rx_desc;
    uint32_t idx_rx = 0;
    uint32_t i;
    
    /* Get received packets from RX ring */
    received = 0;  /* xsk_ring_cons__peek(&socket->rx_ring, max_packets, &idx_rx); */
    
    for (i = 0; i < received; i++) {
        /* rx_desc = xsk_ring_cons__rx_desc(&socket->rx_ring, idx_rx++); */
        /* Fill packet structure from descriptor */
        packets[i].data = (uint8_t*)socket->umem->buffer + 0; /* rx_desc->addr */
        packets[i].length = 64;  /* rx_desc->len */
        packets[i].captured_length = 64;
        packets[i].timestamp_ns = 0;  /* Would get from kernel */
        packets[i].interface_index = 0;
        packets[i].flags = 0;
    }
    
    /* Release processed descriptors */
    /* xsk_ring_cons__release(&socket->rx_ring, received); */
    
#else
    /* Stub implementation */
    (void)socket;
    received = 0;
    printf("Linux stub: Would receive up to %u packets\n", max_packets);
#endif
    
    return received;
}

/* Process RX ring */
int pcv_xdp_process_rx_ring(pcv_xdp_socket* socket, pcv_callback callback, 
                           void* user_data) {
    pcv_packet packets[PCV_XDP_MAX_BATCH_SIZE];
    int received;
    uint32_t i;
    
    if (!socket || !callback) {
        return -1;
    }
    
    /* Fill ring initially */
    pcv_xdp_fill_ring_populate(socket->umem);
    
    while (1) {
        /* Receive batch of packets */
        received = pcv_xdp_receive_batch(socket, packets, PCV_XDP_MAX_BATCH_SIZE);
        
        if (received > 0) {
            /* Process each packet */
            for (i = 0; i < (uint32_t)received; i++) {
                callback(&packets[i], user_data);
                socket->rx_packets++;
                socket->rx_bytes += packets[i].captured_length;
            }
        } else if (received < 0) {
            return received;
        }
        
        /* In stub mode, break to avoid infinite loop */
#ifndef HAVE_LIBXDP
        break;
#endif
        
        /* Real implementation would poll/wait for more packets */
        usleep(1000);  /* 1ms delay */
    }
    
    return 0;
}

/* Platform operations implementation */
static pcv_handle* linux_open(const char* interface, const pcv_config* config) {
    pcv_xdp_handle* handle;
    int ifindex;
    
    ifindex = pcv_xdp_get_ifindex(interface);
    if (ifindex < 0) {
        return NULL;
    }
    
    handle = calloc(1, sizeof(pcv_xdp_handle));
    if (!handle) {
        return NULL;
    }
    
    handle->interface_name = strdup(interface);
    handle->ifindex = ifindex;
    handle->mode = PCV_XDP_MODE_DRV;  /* Default to native XDP */
    handle->frame_size = config && config->buffer_size > 0 ? 
                        config->buffer_size : PCV_XDP_DEFAULT_FRAME_SIZE;
    handle->ring_size = PCV_XDP_DEFAULT_RING_SIZE;
    handle->batch_size = PCV_XDP_MAX_BATCH_SIZE;
    handle->cpu_core = -1;
    
    /* Create UMEM */
    handle->umem = pcv_xdp_umem_create(PCV_XDP_DEFAULT_UMEM_SIZE, 
                                       handle->frame_size, 
                                       handle->ring_size);
    if (!handle->umem) {
        free(handle->interface_name);
        free(handle);
        return NULL;
    }
    
    /* Create socket */
    handle->socket = pcv_xdp_socket_create(interface, 0, handle->umem, 
                                          handle->mode);
    if (!handle->socket) {
        pcv_xdp_umem_destroy(handle->umem);
        free(handle->interface_name);
        free(handle);
        return NULL;
    }
    
    /* Set XDP program */
    pcv_xdp_set_prog(handle->ifindex, handle->mode);
    
    printf("Linux stub: Opened XDP capture on %s (ifindex %d)\n", 
           interface, ifindex);
    
    return (pcv_handle*)handle;
}

static void linux_close(pcv_handle* handle) {
    pcv_xdp_handle* xdp_handle = (pcv_xdp_handle*)handle;
    
    if (!xdp_handle) return;
    
    /* Remove XDP program */
    if (xdp_handle->ifindex > 0) {
        pcv_xdp_remove_prog(xdp_handle->ifindex);
    }
    
    /* Cleanup socket and UMEM */
    if (xdp_handle->socket) {
        pcv_xdp_socket_destroy(xdp_handle->socket);
    }
    
    if (xdp_handle->umem) {
        pcv_xdp_umem_destroy(xdp_handle->umem);
    }
    
    free(xdp_handle->interface_name);
    free(xdp_handle);
}

static int linux_capture(pcv_handle* handle, pcv_callback callback, void* user_data) {
    pcv_xdp_handle* xdp_handle = (pcv_xdp_handle*)handle;
    
    if (!xdp_handle || !callback) {
        return -PCV_ERROR_INVALID_ARG;
    }
    
    printf("Linux stub: Would start packet capture loop\n");
    
    /* Stub: would implement AF_XDP packet processing loop here */
    return pcv_xdp_process_rx_ring(xdp_handle->socket, callback, user_data);
}

static int linux_capture_batch(pcv_handle* handle, pcv_batch_callback callback, void* user_data) {
    pcv_xdp_handle* xdp_handle = (pcv_xdp_handle*)handle;
    pcv_packet packets[PCV_XDP_MAX_BATCH_SIZE];
    int count;
    
    if (!xdp_handle || !callback) {
        return -PCV_ERROR_INVALID_ARG;
    }
    
    printf("Linux stub: Would start batch packet capture\n");
    
    /* Stub: would implement batch processing here */
    while (1) {
        count = pcv_xdp_receive_batch(xdp_handle->socket, packets, 
                                     xdp_handle->batch_size);
        if (count > 0) {
            callback(packets, count, user_data);
        }
        
        /* Break for stub */
        break;
    }
    
    return PCV_SUCCESS;
}

static int linux_breakloop(pcv_handle* handle) {
    (void)handle;
    printf("Linux stub: Would break capture loop\n");
    return PCV_SUCCESS;
}

static int linux_set_filter(pcv_handle* handle, const void* filter, size_t filter_len) {
    (void)handle;
    (void)filter;
    (void)filter_len;
    printf("Linux stub: Would set XDP/eBPF filter\n");
    return PCV_SUCCESS;
}

static int linux_get_stats(pcv_handle* handle, pcv_stats* stats) {
    pcv_xdp_handle* xdp_handle = (pcv_xdp_handle*)handle;
    
    if (!xdp_handle || !stats) {
        return -PCV_ERROR_INVALID_ARG;
    }
    
    stats->packets_received = xdp_handle->packets_received;
    stats->packets_dropped = xdp_handle->packets_dropped;
    stats->packets_filtered = xdp_handle->packets_received;
    stats->bytes_received = xdp_handle->bytes_received;
    stats->buffer_overruns = 0;
    
    return PCV_SUCCESS;
}

static const char* linux_get_platform_name(void) {
    return "Linux AF_XDP";
}

static uint32_t linux_get_capabilities(void) {
    return PCV_CAP_ZERO_COPY | 
           PCV_CAP_BATCH_PROCESSING | 
           PCV_CAP_HARDWARE_OFFLOAD |
           PCV_CAP_NUMA_AWARE;
}

/* Platform operations vtable */
const pcv_platform_ops pcv_linux_ops = {
    .open = linux_open,
    .close = linux_close,
    .capture = linux_capture,
    .capture_batch = linux_capture_batch,
    .breakloop = linux_breakloop,
    .set_filter = linux_set_filter,
    .get_stats = linux_get_stats,
    .get_platform_name = linux_get_platform_name,
    .get_capabilities = linux_get_capabilities
};