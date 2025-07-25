#ifdef __linux__
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L  /* For strdup and other POSIX functions */
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE  /* For additional system functions */
#endif
#endif

#include "pcv_raw_linux.h"
#include "pcv_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Include packet socket headers with fallbacks for musl/Alpine */
#ifdef __has_include
#if __has_include(<linux/if_packet.h>)
#include <linux/if_packet.h>
#else
#include <netpacket/packet.h>
#endif
#if __has_include(<linux/if_ether.h>)
#include <linux/if_ether.h>
#else
#include <net/ethernet.h>
#endif
#else
/* Fallback for older compilers */
#include <netpacket/packet.h>
#include <net/ethernet.h>
#endif

/* Define ETH_P_ALL if not available */
#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif

/* Get interface index */
int pcv_raw_get_ifindex(const char* interface) {
    int ifindex = if_nametoindex(interface);
    if (ifindex == 0) {
        return -PCV_ERROR_NO_DEVICE;
    }
    return ifindex;
}

/* Create raw socket */
int pcv_raw_create_socket(void) {
    int sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd < 0) {
        return -PCV_ERROR_PERMISSION;
    }
    return sock_fd;
}

/* Set promiscuous mode */
int pcv_raw_set_promiscuous(int socket_fd, const char* interface, bool enable) {
    struct ifreq ifr;
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    
    /* Get current flags */
    if (ioctl(socket_fd, SIOCGIFFLAGS, &ifr) < 0) {
        return -1;
    }
    
    /* Set or clear promiscuous flag */
    if (enable) {
        ifr.ifr_flags |= IFF_PROMISC;
    } else {
        ifr.ifr_flags &= ~IFF_PROMISC;
    }
    
    /* Apply new flags */
    if (ioctl(socket_fd, SIOCSIFFLAGS, &ifr) < 0) {
        return -1;
    }
    
    return 0;
}

/* Platform operations implementation */
static pcv_handle* linux_open(const char* interface, const pcv_config* config) {
    pcv_raw_handle* handle;
    int ifindex;
    int sock_fd;
    struct sockaddr_ll bind_addr;
    
    ifindex = pcv_raw_get_ifindex(interface);
    if (ifindex < 0) {
        return NULL;
    }
    
    sock_fd = pcv_raw_create_socket();
    if (sock_fd < 0) {
        return NULL;
    }
    
    handle = calloc(1, sizeof(pcv_raw_handle));
    if (!handle) {
        close(sock_fd);
        return NULL;
    }
    
    handle->interface_name = strdup(interface);
    handle->ifindex = ifindex;
    handle->socket_fd = sock_fd;
    handle->buffer_size = config && config->buffer_size > 0 ? 
                         config->buffer_size : PCV_RAW_DEFAULT_BUFFER_SIZE;
    handle->batch_size = PCV_RAW_MAX_BATCH_SIZE;
    handle->promiscuous = true;
    handle->break_loop = false;
    
    /* Bind socket to interface */
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sll_family = AF_PACKET;
    bind_addr.sll_protocol = htons(ETH_P_ALL);
    bind_addr.sll_ifindex = ifindex;
    
    if (bind(sock_fd, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
        free(handle->interface_name);
        free(handle);
        close(sock_fd);
        return NULL;
    }
    
    /* Set promiscuous mode */
    if (pcv_raw_set_promiscuous(sock_fd, interface, true) < 0) {
        printf("Warning: Could not enable promiscuous mode on %s\n", interface);
    }
    
    /* Set socket buffer size */
    int buffer_size = handle->buffer_size;
    if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size)) < 0) {
        printf("Warning: Could not set socket buffer size\n");
    }
    
    printf("Linux: Opened raw socket capture on %s (ifindex %d)\n", 
           interface, ifindex);
    
    return (pcv_handle*)handle;
}

static void linux_close(pcv_handle* handle) {
    pcv_raw_handle* raw_handle = (pcv_raw_handle*)handle;
    
    if (!raw_handle) return;
    
    /* Disable promiscuous mode */
    if (raw_handle->socket_fd >= 0) {
        pcv_raw_set_promiscuous(raw_handle->socket_fd, raw_handle->interface_name, false);
        close(raw_handle->socket_fd);
    }
    
    free(raw_handle->interface_name);
    free(raw_handle);
}

static int linux_capture(pcv_handle* handle, pcv_callback callback, void* user_data) {
    pcv_raw_handle* raw_handle = (pcv_raw_handle*)handle;
    uint8_t buffer[PCV_RAW_MAX_PACKET_SIZE];
    pcv_packet packet;
    ssize_t packet_len;
    struct timespec ts;
    
    if (!raw_handle || !callback) {
        return -PCV_ERROR_INVALID_ARG;
    }
    
    printf("Linux: Starting raw socket packet capture loop\n");
    
    while (!raw_handle->break_loop) {
        /* Receive packet */
        packet_len = recv(raw_handle->socket_fd, buffer, sizeof(buffer), 0);
        
        if (packet_len < 0) {
            if (errno == EINTR) {
                continue;  /* Interrupted by signal */
            }
            return -PCV_ERROR_GENERIC;
        }
        
        if (packet_len == 0) {
            continue;  /* No data */
        }
        
        /* Get timestamp */
        clock_gettime(CLOCK_REALTIME, &ts);
        
        /* Fill packet structure */
        packet.data = buffer;
        packet.length = packet_len;
        packet.captured_length = packet_len;
        packet.timestamp_ns = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
        packet.interface_index = raw_handle->ifindex;
        packet.flags = 0;
        
        /* Call user callback */
        callback(&packet, user_data);
        
        /* Update statistics */
        raw_handle->packets_received++;
        raw_handle->bytes_received += packet_len;
    }
    
    return PCV_SUCCESS;
}

static int linux_capture_batch(pcv_handle* handle, pcv_batch_callback callback, void* user_data) {
    pcv_raw_handle* raw_handle = (pcv_raw_handle*)handle;
    
    (void)user_data;  /* Unused parameter */
    
    if (!raw_handle || !callback) {
        return -PCV_ERROR_INVALID_ARG;
    }
    
    printf("Linux: Batch capture not implemented for raw sockets\n");
    return -PCV_ERROR_GENERIC;
}

static int linux_breakloop(pcv_handle* handle) {
    pcv_raw_handle* raw_handle = (pcv_raw_handle*)handle;
    
    if (!raw_handle) {
        return -PCV_ERROR_INVALID_ARG;
    }
    
    raw_handle->break_loop = true;
    return PCV_SUCCESS;
}

static int linux_set_filter(pcv_handle* handle, const void* filter, size_t filter_len) {
    (void)handle;
    (void)filter;
    (void)filter_len;
    printf("Linux: VFM filtering handled in userspace, not kernel\n");
    return PCV_SUCCESS;
}

static int linux_get_stats(pcv_handle* handle, pcv_stats* stats) {
    pcv_raw_handle* raw_handle = (pcv_raw_handle*)handle;
    
    if (!raw_handle || !stats) {
        return -PCV_ERROR_INVALID_ARG;
    }
    
    stats->packets_received = raw_handle->packets_received;
    stats->packets_dropped = raw_handle->packets_dropped;
    stats->packets_filtered = raw_handle->packets_received;
    stats->bytes_received = raw_handle->bytes_received;
    stats->buffer_overruns = 0;
    
    return PCV_SUCCESS;
}

static const char* linux_get_platform_name(void) {
    return "Linux Raw Sockets";
}

static uint32_t linux_get_capabilities(void) {
    return 0;  /* No special capabilities for raw sockets */
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