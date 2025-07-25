#ifndef PCV_RAW_LINUX_H
#define PCV_RAW_LINUX_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include "pcv_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Linux raw socket implementation specifics */

/* Raw socket configuration */
#define PCV_RAW_DEFAULT_BUFFER_SIZE   (2 * 1024 * 1024)  /* 2MB */
#define PCV_RAW_MAX_PACKET_SIZE       65536
#define PCV_RAW_MAX_BATCH_SIZE        64

/* Raw socket handle structure */
typedef struct pcv_raw_handle {
    char* interface_name;      /* Network interface name */
    int ifindex;               /* Interface index */
    int socket_fd;             /* Raw socket file descriptor */
    
    /* Configuration */
    uint32_t buffer_size;
    uint32_t batch_size;
    bool promiscuous;          /* Promiscuous mode enabled */
    volatile bool break_loop;  /* Signal to break capture loop */
    
    /* Statistics */
    uint64_t packets_received;
    uint64_t packets_dropped;
    uint64_t bytes_received;
    
    /* Error handling */
    char error_buffer[256];
} pcv_raw_handle;

/* Raw socket-specific functions */

/* Utility functions */
int pcv_raw_get_ifindex(const char* interface);
int pcv_raw_set_promiscuous(int socket_fd, const char* interface, bool enable);
int pcv_raw_create_socket(void);

/* Platform operations implementation */
extern const pcv_platform_ops pcv_linux_ops;

#ifdef __cplusplus
}
#endif

#endif /* PCV_RAW_LINUX_H */