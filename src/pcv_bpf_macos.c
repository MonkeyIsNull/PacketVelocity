#include "pcv_bpf_macos.h"
#include "pcv_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <net/bpf.h>
#include <net/if.h>
#include <ifaddrs.h>

/* BPF alignment macro if not defined */
#ifndef BPF_WORDALIGN
#define BPF_WORDALIGN(x) (((x) + (BPF_ALIGNMENT - 1)) & ~(BPF_ALIGNMENT - 1))
#define BPF_ALIGNMENT 4
#endif

/* Find an available BPF device */
int pcv_bpf_find_device(char* path_buffer, size_t buffer_size) {
    int fd = -1;
    char device_path[256];
    
    /* Try to open BPF devices from 0 to MAX */
    for (int i = 0; i < PCV_BPF_MAX_DEVICES; i++) {
        snprintf(device_path, sizeof(device_path), "%s%d", PCV_BPF_DEVICE_PREFIX, i);
        
        fd = open(device_path, O_RDWR);
        if (fd >= 0) {
            /* Found an available device */
            close(fd);
            if (path_buffer && buffer_size > 0) {
                strncpy(path_buffer, device_path, buffer_size - 1);
                path_buffer[buffer_size - 1] = '\0';
            }
            return i;
        }
        
        /* If permission denied, no point trying higher numbers */
        if (errno == EACCES || errno == EPERM) {
            return -PCV_ERROR_PERMISSION;
        }
    }
    
    return -PCV_ERROR_NO_DEVICE;
}

/* Open a specific BPF device */
int pcv_bpf_open_device(const char* device_path) {
    int fd = open(device_path, O_RDWR);
    if (fd < 0) {
        if (errno == EACCES || errno == EPERM) {
            return -PCV_ERROR_PERMISSION;
        }
        return -PCV_ERROR_NO_DEVICE;
    }
    
    /* Set non-blocking mode */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd);
        return -PCV_ERROR_GENERIC;
    }
    
    return fd;
}

/* Bind BPF device to network interface */
int pcv_bpf_set_interface(int fd, const char* interface) {
    struct ifreq ifr;
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name) - 1);
    
    if (ioctl(fd, BIOCSETIF, &ifr) < 0) {
        return -PCV_ERROR_NO_DEVICE;
    }
    
    return PCV_SUCCESS;
}

/* Enable/disable immediate mode */
int pcv_bpf_set_immediate(int fd, bool enable) {
    unsigned int immediate = enable ? 1 : 0;
    
    if (ioctl(fd, BIOCIMMEDIATE, &immediate) < 0) {
        return -PCV_ERROR_GENERIC;
    }
    
    return PCV_SUCCESS;
}

/* Set BPF buffer size */
int pcv_bpf_set_buffer_size(int fd, uint32_t size) {
    /* Clamp to valid range */
    if (size < PCV_BPF_MIN_BUFFER_SIZE) {
        size = PCV_BPF_MIN_BUFFER_SIZE;
    } else if (size > PCV_BPF_MAX_BUFFER_SIZE) {
        size = PCV_BPF_MAX_BUFFER_SIZE;
    }
    
    if (ioctl(fd, BIOCSBLEN, &size) < 0) {
        return -PCV_ERROR_GENERIC;
    }
    
    return PCV_SUCCESS;
}

/* Get current BPF buffer size */
int pcv_bpf_get_buffer_size(int fd, uint32_t* size) {
    if (ioctl(fd, BIOCGBLEN, size) < 0) {
        return -PCV_ERROR_GENERIC;
    }
    
    return PCV_SUCCESS;
}

/* Enable memory-mapped access (macOS 10.6+) */
int pcv_bpf_enable_mmap(int fd) {
    /* Check if BIOCGDLTLIST is available (indicates mmap support) */
    struct bpf_dltlist dlt_list;
    dlt_list.bfl_list = NULL;
    dlt_list.bfl_len = 0;
    
    if (ioctl(fd, BIOCGDLTLIST, &dlt_list) < 0) {
        /* mmap might not be supported */
        return -PCV_ERROR_GENERIC;
    }
    
    return PCV_SUCCESS;
}

/* Memory map the BPF buffer */
void* pcv_bpf_mmap_buffer(int fd, size_t size) {
    void* buffer = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    
    if (buffer == MAP_FAILED) {
        return NULL;
    }
    
    return buffer;
}

/* Platform operations implementation */
static pcv_handle* macos_open(const char* interface, const pcv_config* config) {
    pcv_bpf_handle* handle = NULL;
    char device_path[256];
    int result;
    
    /* Find available BPF device */
    result = pcv_bpf_find_device(device_path, sizeof(device_path));
    if (result < 0) {
        return NULL;
    }
    
    /* Allocate handle */
    handle = calloc(1, sizeof(pcv_bpf_handle));
    if (!handle) {
        return NULL;
    }
    
    /* Open BPF device */
    handle->fd = pcv_bpf_open_device(device_path);
    if (handle->fd < 0) {
        free(handle);
        return NULL;
    }
    
    /* Save device info */
    handle->device_path = strdup(device_path);
    handle->interface_name = strdup(interface);
    
    /* Apply configuration */
    uint32_t buffer_size = config && config->buffer_size > 0 ? 
                          config->buffer_size : PCV_BPF_DEFAULT_BUFFER_SIZE;
    
    pcv_bpf_set_buffer_size(handle->fd, buffer_size);
    uint32_t actual_buffer_size = 0;
    pcv_bpf_get_buffer_size(handle->fd, &actual_buffer_size);
    handle->buffer_size = actual_buffer_size;
    
    /* Set interface */
    if (pcv_bpf_set_interface(handle->fd, interface) < 0) {
        close(handle->fd);
        free(handle->device_path);
        free(handle->interface_name);
        free(handle);
        return NULL;
    }
    
    /* Configure immediate mode if requested */
    if (config && config->immediate_mode) {
        pcv_bpf_set_immediate(handle->fd, true);
        handle->immediate_mode = true;
    }
    
    /* Enable promiscuous mode if requested */
    if (config && config->promiscuous) {
        unsigned int promisc = 1;
        ioctl(handle->fd, BIOCPROMISC, &promisc);
        handle->promiscuous = true;
    }
    
    /* Try to enable mmap */
    if (pcv_bpf_enable_mmap(handle->fd) == PCV_SUCCESS) {
        handle->buffer = pcv_bpf_mmap_buffer(handle->fd, handle->buffer_size);
    }
    
    /* Fall back to regular buffer if mmap fails */
    if (!handle->buffer) {
        handle->buffer = malloc(handle->buffer_size);
        if (!handle->buffer) {
            close(handle->fd);
            free(handle->device_path);
            free(handle->interface_name);
            free(handle);
            return NULL;
        }
    }
    
    return (pcv_handle*)handle;
}

static void macos_close(pcv_handle* handle) {
    pcv_bpf_handle* bpf_handle = (pcv_bpf_handle*)handle;
    
    if (!bpf_handle) return;
    
    if (bpf_handle->fd >= 0) {
        close(bpf_handle->fd);
    }
    
    if (bpf_handle->buffer) {
        /* Check if it's mmap'd or malloc'd */
        if (munmap(bpf_handle->buffer, bpf_handle->buffer_size) < 0) {
            /* Not mmap'd, must be malloc'd */
            free(bpf_handle->buffer);
        }
    }
    
    free(bpf_handle->device_path);
    free(bpf_handle->interface_name);
    free(bpf_handle);
}

static int macos_capture(pcv_handle* handle, pcv_callback callback, void* user_data) {
    pcv_bpf_handle* bpf_handle = (pcv_bpf_handle*)handle;
    struct bpf_hdr* hdr;
    uint8_t* ptr;
    pcv_packet packet;
    ssize_t bytes_read;
    
    if (!bpf_handle || !callback) {
        return -PCV_ERROR_INVALID_ARG;
    }
    
    while (!bpf_handle->break_loop) {
        /* Read from BPF device */
        bytes_read = read(bpf_handle->fd, bpf_handle->buffer, bpf_handle->buffer_size);
        
        if (bytes_read < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* No data available in non-blocking mode */
                continue;
            }
            return -PCV_ERROR_GENERIC;
        }
        
        if (bytes_read == 0) {
            continue;
        }
        
        /* Process all packets in the buffer */
        ptr = (uint8_t*)bpf_handle->buffer;
        
        while (bytes_read > 0) {
            /* BPF header */
            hdr = (struct bpf_hdr*)ptr;
            
            /* Sanity check */
            if (hdr->bh_caplen > bytes_read || hdr->bh_datalen > 65535) {
                break;
            }
            
            /* Fill packet structure */
            packet.data = ptr + hdr->bh_hdrlen;
            packet.length = hdr->bh_datalen;
            packet.captured_length = hdr->bh_caplen;
            packet.timestamp_ns = (uint64_t)hdr->bh_tstamp.tv_sec * 1000000000ULL + 
                                 (uint64_t)hdr->bh_tstamp.tv_usec * 1000ULL;
            packet.interface_index = 0; /* Not provided by BPF */
            packet.flags = 0;
            
            /* Update statistics */
            bpf_handle->packets_seen++;
            bpf_handle->bytes_received += packet.captured_length;
            
            /* Call user callback */
            callback(&packet, user_data);
            
            /* Move to next packet */
            uint32_t total_len = BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
            ptr += total_len;
            bytes_read -= total_len;
        }
    }
    
    return PCV_SUCCESS;
}

static int macos_capture_batch(pcv_handle* handle, pcv_batch_callback callback, void* user_data) {
    pcv_bpf_handle* bpf_handle = (pcv_bpf_handle*)handle;
    struct bpf_hdr* hdr;
    uint8_t* ptr;
    pcv_packet* packets;
    size_t packet_count;
    size_t max_batch = 256; /* Default batch size */
    ssize_t bytes_read;
    
    if (!bpf_handle || !callback) {
        return -PCV_ERROR_INVALID_ARG;
    }
    
    /* Allocate batch buffer */
    packets = calloc(max_batch, sizeof(pcv_packet));
    if (!packets) {
        return -PCV_ERROR_NO_MEMORY;
    }
    
    while (!bpf_handle->break_loop) {
        /* Read from BPF device */
        bytes_read = read(bpf_handle->fd, bpf_handle->buffer, bpf_handle->buffer_size);
        
        if (bytes_read < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* No data available in non-blocking mode */
                continue;
            }
            free(packets);
            return -PCV_ERROR_GENERIC;
        }
        
        if (bytes_read == 0) {
            continue;
        }
        
        /* Process all packets in the buffer */
        ptr = (uint8_t*)bpf_handle->buffer;
        packet_count = 0;
        
        while (bytes_read > 0 && packet_count < max_batch) {
            /* BPF header */
            hdr = (struct bpf_hdr*)ptr;
            
            /* Sanity check */
            if (hdr->bh_caplen > bytes_read || hdr->bh_datalen > 65535) {
                break;
            }
            
            /* Fill packet structure */
            packets[packet_count].data = ptr + hdr->bh_hdrlen;
            packets[packet_count].length = hdr->bh_datalen;
            packets[packet_count].captured_length = hdr->bh_caplen;
            packets[packet_count].timestamp_ns = (uint64_t)hdr->bh_tstamp.tv_sec * 1000000000ULL + 
                                                (uint64_t)hdr->bh_tstamp.tv_usec * 1000ULL;
            packets[packet_count].interface_index = 0;
            packets[packet_count].flags = 0;
            
            /* Update statistics */
            bpf_handle->packets_seen++;
            bpf_handle->bytes_received += packets[packet_count].captured_length;
            
            packet_count++;
            
            /* Move to next packet */
            uint32_t total_len = BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
            ptr += total_len;
            bytes_read -= total_len;
        }
        
        /* Call batch callback if we have packets */
        if (packet_count > 0) {
            callback(packets, packet_count, user_data);
        }
    }
    
    free(packets);
    return PCV_SUCCESS;
}

static int macos_breakloop(pcv_handle* handle) {
    pcv_bpf_handle* bpf_handle = (pcv_bpf_handle*)handle;
    
    if (!bpf_handle) {
        return -PCV_ERROR_INVALID_ARG;
    }
    
    bpf_handle->break_loop = true;
    return PCV_SUCCESS;
}

static int macos_set_filter(pcv_handle* handle, const void* filter, size_t filter_len) {
    /* TODO: Implement filter setting */
    (void)handle;
    (void)filter;
    (void)filter_len;
    return PCV_SUCCESS;
}

static int macos_get_stats(pcv_handle* handle, pcv_stats* stats) {
    pcv_bpf_handle* bpf_handle = (pcv_bpf_handle*)handle;
    struct bpf_stat bpf_stats;
    
    if (ioctl(bpf_handle->fd, BIOCGSTATS, &bpf_stats) < 0) {
        return -PCV_ERROR_GENERIC;
    }
    
    stats->packets_received = bpf_stats.bs_recv;
    stats->packets_dropped = bpf_stats.bs_drop;
    stats->packets_filtered = bpf_handle->packets_seen;
    stats->bytes_received = bpf_handle->bytes_received;
    stats->buffer_overruns = 0; /* Not tracked by BPF */
    
    return PCV_SUCCESS;
}

static const char* macos_get_platform_name(void) {
    return "macOS BPF";
}

static uint32_t macos_get_capabilities(void) {
    return PCV_CAP_ZERO_COPY | PCV_CAP_BATCH_PROCESSING;
}

/* Platform operations vtable */
const pcv_platform_ops pcv_macos_ops = {
    .open = macos_open,
    .close = macos_close,
    .capture = macos_capture,
    .capture_batch = macos_capture_batch,
    .breakloop = macos_breakloop,
    .set_filter = macos_set_filter,
    .get_stats = macos_get_stats,
    .get_platform_name = macos_get_platform_name,
    .get_capabilities = macos_get_capabilities
};
