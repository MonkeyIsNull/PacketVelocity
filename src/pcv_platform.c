#include "pcv_platform.h"
#include "pcv.h"

#ifdef PCV_PLATFORM_MACOS
#include "pcv_bpf_macos.h"
#elif defined(PCV_PLATFORM_LINUX)
#include "pcv_xdp_linux.h"
#endif

/* Platform implementation selector */
const pcv_platform_ops* pcv_get_platform_ops(void) {
#ifdef PCV_PLATFORM_MACOS
    return &pcv_macos_ops;
#elif defined(PCV_PLATFORM_LINUX)
    return &pcv_linux_ops;
#elif defined(PCV_PLATFORM_FREEBSD)
    /* TODO: Return FreeBSD netmap ops */
    return NULL;
#else
    /* TODO: Return libpcap fallback ops */
    return NULL;
#endif
}

/* Main API implementation */
pcv_handle* pcv_open(const char* interface, pcv_config* config) {
    const pcv_platform_ops* ops = pcv_get_platform_ops();
    
    if (!ops || !ops->open) {
        return NULL;
    }
    
    return ops->open(interface, config);
}

void pcv_close(pcv_handle* handle) {
    const pcv_platform_ops* ops = pcv_get_platform_ops();
    
    if (ops && ops->close) {
        ops->close(handle);
    }
}

int pcv_set_filter(pcv_handle* handle, void* filter, size_t filter_len) {
    const pcv_platform_ops* ops = pcv_get_platform_ops();
    
    if (!ops || !ops->set_filter) {
        return -PCV_ERROR_GENERIC;
    }
    
    return ops->set_filter(handle, filter, filter_len);
}

int pcv_capture(pcv_handle* handle, pcv_callback callback, void* user_data) {
    const pcv_platform_ops* ops = pcv_get_platform_ops();
    
    if (!ops || !ops->capture) {
        return -PCV_ERROR_GENERIC;
    }
    
    return ops->capture(handle, callback, user_data);
}

int pcv_capture_batch(pcv_handle* handle, pcv_batch_callback callback, void* user_data) {
    const pcv_platform_ops* ops = pcv_get_platform_ops();
    
    if (!ops || !ops->capture_batch) {
        return -PCV_ERROR_GENERIC;
    }
    
    return ops->capture_batch(handle, callback, user_data);
}

int pcv_breakloop(pcv_handle* handle) {
    const pcv_platform_ops* ops = pcv_get_platform_ops();
    
    if (!ops || !ops->breakloop) {
        return -PCV_ERROR_GENERIC;
    }
    
    return ops->breakloop(handle);
}

pcv_stats* pcv_get_stats(pcv_handle* handle) {
    const pcv_platform_ops* ops = pcv_get_platform_ops();
    static pcv_stats stats;
    
    if (!ops || !ops->get_stats) {
        return NULL;
    }
    
    if (ops->get_stats(handle, &stats) < 0) {
        return NULL;
    }
    
    return &stats;
}

const char* pcv_get_error(pcv_handle* handle) {
    /* TODO: Implement error handling */
    (void)handle;
    return "Unknown error";
}

const char* pcv_version(void) {
    return PCV_VERSION_STRING;
}

const char* pcv_platform_name(void) {
    const pcv_platform_ops* ops = pcv_get_platform_ops();
    
    if (ops && ops->get_platform_name) {
        return ops->get_platform_name();
    }
    
    return "Unknown";
}

uint32_t pcv_get_capabilities(void) {
    const pcv_platform_ops* ops = pcv_get_platform_ops();
    
    if (ops && ops->get_capabilities) {
        return ops->get_capabilities();
    }
    
    return 0;
}
