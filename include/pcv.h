#ifndef PCV_H
#define PCV_H

#include "pcv_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/* PacketVelocity - High-performance packet capture library */

/* Version info */
#define PCV_VERSION_MAJOR 0
#define PCV_VERSION_MINOR 1
#define PCV_VERSION_PATCH 0
#define PCV_VERSION_STRING "0.1.0"

/* Main API functions */

/* Initialize capture on specified interface */
pcv_handle* pcv_open(const char* interface, pcv_config* config);

/* Close capture handle and free resources */
void pcv_close(pcv_handle* handle);

/* Set filter (TinyTotVM bytecode or BPF) */
int pcv_set_filter(pcv_handle* handle, void* filter, size_t filter_len);

/* Capture packets with callback */
int pcv_capture(pcv_handle* handle, pcv_callback callback, void* user_data);

/* Batch capture for performance */
int pcv_capture_batch(pcv_handle* handle, pcv_batch_callback callback, void* user_data);

/* Break out of capture loop */
int pcv_breakloop(pcv_handle* handle);

/* Get capture statistics */
pcv_stats* pcv_get_stats(pcv_handle* handle);

/* Get last error message */
const char* pcv_get_error(pcv_handle* handle);

/* Utility functions */
const char* pcv_version(void);
const char* pcv_platform_name(void);
uint32_t pcv_get_capabilities(void);

#ifdef __cplusplus
}
#endif

#endif /* PCV_H */
