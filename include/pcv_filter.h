#ifndef PCV_FILTER_H
#define PCV_FILTER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PacketVelocity Filter Interface */

/* Filter types */
typedef enum pcv_filter_type {
    PCV_FILTER_VFM,      /* VelocityFilterMachine bytecode */
    PCV_FILTER_BPF,      /* Berkeley Packet Filter */
    PCV_FILTER_CUSTOM    /* Custom filter function */
} pcv_filter_type;

/* Filter decision */
typedef enum pcv_filter_decision {
    PCV_FILTER_ACCEPT = 1,
    PCV_FILTER_DROP = 0,
    PCV_FILTER_ERROR = -1
} pcv_filter_decision;

/* Filter context */
typedef struct pcv_filter {
    pcv_filter_type type;
    void* filter_data;
    size_t filter_size;
    
    /* VFM specific */
    void* vfm_context;
    
    /* Statistics */
    uint64_t packets_processed;
    uint64_t packets_accepted;
    uint64_t packets_dropped;
} pcv_filter;

/* Custom filter callback */
typedef pcv_filter_decision (*pcv_filter_func)(const uint8_t* data, 
                                                uint32_t length, 
                                                void* user_data);

/* Filter functions */

/* Create filter from bytecode */
pcv_filter* pcv_filter_create(pcv_filter_type type, const void* bytecode, 
                              size_t bytecode_len);

/* Create custom filter */
pcv_filter* pcv_filter_create_custom(pcv_filter_func func, void* user_data);

/* Destroy filter */
void pcv_filter_destroy(pcv_filter* filter);

/* Apply filter to packet */
pcv_filter_decision pcv_filter_apply(pcv_filter* filter, const uint8_t* data, 
                                     uint32_t length);

/* Get filter statistics */
void pcv_filter_get_stats(const pcv_filter* filter, uint64_t* processed,
                          uint64_t* accepted, uint64_t* dropped);

/* Reset filter statistics */
void pcv_filter_reset_stats(pcv_filter* filter);

/* VFM specific functions */
int pcv_filter_vfm_init(void);
void pcv_filter_vfm_cleanup(void);
const char* pcv_filter_vfm_version(void);

/* Load VFM filter from file */
pcv_filter* pcv_filter_create_from_file(const char* filename);

#ifdef __cplusplus
}
#endif

#endif /* PCV_FILTER_H */
