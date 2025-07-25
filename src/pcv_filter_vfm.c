#ifdef __linux__
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L  /* For strdup and other POSIX functions */
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE  /* For additional system functions */
#endif
#endif

#include "pcv_filter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vfm.h>

/* Create filter from bytecode */
pcv_filter* pcv_filter_create(pcv_filter_type type, const void* bytecode, 
                              size_t bytecode_len) {
    pcv_filter* filter;
    
    if (!bytecode || bytecode_len == 0) {
        return NULL;
    }
    
    filter = calloc(1, sizeof(pcv_filter));
    if (!filter) {
        return NULL;
    }
    
    filter->type = type;
    
    switch (type) {
    case PCV_FILTER_VFM:
        /* Create VFM VM state */
        filter->vfm_context = vfm_create();
        if (!filter->vfm_context) {
            free(filter);
            return NULL;
        }
        
        /* Copy bytecode for reference first */
        filter->filter_data = malloc(bytecode_len);
        if (!filter->filter_data) {
            vfm_destroy(filter->vfm_context);
            free(filter);
            return NULL;
        }
        memcpy(filter->filter_data, bytecode, bytecode_len);
        
        /* Load VFM program using the stable copy */
        if (vfm_load_program(filter->vfm_context, (const uint8_t*)filter->filter_data, (uint32_t)bytecode_len) != VFM_SUCCESS) {
            free(filter->filter_data);
            vfm_destroy(filter->vfm_context);
            free(filter);
            return NULL;
        }
        filter->filter_size = bytecode_len;
        break;
        
    case PCV_FILTER_BPF:
        /* TODO: Implement BPF filter support */
        free(filter);
        return NULL;
        
    default:
        free(filter);
        return NULL;
    }
    
    return filter;
}

/* Create custom filter */
pcv_filter* pcv_filter_create_custom(pcv_filter_func func, void* user_data) {
    pcv_filter* filter;
    
    if (!func) {
        return NULL;
    }
    
    filter = calloc(1, sizeof(pcv_filter));
    if (!filter) {
        return NULL;
    }
    
    filter->type = PCV_FILTER_CUSTOM;
    /* Store function pointer in vfm_context to avoid pedantic warning */
    *(pcv_filter_func*)&filter->filter_data = func;
    filter->vfm_context = user_data; /* Reuse for user data */
    
    return filter;
}

/* Destroy filter */
void pcv_filter_destroy(pcv_filter* filter) {
    if (!filter) return;
    
    switch (filter->type) {
    case PCV_FILTER_VFM:
        if (filter->vfm_context) {
            vfm_destroy(filter->vfm_context);
        }
        if (filter->filter_data) {
            free(filter->filter_data);
        }
        break;
        
    case PCV_FILTER_BPF:
        if (filter->filter_data) {
            free(filter->filter_data);
        }
        break;
        
    case PCV_FILTER_CUSTOM:
        /* Nothing to free for custom filters */
        break;
    }
    
    free(filter);
}

/* Apply filter to packet */
pcv_filter_decision pcv_filter_apply(pcv_filter* filter, const uint8_t* data, 
                                     uint32_t length) {
    pcv_filter_decision decision = PCV_FILTER_DROP;
    
    if (!filter || !data) {
        return PCV_FILTER_ERROR;
    }
    
    filter->packets_processed++;
    
    switch (filter->type) {
    case PCV_FILTER_VFM:
        if (filter->vfm_context) {
            int result = vfm_execute(filter->vfm_context, data, (uint16_t)length);
            decision = result > 0 ? PCV_FILTER_ACCEPT : PCV_FILTER_DROP;
        }
        break;
        
    case PCV_FILTER_BPF:
        /* TODO: Implement BPF execution */
        decision = PCV_FILTER_ERROR;
        break;
        
    case PCV_FILTER_CUSTOM:
        if (filter->filter_data) {
            pcv_filter_func func;
            /* Retrieve function pointer avoiding pedantic warning */
            memcpy(&func, &filter->filter_data, sizeof(func));
            decision = func(data, length, filter->vfm_context);
        }
        break;
    }
    
    /* Update statistics */
    if (decision == PCV_FILTER_ACCEPT) {
        filter->packets_accepted++;
    } else if (decision == PCV_FILTER_DROP) {
        filter->packets_dropped++;
    }
    
    return decision;
}

/* Get filter statistics */
void pcv_filter_get_stats(const pcv_filter* filter, uint64_t* processed,
                          uint64_t* accepted, uint64_t* dropped) {
    if (!filter) return;
    
    if (processed) *processed = filter->packets_processed;
    if (accepted) *accepted = filter->packets_accepted;
    if (dropped) *dropped = filter->packets_dropped;
}

/* Reset filter statistics */
void pcv_filter_reset_stats(pcv_filter* filter) {
    if (!filter) return;
    
    filter->packets_processed = 0;
    filter->packets_accepted = 0;
    filter->packets_dropped = 0;
}

/* VFM specific functions */
int pcv_filter_vfm_init(void) {
    /* Initialize VFM if needed */
    return 0;
}

void pcv_filter_vfm_cleanup(void) {
    /* Cleanup VFM if needed */
}

const char* pcv_filter_vfm_version(void) {
    return "VFM 1.0.0";  /* VFM doesn't expose version function in the header */
}

/* Load VFM filter from file */
pcv_filter* pcv_filter_create_from_file(const char* filename) {
    FILE* file;
    uint8_t* bytecode;
    size_t file_size;
    pcv_filter* filter;
    
    if (!filename) {
        return NULL;
    }
    
    file = fopen(filename, "rb");
    if (!file) {
        return NULL;
    }
    
    /* Get file size */
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (file_size == 0) {
        fclose(file);
        return NULL;
    }
    
    /* Allocate buffer */
    bytecode = malloc(file_size);
    if (!bytecode) {
        fclose(file);
        return NULL;
    }
    
    /* Read file */
    if (fread(bytecode, 1, file_size, file) != file_size) {
        free(bytecode);
        fclose(file);
        return NULL;
    }
    
    fclose(file);
    
    
    /* Create filter - note: pcv_filter_create will copy the bytecode */
    filter = pcv_filter_create(PCV_FILTER_VFM, bytecode, file_size);
    
    free(bytecode);
    return filter;
}
