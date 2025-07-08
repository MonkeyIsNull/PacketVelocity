#include "pcv_ringbuf.h"
#include <stdlib.h>
#include <string.h>

/* Initialize ring buffer with given memory */
int pcv_ringbuf_init(pcv_ringbuf* rb, void* buffer, size_t size) {
    if (!rb || !buffer || size < sizeof(pcv_ringbuf_packet_header)) {
        return -1;
    }
    
    memset(rb, 0, sizeof(pcv_ringbuf));
    rb->buffer = (uint8_t*)buffer;
    rb->size = size;
    rb->owns_memory = false;
    
    return 0;
}

/* Allocate and initialize ring buffer */
pcv_ringbuf* pcv_ringbuf_create(size_t size) {
    pcv_ringbuf* rb;
    void* buffer;
    
    if (size < sizeof(pcv_ringbuf_packet_header)) {
        return NULL;
    }
    
    rb = calloc(1, sizeof(pcv_ringbuf));
    if (!rb) {
        return NULL;
    }
    
    buffer = calloc(1, size);
    if (!buffer) {
        free(rb);
        return NULL;
    }
    
    rb->buffer = buffer;
    rb->size = size;
    rb->owns_memory = true;
    
    return rb;
}

/* Destroy ring buffer */
void pcv_ringbuf_destroy(pcv_ringbuf* rb) {
    if (!rb) return;
    
    if (rb->owns_memory && rb->buffer) {
        free(rb->buffer);
    }
    
    free(rb);
}

/* Reset ring buffer to empty state */
void pcv_ringbuf_reset(pcv_ringbuf* rb) {
    if (!rb) return;
    
    rb->read_pos = 0;
    rb->write_pos = 0;
    rb->packet_count = 0;
    rb->is_full = false;
}

/* Calculate available contiguous write space */
static size_t pcv_ringbuf_write_space(const pcv_ringbuf* rb) {
    if (rb->is_full) {
        return 0;
    }
    
    if (rb->write_pos >= rb->read_pos) {
        size_t space_to_end = rb->size - rb->write_pos;
        size_t space_from_start = rb->read_pos;
        return (space_to_end > 0) ? space_to_end : space_from_start;
    } else {
        return rb->read_pos - rb->write_pos;
    }
}

/* Write packet to ring buffer */
int pcv_ringbuf_write(pcv_ringbuf* rb, const void* data, size_t length, 
                      uint64_t timestamp_ns) {
    pcv_ringbuf_packet_header header;
    size_t total_size = sizeof(header) + length;
    size_t available;
    
    if (!rb || !data || length == 0) {
        return -1;
    }
    
    /* Check if packet fits */
    available = pcv_ringbuf_available(rb);
    if (total_size > available) {
        rb->dropped_packets++;
        return -1;
    }
    
    /* Prepare header */
    header.length = length;
    header.captured_length = length;
    header.timestamp_ns = timestamp_ns;
    header.offset = total_size;
    
    /* Write header */
    if (rb->write_pos + sizeof(header) <= rb->size) {
        memcpy(rb->buffer + rb->write_pos, &header, sizeof(header));
        rb->write_pos += sizeof(header);
    } else {
        /* Header wraps around */
        size_t first_part = rb->size - rb->write_pos;
        memcpy(rb->buffer + rb->write_pos, &header, first_part);
        memcpy(rb->buffer, (uint8_t*)&header + first_part, sizeof(header) - first_part);
        rb->write_pos = sizeof(header) - first_part;
    }
    
    /* Write data */
    if (rb->write_pos + length <= rb->size) {
        memcpy(rb->buffer + rb->write_pos, data, length);
        rb->write_pos += length;
    } else {
        /* Data wraps around */
        size_t first_part = rb->size - rb->write_pos;
        memcpy(rb->buffer + rb->write_pos, data, first_part);
        memcpy(rb->buffer, (uint8_t*)data + first_part, length - first_part);
        rb->write_pos = length - first_part;
    }
    
    /* Wrap write position if at end */
    if (rb->write_pos >= rb->size) {
        rb->write_pos = 0;
    }
    
    /* Update counters */
    rb->packet_count++;
    rb->total_packets++;
    
    /* Check if full */
    if (rb->write_pos == rb->read_pos) {
        rb->is_full = true;
    }
    
    return 0;
}

/* Read next packet from ring buffer */
int pcv_ringbuf_read(pcv_ringbuf* rb, void* data, size_t* length,
                     uint64_t* timestamp_ns) {
    pcv_ringbuf_packet_header header;
    
    if (!rb || !data || !length || pcv_ringbuf_empty(rb)) {
        return -1;
    }
    
    /* Read header */
    if (rb->read_pos + sizeof(header) <= rb->size) {
        memcpy(&header, rb->buffer + rb->read_pos, sizeof(header));
        rb->read_pos += sizeof(header);
    } else {
        /* Header wraps around */
        size_t first_part = rb->size - rb->read_pos;
        memcpy(&header, rb->buffer + rb->read_pos, first_part);
        memcpy((uint8_t*)&header + first_part, rb->buffer, sizeof(header) - first_part);
        rb->read_pos = sizeof(header) - first_part;
    }
    
    /* Check buffer size */
    if (*length < header.length) {
        return -1;
    }
    
    /* Read data */
    if (rb->read_pos + header.length <= rb->size) {
        memcpy(data, rb->buffer + rb->read_pos, header.length);
        rb->read_pos += header.length;
    } else {
        /* Data wraps around */
        size_t first_part = rb->size - rb->read_pos;
        memcpy(data, rb->buffer + rb->read_pos, first_part);
        memcpy((uint8_t*)data + first_part, rb->buffer, header.length - first_part);
        rb->read_pos = header.length - first_part;
    }
    
    /* Wrap read position if at end */
    if (rb->read_pos >= rb->size) {
        rb->read_pos = 0;
    }
    
    /* Update outputs */
    *length = header.length;
    if (timestamp_ns) {
        *timestamp_ns = header.timestamp_ns;
    }
    
    /* Update counters */
    rb->packet_count--;
    rb->is_full = false;
    
    return 0;
}

/* Peek at next packet without removing */
int pcv_ringbuf_peek(pcv_ringbuf* rb, void** data, size_t* length,
                     uint64_t* timestamp_ns) {
    pcv_ringbuf_packet_header header;
    size_t read_pos;
    
    if (!rb || !data || !length || pcv_ringbuf_empty(rb)) {
        return -1;
    }
    
    read_pos = rb->read_pos;
    
    /* Read header */
    if (read_pos + sizeof(header) <= rb->size) {
        memcpy(&header, rb->buffer + read_pos, sizeof(header));
        read_pos += sizeof(header);
    } else {
        /* Header wraps around */
        size_t first_part = rb->size - read_pos;
        memcpy(&header, rb->buffer + read_pos, first_part);
        memcpy((uint8_t*)&header + first_part, rb->buffer, sizeof(header) - first_part);
        read_pos = sizeof(header) - first_part;
    }
    
    /* Return pointer to data (may not be contiguous) */
    *data = rb->buffer + read_pos;
    *length = header.length;
    if (timestamp_ns) {
        *timestamp_ns = header.timestamp_ns;
    }
    
    return 0;
}

/* Advance read position (after peek) */
int pcv_ringbuf_advance(pcv_ringbuf* rb) {
    pcv_ringbuf_packet_header header;
    
    if (!rb || pcv_ringbuf_empty(rb)) {
        return -1;
    }
    
    /* Read header to get offset */
    if (rb->read_pos + sizeof(header) <= rb->size) {
        memcpy(&header, rb->buffer + rb->read_pos, sizeof(header));
    } else {
        /* Header wraps around */
        size_t first_part = rb->size - rb->read_pos;
        memcpy(&header, rb->buffer + rb->read_pos, first_part);
        memcpy((uint8_t*)&header + first_part, rb->buffer, sizeof(header) - first_part);
    }
    
    /* Advance by total packet size */
    rb->read_pos = (rb->read_pos + header.offset) % rb->size;
    rb->packet_count--;
    rb->is_full = false;
    
    return 0;
}

/* Get available space */
size_t pcv_ringbuf_available(const pcv_ringbuf* rb) {
    if (!rb) return 0;
    
    if (rb->is_full) {
        return 0;
    }
    
    if (rb->write_pos >= rb->read_pos) {
        return rb->size - (rb->write_pos - rb->read_pos) - 1;
    } else {
        return rb->read_pos - rb->write_pos - 1;
    }
}

/* Get used space */
size_t pcv_ringbuf_used(const pcv_ringbuf* rb) {
    if (!rb) return 0;
    
    if (rb->is_full) {
        return rb->size;
    }
    
    if (rb->write_pos >= rb->read_pos) {
        return rb->write_pos - rb->read_pos;
    } else {
        return rb->size - rb->read_pos + rb->write_pos;
    }
}

/* Check if empty */
bool pcv_ringbuf_empty(const pcv_ringbuf* rb) {
    return rb && (rb->packet_count == 0);
}

/* Check if full */
bool pcv_ringbuf_full(const pcv_ringbuf* rb) {
    return rb && rb->is_full;
}

/* Get packet count */
size_t pcv_ringbuf_packet_count(const pcv_ringbuf* rb) {
    return rb ? rb->packet_count : 0;
}
