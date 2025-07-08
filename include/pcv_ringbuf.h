#ifndef PCV_RINGBUF_H
#define PCV_RINGBUF_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PacketVelocity Ring Buffer Abstraction */

/* Ring buffer structure */
typedef struct pcv_ringbuf {
    uint8_t* buffer;          /* Buffer memory */
    size_t size;              /* Total buffer size */
    size_t read_pos;          /* Read position */
    size_t write_pos;         /* Write position */
    size_t packet_count;      /* Number of packets in buffer */
    bool is_full;             /* Buffer full flag */
    
    /* Memory management */
    bool owns_memory;         /* Whether we allocated the buffer */
    
    /* Statistics */
    uint64_t total_packets;   /* Total packets processed */
    uint64_t dropped_packets; /* Packets dropped due to full buffer */
} pcv_ringbuf;

/* Packet header stored in ring buffer */
typedef struct pcv_ringbuf_packet_header {
    uint32_t length;          /* Packet data length */
    uint32_t captured_length; /* Captured length */
    uint64_t timestamp_ns;    /* Timestamp in nanoseconds */
    uint32_t offset;          /* Offset to next packet */
} pcv_ringbuf_packet_header;

/* Ring buffer functions */

/* Initialize ring buffer with given memory */
int pcv_ringbuf_init(pcv_ringbuf* rb, void* buffer, size_t size);

/* Allocate and initialize ring buffer */
pcv_ringbuf* pcv_ringbuf_create(size_t size);

/* Destroy ring buffer */
void pcv_ringbuf_destroy(pcv_ringbuf* rb);

/* Reset ring buffer to empty state */
void pcv_ringbuf_reset(pcv_ringbuf* rb);

/* Write packet to ring buffer */
int pcv_ringbuf_write(pcv_ringbuf* rb, const void* data, size_t length, 
                      uint64_t timestamp_ns);

/* Read next packet from ring buffer */
int pcv_ringbuf_read(pcv_ringbuf* rb, void* data, size_t* length,
                     uint64_t* timestamp_ns);

/* Peek at next packet without removing */
int pcv_ringbuf_peek(pcv_ringbuf* rb, void** data, size_t* length,
                     uint64_t* timestamp_ns);

/* Advance read position (after peek) */
int pcv_ringbuf_advance(pcv_ringbuf* rb);

/* Get available space */
size_t pcv_ringbuf_available(const pcv_ringbuf* rb);

/* Get used space */
size_t pcv_ringbuf_used(const pcv_ringbuf* rb);

/* Check if empty */
bool pcv_ringbuf_empty(const pcv_ringbuf* rb);

/* Check if full */
bool pcv_ringbuf_full(const pcv_ringbuf* rb);

/* Get packet count */
size_t pcv_ringbuf_packet_count(const pcv_ringbuf* rb);

#ifdef __cplusplus
}
#endif

#endif /* PCV_RINGBUF_H */
