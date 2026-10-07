/* Unit tests for the ring buffer (src/pcv_ringbuf.c). */
#include "pcv_ringbuf.h"
#include "pcv_test.h"

int main(void) {
    fprintf(stdout, "ring buffer tests\n");

    pcv_ringbuf* rb = pcv_ringbuf_create(4096);
    CHECK(rb != NULL, "create ring buffer");
    CHECK(pcv_ringbuf_empty(rb), "new buffer is empty");
    CHECK(!pcv_ringbuf_full(rb), "new buffer is not full");
    CHECK_EQ_U64(pcv_ringbuf_packet_count(rb), 0, "new buffer packet count");

    /* Write three packets of distinct contents. */
    const char* p0 = "hello";
    const char* p1 = "packetvelocity";
    const char* p2 = "ringbuffer-test-payload";

    CHECK(pcv_ringbuf_write(rb, p0, strlen(p0), 1000) == 0, "write packet 0");
    CHECK(pcv_ringbuf_write(rb, p1, strlen(p1), 2000) == 0, "write packet 1");
    CHECK(pcv_ringbuf_write(rb, p2, strlen(p2), 3000) == 0, "write packet 2");
    CHECK_EQ_U64(pcv_ringbuf_packet_count(rb), 3, "packet count after 3 writes");
    CHECK(!pcv_ringbuf_empty(rb), "buffer not empty after writes");

    /* Read them back FIFO and verify contents + timestamps. */
    char out[256];
    size_t len;
    uint64_t ts;

    len = sizeof(out);
    CHECK(pcv_ringbuf_read(rb, out, &len, &ts) == 0, "read packet 0");
    CHECK(len == strlen(p0) && memcmp(out, p0, len) == 0, "packet 0 contents");
    CHECK_EQ_U64(ts, 1000, "packet 0 timestamp");

    len = sizeof(out);
    CHECK(pcv_ringbuf_read(rb, out, &len, &ts) == 0, "read packet 1");
    CHECK(len == strlen(p1) && memcmp(out, p1, len) == 0, "packet 1 contents");
    CHECK_EQ_U64(ts, 2000, "packet 1 timestamp");

    len = sizeof(out);
    CHECK(pcv_ringbuf_read(rb, out, &len, &ts) == 0, "read packet 2");
    CHECK(len == strlen(p2) && memcmp(out, p2, len) == 0, "packet 2 contents");
    CHECK_EQ_U64(ts, 3000, "packet 2 timestamp");

    CHECK(pcv_ringbuf_empty(rb), "buffer empty after draining");
    CHECK(pcv_ringbuf_read(rb, out, &len, &ts) != 0, "read on empty fails");

    /* Reset clears state. */
    CHECK(pcv_ringbuf_write(rb, p0, strlen(p0), 42) == 0, "write before reset");
    pcv_ringbuf_reset(rb);
    CHECK(pcv_ringbuf_empty(rb), "empty after reset");
    CHECK_EQ_U64(pcv_ringbuf_packet_count(rb), 0, "count 0 after reset");

    /* Dropped-packet accounting: an oversized write must be rejected. */
    uint8_t big[8192];
    memset(big, 0xAB, sizeof(big));
    CHECK(pcv_ringbuf_write(rb, big, sizeof(big), 1) != 0,
          "oversized write rejected");

    /* Fill-and-drain many small packets to exercise wraparound. */
    int wrote = 0;
    for (int i = 0; i < 1000; i++) {
        uint8_t b[16];
        memset(b, (uint8_t)i, sizeof(b));
        if (pcv_ringbuf_write(rb, b, sizeof(b), (uint64_t)i) != 0) break;
        wrote++;
        /* Drain one every few writes so the buffer wraps rather than fills. */
        if ((i % 3) == 0) {
            len = sizeof(out);
            pcv_ringbuf_read(rb, out, &len, &ts);
        }
    }
    CHECK(wrote > 0, "wraparound writes succeeded");

    pcv_ringbuf_destroy(rb);

    return pcv_test_summary("test_ringbuf");
}
