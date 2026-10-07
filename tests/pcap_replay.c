/* PacketVelocity - offline pcap replay harness implementation. */
#include "pcap_replay.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* classic libpcap global header (little-endian magic a1b2c3d4) */
#define PCAP_MAGIC        0xa1b2c3d4u
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4
#define PCAP_SNAPLEN       65535u
#define PCAP_LINKTYPE_EN10MB 1u   /* Ethernet */

typedef struct {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_file_header;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_record_header;

int pcap_replay_write(const char* path,
                      const pcap_replay_packet* packets, size_t count) {
    if (!path || (!packets && count > 0)) return -1;

    FILE* f = fopen(path, "wb");
    if (!f) return -1;

    pcap_file_header gh;
    gh.magic = PCAP_MAGIC;
    gh.version_major = PCAP_VERSION_MAJOR;
    gh.version_minor = PCAP_VERSION_MINOR;
    gh.thiszone = 0;
    gh.sigfigs = 0;
    gh.snaplen = PCAP_SNAPLEN;
    gh.network = PCAP_LINKTYPE_EN10MB;

    if (fwrite(&gh, sizeof(gh), 1, f) != 1) {
        fclose(f);
        return -1;
    }

    for (size_t i = 0; i < count; i++) {
        const pcap_replay_packet* p = &packets[i];
        pcap_record_header rh;
        rh.ts_sec = (uint32_t)(p->timestamp_ns / 1000000000ULL);
        rh.ts_usec = (uint32_t)((p->timestamp_ns % 1000000000ULL) / 1000ULL);
        rh.incl_len = p->length;
        rh.orig_len = p->length;

        if (fwrite(&rh, sizeof(rh), 1, f) != 1 ||
            fwrite(p->data, 1, p->length, f) != p->length) {
            fclose(f);
            return -1;
        }
    }

    fclose(f);
    return 0;
}

int pcap_replay_file(const char* path, pcv_callback cb, void* user) {
    if (!path || !cb) return -1;

    FILE* f = fopen(path, "rb");
    if (!f) return -1;

    pcap_file_header gh;
    if (fread(&gh, sizeof(gh), 1, f) != 1) {
        fclose(f);
        return -1;
    }

    /* Only the native-endian classic magic is supported here (sufficient for
     * the savefiles this harness writes). */
    if (gh.magic != PCAP_MAGIC) {
        fclose(f);
        return -1;
    }

    int replayed = 0;
    uint8_t* buf = NULL;
    size_t buf_cap = 0;

    for (;;) {
        pcap_record_header rh;
        size_t got = fread(&rh, sizeof(rh), 1, f);
        if (got != 1) break;  /* clean EOF */

        if (rh.incl_len == 0 || rh.incl_len > PCAP_SNAPLEN) {
            replayed = -1;
            break;
        }

        if (rh.incl_len > buf_cap) {
            uint8_t* nb = realloc(buf, rh.incl_len);
            if (!nb) {
                replayed = -1;
                break;
            }
            buf = nb;
            buf_cap = rh.incl_len;
        }

        if (fread(buf, 1, rh.incl_len, f) != rh.incl_len) {
            replayed = -1;
            break;
        }

        pcv_packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.data = buf;
        pkt.length = rh.orig_len;
        pkt.captured_length = rh.incl_len;
        pkt.timestamp_ns =
            (uint64_t)rh.ts_sec * 1000000000ULL + (uint64_t)rh.ts_usec * 1000ULL;

        cb(&pkt, user);
        replayed++;
    }

    free(buf);
    fclose(f);
    return replayed;
}
