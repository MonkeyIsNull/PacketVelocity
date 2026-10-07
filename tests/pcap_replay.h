/* PacketVelocity - offline pcap replay harness.
 *
 * A tiny, dependency-free reader/writer for the classic libpcap savefile
 * format (LINKTYPE_ETHERNET). It lets tests push packets through the
 * capture -> filter -> flow pipeline WITHOUT root privileges and WITHOUT live
 * sniffing: either replay a real .pcap file, or synthesize frames in memory,
 * write them to a savefile, and replay that.
 *
 * The replay callback uses the exact same pcv_packet / pcv_callback contract as
 * the live capture backends, so the same downstream logic is exercised.
 */
#ifndef PCV_PCAP_REPLAY_H
#define PCV_PCAP_REPLAY_H

#include <stddef.h>
#include <stdint.h>
#include "pcv_platform.h"   /* pcv_packet, pcv_callback */

#ifdef __cplusplus
extern "C" {
#endif

/* One packet to be written to a savefile. */
typedef struct pcap_replay_packet {
    const uint8_t* data;
    uint32_t length;
    uint64_t timestamp_ns;
} pcap_replay_packet;

/* Write an Ethernet-linktype pcap savefile containing the given packets.
 * Returns 0 on success, -1 on error. */
int pcap_replay_write(const char* path,
                      const pcap_replay_packet* packets, size_t count);

/* Read a pcap savefile and invoke cb once per packet, building a pcv_packet
 * with the same contract the live backends use. Returns the number of packets
 * replayed, or -1 on error. */
int pcap_replay_file(const char* path, pcv_callback cb, void* user);

#ifdef __cplusplus
}
#endif

#endif /* PCV_PCAP_REPLAY_H */
