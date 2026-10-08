#ifndef PCV_FORMAT_H
#define PCV_FORMAT_H

#include <stddef.h>
#include <stdint.h>
#include "pcv_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Format a captured frame into a tcpdump-style, human-readable line.
 *
 * Produces (direction prefix "OUT"/"IN " then the decode):
 *   - IPv4 / IPv6 TCP/UDP:  "<dir> IPv4 <src>.<sport> > <dst>.<dport>: TCP <len>"
 *   - IPv4 / IPv6 other L4: "<dir> IPv4 <src> > <dst>: <proto> <len>"
 *   - ARP (EtherType 0x0806):
 *         "<dir> ARP request who-has <target-ip> tell <sender-ip>"
 *         "<dir> ARP reply <sender-ip> is-at <sender-mac>"
 *         "<dir> ARP op=<n>"            (other opcodes)
 *   - Any other EtherType:  "EtherType 0x<hhhh> <len> bytes"
 *   - Truly short/malformed frames:  "[unparseable packet, <len> bytes]"
 *
 * local_ip is the interface's IPv4 address in host byte order (0 if unknown);
 * interface_name is used for IPv6 direction detection ("" to skip). Both only
 * affect the OUT/IN direction prefix, never whether a frame decodes.
 */
void pcv_format_packet_info(const pcv_packet* packet, uint32_t local_ip,
                            const char* interface_name, char* buffer, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* PCV_FORMAT_H */
