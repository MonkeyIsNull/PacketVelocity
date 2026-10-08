/* PacketVelocity - packet display formatting.
 *
 * Renders a captured frame into a tcpdump-style line for the default
 * stdout sink. Kept separate from pcv_main.c so the decode logic is unit
 * testable offline (see tests/test_display.c) without pulling in main().
 *
 * Decodes IPv4/IPv6 (TCP/UDP/other L4) via the flow key extractor, ARP
 * (EtherType 0x0806), and labels any other EtherType instead of calling it
 * "unparseable"; only truly short/malformed frames keep that label.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "pcv_format.h"
#include "pcv_flow.h"

/* Convert protocol number to string */
static const char* protocol_to_string(uint8_t protocol) {
    switch (protocol) {
        case 1:  return "ICMP";
        case 6:  return "TCP";
        case 17: return "UDP";
        case 2:  return "IGMP";
        case 47: return "GRE";
        case 50: return "ESP";
        case 51: return "AH";
        case 58: return "ICMPv6";
        case 89: return "OSPF";
        default: return "proto";
    }
}

/* Check if IPv6 address belongs to interface (checks all addresses) */
static bool is_local_ipv6(const char* interface_name, const uint8_t* test_addr) {
    struct ifaddrs *ifaddrs_ptr = NULL;
    struct ifaddrs *ifa = NULL;
    bool is_local = false;

    if (interface_name == NULL || interface_name[0] == '\0') {
        return false;
    }

    if (getifaddrs(&ifaddrs_ptr) == -1) {
        return false;
    }

    for (ifa = ifaddrs_ptr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        if (ifa->ifa_addr->sa_family == AF_INET6 &&
            strcmp(ifa->ifa_name, interface_name) == 0) {
            struct sockaddr_in6* addr_in6 = (struct sockaddr_in6*)ifa->ifa_addr;

            /* Check against all IPv6 addresses (including temporary/privacy addresses) */
            if (memcmp(&addr_in6->sin6_addr, test_addr, 16) == 0) {
                is_local = true;
                break;
            }
        }
    }

    freeifaddrs(ifaddrs_ptr);
    return is_local;
}

/* Decode an ARP frame (EtherType 0x0806) into a readable, tcpdump-style line.
 * Expects data/len to be the full Ethernet frame. Returns 0 on success. */
static int format_arp(const uint8_t* data, uint32_t len, uint32_t local_ip,
                      char* buffer, size_t size) {
    /* Ethernet (14) + ARP IPv4 payload (28) = 42 bytes minimum. */
    if (len < 42) {
        return -1;
    }

    const uint8_t* arp = data + 14;
    uint16_t oper = (uint16_t)((arp[6] << 8) | arp[7]);

    /* Sender/target hardware (MAC) and protocol (IPv4) addresses. */
    const uint8_t* sha = arp + 8;   /* sender MAC */
    const uint8_t* spa = arp + 14;  /* sender IPv4 */
    const uint8_t* tpa = arp + 24;  /* target IPv4 */

    char sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, spa, sender_ip, sizeof(sender_ip));
    inet_ntop(AF_INET, tpa, target_ip, sizeof(target_ip));

    /* Direction: outgoing if the sender's IPv4 is our local address. */
    uint32_t sender_ip_host = ((uint32_t)spa[0] << 24) | ((uint32_t)spa[1] << 16) |
                              ((uint32_t)spa[2] << 8) | (uint32_t)spa[3];
    const char* direction = (local_ip != 0 && sender_ip_host == local_ip) ? "OUT" : "IN ";

    if (oper == 1) {
        snprintf(buffer, size, "%s ARP request who-has %s tell %s",
                 direction, target_ip, sender_ip);
    } else if (oper == 2) {
        snprintf(buffer, size,
                 "%s ARP reply %s is-at %02x:%02x:%02x:%02x:%02x:%02x",
                 direction, sender_ip,
                 sha[0], sha[1], sha[2], sha[3], sha[4], sha[5]);
    } else {
        snprintf(buffer, size, "%s ARP op=%u", direction, oper);
    }
    return 0;
}

/* Format packet information with directional arrows and IPv6 support */
void pcv_format_packet_info(const pcv_packet* packet, uint32_t local_ip,
                            const char* interface_name, char* buffer, size_t size) {
    pcv_flow_key_v6 key;
    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
    bool is_outgoing;

    /* Extract flow key from packet using IPv6-capable parser. On failure the
     * frame is not IP (ARP, etc.) or is too short; fall through to the
     * EtherType-based decode below instead of calling it "unparseable". */
    if (pcv_flow_extract_key_v6(packet, &key) != 0) {
        /* Need at least an Ethernet header to read the EtherType. */
        if (packet->data == NULL || packet->captured_length < 14) {
            snprintf(buffer, size, "[unparseable packet, %u bytes]",
                     packet->captured_length);
            return;
        }

        uint16_t ethertype = (uint16_t)((packet->data[12] << 8) | packet->data[13]);

        if (ethertype == 0x0806) {
            /* ARP */
            if (format_arp(packet->data, packet->captured_length, local_ip,
                           buffer, size) == 0) {
                return;
            }
            /* Short/truncated ARP: label it rather than drop the EtherType. */
            snprintf(buffer, size, "ARP (truncated) %u bytes",
                     packet->captured_length);
            return;
        }

        /* Any other EtherType: label it informatively. */
        snprintf(buffer, size, "EtherType 0x%04x %u bytes",
                 ethertype, packet->captured_length);
        return;
    }

    /* Format addresses and determine direction based on address family */
    if (key.addr_family == PCV_ADDR_IPV4) {
        /* IPv4 packet */
        inet_ntop(AF_INET, &key.src_ip.ipv4, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &key.dst_ip.ipv4, dst_ip, sizeof(dst_ip));
        is_outgoing = (ntohl(key.src_ip.ipv4) == local_ip);
    } else if (key.addr_family == PCV_ADDR_IPV6) {
        /* IPv6 packet - check if source address is local to this interface */
        inet_ntop(AF_INET6, key.src_ip.ipv6, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET6, key.dst_ip.ipv6, dst_ip, sizeof(dst_ip));
        is_outgoing = is_local_ipv6(interface_name, key.src_ip.ipv6);
    } else {
        snprintf(buffer, size, "[unknown IP version %u, %u bytes]", key.addr_family, packet->captured_length);
        return;
    }

    const char* ip_version = (key.addr_family == PCV_ADDR_IPV6) ? "IPv6" : "IPv4";

    /* Always use tcpdump standard: source > destination */
    if (key.protocol == 6 || key.protocol == 17) {
        /* TCP or UDP with ports */
        const char* direction = is_outgoing ? "OUT" : "IN ";
        if (key.addr_family == PCV_ADDR_IPV6) {
            /* IPv6 addresses need brackets for port notation */
            snprintf(buffer, size, "%s %s [%s].%u > [%s].%u: %s %u",
                     direction, ip_version,
                     src_ip, key.src_port,
                     dst_ip, key.dst_port,
                     protocol_to_string(key.protocol),
                     packet->captured_length);
        } else {
            /* IPv4 standard notation */
            snprintf(buffer, size, "%s %s %s.%u > %s.%u: %s %u",
                     direction, ip_version,
                     src_ip, key.src_port,
                     dst_ip, key.dst_port,
                     protocol_to_string(key.protocol),
                     packet->captured_length);
        }
    } else {
        /* Other protocols without ports */
        const char* direction = is_outgoing ? "OUT" : "IN ";
        snprintf(buffer, size, "%s %s %s > %s: %s %u",
                 direction, ip_version,
                 src_ip, dst_ip,
                 protocol_to_string(key.protocol),
                 packet->captured_length);
    }
}
