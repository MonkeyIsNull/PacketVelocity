/* PacketVelocity - minimal unit-test harness and synthetic packet builders.
 *
 * Header-only. No external dependencies. All helpers are offline: they build
 * in-memory frames so capture/filter/flow logic can be exercised without root
 * and without live packet capture.
 */
#ifndef PCV_TEST_H
#define PCV_TEST_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

/* ---- Tiny assertion harness -------------------------------------------- */

static int g_checks_run = 0;
static int g_checks_failed = 0;

#define CHECK(cond, msg)                                                    \
    do {                                                                    \
        g_checks_run++;                                                     \
        if (!(cond)) {                                                      \
            g_checks_failed++;                                              \
            fprintf(stderr, "  FAIL: %s (%s:%d)\n", (msg), __FILE__,        \
                    __LINE__);                                              \
        } else {                                                           \
            fprintf(stdout, "  ok:   %s\n", (msg));                         \
        }                                                                   \
    } while (0)

#define CHECK_EQ_U64(got, want, msg)                                        \
    do {                                                                    \
        g_checks_run++;                                                     \
        uint64_t _g = (uint64_t)(got), _w = (uint64_t)(want);              \
        if (_g != _w) {                                                     \
            g_checks_failed++;                                              \
            fprintf(stderr, "  FAIL: %s (got %llu, want %llu) (%s:%d)\n",   \
                    (msg), (unsigned long long)_g, (unsigned long long)_w,  \
                    __FILE__, __LINE__);                                    \
        } else {                                                           \
            fprintf(stdout, "  ok:   %s (= %llu)\n", (msg),                 \
                    (unsigned long long)_g);                               \
        }                                                                   \
    } while (0)

/* Return 0 if all checks passed, 1 otherwise. Call once at end of main(). */
static int pcv_test_summary(const char* suite) {
    fprintf(stdout, "%s: %d checks, %d failed\n", suite,
            g_checks_run, g_checks_failed);
    return g_checks_failed == 0 ? 0 : 1;
}

/* ---- Synthetic frame builders ------------------------------------------ */

/* Build an Ethernet + IPv4 + (TCP|UDP) frame into buf.
 * src_ip/dst_ip are host-order IPv4 addresses.
 * proto is 6 (TCP) or 17 (UDP); for other protocols no L4 ports are added.
 * tcp_flags is only used for TCP.
 * Returns the total frame length in bytes.
 */
static size_t pcv_build_ipv4_frame(uint8_t* buf, size_t buf_size,
                                   uint8_t proto,
                                   uint32_t src_ip, uint32_t dst_ip,
                                   uint16_t src_port, uint16_t dst_port,
                                   uint8_t tcp_flags,
                                   size_t payload_len) {
    const size_t eth_len = 14;
    const size_t ip_len = 20;
    size_t l4_len = 0;
    if (proto == 6) l4_len = 20;        /* minimal TCP header */
    else if (proto == 17) l4_len = 8;   /* UDP header */

    size_t total = eth_len + ip_len + l4_len + payload_len;
    if (total > buf_size) return 0;
    memset(buf, 0, total);

    /* Ethernet: dst MAC, src MAC, ethertype 0x0800 (IPv4) */
    static const uint8_t dmac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    static const uint8_t smac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    memcpy(buf + 0, dmac, 6);
    memcpy(buf + 6, smac, 6);
    buf[12] = 0x08;
    buf[13] = 0x00;

    /* IPv4 header */
    uint8_t* ip = buf + eth_len;
    ip[0] = 0x45;                        /* version 4, IHL 5 (20 bytes) */
    ip[1] = 0x00;                        /* DSCP/ECN */
    uint16_t ip_total = (uint16_t)(ip_len + l4_len + payload_len);
    ip[2] = (uint8_t)(ip_total >> 8);
    ip[3] = (uint8_t)(ip_total & 0xFF);
    ip[4] = 0x00; ip[5] = 0x01;          /* identification */
    ip[6] = 0x40; ip[7] = 0x00;          /* flags: don't fragment */
    ip[8] = 64;                          /* TTL */
    ip[9] = proto;                       /* protocol */
    ip[10] = 0x00; ip[11] = 0x00;        /* header checksum (0 - not verified) */
    uint32_t s = htonl(src_ip), d = htonl(dst_ip);
    memcpy(ip + 12, &s, 4);
    memcpy(ip + 16, &d, 4);

    /* L4 */
    if (l4_len > 0) {
        uint8_t* l4 = ip + ip_len;
        uint16_t sp = htons(src_port), dp = htons(dst_port);
        memcpy(l4 + 0, &sp, 2);
        memcpy(l4 + 2, &dp, 2);
        if (proto == 6) {
            /* TCP: data offset 5 (20 bytes) at byte 12, flags at byte 13 */
            l4[12] = 0x50;
            l4[13] = tcp_flags;
        } else {
            /* UDP: length field */
            uint16_t ulen = (uint16_t)(l4_len + payload_len);
            l4[4] = (uint8_t)(ulen >> 8);
            l4[5] = (uint8_t)(ulen & 0xFF);
        }
    }

    return total;
}

/* Build an Ethernet + IPv6 + (TCP|UDP) frame into buf.
 * src_ip6/dst_ip6 are 16-byte IPv6 addresses in network byte order.
 * proto is 6 (TCP) or 17 (UDP); for other protocols no L4 ports are added.
 * Returns the total frame length in bytes (0 if it would not fit).
 */
static size_t pcv_build_ipv6_frame(uint8_t* buf, size_t buf_size,
                                   uint8_t proto,
                                   const uint8_t src_ip6[16],
                                   const uint8_t dst_ip6[16],
                                   uint16_t src_port, uint16_t dst_port,
                                   uint8_t tcp_flags,
                                   size_t payload_len) {
    const size_t eth_len = 14;
    const size_t ip6_len = 40;           /* fixed IPv6 header */
    size_t l4_len = 0;
    if (proto == 6) l4_len = 20;         /* minimal TCP header */
    else if (proto == 17) l4_len = 8;    /* UDP header */

    size_t total = eth_len + ip6_len + l4_len + payload_len;
    if (total > buf_size) return 0;
    memset(buf, 0, total);

    /* Ethernet: dst MAC, src MAC, ethertype 0x86DD (IPv6) */
    static const uint8_t dmac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    static const uint8_t smac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    memcpy(buf + 0, dmac, 6);
    memcpy(buf + 6, smac, 6);
    buf[12] = 0x86;
    buf[13] = 0xDD;

    /* IPv6 header */
    uint8_t* ip6 = buf + eth_len;
    ip6[0] = 0x60;                       /* version 6, traffic class 0 */
    uint16_t payload = (uint16_t)(l4_len + payload_len);
    ip6[4] = (uint8_t)(payload >> 8);    /* payload length (excludes IPv6 hdr) */
    ip6[5] = (uint8_t)(payload & 0xFF);
    ip6[6] = proto;                      /* next header */
    ip6[7] = 64;                         /* hop limit */
    memcpy(ip6 + 8, src_ip6, 16);        /* source address */
    memcpy(ip6 + 24, dst_ip6, 16);       /* destination address */

    /* L4 */
    if (l4_len > 0) {
        uint8_t* l4 = ip6 + ip6_len;
        uint16_t sp = htons(src_port), dp = htons(dst_port);
        memcpy(l4 + 0, &sp, 2);
        memcpy(l4 + 2, &dp, 2);
        if (proto == 6) {
            l4[12] = 0x50;               /* data offset 5 (20 bytes) */
            l4[13] = tcp_flags;
        } else {
            uint16_t ulen = (uint16_t)(l4_len + payload_len);
            l4[4] = (uint8_t)(ulen >> 8);
            l4[5] = (uint8_t)(ulen & 0xFF);
        }
    }

    return total;
}

/* Build an Ethernet + ARP (IPv4-over-Ethernet) frame into buf.
 * opcode is 1 (request) or 2 (reply); sender_ip/target_ip are host-order IPv4.
 * sender_mac/target_mac are 6-byte MACs (target_mac may be NULL -> all zero,
 * as in a who-has request). Produces a standard 42-byte ARP frame.
 * Returns the total frame length in bytes (0 if it would not fit).
 */
static size_t pcv_build_arp_frame(uint8_t* buf, size_t buf_size,
                                  uint16_t opcode,
                                  uint32_t sender_ip, uint32_t target_ip,
                                  const uint8_t sender_mac[6],
                                  const uint8_t target_mac[6]) {
    const size_t eth_len = 14;
    const size_t arp_len = 28;           /* ARP IPv4-over-Ethernet payload */
    size_t total = eth_len + arp_len;    /* 42 bytes */
    if (total > buf_size) return 0;
    memset(buf, 0, total);

    /* Ethernet: dst MAC, src MAC, ethertype 0x0806 (ARP) */
    static const uint8_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    memcpy(buf + 0, (opcode == 1 || target_mac == NULL) ? bcast : target_mac, 6);
    memcpy(buf + 6, sender_mac, 6);
    buf[12] = 0x08;
    buf[13] = 0x06;

    /* ARP payload */
    uint8_t* arp = buf + eth_len;
    arp[0] = 0x00; arp[1] = 0x01;        /* HTYPE: Ethernet */
    arp[2] = 0x08; arp[3] = 0x00;        /* PTYPE: IPv4 */
    arp[4] = 6;                          /* HLEN */
    arp[5] = 4;                          /* PLEN */
    arp[6] = (uint8_t)(opcode >> 8);     /* OPER */
    arp[7] = (uint8_t)(opcode & 0xFF);

    memcpy(arp + 8, sender_mac, 6);      /* SHA: sender MAC */
    uint32_t spa = htonl(sender_ip);
    memcpy(arp + 14, &spa, 4);           /* SPA: sender IPv4 */
    if (target_mac != NULL) {
        memcpy(arp + 18, target_mac, 6); /* THA: target MAC (0 in a request) */
    }
    uint32_t tpa = htonl(target_ip);
    memcpy(arp + 24, &tpa, 4);           /* TPA: target IPv4 */

    return total;
}

#endif /* PCV_TEST_H */
