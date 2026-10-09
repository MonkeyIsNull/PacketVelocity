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

/* ---- DNS / mDNS response builders -------------------------------------- */

/* One answer record to encode into a synthetic DNS message. type is 1 (A) or
 * 28 (AAAA); for A, addr is 4 bytes; for AAAA, 16 bytes (network order). */
typedef struct {
    uint16_t type;              /* 1 = A, 28 = AAAA (others encoded verbatim) */
    uint16_t rdlen_override;    /* 0 => use the natural rdlen (4 or 16) */
    const uint8_t* rdata;       /* addr bytes (network order) */
} pcv_dns_answer;

/* Encode a DNS message body (header + one question + N answers) into out.
 * - qname: a single dotted name, e.g. "lingq.com" (<=255).
 * - qr: 1 => response (bit set), 0 => query.
 * - cache_flush: OR 0x8001 into each answer CLASS (mDNS cache-flush) when set,
 *   else class = 1 (IN).
 * - compress_owner: when 1, each answer's OWNER NAME is the 0xC00C pointer back
 *   to the question name (what real traffic does); when 0, the literal qname is
 *   repeated inline.
 * Returns the DNS message length, or 0 on overflow. This is the UDP PAYLOAD
 * (what pcv_dns_parse consumes); the frame builders below prepend Eth+IP+UDP. */
static size_t __attribute__((unused)) pcv_build_dns_msg(uint8_t* out, size_t out_size,
                                const char* qname, uint16_t qtype,
                                int qr, int cache_flush, int compress_owner,
                                const pcv_dns_answer* answers, int nanswers) {
    size_t o = 0;
    if (out_size < 12) return 0;

    /* ---- Header ---- */
    out[0] = 0x12; out[1] = 0x34;                 /* id */
    uint16_t flags = qr ? 0x8180 : 0x0100;        /* QR+RD+RA (resp) / RD (query) */
    out[2] = (uint8_t)(flags >> 8); out[3] = (uint8_t)(flags & 0xFF);
    out[4] = 0x00; out[5] = 0x01;                 /* QDCOUNT = 1 */
    out[6] = (uint8_t)(nanswers >> 8); out[7] = (uint8_t)(nanswers & 0xFF);
    out[8] = 0x00; out[9] = 0x00;                 /* NSCOUNT */
    out[10] = 0x00; out[11] = 0x00;               /* ARCOUNT */
    o = 12;

    /* ---- Encode the question name as DNS labels (record offset 12). ---- */
    size_t name_off = o;
    {
        const char* p = qname;
        while (*p) {
            const char* dot = strchr(p, '.');
            size_t llen = dot ? (size_t)(dot - p) : strlen(p);
            if (llen == 0 || llen > 63) return 0;
            if (o + 1 + llen > out_size) return 0;
            out[o++] = (uint8_t)llen;
            memcpy(out + o, p, llen); o += llen;
            if (!dot) break;
            p = dot + 1;
        }
        if (o + 1 > out_size) return 0;
        out[o++] = 0x00;                          /* root label */
    }
    if (o + 4 > out_size) return 0;
    out[o++] = (uint8_t)(qtype >> 8); out[o++] = (uint8_t)(qtype & 0xFF);
    out[o++] = 0x00; out[o++] = 0x01;             /* QCLASS = IN */

    /* ---- Answers ---- */
    for (int i = 0; i < nanswers; i++) {
        const pcv_dns_answer* an = &answers[i];
        /* OWNER NAME */
        if (compress_owner) {
            if (o + 2 > out_size) return 0;
            out[o++] = (uint8_t)(0xC0 | ((name_off >> 8) & 0x3F));
            out[o++] = (uint8_t)(name_off & 0xFF);
        } else {
            const char* p = qname;
            while (*p) {
                const char* dot = strchr(p, '.');
                size_t llen = dot ? (size_t)(dot - p) : strlen(p);
                if (llen == 0 || llen > 63) return 0;
                if (o + 1 + llen > out_size) return 0;
                out[o++] = (uint8_t)llen;
                memcpy(out + o, p, llen); o += llen;
                if (!dot) break;
                p = dot + 1;
            }
            if (o + 1 > out_size) return 0;
            out[o++] = 0x00;
        }
        uint16_t rdlen = an->rdlen_override ? an->rdlen_override
                       : (an->type == 1 ? 4 : (an->type == 28 ? 16 : 0));
        uint16_t cls = cache_flush ? 0x8001 : 0x0001;
        if (o + 10 + rdlen > out_size) return 0;
        out[o++] = (uint8_t)(an->type >> 8); out[o++] = (uint8_t)(an->type & 0xFF);
        out[o++] = (uint8_t)(cls >> 8); out[o++] = (uint8_t)(cls & 0xFF);
        out[o++] = 0x00; out[o++] = 0x00; out[o++] = 0x00; out[o++] = 0x3C; /* TTL 60 */
        out[o++] = (uint8_t)(rdlen >> 8); out[o++] = (uint8_t)(rdlen & 0xFF);
        if (rdlen && an->rdata) { memcpy(out + o, an->rdata, rdlen); }
        o += rdlen;
    }
    return o;
}

/* Build Eth+IPv4+UDP carrying a DNS message. src_port/dst_port are the UDP
 * ports (a classic reply uses src_port 53; mDNS uses 5353). src_ip/dst_ip are
 * host-order IPv4. Returns the total frame length (0 on overflow). */
static size_t __attribute__((unused)) pcv_build_dns_ipv4(uint8_t* buf, size_t buf_size,
                                 uint32_t src_ip, uint32_t dst_ip,
                                 uint16_t src_port, uint16_t dst_port,
                                 const char* qname, uint16_t qtype,
                                 int qr, int cache_flush, int compress_owner,
                                 const pcv_dns_answer* answers, int nanswers) {
    uint8_t msg[1024];
    size_t mlen = pcv_build_dns_msg(msg, sizeof(msg), qname, qtype, qr,
                                    cache_flush, compress_owner,
                                    answers, nanswers);
    if (mlen == 0) return 0;

    const size_t eth = 14, ip = 20, udp = 8;
    size_t total = eth + ip + udp + mlen;
    if (total > buf_size) return 0;
    memset(buf, 0, total);

    static const uint8_t dmac[6] = {0x02,0,0,0,0,0x01};
    static const uint8_t smac[6] = {0x02,0,0,0,0,0x02};
    memcpy(buf, dmac, 6); memcpy(buf + 6, smac, 6);
    buf[12] = 0x08; buf[13] = 0x00;

    uint8_t* iph = buf + eth;
    iph[0] = 0x45;
    uint16_t iptot = (uint16_t)(ip + udp + mlen);
    iph[2] = (uint8_t)(iptot >> 8); iph[3] = (uint8_t)(iptot & 0xFF);
    iph[8] = 64; iph[9] = 17;                      /* TTL, proto UDP */
    uint32_t s = htonl(src_ip), d = htonl(dst_ip);
    memcpy(iph + 12, &s, 4); memcpy(iph + 16, &d, 4);

    uint8_t* u = iph + ip;
    uint16_t sp = htons(src_port), dp = htons(dst_port);
    memcpy(u, &sp, 2); memcpy(u + 2, &dp, 2);
    uint16_t ulen = (uint16_t)(udp + mlen);
    u[4] = (uint8_t)(ulen >> 8); u[5] = (uint8_t)(ulen & 0xFF);
    memcpy(u + udp, msg, mlen);
    return total;
}

/* Build Eth+IPv6+UDP carrying a DNS message (ethertype 0x86DD) - proves the
 * hot-path IPv6 DNS gate (e.g. a reply from ff02::fb over IPv6). */
static size_t __attribute__((unused)) pcv_build_dns_ipv6(uint8_t* buf, size_t buf_size,
                                 const uint8_t src_ip6[16],
                                 const uint8_t dst_ip6[16],
                                 uint16_t src_port, uint16_t dst_port,
                                 const char* qname, uint16_t qtype,
                                 int qr, int cache_flush, int compress_owner,
                                 const pcv_dns_answer* answers, int nanswers) {
    uint8_t msg[1024];
    size_t mlen = pcv_build_dns_msg(msg, sizeof(msg), qname, qtype, qr,
                                    cache_flush, compress_owner,
                                    answers, nanswers);
    if (mlen == 0) return 0;

    const size_t eth = 14, ip6 = 40, udp = 8;
    size_t total = eth + ip6 + udp + mlen;
    if (total > buf_size) return 0;
    memset(buf, 0, total);

    static const uint8_t dmac[6] = {0x02,0,0,0,0,0x01};
    static const uint8_t smac[6] = {0x02,0,0,0,0,0x02};
    memcpy(buf, dmac, 6); memcpy(buf + 6, smac, 6);
    buf[12] = 0x86; buf[13] = 0xDD;

    uint8_t* iph = buf + eth;
    iph[0] = 0x60;
    uint16_t plen = (uint16_t)(udp + mlen);
    iph[4] = (uint8_t)(plen >> 8); iph[5] = (uint8_t)(plen & 0xFF);
    iph[6] = 17; iph[7] = 64;                      /* next header UDP, hop limit */
    memcpy(iph + 8, src_ip6, 16); memcpy(iph + 24, dst_ip6, 16);

    uint8_t* u = iph + ip6;
    uint16_t sp = htons(src_port), dp = htons(dst_port);
    memcpy(u, &sp, 2); memcpy(u + 2, &dp, 2);
    uint16_t ulen = (uint16_t)(udp + mlen);
    u[4] = (uint8_t)(ulen >> 8); u[5] = (uint8_t)(ulen & 0xFF);
    memcpy(u + udp, msg, mlen);
    return total;
}

/* ---- TLS ClientHello builders ------------------------------------------- */

/* Encode a TLS ClientHello RECORD (the TCP payload pcv_tls_parse_sni consumes)
 * into out: a 5-byte TLS record header (handshake 0x16, version 0x0301) wrapping
 * a ClientHello (handshake type `hs_type`, normally 0x01) with legacy_version
 * 0x0303, a 32-byte random, an empty session_id, one cipher suite (0x1301), a
 * null compression method, and an extensions block containing ONE server_name
 * (type 0x0000) extension carrying `sni` as a host_name entry. When sni is NULL
 * or empty, NO server_name extension is emitted (an empty extensions block).
 * `hs_type` lets a test build a ServerHello (0x02) false-positive. Returns the
 * record length, or 0 on overflow. */
static size_t __attribute__((unused)) pcv_build_tls_clienthello(
        uint8_t* out, size_t out_size, const char* sni, uint8_t hs_type) {
    size_t sni_len = sni ? strlen(sni) : 0;
    if (sni_len > 0xFFFF) return 0;

    /* --- extensions block --- */
    uint8_t exts[600];
    size_t e = 0;
    if (sni_len > 0) {
        /* server_name extension: type 0x0000, then ext body. */
        size_t host_entry = 3 + sni_len;             /* type(1)+len(2)+host */
        size_t list_len   = host_entry;              /* server_name_list */
        size_t ext_body   = 2 + list_len;            /* list length(2)+list */
        if (ext_body + 4 > sizeof(exts)) return 0;
        exts[e++] = 0x00; exts[e++] = 0x00;          /* ext type: server_name */
        exts[e++] = (uint8_t)(ext_body >> 8); exts[e++] = (uint8_t)(ext_body & 0xFF);
        exts[e++] = (uint8_t)(list_len >> 8); exts[e++] = (uint8_t)(list_len & 0xFF);
        exts[e++] = 0x00;                            /* name type: host_name */
        exts[e++] = (uint8_t)(sni_len >> 8); exts[e++] = (uint8_t)(sni_len & 0xFF);
        memcpy(exts + e, sni, sni_len); e += sni_len;
    }

    /* --- ClientHello body --- */
    uint8_t body[768];
    size_t o = 0;
    body[o++] = 0x03; body[o++] = 0x03;              /* legacy_version TLS 1.2 */
    memset(body + o, 0xAB, 32); o += 32;             /* random */
    body[o++] = 0x00;                                /* session_id length 0 */
    body[o++] = 0x00; body[o++] = 0x02;              /* cipher_suites length 2 */
    body[o++] = 0x13; body[o++] = 0x01;              /* TLS_AES_128_GCM_SHA256 */
    body[o++] = 0x01;                                /* compression methods len */
    body[o++] = 0x00;                                /* null compression */
    body[o++] = (uint8_t)(e >> 8); body[o++] = (uint8_t)(e & 0xFF); /* ext total */
    if (o + e > sizeof(body)) return 0;
    memcpy(body + o, exts, e); o += e;

    /* --- handshake header (type + 24-bit length) --- */
    size_t hs_len = o;
    size_t rec_len = 4 + hs_len;
    size_t total = 5 + rec_len;
    if (total > out_size) return 0;

    out[0] = 0x16;                                   /* content type: handshake */
    out[1] = 0x03; out[2] = 0x01;                    /* record version TLS 1.0 */
    out[3] = (uint8_t)(rec_len >> 8); out[4] = (uint8_t)(rec_len & 0xFF);
    out[5] = hs_type;                                /* handshake type */
    out[6] = (uint8_t)(hs_len >> 16);
    out[7] = (uint8_t)(hs_len >> 8);
    out[8] = (uint8_t)(hs_len & 0xFF);
    memcpy(out + 9, body, hs_len);
    return total;
}

/* Build Eth+IPv4+TCP carrying a raw TLS record (`rec`,`rec_len`) as the TCP
 * payload. TCP data offset is 5 (20-byte header). src_ip/dst_ip are host-order
 * IPv4; sport/dport are the TCP ports. Returns the total frame length (0 on
 * overflow). */
static size_t __attribute__((unused)) pcv_build_tls_raw_ipv4(
        uint8_t* buf, size_t buf_size, uint32_t src_ip, uint32_t dst_ip,
        uint16_t sport, uint16_t dport, const uint8_t* rec, size_t rec_len) {
    const size_t eth = 14, ip = 20, tcp = 20;
    size_t total = eth + ip + tcp + rec_len;
    if (total > buf_size) return 0;
    memset(buf, 0, total);

    static const uint8_t dmac[6] = {0x02,0,0,0,0,0x01};
    static const uint8_t smac[6] = {0x02,0,0,0,0,0x02};
    memcpy(buf, dmac, 6); memcpy(buf + 6, smac, 6);
    buf[12] = 0x08; buf[13] = 0x00;

    uint8_t* iph = buf + eth;
    iph[0] = 0x45;
    uint16_t iptot = (uint16_t)(ip + tcp + rec_len);
    iph[2] = (uint8_t)(iptot >> 8); iph[3] = (uint8_t)(iptot & 0xFF);
    iph[8] = 64; iph[9] = 6;                         /* TTL, proto TCP */
    uint32_t s = htonl(src_ip), d = htonl(dst_ip);
    memcpy(iph + 12, &s, 4); memcpy(iph + 16, &d, 4);

    uint8_t* t = iph + ip;
    uint16_t sp = htons(sport), dp = htons(dport);
    memcpy(t, &sp, 2); memcpy(t + 2, &dp, 2);
    t[12] = 0x50;                                    /* data offset 5 (20 bytes) */
    t[13] = 0x18;                                    /* PSH|ACK */
    if (rec_len && rec) memcpy(t + tcp, rec, rec_len);
    return total;
}

/* Build Eth+IPv6+TCP carrying a raw TLS record. src_ip6/dst_ip6 are 16-byte
 * network-order addresses. Returns the total frame length (0 on overflow). */
static size_t __attribute__((unused)) pcv_build_tls_raw_ipv6(
        uint8_t* buf, size_t buf_size, const uint8_t src_ip6[16],
        const uint8_t dst_ip6[16], uint16_t sport, uint16_t dport,
        const uint8_t* rec, size_t rec_len) {
    const size_t eth = 14, ip6 = 40, tcp = 20;
    size_t total = eth + ip6 + tcp + rec_len;
    if (total > buf_size) return 0;
    memset(buf, 0, total);

    static const uint8_t dmac[6] = {0x02,0,0,0,0,0x01};
    static const uint8_t smac[6] = {0x02,0,0,0,0,0x02};
    memcpy(buf, dmac, 6); memcpy(buf + 6, smac, 6);
    buf[12] = 0x86; buf[13] = 0xDD;

    uint8_t* iph = buf + eth;
    iph[0] = 0x60;
    uint16_t plen = (uint16_t)(tcp + rec_len);
    iph[4] = (uint8_t)(plen >> 8); iph[5] = (uint8_t)(plen & 0xFF);
    iph[6] = 6; iph[7] = 64;                          /* next header TCP, hop lim */
    memcpy(iph + 8, src_ip6, 16); memcpy(iph + 24, dst_ip6, 16);

    uint8_t* t = iph + ip6;
    uint16_t sp = htons(sport), dp = htons(dport);
    memcpy(t, &sp, 2); memcpy(t + 2, &dp, 2);
    t[12] = 0x50;                                     /* data offset 5 */
    t[13] = 0x18;                                     /* PSH|ACK */
    if (rec_len && rec) memcpy(t + tcp, rec, rec_len);
    return total;
}

/* Convenience: Eth+IPv4+TCP ClientHello with the given SNI (handshake type 1).
 * Returns the total frame length (0 on overflow). */
static size_t __attribute__((unused)) pcv_build_tls_clienthello_ipv4(
        uint8_t* buf, size_t buf_size, uint32_t src_ip, uint32_t dst_ip,
        uint16_t sport, uint16_t dport, const char* sni) {
    uint8_t rec[900];
    size_t rl = pcv_build_tls_clienthello(rec, sizeof(rec), sni, 0x01);
    if (rl == 0) return 0;
    return pcv_build_tls_raw_ipv4(buf, buf_size, src_ip, dst_ip, sport, dport,
                                  rec, rl);
}

/* Convenience: Eth+IPv6+TCP ClientHello with the given SNI (handshake type 1). */
static size_t __attribute__((unused)) pcv_build_tls_clienthello_ipv6(
        uint8_t* buf, size_t buf_size, const uint8_t src_ip6[16],
        const uint8_t dst_ip6[16], uint16_t sport, uint16_t dport,
        const char* sni) {
    uint8_t rec[900];
    size_t rl = pcv_build_tls_clienthello(rec, sizeof(rec), sni, 0x01);
    if (rl == 0) return 0;
    return pcv_build_tls_raw_ipv6(buf, buf_size, src_ip6, dst_ip6, sport, dport,
                                  rec, rl);
}

#endif /* PCV_TEST_H */
