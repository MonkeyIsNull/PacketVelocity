/* Offline packet display/decode test.
 *
 * Feeds synthetic frames through pcv_format_packet_info() - the exact routine
 * the live stdout sink uses - and asserts the rendered tcpdump-style line. No
 * root, no live capture. Direction is forced to "IN " by passing local_ip 0
 * and an empty interface name, so these assertions are deterministic.
 *
 * Covers the regression where ARP (and any non-IP EtherType) printed as
 * "[unparseable packet, N bytes]".
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "pcv_platform.h"
#include "pcv_format.h"
#include "pcv_test.h"

/* Render a frame and compare the formatted line to `expected`. */
static void check_line(const uint8_t* data, size_t len,
                       const char* expected, const char* msg) {
    pcv_packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.data = data;
    pkt.length = (uint32_t)len;
    pkt.captured_length = (uint32_t)len;
    pkt.timestamp_ns = 1000000000ULL;

    char buf[256];
    pcv_format_packet_info(&pkt, 0 /*local_ip*/, "" /*iface*/, buf, sizeof(buf));

    g_checks_run++;
    if (strcmp(buf, expected) != 0) {
        g_checks_failed++;
        fprintf(stderr, "  FAIL: %s\n        got:  \"%s\"\n        want: \"%s\" (%s:%d)\n",
                msg, buf, expected, __FILE__, __LINE__);
    } else {
        fprintf(stdout, "  ok:   %s -> \"%s\"\n", msg, buf);
    }
}

/* Assert a frame does NOT render as "[unparseable ...]". */
static void check_not_unparseable(const uint8_t* data, size_t len, const char* msg) {
    pcv_packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.data = data;
    pkt.length = (uint32_t)len;
    pkt.captured_length = (uint32_t)len;

    char buf[256];
    pcv_format_packet_info(&pkt, 0, "", buf, sizeof(buf));
    CHECK(strstr(buf, "unparseable") == NULL, msg);
}

int main(void) {
    fprintf(stdout, "packet display/decode tests\n");

    uint8_t frame[256];
    size_t len;

    /* --- IPv4 TCP (existing path must be undisturbed) --------------------- */
    len = pcv_build_ipv4_frame(frame, sizeof(frame), 6,
                               0x0A000001, 0x0A000002, 1234, 80, 0x02, 0);
    CHECK(len == 54, "build IPv4 TCP frame (54 bytes)");
    check_line(frame, len,
               "IN  IPv4 10.0.0.1.1234 > 10.0.0.2.80: TCP 54",
               "IPv4 TCP decodes to tcpdump-style line");

    /* --- IPv6 TCP (display already supported; confirm it still works) ----- */
    {
        /* 2001:db8::1 -> 2001:db8::2 */
        uint8_t src6[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0, 0,0,0,0,0,0,0,0x01};
        uint8_t dst6[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0, 0,0,0,0,0,0,0,0x02};
        len = pcv_build_ipv6_frame(frame, sizeof(frame), 6,
                                   src6, dst6, 1111, 2222, 0x02, 0);
        CHECK(len == 74, "build IPv6 TCP frame (74 bytes)");
        check_line(frame, len,
                   "IN  IPv6 [2001:db8::1].1111 > [2001:db8::2].2222: TCP 74",
                   "IPv6 TCP decodes to tcpdump-style line");
    }

    /* --- ARP request (was "[unparseable packet, 42 bytes]") --------------- */
    {
        uint8_t smac[6] = {0x02,0x00,0x00,0x00,0x00,0x11};
        len = pcv_build_arp_frame(frame, sizeof(frame), 1 /*request*/,
                                  0x0A000001, 0x0A000002, smac, NULL);
        CHECK(len == 42, "build ARP request frame (42 bytes)");
        check_not_unparseable(frame, len, "ARP request is no longer unparseable");
        check_line(frame, len,
                   "IN  ARP request who-has 10.0.0.2 tell 10.0.0.1",
                   "ARP request decodes to who-has/tell line");
    }

    /* --- ARP reply -------------------------------------------------------- */
    {
        uint8_t smac[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0xff};
        uint8_t tmac[6] = {0x02,0x00,0x00,0x00,0x00,0x11};
        len = pcv_build_arp_frame(frame, sizeof(frame), 2 /*reply*/,
                                  0x0A000002, 0x0A000001, smac, tmac);
        CHECK(len == 42, "build ARP reply frame (42 bytes)");
        check_not_unparseable(frame, len, "ARP reply is no longer unparseable");
        check_line(frame, len,
                   "IN  ARP reply 10.0.0.2 is-at aa:bb:cc:dd:ee:ff",
                   "ARP reply decodes to is-at line");
    }

    /* --- ARP with an uncommon opcode -> sane fallback --------------------- */
    {
        uint8_t smac[6] = {0x02,0x00,0x00,0x00,0x00,0x22};
        len = pcv_build_arp_frame(frame, sizeof(frame), 3 /*RARP request*/,
                                  0x0A000003, 0x0A000004, smac, NULL);
        check_line(frame, len, "IN  ARP op=3",
                   "uncommon ARP opcode falls back to op=<n>");
    }

    /* --- Other EtherType (e.g. LLDP 0x88cc) ------------------------------- */
    {
        memset(frame, 0, 60);
        /* dst/src MAC left zero; EtherType 0x88cc (LLDP) */
        frame[12] = 0x88; frame[13] = 0xcc;
        check_not_unparseable(frame, 60, "other EtherType is no longer unparseable");
        check_line(frame, 60, "EtherType 0x88cc 60 bytes",
                   "unknown EtherType is labeled, not mysterious");
    }

    /* --- Truly short/malformed frame keeps the catch-all ------------------ */
    {
        memset(frame, 0, 10);
        check_line(frame, 10, "[unparseable packet, 10 bytes]",
                   "short frame keeps the unparseable catch-all");
    }

    return pcv_test_summary("test_display");
}
