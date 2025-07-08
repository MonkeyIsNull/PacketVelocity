/* XDP Program for PacketVelocity
 * This program runs in kernel space and decides packet routing
 * Compile with: clang -target bpf -O2 -c pcv_xdp_prog.c -o pcv_xdp_prog.o
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

/* BPF map for packet filtering rules */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 16);
} filter_map SEC(".maps");

/* BPF map for statistics */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 8);
} stats_map SEC(".maps");

/* Statistics indices */
#define STAT_RX_PACKETS     0
#define STAT_RX_BYTES       1
#define STAT_PASSED         2
#define STAT_DROPPED        3

/* Filter actions */
#define FILTER_PASS         1
#define FILTER_DROP         0

/* Simple packet parsing helper */
static __always_inline int parse_packet(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    __u32 key, *value;
    __u64 *stat;
    
    /* Basic bounds check */
    if (data + sizeof(*eth) > data_end)
        return XDP_DROP;
    
    /* Update RX statistics */
    key = STAT_RX_PACKETS;
    stat = bpf_map_lookup_elem(&stats_map, &key);
    if (stat)
        __sync_fetch_and_add(stat, 1);
    
    key = STAT_RX_BYTES;
    stat = bpf_map_lookup_elem(&stats_map, &key);
    if (stat)
        __sync_fetch_and_add(stat, ctx->data_end - ctx->data);
    
    /* Only handle IPv4 for now */
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;
    
    ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_DROP;
    
    /* Check filter rules - simple example */
    key = 0;  /* First filter rule */
    value = bpf_map_lookup_elem(&filter_map, &key);
    if (value && *value == FILTER_DROP) {
        /* Drop packets from specific source */
        if (ip->saddr == __constant_htonl(0xC0A80001)) {  /* 192.168.0.1 */
            key = STAT_DROPPED;
            stat = bpf_map_lookup_elem(&stats_map, &key);
            if (stat)
                __sync_fetch_and_add(stat, 1);
            return XDP_DROP;
        }
    }
    
    /* Pass packet to userspace */
    key = STAT_PASSED;
    stat = bpf_map_lookup_elem(&stats_map, &key);
    if (stat)
        __sync_fetch_and_add(stat, 1);
    
    return XDP_PASS;
}

SEC("xdp")
int pcv_xdp_main(struct xdp_md *ctx) {
    return parse_packet(ctx);
}

char _license[] SEC("license") = "GPL";