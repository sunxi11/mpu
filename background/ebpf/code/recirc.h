#include <uapi/linux/bpf.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

//#include "common.h"
//#include "fasthash.h"
//#include "murmurhash3.h"

#define SEC(NAME) __attribute__((section(NAME), used))

// #define ROWS 8
// #define COLUMNS 327680
// #define  _OUTPUT_INTERFACE_IFINDEX 5
// _Static_assert((COLUMNS & (COLUMNS - 1)) == 0, "COLUMNS must be a power of two");

// struct countSketch
// {
//     __u32 values[ROWS][COLUMNS];
// };

static __always_inline void swap_src_dst_mac(struct ethhdr *eth)
{
	/* Assignment 1: swap source and destination addresses in the eth.
	 * For simplicity you can use the memcpy macro defined above */
	unsigned char swap[6];
	memcpy(swap, eth->h_source, sizeof(swap));
	memcpy(eth->h_source, eth->h_dest, sizeof(eth->h_source));
	memcpy(eth->h_dest, swap, sizeof(eth->h_dest));
}

static __always_inline void swap_src_dst_ipv4(struct iphdr *iphdr)
{
	/* Assignment 1: swap source and destination addresses in the iphdr */
	unsigned int swap = iphdr->saddr;
	iphdr->saddr = iphdr->daddr;
	iphdr->daddr = swap;
}

struct pkt_5tuple
{
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    uint8_t proto;
} __attribute__((packed));

struct pkt_md
{
    uint64_t drop_cnt;
};

// BPF_TABLE("array", uint32_t, long, dropcnt, 256);
// // BPF_ARRAY(count, struct countSketch, 1);
// BPF_ARRAY(countSketch1, __u32, 327680);
// BPF_ARRAY(countSketch2, __u32, 327680);
// BPF_ARRAY(countSketch3, __u32, 327680);
// BPF_ARRAY(countSketch4, __u32, 327680);
// BPF_ARRAY(countSketch5, __u32, 327680);
// BPF_ARRAY(countSketch6, __u32, 327680);
// BPF_ARRAY(countSketch7, __u32, 327680);
// BPF_ARRAY(countSketch8, __u32, 327680);

SEC("xdp")
int xdp_prog1(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    uint64_t nh_off = 0;
    struct ethhdr *eth = data;
    nh_off = sizeof(*eth);
    if (data + nh_off > data_end)
        return XDP_PASS;

    struct pkt_5tuple pkt;

    struct iphdr *ip = data + nh_off;
    if ((void *)&ip[1] > data_end)
        return XDP_PASS;

    pkt.src_ip = ip->saddr;
    pkt.dst_ip = ip->daddr;
    pkt.proto = ip->protocol;

    /*
    if (ip->protocol == IPPROTO_TCP) {
        struct tcp_hdr *tcp = NULL;
        tcp = data + nh_off + sizeof(*ip);
        if (data + nh_off + sizeof(*ip) + sizeof(*tcp) > data_end)
	    	return XDP_PASS;
        pkt.src_port = tcp->source;
        pkt.dst_port = tcp->dest;
    } else*/ 
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = NULL;
        udp = data + nh_off + sizeof(*ip);
        if (data + nh_off + sizeof(*ip) + sizeof(*udp) > data_end)
            return XDP_PASS;
        pkt.src_port = udp->source;
        pkt.dst_port = udp->dest;
    }// else {
    //    return XDP_PASS;
    //}

    // swap_src_dst_mac(eth);
    // swap_src_dst_ipv4(ip);

    unsigned char dst[ETH_ALEN] = {0xd0, 0x9f, 0xd9, 0x70, 0x50, 0x69};
    memcpy(eth->h_dest, dst, ETH_ALEN);

    int action = XDP_REDIRECT;
    action = bpf_redirect(5, 0);
    // action = XDP_TX;
    return action;
}

// This is only used when the action is redirect
SEC("xdp")
int xdp_dummy(struct xdp_md *ctx)
{
    return XDP_PASS;
}


