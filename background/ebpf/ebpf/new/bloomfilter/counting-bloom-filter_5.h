#include <uapi/linux/bpf.h>
#include <uapi/linux/filter.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/if_arp.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <linux/if_vlan.h>

#include "common.h"
#include "murmurhash3.h"

#define HASHFN_N 4
#define COLUMNS 2621440
#define k 4

// #define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
// _Static_assert((COLUMNS & (COLUMNS - 1)) == 0, "COLUMNS must be a power of two");

// struct bloom
// {
//     __u32 values[COLUMNS];
// };

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

BPF_PERCPU_ARRAY(dropcnt, struct pkt_md, 1);
BPF_ARRAY(countingbloomfilter, __u32, 2621440);
BPF_ARRAY(countingbloomfilter2, __u32, 2621440);
BPF_ARRAY(countingbloomfilter3, __u32, 2621440);
BPF_ARRAY(countingbloomfilter4, __u32, 2621440);
BPF_ARRAY(countingbloomfilter5, __u32, 2621440);

// static void __always_inline counting_bloom_insert(struct bloom *bf, void *element, __u64 len)
// {
//     for (int i = 0; i < k; i++)
//     {
//         uint32_t hash = MurmurHash3_x86_32(element, len, i * i);
//         __u32 target_idx = hash & (COLUMNS - 1);
//         if (CHECK_BIT(hash, 31))
//             bf->values[target_idx]++;
//     }
//     return;
// }

int xdp_prog1(struct CTXTYPE *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    uint64_t nh_off = 0;
    struct eth_hdr *eth = data;
    nh_off = sizeof(*eth);
    if (data + nh_off > data_end)
        goto DROP;

    uint16_t h_proto = eth->proto;

// parse double vlans
#pragma unroll
    for (int i = 0; i < 2; i++)
    {
        if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD))
        {
            struct vlan_hdr *vhdr;
            vhdr = data + nh_off;
            nh_off += sizeof(struct vlan_hdr);
            if (data + nh_off > data_end)
                goto DROP;
            h_proto = vhdr->h_vlan_encapsulated_proto;
        }
    }

    switch (h_proto)
    {
    case htons(ETH_P_IP):
        break;
    default:
        return XDP_PASS;
    }

    struct pkt_5tuple pkt;

    struct iphdr *ip = data + nh_off;
    if ((void *)&ip[1] > data_end)
        goto DROP;

    pkt.src_ip = ip->saddr;
    pkt.dst_ip = ip->daddr;
    pkt.proto = ip->protocol;

    switch (ip->protocol)
    {
    case IPPROTO_TCP:
    {
        struct tcp_hdr *tcp = NULL;
        tcp = data + nh_off + sizeof(*ip);
        if (data + nh_off + sizeof(*ip) + sizeof(*tcp) > data_end)
            goto DROP;
        pkt.src_port = tcp->source;
        pkt.dst_port = tcp->dest;
        break;
    }
    case IPPROTO_UDP:
    {
        struct udphdr *udp = NULL;
        udp = data + nh_off + sizeof(*ip);
        if (data + nh_off + sizeof(*ip) + sizeof(*udp) > data_end)
            goto DROP;
        pkt.src_port = udp->source;
        pkt.dst_port = udp->dest;
        break;
    }
    default:
        goto DROP;
    }

    uint32_t zero = 0;
    for (int i = 0; i < k; i++)
    {
        uint32_t hash5 = MurmurHash3_x86_32(&pkt, sizeof(pkt), i * i);
        __u32 target_idx5 = hash5 & (COLUMNS - 1);
        if (CHECK_BIT(hash5, 31))
        {
            __u32 *val5 = countingbloomfilter5.lookup(&target_idx5);
            if (val5)
            {
                (*val5) += 1;
            }
        }
    }
    for (int i = 0; i < k; i++)
    {
        uint32_t hash4 = MurmurHash3_x86_32(&pkt, sizeof(pkt), i * i);
        __u32 target_idx4 = hash4 & (COLUMNS - 1);
        if (CHECK_BIT(hash4, 31))
        {
            __u32 *val4 = countingbloomfilter4.lookup(&target_idx4);
            if (val4)
            {
                (*val4) += 1;
            }
        }
    }
    // struct bloom *bl;
    for (int i = 0; i < k; i++)
    {
        uint32_t hash3 = MurmurHash3_x86_32(&pkt, sizeof(pkt), i * i);
        __u32 target_idx3 = hash3 & (COLUMNS - 1);
        if (CHECK_BIT(hash3, 31))
        {
            __u32 *val3 = countingbloomfilter3.lookup(&target_idx3);
            if (val3)
            {
                (*val3) += 1;
            }
        }
    }
    for (int i = 0; i < k; i++)
    {
        uint32_t hash = MurmurHash3_x86_32(&pkt, sizeof(pkt), i * i);
        __u32 target_idx = hash & (COLUMNS - 1);
        if (CHECK_BIT(hash, 31))
        {
            __u32 *val = countingbloomfilter.lookup(&target_idx);
            if (val)
            {
                (*val) += 1;
            }
        }
    }
    for (int i = 0; i < k; i++)
    {
        uint32_t hash2 = MurmurHash3_x86_32(&pkt, sizeof(pkt), i * i);
        __u32 target_idx2 = hash2 & (COLUMNS - 1);
        if (CHECK_BIT(hash2, 31))
        {
            __u32 *val2 = countingbloomfilter2.lookup(&target_idx2);
            if (val2)
            {
                (*val2) += 1;
            }
        }
    }

    struct pkt_md *md;
    uint32_t index = 0;
    md = dropcnt.lookup(&index);
    if (md)
    {
        NO_TEAR_INC(md->drop_cnt);
    }

    return bpf_redirect(5, 0);

DROP:;
    bpf_trace_printk("Error. Dropping packet\n");
    return XDP_DROP;
}
