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
#include "xxhash32.h"
#include "murmurhash3.h"

// #define heavy_size _HEAVY_SIZE
// #define light_size _LIGHT_SIZE
// #define light_size_m _LIGHT_SIZE_M
// #define light_size_n _LIGHT_SIZE_N
// #define lamda _LAMDA
#define heavy_size 100000
#define light_size _LIGHT_SIZE
#define light_size_m 8
#define light_size_n 245760
#define lamda 8

//_Static_assert((COLUMNS & (COLUMNS - 1)) == 0, "COLUMNS must be a power of two");

struct twoTuple_t
{
    __be32 srcIP;
    __be32 dstIP;
} __attribute__((packed));

struct Bucket
{
    struct twoTuple_t flow_id;
    uint32_t posvote;
    uint32_t negvote;
    bool flag;
};

// struct LightPart
// {
//     uint32_t value[light_size_m][light_size_n];
// };

// struct HeavyPart
// {
//     uint32_t flag[heavy_size];
//     struct Bucket buckets[heavy_size];
// };

struct pkt_md
{
    uint64_t drop_cnt;
};

struct pkt_5tuple
{
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    uint8_t proto;
} __attribute__((packed));

// BPF_PERCPU_ARRAY(metadata, struct pkt_md, 1);
BPF_PERCPU_ARRAY(dropcnt, struct pkt_md, 1);
BPF_ARRAY(LightPart1, __u32, 245760);
BPF_ARRAY(LightPart2, __u32, 245760);
BPF_ARRAY(LightPart3, __u32, 245760);
BPF_ARRAY(LightPart4, __u32, 245760);
BPF_ARRAY(LightPart5, __u32, 245760);
BPF_ARRAY(LightPart6, __u32, 245760);
BPF_ARRAY(LightPart7, __u32, 245760);
BPF_ARRAY(LightPart8, __u32, 245760);
BPF_ARRAY(HeavyParts_flag, __u32, 100000);
BPF_ARRAY(HeavyParts_buckets, struct Bucket, 100000);

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

    // md = metadata.lookup(&zero);
    // if (!md)
    // {
    //     bpf_trace_printk("Error! Invalid metadata.");
    //     goto DROP;
    // }
    // bpf_trace_printk("-----------------------------------------");

    uint32_t srcIP = pkt.src_ip;
    uint32_t dstIP = pkt.dst_ip;
    uint32_t hash = MurmurHash3_x86_32(&pkt, sizeof(pkt), 1234);
    __u32 pos = hash & (heavy_size - 1);

    struct Bucket *hpb;
    struct Bucket *hpb_init;
    // hpb_init->posvote = 1;
    // hpb_init->negvote = 0;
    // hpb_init->flag == false;
    // hpb_init->flow_id.dstIP = dstIP;
    // hpb_init->flow_id.srcIP = srcIP;
    __u32 *hpf;
    hpf = HeavyParts_flag.lookup(&pos);
    hpb = HeavyParts_buckets.lookup(&pos);

    // if (!hpb)
    // {
    //     bpf_trace_printk("Invalid entry in the countsketch sketch");
    //     goto DROP;
    // }

    // bpf_probe_read_kernel();
    __u32 res = 0;
  
    if (hpf)
    {
        if (hpb)
        {
            if (*hpf == 0)
            {
                // hpf = HeavyParts_flag.lookup_or_try_init(&pos, &one);
                *hpf = 1;
                // hpb = HeavyParts_buckets.lookup_or_try_init(&pos, &hpb_init);
                hpb->posvote = 1;
                hpb->negvote = 0;
                hpb->flag == false;
                hpb->flow_id.dstIP = dstIP;
                hpb->flow_id.srcIP = srcIP;
            }
            else if (*hpf != 0)
            {
                if (hpb->flow_id.srcIP == srcIP && hpb->flow_id.dstIP == dstIP)
                {
                    hpb->posvote++;
                }
                else
                {
                    hpb->negvote++;
                    u_int64_t temp = hpb->negvote / hpb->posvote;
                    if (temp < lamda)
                    {
                        res = 1;
                    }
                    else
                    {
                        res = hpb->posvote;
                        (*hpf) = true;
                        hpb->negvote = 1;
                        hpb->posvote = 1;
                        uint32_t tmp = srcIP;
                        srcIP = hpb->flow_id.srcIP;
                        hpb->flow_id.srcIP = tmp;
                        tmp = dstIP;
                        dstIP = hpb->flow_id.dstIP;
                        hpb->flow_id.dstIP = tmp;
                    }
                }
            }
        
            if (res > 0)
            {
                // lp->update(srcIP, dstIP, status);

                uint32_t hash1 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 11);
                uint32_t hash2 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 22);
                uint32_t hash3 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 33);
                uint32_t hash4 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 44);
                uint32_t hash5 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 55);
                uint32_t hash6 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 66);
                uint32_t hash7 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 77);
                uint32_t hash8 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 88);
                __u32 pos1 = hash1 & (light_size_n - 1);
                __u32 pos2 = hash2 & (light_size_n - 1);
                __u32 pos3 = hash3 & (light_size_n - 1);
                __u32 pos4 = hash4 & (light_size_n - 1);
                __u32 pos5 = hash5 & (light_size_n - 1);
                __u32 pos6 = hash6 & (light_size_n - 1);
                __u32 pos7 = hash7 & (light_size_n - 1);
                __u32 pos8 = hash8 & (light_size_n - 1);

                // uint64_t j = two_tuple_sketch_hash(srcIP, dstIP, i, n); // crc32(buf, i + 1) % n;

                __u32 *val1 = LightPart1.lookup(&hash1);
                if (val1)
                    (*val1) += 1;

                __u32 *val2 = LightPart2.lookup(&hash2);
                if (val2)
                    (*val2) += 1;

                __u32 *val3 = LightPart3.lookup(&hash3);
                if (val3)
                    (*val3) += 1;
                __u32 *val4 = LightPart4.lookup(&hash4);
                if (val4)
                    (*val4) += 1;
                __u32 *val5 = LightPart5.lookup(&hash5);
                if (val5)
                    (*val5) += 1;
                __u32 *val6 = LightPart6.lookup(&hash6);
                if (val6)
                    (*val6) += 1;
                __u32 *val7 = LightPart7.lookup(&hash7);
                if (val7)
                    (*val7) += 1;

                __u32 *val8 = LightPart8.lookup(&hash8);
                if (val8)
                    (*val8) += 1;
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
    return XDP_DROP;

DROP:;
    bpf_trace_printk("Error. Dropping packet\n");
    return XDP_DROP;
}

// This is only used when the action is redirect
int xdp_dummy(struct xdp_md *ctx)
{
    return XDP_PASS;
}
