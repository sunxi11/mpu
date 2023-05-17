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
BPF_ARRAY(LightPart11, __u32, 245760);
BPF_ARRAY(LightPart12, __u32, 245760);
BPF_ARRAY(LightPart13, __u32, 245760);
BPF_ARRAY(LightPart14, __u32, 245760);
BPF_ARRAY(LightPart15, __u32, 245760);
BPF_ARRAY(LightPart16, __u32, 245760);
BPF_ARRAY(LightPart17, __u32, 245760);
BPF_ARRAY(LightPart18, __u32, 245760);
BPF_ARRAY(HeavyParts_flag1, __u32, 100000);
BPF_ARRAY(HeavyParts_buckets1, struct Bucket, 100000);

BPF_ARRAY(LightPart21, __u32, 245760);
BPF_ARRAY(LightPart22, __u32, 245760);
BPF_ARRAY(LightPart23, __u32, 245760);
BPF_ARRAY(LightPart24, __u32, 245760);
BPF_ARRAY(LightPart25, __u32, 245760);
BPF_ARRAY(LightPart26, __u32, 245760);
BPF_ARRAY(LightPart27, __u32, 245760);
BPF_ARRAY(LightPart28, __u32, 245760);
BPF_ARRAY(HeavyParts_flag2, __u32, 100000);
BPF_ARRAY(HeavyParts_buckets2, struct Bucket, 100000);

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
    uint32_t hash1 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 1234);
    __u32 pos1 = hash1 & (heavy_size - 1);

    struct Bucket *hpb1;
    struct Bucket *hpb_init1;
    // hpb_init->posvote = 1;
    // hpb_init->negvote = 0;
    // hpb_init->flag == false;
    // hpb_init->flow_id.dstIP = dstIP;
    // hpb_init->flow_id.srcIP = srcIP;
    __u32 *hpf1;
    hpf1 = HeavyParts_flag1.lookup(&pos1);
    hpb1 = HeavyParts_buckets1.lookup(&pos1);

    // if (!hpb)
    // {
    //     bpf_trace_printk("Invalid entry in the countsketch sketch");
    //     goto DROP;
    // }

    // bpf_probe_read_kernel();
    __u32 res1 = 0;
    __u32 res2=0;
    if (hpf1)
    {
        if (hpb1)
        {
            if (*hpf1 == 0)
            {
                // hpf = HeavyParts_flag.lookup_or_try_init(&pos, &one);
                *hpf1 = 1;
                // hpb = HeavyParts_buckets.lookup_or_try_init(&pos, &hpb_init);
                hpb1->posvote = 1;
                hpb1->negvote = 0;
                hpb1->flag == false;
                hpb1->flow_id.dstIP = dstIP;
                hpb1->flow_id.srcIP = srcIP;
            }
            else if (*hpf1 != 0)
            {
                if (hpb1->flow_id.srcIP == srcIP && hpb1->flow_id.dstIP == dstIP)
                {
                    hpb1->posvote++;
                }
                else
                {
                    hpb1->negvote++;
                    u_int64_t temp1 = hpb1->negvote / hpb1->posvote;
                    if (temp1 < lamda)
                    {
                        res1 = 1;
                    }
                    else
                    {
                        res1 = hpb1->posvote;
                        (*hpf1) = true;
                        hpb1->negvote = 1;
                        hpb1->posvote = 1;
                        uint32_t tmp = srcIP;
                        srcIP = hpb1->flow_id.srcIP;
                        hpb1->flow_id.srcIP = tmp;
                        tmp = dstIP;
                        dstIP = hpb1->flow_id.dstIP;
                        hpb1->flow_id.dstIP = tmp;
                    }
                }
            }
        
            if (res1 > 0)
            {
                // lp->update(srcIP, dstIP, status);

                uint32_t hash11 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 11);
                uint32_t hash12 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 22);
                uint32_t hash13 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 33);
                uint32_t hash14 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 44);
                uint32_t hash15 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 55);
                uint32_t hash16 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 66);
                uint32_t hash17 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 77);
                uint32_t hash18 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 88);
                __u32 pos11 = hash11 & (light_size_n - 1);
                __u32 pos12 = hash12 & (light_size_n - 1);
                __u32 pos13 = hash13 & (light_size_n - 1);
                __u32 pos14 = hash14 & (light_size_n - 1);
                __u32 pos15 = hash15 & (light_size_n - 1);
                __u32 pos16 = hash16 & (light_size_n - 1);
                __u32 pos17 = hash17 & (light_size_n - 1);
                __u32 pos18 = hash18 & (light_size_n - 1);

                // uint64_t j = two_tuple_sketch_hash(srcIP, dstIP, i, n); // crc32(buf, i + 1) % n;

                __u32 *val11 = LightPart11.lookup(&hash11);
                if (val11)
                    (*val11) += 1;

                __u32 *val12 = LightPart12.lookup(&hash12);
                if (val12)
                    (*val12) += 1;

                __u32 *val13 = LightPart13.lookup(&hash13);
                if (val13)
                    (*val13) += 1;
                __u32 *val14 = LightPart14.lookup(&hash14);
                if (val14)
                    (*val14) += 1;
                __u32 *val15 = LightPart15.lookup(&hash15);
                if (val15)
                    (*val15) += 1;
                __u32 *val16 = LightPart16.lookup(&hash16);
                if (val16)
                    (*val16) += 1;
                __u32 *val17 = LightPart17.lookup(&hash17);
                if (val17)
                    (*val17) += 1;

                __u32 *val18 = LightPart18.lookup(&hash18);
                if (val18)
                    (*val18) += 1;
            }
        
        }
    }
uint32_t hash2 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 1234);
    __u32 pos2 = hash2 & (heavy_size - 1);

    struct Bucket *hpb2;
    struct Bucket *hpb_init2;
    // hpb_init->posvote = 1;
    // hpb_init->negvote = 0;
    // hpb_init->flag == false;
    // hpb_init->flow_id.dstIP = dstIP;
    // hpb_init->flow_id.srcIP = srcIP;
    __u32 *hpf2;
    hpf2 = HeavyParts_flag2.lookup(&pos2);
    hpb2 = HeavyParts_buckets2.lookup(&pos2);
if (hpf2)
    {
        if (hpb2)
        {
            if (*hpf2 == 0)
            {
                // hpf = HeavyParts_flag.lookup_or_try_init(&pos, &one);
                *hpf2 = 1;
                // hpb = HeavyParts_buckets.lookup_or_try_init(&pos, &hpb_init);
                hpb2->posvote = 1;
                hpb2->negvote = 0;
                hpb2->flag == false;
                hpb2->flow_id.dstIP = dstIP;
                hpb2->flow_id.srcIP = srcIP;
            }
           else if (*hpf2 != 0)
            {
                if (hpb2->flow_id.srcIP == srcIP && hpb2->flow_id.dstIP == dstIP)
                {
                    hpb2->posvote++;
                }
                else
                {
                    hpb2->negvote++;
                    u_int64_t temp2 = hpb2->negvote / hpb2->posvote;
                    if (temp2 < lamda)
                    {
                        res2 = 1;
                    }
                    else
                    {
                        res2 = hpb2->posvote;
                        (*hpf2) = true;
                        hpb2->negvote = 1;
                        hpb2->posvote = 1;
                        uint32_t tmp2 = srcIP;
                        srcIP = hpb2->flow_id.srcIP;
                        hpb2->flow_id.srcIP = tmp2;
                        tmp2 = dstIP;
                        dstIP = hpb2->flow_id.dstIP;
                        hpb2->flow_id.dstIP = tmp2;
                    }
                }
								}
            if (res2 > 0)
            {
                // lp->update(srcIP, dstIP, status);

                uint32_t hash21 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 11);
                uint32_t hash22 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 22);
                uint32_t hash23 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 33);
                uint32_t hash24 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 44);
                uint32_t hash25 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 55);
                uint32_t hash26 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 66);
                uint32_t hash27 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 77);
                uint32_t hash28 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 88);
                __u32 pos21 = hash21 & (light_size_n - 1);
                __u32 pos22 = hash22 & (light_size_n - 1);
                __u32 pos23 = hash23 & (light_size_n - 1);
                __u32 pos24 = hash24 & (light_size_n - 1);
                __u32 pos25 = hash25 & (light_size_n - 1);
                __u32 pos26 = hash26 & (light_size_n - 1);
                __u32 pos27 = hash27 & (light_size_n - 1);
                __u32 pos28 = hash28 & (light_size_n - 1);
                __u32 *val21 = LightPart21.lookup(&hash21);
                if (val21)
                    (*val21) += 1;

                __u32 *val22 = LightPart22.lookup(&hash22);
                if (val22)
                    (*val22) += 1;

                __u32 *val23 = LightPart23.lookup(&hash23);
                if (val23)
                    (*val23) += 1;
                __u32 *val24 = LightPart24.lookup(&hash24);
                if (val24)
                    (*val24) += 1;
                __u32 *val25 = LightPart25.lookup(&hash25);
                if (val25)
                    (*val25) += 1;
                __u32 *val26 = LightPart26.lookup(&hash26);
                if (val26)
                    (*val26) += 1;
                __u32 *val27 = LightPart27.lookup(&hash27);
                if (val27)
                    (*val27) += 1;

                __u32 *val28 = LightPart28.lookup(&hash28);
                if (val28)
                    (*val28) += 1;
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

// This is only used when the action is redirect
int xdp_dummy(struct xdp_md *ctx)
{
    return XDP_PASS;
}
