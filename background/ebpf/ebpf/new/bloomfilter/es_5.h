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


BPF_PERCPU_ARRAY(dropcnt, struct pkt_md, 1);
BPF_ARRAY(LightPart11, __u32, 245760);
BPF_ARRAY(LightPart21, __u32, 245760);
BPF_ARRAY(LightPart31, __u32, 245760);
BPF_ARRAY(LightPart41, __u32, 245760);
BPF_ARRAY(LightPart51, __u32, 245760);
BPF_ARRAY(LightPart61, __u32, 245760);
BPF_ARRAY(LightPart71, __u32, 245760);
BPF_ARRAY(LightPart81, __u32, 245760);
BPF_ARRAY(HeavyParts_flag1, __u32, 100000);
BPF_ARRAY(HeavyParts_buckets1, struct Bucket, 100000);

//BPF_PERCPU_ARRAY(dropcnt, struct pkt_md, 1);
BPF_ARRAY(LightPart13, __u32, 245760);
BPF_ARRAY(LightPart23, __u32, 245760);
BPF_ARRAY(LightPart33, __u32, 245760);
BPF_ARRAY(LightPart43, __u32, 245760);
BPF_ARRAY(LightPart53, __u32, 245760);
BPF_ARRAY(LightPart63, __u32, 245760);
BPF_ARRAY(LightPart73, __u32, 245760);
BPF_ARRAY(LightPart83, __u32, 245760);
BPF_ARRAY(HeavyParts_flag3, __u32, 100000);
BPF_ARRAY(HeavyParts_buckets3, struct Bucket, 100000);

//BPF_PERCPU_ARRAY(dropcnt, struct pkt_md, 1);
BPF_ARRAY(LightPart12, __u32, 245760);
BPF_ARRAY(LightPart22, __u32, 245760);
BPF_ARRAY(LightPart32, __u32, 245760);
BPF_ARRAY(LightPart42, __u32, 245760);
BPF_ARRAY(LightPart52, __u32, 245760);
BPF_ARRAY(LightPart62, __u32, 245760);
BPF_ARRAY(LightPart72, __u32, 245760);
BPF_ARRAY(LightPart82, __u32, 245760);
BPF_ARRAY(HeavyParts_flag2, __u32, 100000);
BPF_ARRAY(HeavyParts_buckets2, struct Bucket, 100000);

BPF_ARRAY(LightPart14, __u32, 245760);
BPF_ARRAY(LightPart24, __u32, 245760);
BPF_ARRAY(LightPart34, __u32, 245760);
BPF_ARRAY(LightPart44, __u32, 245760);
BPF_ARRAY(LightPart54, __u32, 245760);
BPF_ARRAY(LightPart64, __u32, 245760);
BPF_ARRAY(LightPart74, __u32, 245760);
BPF_ARRAY(LightPart84, __u32, 245760);
BPF_ARRAY(HeavyParts_flag4, __u32, 100000);
BPF_ARRAY(HeavyParts_buckets4, struct Bucket, 100000);

BPF_ARRAY(LightPart15, __u32, 245760);
BPF_ARRAY(LightPart25, __u32, 245760);
BPF_ARRAY(LightPart35, __u32, 245760);
BPF_ARRAY(LightPart45, __u32, 245760);
BPF_ARRAY(LightPart55, __u32, 245760);
BPF_ARRAY(LightPart65, __u32, 245760);
BPF_ARRAY(LightPart75, __u32, 245760);
BPF_ARRAY(LightPart85, __u32, 245760);
BPF_ARRAY(HeavyParts_flag5, __u32, 100000);
BPF_ARRAY(HeavyParts_buckets5, struct Bucket, 100000);

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
    uint32_t hash5 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 1234);
    __u32 pos5 = hash5 & (heavy_size - 1);

    struct Bucket *hpb5;
    struct Bucket *hpb5_init;
    // hpb5_init->posvote = 1;
    // hpb5_init->negvote = 0;
    // hpb5_init->flag == false;
    // hpb5_init->flow_id.dstIP = dstIP;
    // hpb5_init->flow_id.srcIP = srcIP;
    __u32 *hpf5;
    hpf5 = HeavyParts_flag5.lookup(&pos5);
    hpb5 = HeavyParts_buckets5.lookup(&pos5);

    // if (!hpb5)
    // {
    //     bpf_trace_printk("Invalid entry in the countsketch sketch");
    //     goto DROP;
    // }

    // bpf_probe_read_kernel();
    __u32 res5 = 0;
  
    if (hpf5)
    {
        if (hpb5)
        {
            if (*hpf5 == 0)
            {
                // hpf5 = HeavyParts_flag5.lookup_or_try_init(&pos, &one);
                *hpf5 = 1;
                // hpb5 = HeavyParts_buckets5.lookup_or_try_init(&pos, &hpb5_init);
                hpb5->posvote = 1;
                hpb5->negvote = 0;
                hpb5->flag == false;
                hpb5->flow_id.dstIP = dstIP;
                hpb5->flow_id.srcIP = srcIP;
            }
            else if (*hpf5 != 0)
            {
                if (hpb5->flow_id.srcIP == srcIP && hpb5->flow_id.dstIP == dstIP)
                {
                    hpb5->posvote++;
                }
                else
                {
                    hpb5->negvote++;
                    u_int64_t temp5 = hpb5->negvote / hpb5->posvote;
                    if (temp5 < lamda)
                    {
                        res5 = 1;
                    }
                    else
                    {
                        res5 = hpb5->posvote;
                        (*hpf5) = true;
                        hpb5->negvote = 1;
                        hpb5->posvote = 1;
                        uint32_t tmp5 = srcIP;
                        srcIP = hpb5->flow_id.srcIP;
                        hpb5->flow_id.srcIP = tmp5;
                        tmp5 = dstIP;
                        dstIP = hpb5->flow_id.dstIP;
                        hpb5->flow_id.dstIP = tmp5;
                    }
                }
            }
        
            if (res5 > 0)
            {
                // lp->update(srcIP, dstIP, status);

                uint32_t hash15 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 11);
                uint32_t hash25 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 22);
                uint32_t hash35 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 33);
                uint32_t hash45 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 44);
                uint32_t hash55 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 55);
                uint32_t hash65 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 66);
                uint32_t hash75 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 77);
                uint32_t hash85 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 88);
                __u32 pos15 = hash15 & (light_size_n - 1);
                __u32 pos25 = hash25 & (light_size_n - 1);
                __u32 pos35 = hash35 & (light_size_n - 1);
                __u32 pos45 = hash45 & (light_size_n - 1);
                __u32 pos55 = hash55 & (light_size_n - 1);
                __u32 pos65 = hash65 & (light_size_n - 1);
                __u32 pos75 = hash75 & (light_size_n - 1);
                __u32 pos85 = hash85 & (light_size_n - 1);

                // uint64_t j = two_tuple_sketch_hash(srcIP, dstIP, i, n); // crc32(buf, i + 1) % n;

                __u32 *val15 = LightPart15.lookup(&hash15);
                if (val15)
                    (*val15) += 1;

                __u32 *val25 = LightPart25.lookup(&hash25);
                if (val25)
                    (*val25) += 1;

                __u32 *val35 = LightPart35.lookup(&hash35);
                if (val35)
                    (*val35) += 1;
                __u32 *val45 = LightPart45.lookup(&hash45);
                if (val45)
                    (*val45) += 1;
                __u32 *val55 = LightPart55.lookup(&hash55);
                if (val55)
                    (*val55) += 1;
                __u32 *val65 = LightPart65.lookup(&hash65);
                if (val65)
                    (*val65) += 1;
                __u32 *val75 = LightPart75.lookup(&hash75);
                if (val75)
                    (*val75) += 1;

                __u32 *val85 = LightPart85.lookup(&hash85);
                if (val85)
                    (*val85) += 1;
            }
        
        }
    }

    uint32_t hash4 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 1234);
    __u32 pos4 = hash4 & (heavy_size - 1);

    struct Bucket *hpb4;
    struct Bucket *hpb4_init;
    // hpb4_init->posvote = 1;
    // hpb4_init->negvote = 0;
    // hpb4_init->flag == false;
    // hpb4_init->flow_id.dstIP = dstIP;
    // hpb4_init->flow_id.srcIP = srcIP;
    __u32 *hpf4;
    hpf4 = HeavyParts_flag4.lookup(&pos4);
    hpb4 = HeavyParts_buckets4.lookup(&pos4);

    // if (!hpb4)
    // {
    //     bpf_trace_printk("Invalid entry in the countsketch sketch");
    //     goto DROP;
    // }

    // bpf_probe_read_kernel();
    __u32 res4 = 0;
  
    if (hpf4)
    {
        if (hpb4)
        {
            if (*hpf4 == 0)
            {
                // hpf4 = HeavyParts_flag4.lookup_or_try_init(&pos, &one);
                *hpf4 = 1;
                // hpb4 = HeavyParts_buckets4.lookup_or_try_init(&pos, &hpb4_init);
                hpb4->posvote = 1;
                hpb4->negvote = 0;
                hpb4->flag == false;
                hpb4->flow_id.dstIP = dstIP;
                hpb4->flow_id.srcIP = srcIP;
            }
            else if (*hpf4 != 0)
            {
                if (hpb4->flow_id.srcIP == srcIP && hpb4->flow_id.dstIP == dstIP)
                {
                    hpb4->posvote++;
                }
                else
                {
                    hpb4->negvote++;
                    u_int64_t temp4 = hpb4->negvote / hpb4->posvote;
                    if (temp4 < lamda)
                    {
                        res4 = 1;
                    }
                    else
                    {
                        res4 = hpb4->posvote;
                        (*hpf4) = true;
                        hpb4->negvote = 1;
                        hpb4->posvote = 1;
                        uint32_t tmp4 = srcIP;
                        srcIP = hpb4->flow_id.srcIP;
                        hpb4->flow_id.srcIP = tmp4;
                        tmp4 = dstIP;
                        dstIP = hpb4->flow_id.dstIP;
                        hpb4->flow_id.dstIP = tmp4;
                    }
                }
            }
        
            if (res4 > 0)
            {
                // lp->update(srcIP, dstIP, status);

                uint32_t hash14 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 11);
                uint32_t hash24 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 22);
                uint32_t hash34 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 33);
                uint32_t hash44 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 44);
                uint32_t hash54 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 55);
                uint32_t hash64 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 66);
                uint32_t hash74 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 77);
                uint32_t hash84 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 88);
                __u32 pos14 = hash14 & (light_size_n - 1);
                __u32 pos24 = hash24 & (light_size_n - 1);
                __u32 pos34 = hash34 & (light_size_n - 1);
                __u32 pos44 = hash44 & (light_size_n - 1);
                __u32 pos54 = hash54 & (light_size_n - 1);
                __u32 pos64 = hash64 & (light_size_n - 1);
                __u32 pos74 = hash74 & (light_size_n - 1);
                __u32 pos84 = hash84 & (light_size_n - 1);

                // uint64_t j = two_tuple_sketch_hash(srcIP, dstIP, i, n); // crc32(buf, i + 1) % n;

                __u32 *val14 = LightPart14.lookup(&hash14);
                if (val14)
                    (*val14) += 1;

                __u32 *val24 = LightPart24.lookup(&hash24);
                if (val24)
                    (*val24) += 1;

                __u32 *val34 = LightPart34.lookup(&hash34);
                if (val34)
                    (*val34) += 1;
                __u32 *val44 = LightPart44.lookup(&hash44);
                if (val44)
                    (*val44) += 1;
                __u32 *val54 = LightPart54.lookup(&hash54);
                if (val54)
                    (*val54) += 1;
                __u32 *val64 = LightPart64.lookup(&hash64);
                if (val64)
                    (*val64) += 1;
                __u32 *val74 = LightPart74.lookup(&hash74);
                if (val74)
                    (*val74) += 1;

                __u32 *val84 = LightPart84.lookup(&hash84);
                if (val84)
                    (*val84) += 1;
            }
        
        }
    }
 uint32_t hash1 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 1234);
    __u32 pos1 = hash1 & (heavy_size - 1);

    struct Bucket *hpb1;
    struct Bucket *hpb1_init;
    // hpb1_init->posvote = 1;
    // hpb1_init->negvote = 0;
    // hpb1_init->flag == false;
    // hpb1_init->flow_id.dstIP = dstIP;
    // hpb1_init->flow_id.srcIP = srcIP;
    __u32 *hpf1;
    hpf1 = HeavyParts_flag1.lookup(&pos1);
    hpb1 = HeavyParts_buckets1.lookup(&pos1);

    // if (!hpb1)
    // {
    //     bpf_trace_printk("Invalid entry in the countsketch sketch");
    //     goto DROP;
    // }

    // bpf_probe_read_kernel();
    __u32 res1 = 0;
  
    if (hpf1)
    {
        if (hpb1)
        {
            if (*hpf1 == 0)
            {
                // hpf1 = HeavyParts_flag1.lookup_or_try_init(&pos, &one);
                *hpf1 = 1;
                // hpb1 = HeavyParts_buckets1.lookup_or_try_init(&pos, &hpb1_init);
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
                        uint32_t tmp1 = srcIP;
                        srcIP = hpb1->flow_id.srcIP;
                        hpb1->flow_id.srcIP = tmp1;
                        tmp1 = dstIP;
                        dstIP = hpb1->flow_id.dstIP;
                        hpb1->flow_id.dstIP = tmp1;
                    }
                }
            }
        
            if (res1 > 0)
            {
                // lp->update(srcIP, dstIP, status);

                uint32_t hash11 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 11);
                uint32_t hash21 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 22);
                uint32_t hash31 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 33);
                uint32_t hash41 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 44);
                uint32_t hash51 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 55);
                uint32_t hash61 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 66);
                uint32_t hash71 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 77);
                uint32_t hash81 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 88);
                __u32 pos11 = hash11 & (light_size_n - 1);
                __u32 pos21 = hash21 & (light_size_n - 1);
                __u32 pos31 = hash31 & (light_size_n - 1);
                __u32 pos41 = hash41 & (light_size_n - 1);
                __u32 pos51 = hash51 & (light_size_n - 1);
                __u32 pos61 = hash61 & (light_size_n - 1);
                __u32 pos71 = hash71 & (light_size_n - 1);
                __u32 pos81 = hash81 & (light_size_n - 1);

                // uint64_t j = two_tuple_sketch_hash(srcIP, dstIP, i, n); // crc32(buf, i + 1) % n;

                __u32 *val11 = LightPart11.lookup(&hash11);
                if (val11)
                    (*val11) += 1;

                __u32 *val21 = LightPart21.lookup(&hash21);
                if (val21)
                    (*val21) += 1;

                __u32 *val31 = LightPart31.lookup(&hash31);
                if (val31)
                    (*val31) += 1;
                __u32 *val41 = LightPart41.lookup(&hash41);
                if (val41)
                    (*val41) += 1;
                __u32 *val51 = LightPart51.lookup(&hash51);
                if (val51)
                    (*val51) += 1;
                __u32 *val61 = LightPart61.lookup(&hash61);
                if (val61)
                    (*val61) += 1;
                __u32 *val71 = LightPart71.lookup(&hash71);
                if (val71)
                    (*val71) += 1;

                __u32 *val81 = LightPart81.lookup(&hash81);
                if (val81)
                    (*val81) += 1;
            }
        
        }
    }
    

    uint32_t hash2 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 1234);
    __u32 pos2 = hash2 & (heavy_size - 1);

    struct Bucket *hpb2;
    struct Bucket *hpb2_init;
    // hpb2_init->posvote = 1;
    // hpb2_init->negvote = 0;
    // hpb2_init->flag == false;
    // hpb2_init->flow_id.dstIP = dstIP;
    // hpb2_init->flow_id.srcIP = srcIP;
    __u32 *hpf2;
    hpf2 = HeavyParts_flag2.lookup(&pos2);
    hpb2 = HeavyParts_buckets2.lookup(&pos2);

    // if (!hpb2)
    // {
    //     bpf_trace_printk("Invalid entry in the countsketch sketch");
    //     goto DROP;
    // }

    // bpf_probe_read_kernel();
    __u32 res2 = 0;
  
    if (hpf2)
    {
        if (hpb2)
        {
            if (*hpf2 == 0)
            {
                // hpf2 = HeavyParts_flag2.lookup_or_try_init(&pos, &one);
                *hpf2 = 1;
                // hpb2 = HeavyParts_buckets2.lookup_or_try_init(&pos, &hpb2_init);
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

                uint32_t hash12 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 11);
                uint32_t hash22 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 22);
                uint32_t hash32 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 33);
                uint32_t hash42 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 44);
                uint32_t hash52 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 55);
                uint32_t hash62 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 66);
                uint32_t hash72 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 77);
                uint32_t hash82 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 88);
                __u32 pos12 = hash12 & (light_size_n - 1);
                __u32 pos22 = hash22 & (light_size_n - 1);
                __u32 pos32 = hash32 & (light_size_n - 1);
                __u32 pos42 = hash42 & (light_size_n - 1);
                __u32 pos52 = hash52 & (light_size_n - 1);
                __u32 pos62 = hash62 & (light_size_n - 1);
                __u32 pos72 = hash72 & (light_size_n - 1);
                __u32 pos82 = hash82 & (light_size_n - 1);

                // uint64_t j = two_tuple_sketch_hash(srcIP, dstIP, i, n); // crc32(buf, i + 1) % n;

                __u32 *val12 = LightPart12.lookup(&hash12);
                if (val12)
                    (*val12) += 1;

                __u32 *val22 = LightPart22.lookup(&hash22);
                if (val22)
                    (*val22) += 1;

                __u32 *val32 = LightPart32.lookup(&hash32);
                if (val32)
                    (*val32) += 1;
                __u32 *val42 = LightPart42.lookup(&hash42);
                if (val42)
                    (*val42) += 1;
                __u32 *val52 = LightPart52.lookup(&hash52);
                if (val52)
                    (*val52) += 1;
                __u32 *val62 = LightPart62.lookup(&hash62);
                if (val62)
                    (*val62) += 1;
                __u32 *val72 = LightPart72.lookup(&hash72);
                if (val72)
                    (*val72) += 1;

                __u32 *val82 = LightPart82.lookup(&hash82);
                if (val82)
                    (*val82) += 1;
            }
        
        }
    }

uint32_t hash3 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 1234);
    __u32 pos3 = hash3 & (heavy_size - 1);

    struct Bucket *hpb3;
    struct Bucket *hpb3_init;
    // hpb3_init->posvote = 1;
    // hpb3_init->negvote = 0;
    // hpb3_init->flag == false;
    // hpb3_init->flow_id.dstIP = dstIP;
    // hpb3_init->flow_id.srcIP = srcIP;
    __u32 *hpf3;
    hpf3 = HeavyParts_flag3.lookup(&pos3);
    hpb3 = HeavyParts_buckets3.lookup(&pos3);

    // if (!hpb3)
    // {
    //     bpf_trace_printk("Invalid entry in the countsketch sketch");
    //     goto DROP;
    // }

    // bpf_probe_read_kernel();
    __u32 res3 = 0;
  
    if (hpf3)
    {
        if (hpb3)
        {
            if (*hpf3 == 0)
            {
                // hpf3 = HeavyParts_flag3.lookup_or_try_init(&pos, &one);
                *hpf3 = 1;
                // hpb3 = HeavyParts_buckets3.lookup_or_try_init(&pos, &hpb3_init);
                hpb3->posvote = 1;
                hpb3->negvote = 0;
                hpb3->flag == false;
                hpb3->flow_id.dstIP = dstIP;
                hpb3->flow_id.srcIP = srcIP;
            }
            else if (*hpf3 != 0)
            {
                if (hpb3->flow_id.srcIP == srcIP && hpb3->flow_id.dstIP == dstIP)
                {
                    hpb3->posvote++;
                }
                else
                {
                    hpb3->negvote++;
                    u_int64_t temp3 = hpb3->negvote / hpb3->posvote;
                    if (temp3 < lamda)
                    {
                        res3 = 1;
                    }
                    else
                    {
                        res3 = hpb3->posvote;
                        (*hpf3) = true;
                        hpb3->negvote = 1;
                        hpb3->posvote = 1;
                        uint32_t tmp3 = srcIP;
                        srcIP = hpb3->flow_id.srcIP;
                        hpb3->flow_id.srcIP = tmp3;
                        tmp3 = dstIP;
                        dstIP = hpb3->flow_id.dstIP;
                        hpb3->flow_id.dstIP = tmp3;
                    }
                }
            }
        
            if (res3 > 0)
            {
                // lp->update(srcIP, dstIP, status);

                uint32_t hash13 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 11);
                uint32_t hash23 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 22);
                uint32_t hash33 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 33);
                uint32_t hash43 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 44);
                uint32_t hash53 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 55);
                uint32_t hash63 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 66);
                uint32_t hash73 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 77);
                uint32_t hash83 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 88);
                __u32 pos13 = hash13 & (light_size_n - 1);
                __u32 pos23 = hash23 & (light_size_n - 1);
                __u32 pos33 = hash33 & (light_size_n - 1);
                __u32 pos43 = hash43 & (light_size_n - 1);
                __u32 pos53 = hash53 & (light_size_n - 1);
                __u32 pos63 = hash63 & (light_size_n - 1);
                __u32 pos73 = hash73 & (light_size_n - 1);
                __u32 pos83 = hash83 & (light_size_n - 1);

                // uint64_t j = two_tuple_sketch_hash(srcIP, dstIP, i, n); // crc32(buf, i + 1) % n;

                __u32 *val13 = LightPart13.lookup(&hash13);
                if (val13)
                    (*val13) += 1;

                __u32 *val23 = LightPart23.lookup(&hash23);
                if (val23)
                    (*val23) += 1;

                __u32 *val33 = LightPart33.lookup(&hash33);
                if (val33)
                    (*val33) += 1;
                __u32 *val43 = LightPart43.lookup(&hash43);
                if (val43)
                    (*val43) += 1;
                __u32 *val53 = LightPart53.lookup(&hash53);
                if (val53)
                    (*val53) += 1;
                __u32 *val63 = LightPart63.lookup(&hash63);
                if (val63)
                    (*val63) += 1;
                __u32 *val73 = LightPart73.lookup(&hash73);
                if (val73)
                    (*val73) += 1;

                __u32 *val83 = LightPart83.lookup(&hash83);
                if (val83)
                    (*val83) += 1;
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
