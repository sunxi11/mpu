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
#include "fasthash.h"
#include "murmurhash3.h"
#include "xxhash32.h"

#define COLUMNS 327680
#define HASHFN_N 4
#define COLUMNS3 2621440
#define k 4
#define heavy_size 100000
#define light_size _LIGHT_SIZE
#define light_size_m 8
#define light_size_n 245760
#define lamda 8
#define ct_k 3
#define w_ct 589824
#define w_bf 262144
#define bf_k 3
//#define COLUMNS6 2621440
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
struct FRBucket
{
    uint64_t FlowXOR;
    uint32_t FlowCount;
    uint32_t PacketCount;
};
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
BPF_ARRAY(countmin1, __u32, 327680);
BPF_ARRAY(countmin2, __u32, 327680);
BPF_ARRAY(countmin3, __u32, 327680);
BPF_ARRAY(countmin4, __u32, 327680);
BPF_ARRAY(countmin5, __u32, 327680);
BPF_ARRAY(countmin6, __u32, 327680);
BPF_ARRAY(countmin7, __u32, 327680);
BPF_ARRAY(countmin8, __u32, 327680);

BPF_ARRAY(countSketch21, __u32, 327680);
BPF_ARRAY(countSketch22, __u32, 327680);
BPF_ARRAY(countSketch23, __u32, 327680);
BPF_ARRAY(countSketch24, __u32, 327680);
BPF_ARRAY(countSketch25, __u32, 327680);
BPF_ARRAY(countSketch26, __u32, 327680);
BPF_ARRAY(countSketch27, __u32, 327680);
BPF_ARRAY(countSketch28, __u32, 327680);

BPF_ARRAY(countingbloomfilter3, __u32, 2621440);

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

BPF_ARRAY(bloomfilters5, __u32, 262144);
BPF_ARRAY(countingtables5, struct FRBucket, 589824);

//BPF_ARRAY(countSketch61, __u32, 2621440);
//BPF_ARRAY(countSketch62, __u32, 2621440);
//BPF_ARRAY(countSketch63, __u32, 2621440);
//BPF_ARRAY(countSketch64, __u32, 2621440);
//BPF_ARRAY(countSketch65, __u32, 2621440);
//BPF_HASH(fastpath6, struct pkt_5tuple, __u64, 10000);


// static void FORCE_INLINE countmin_add(struct countmin *cm, void *element, __u64 len, __u32 id)
// {
//     // Calculate just a single hash and re-use it to update and query the sketch
//     uint32_t hash = MurmurHash3_x86_32(element, len, id * id);
//     __u32 target_idx = hash & (COLUMNS - 1);
//     NO_TEAR_ADD(cm->values[target_idx], 1);

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
    uint32_t one = 1;
    uint32_t two = 2;
    // struct countmin *cm1, *cm3, *cm2;

    uint32_t hash1 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 11);
    uint32_t hash2 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 22);
    uint32_t hash3 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 33);
    uint32_t hash4 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 44);
    uint32_t hash5 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 55);
    uint32_t hash6 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 66);
    uint32_t hash7 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 77);
    uint32_t hash8 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 88);
    __u32 target_idx1 = hash1 & (COLUMNS - 1);
    __u32 target_idx2 = hash2 & (COLUMNS - 1);
    __u32 target_idx3 = hash3 & (COLUMNS - 1);
    __u32 target_idx4 = hash4 & (COLUMNS - 1);
    __u32 target_idx5 = hash5 & (COLUMNS - 1);
    __u32 target_idx6 = hash6 & (COLUMNS - 1);
    __u32 target_idx7 = hash7 & (COLUMNS - 1);
    __u32 target_idx8 = hash8 & (COLUMNS - 1);

    __u32 *val1 = countmin1.lookup(&target_idx1);
    if (val1)
        lock_xadd(val1, 1);

    __u32 *val2 = countmin2.lookup(&target_idx2);
    if (val2)
        lock_xadd(val2, 1);

    __u32 *val3 = countmin3.lookup(&target_idx3);
    if (val3)
        lock_xadd(val3, 1);
    __u32 *val4 = countmin4.lookup(&target_idx4);
    if (val4)
        lock_xadd(val4, 1);
    __u32 *val5 = countmin5.lookup(&target_idx5);
    if (val5)
        lock_xadd(val5, 1);
    __u32 *val6 = countmin6.lookup(&target_idx6);
    if (val6)
        lock_xadd(val6, 1);
    __u32 *val7 = countmin7.lookup(&target_idx7);
    if (val7)
        lock_xadd(val7, 1);
    __u32 *val8 = countmin8.lookup(&target_idx8);
    if (val8)
        lock_xadd(val8, 1);

    // countmin1.update(&target_idx1, 1);
    // countmin2.update(&target_idx2, 1);
    // countmin3.update(&target_idx3, 1);

    // cm1 = countmin.lookup(&zero);
    // cm2 = countmin.lookup(&one);
    // cm3 = countmin.lookup(&two);

    // if (!cm1)
    // {
    //     bpf_trace_printk("Invalid entry in the countmin sketch");
    //     goto DROP;
    // }

    // countmin_add(cm1, &pkt, sizeof(pkt), 0);
    // countmin_add(cm2, &pkt, sizeof(pkt), 1);
    // countmin_add(cm3, &pkt, sizeof(pkt), 2);
  __u32 hash21 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 0x12345678);
    __u32 target_idx21 = hash21 & (COLUMNS - 1);
    // We should probably split the coin here to swap the sign for the countsketch implementation
    // 小于2^n的，CHECK_BIT(hash2, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash2, n)为0
    __u32 *val21 = countSketch21.lookup(&target_idx21);
    if (val21)
    {
        if (CHECK_BIT(hash21, 31))
        {

            (*val21)++;
        }
        else
        {
            (*val21)--;
        }
    }

    __u32 hash22 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 0x6ad611c4);
    __u32 target_idx22 = hash22 & (COLUMNS - 1);
    // We should probably split the coin here to swap the sign for the countsketch implementation
    // 小于2^n的，CHECK_BIT(hash2, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash2, n)为0
    __u32 *val22 = countSketch22.lookup(&target_idx22);
    if (val22)
    {
        if (CHECK_BIT(hash22, 31))
        {

            (*val22)++;
        }
        else
        {
            (*val22)--;
        }
    }
    __u32 hash23 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 3333);
    __u32 target_idx23 = hash23 & (COLUMNS - 1);
    // We should probably split the coin here to swap the sign for the countsketch implementation
    // 小于2^n的，CHECK_BIT(hash2, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash2, n)为0
    __u32 *val23 = countSketch23.lookup(&target_idx23);
    if (val23)
    {
        if (CHECK_BIT(hash23, 31))
        {

            (*val23)++;
        }
        else
        {
            (*val23)--;
        }
    }

    __u32 hash24 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 444);
    __u32 target_idx24 = hash24 & (COLUMNS - 1);
    // We should probably split the coin here to swap the sign for the countsketch implementation
    // 小于2^n的，CHECK_BIT(hash2, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash2, n)为0
    __u32 *val24 = countSketch24.lookup(&target_idx24);
    if (val24)
    {
        if (CHECK_BIT(hash24, 31))
        {

            (*val24)++;
        }
        else
        {
            (*val24)--;
        }
    }

    __u32 hash25 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 555);
    __u32 target_idx25 = hash25 & (COLUMNS - 1);
    // We should probably split the coin here to swap the sign for the countsketch implementation
    // 小于2^n的，CHECK_BIT(hash2, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash2, n)为0
    __u32 *val25 = countSketch25.lookup(&target_idx25);
    if (val25)
    {
        if (CHECK_BIT(hash25, 31))
        {

            (*val25)++;
        }
        else
        {
            (*val25)--;
        }
    }

    __u32 hash26 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 666);
    __u32 target_idx26 = hash26 & (COLUMNS - 1);
    // We should probably split the coin here to swap the sign for the countsketch implementation
    // 小于2^n的，CHECK_BIT(hash2, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash2, n)为0
    __u32 *val26 = countSketch26.lookup(&target_idx26);
    if (val26)
    {
        if (CHECK_BIT(hash26, 31))
        {

            (*val26)++;
        }
        else
        {
            (*val26)--;
        }
    }

    __u32 hash27 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 777);
    __u32 target_idx27 = hash27 & (COLUMNS - 1);
    // We should probably split the coin here to swap the sign for the countsketch implementation
    // 小于2^n的，CHECK_BIT(hash2, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash2, n)为0
    __u32 *val27 = countSketch27.lookup(&target_idx27);
    if (val27)
    {
        if (CHECK_BIT(hash27, 31))
        {

            (*val27)++;
        }
        else
        {
            (*val27)--;
        }
    }

    __u32 hash28 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 888);
    __u32 target_idx28 = hash28 & (COLUMNS - 1);
    // We should probably split the coin here to swap the sign for the countsketch implementation
    // 小于2^n的，CHECK_BIT(hash2, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash2, n)为0
    __u32 *val28 = countSketch28.lookup(&target_idx28);
    if (val28)
    {
        if (CHECK_BIT(hash28, 31))
        {

            (*val28)++;
        }
        else
        {
            (*val28)--;
        }
    }
    for (int i = 0; i < k; i++)
    {
        uint32_t hash3 = MurmurHash3_x86_32(&pkt, sizeof(pkt), i * i);
        __u32 target_idx3 = hash3 & (COLUMNS3 - 1);
        if (CHECK_BIT(hash3, 31))
        {
            __u32 *val3 = countingbloomfilter3.lookup(&target_idx3);
            if (val3)
            {
                (*val3) += 1;
            }
        }
    }
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
    //     bpf_trace_printk("Inval4id entry in the countsketch sketch");
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

                uint32_t hash41 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 11);
                uint32_t hash42 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 22);
                uint32_t hash43 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 33);
                uint32_t hash44 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 44);
                uint32_t hash45 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 55);
                uint32_t hash46 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 66);
                uint32_t hash47 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 77);
                uint32_t hash48 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 88);
                __u32 pos1 = hash41 & (light_size_n - 1);
                __u32 pos2 = hash42 & (light_size_n - 1);
                __u32 pos3 = hash43 & (light_size_n - 1);
                __u32 pos4 = hash44 & (light_size_n - 1);
                __u32 pos5 = hash45 & (light_size_n - 1);
                __u32 pos6 = hash46 & (light_size_n - 1);
                __u32 pos7 = hash47 & (light_size_n - 1);
                __u32 pos8 = hash48 & (light_size_n - 1);

                // uint64_t j = two_tuple_sketch_hash(srcIP, dstIP, i, n); // crc32(buf, i + 1) % n;

                __u32 *val41 = LightPart1.lookup(&hash41);
                if (val41)
                    (*val41) += 1;

                __u32 *val42 = LightPart2.lookup(&hash42);
                if (val42)
                    (*val42) += 1;

                __u32 *val43 = LightPart3.lookup(&hash43);
                if (val43)
                    (*val43) += 1;
                __u32 *val44 = LightPart4.lookup(&hash44);
                if (val44)
                    (*val44) += 1;
                __u32 *val45 = LightPart5.lookup(&hash45);
                if (val45)
                    (*val45) += 1;
                __u32 *val46 = LightPart6.lookup(&hash46);
                if (val46)
                    (*val46) += 1;
                __u32 *val47 = LightPart7.lookup(&hash47);
                if (val47)
                    (*val47) += 1;

                __u32 *val48 = LightPart8.lookup(&hash48);
                if (val48)
                    (*val48) += 1;
            }
        
        }
    }
    bool res5 = true;
    __u64 len5 = sizeof(pkt);
    for (unsigned i = 0; i < bf_k; i++)
    {
        uint32_t hash5 = MurmurHash3_x86_32(&pkt, len5, i * i);
        __u32 target_idx5 = hash5 & (w_bf - 1);
        __u32 *val5 = bloomfilters5.lookup(&target_idx5);
        if (val5)
        { // 如果val5不是null
            if (*val5 == 0)
            {
                res5 = false;
                break;
            }
        }
    }

    if (res5 == false)
    {
        for (unsigned i = 0; i < bf_k; i++)
        {
            uint32_t hash5 = MurmurHash3_x86_32(&pkt, len5, i * i);
            __u32 target_idx5 = hash5 & (w_bf - 1);
            __u32 *val5 = bloomfilters5.lookup(&target_idx5);
            if (val5)
            { // 如果val5不是null
                (*val5) = 1;
            }
        }
    }

    uint64_t k15, k25;
    k15 = (uint64_t)pkt.src_ip;
    k25 = (uint64_t)pkt.dst_ip;
    uint64_t combined_k5 = (k15 << 32) + k25;

    for (unsigned i = 0; i < ct_k; i++)
    {
        uint32_t hash5 = MurmurHash3_x86_32(&pkt, len5, i * i);
        __u32 target_idx5 = hash5 & (w_ct - 1);
        struct FRBucket *val5 = countingtables5.lookup(&target_idx5);
        if (val5)
        { // 如果val5不是null
            if (res5 == false)
            {
                val5->FlowXOR ^= combined_k5;
                val5->FlowCount++;
            }
            val5->PacketCount++;
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
