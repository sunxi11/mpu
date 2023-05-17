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

#include "common.h"
#include "xxhash32.h"
#include "murmurhash3.h"

#define ct_k 3
#define w_ct 589824
#define w_bf 262144
#define bf_k 3

//_Static_assert((COLUMNS & (COLUMNS - 1)) == 0, "COLUMNS must be a power of two");

// struct bloomfilter
// {
//     __u32 values[w_bf];
//     __u32 k;
// };

struct FRBucket
{
    uint64_t FlowXOR;
    uint32_t FlowCount;
    uint32_t PacketCount;
};

// struct countingtable
// {
//     struct FRBucket bucket[w_ct];
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

BPF_PERCPU_ARRAY(metadata, struct pkt_md, 1);
BPF_ARRAY(bloomfilters, __u32, 262144);
BPF_ARRAY(countingtables, struct FRBucket, 589824);
BPF_ARRAY(bloomfilters2, __u32, 262144);
BPF_ARRAY(countingtables2, struct FRBucket, 589824);
BPF_ARRAY(bloomfilters3, __u32, 262144);
BPF_ARRAY(countingtables3, struct FRBucket, 589824);
BPF_ARRAY(bloomfilters4, __u32, 262144);
BPF_ARRAY(countingtables4, struct FRBucket, 589824);
BPF_ARRAY(bloomfilters5, __u32, 262144);
BPF_ARRAY(countingtables5, struct FRBucket, 589824);
BPF_ARRAY(bloomfilters6, __u32, 262144);
BPF_ARRAY(countingtables6, struct FRBucket, 589824);
BPF_ARRAY(bloomfilters7, __u32, 262144);
BPF_ARRAY(countingtables7, struct FRBucket, 589824);

int xdp_prog1(struct CTXTYPE *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct eth_hdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        goto DROP;

    switch (eth->proto)
    {
    case htons(ETH_P_IP):
        break;
    default:
        return XDP_PASS;
    }

    struct pkt_5tuple pkt;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        goto DROP;

    pkt.src_ip = ip->saddr;
    pkt.dst_ip = ip->daddr;
    pkt.proto = ip->protocol;

    switch (ip->protocol)
    {
    case IPPROTO_TCP:
    {
        struct tcp_hdr *tcp = NULL;
        tcp = data + sizeof(struct eth_hdr) + sizeof(*ip);
        if (data + sizeof(struct eth_hdr) + sizeof(*ip) + sizeof(*tcp) > data_end)
            goto DROP;
        pkt.src_port = tcp->source;
        pkt.dst_port = tcp->dest;
        break;
    }
    case IPPROTO_UDP:
    {
        struct udphdr *udp = NULL;
        udp = data + sizeof(struct eth_hdr) + sizeof(*ip);
        if (data + sizeof(struct eth_hdr) + sizeof(*ip) + sizeof(*udp) > data_end)
            goto DROP;
        pkt.src_port = udp->source;
        pkt.dst_port = udp->dest;
        break;
    }
    default:
        goto DROP;
    }

    uint32_t zero = 0;
    struct pkt_md *md;

    md = metadata.lookup(&zero);
    if (!md)
    {
        bpf_trace_printk("Error! Invalid metadata.");
        goto DROP;
    }
    // bpf_trace_printk("-----------------------------------------");

    // zero = 0;
    // struct bloomfilter *bl;
    // bl = bloomfilters.lookup(&zero);

    // if (!bl)
    // {
    //     bpf_trace_printk("Invalid entry in the countsketch sketch");
    //     goto DROP;
    // }
    // bl->k = bf_k;

    // zero = 0;
    // struct countingtable *ct;
    // ct = countingtables.lookup(&zero);
    // if (!ct)
    // {
    //     bpf_trace_printk("Invalid entry in the countsketch sketch");
    //     goto DROP;
    // }
 bool res5 = true;
    bool res7 = true;
    __u64 len7 = sizeof(pkt);
    for (unsigned i = 0; i < bf_k; i++)
    {
        uint32_t hash7 = MurmurHash3_x86_32(&pkt, len7, i * i);
        __u32 target_idx7 = hash7 & (w_bf - 1);
        __u32 *val7 = bloomfilters7.lookup(&target_idx7);
        if (val7)
        { // 如果val7不是null
            if (*val7 == 0)
            {
                res7 = false;
                break;
            }
        }
    }

    if (res7 == false)
    {
        for (unsigned i = 0; i < bf_k; i++)
        {
            uint32_t hash7 = MurmurHash3_x86_32(&pkt, len7, i * i);
            __u32 target_idx7 = hash7 & (w_bf - 1);
            __u32 *val7 = bloomfilters7.lookup(&target_idx7);
            if (val7)
            { // 如果val7不是null
                (*val7) = 1;
            }
        }
    }

    uint64_t k17, k27;
    k17 = (uint64_t)pkt.src_ip;
    k27 = (uint64_t)pkt.dst_ip;
    uint64_t combined_k7 = (k17 << 32) + k27;

    for (unsigned i = 0; i < ct_k; i++)
    {
        uint32_t hash7 = MurmurHash3_x86_32(&pkt, len7, i * i);
        __u32 target_idx7 = hash7 & (w_ct - 1);
        struct FRBucket *val7 = countingtables7.lookup(&target_idx7);
        if (val7)
        { // 如果val7不是null
            if (res7 == false)
            {
                val7->FlowXOR ^= combined_k7;
                val7->FlowCount++;
            }
            val7->PacketCount++;
        }
    }
    bool res6 = true;
    __u64 len6 = sizeof(pkt);
    for (unsigned i = 0; i < bf_k; i++)
    {
        uint32_t hash6 = MurmurHash3_x86_32(&pkt, len6, i * i);
        __u32 target_idx6 = hash6 & (w_bf - 1);
        __u32 *val6 = bloomfilters6.lookup(&target_idx6);
        if (val6)
        { // 如果val6不是null
            if (*val6 == 0)
            {
                res6 = false;
                break;
            }
        }
    }

    if (res6 == false)
    {
        for (unsigned i = 0; i < bf_k; i++)
        {
            uint32_t hash6 = MurmurHash3_x86_32(&pkt, len6, i * i);
            __u32 target_idx6 = hash6 & (w_bf - 1);
            __u32 *val6 = bloomfilters6.lookup(&target_idx6);
            if (val6)
            { // 如果val6不是null
                (*val6) = 1;
            }
        }
    }

    uint64_t k16, k26;
    k16 = (uint64_t)pkt.src_ip;
    k26 = (uint64_t)pkt.dst_ip;
    uint64_t combined_k6 = (k16 << 32) + k26;

    for (unsigned i = 0; i < ct_k; i++)
    {
        uint32_t hash6 = MurmurHash3_x86_32(&pkt, len6, i * i);
        __u32 target_idx6 = hash6 & (w_ct - 1);
        struct FRBucket *val6 = countingtables6.lookup(&target_idx6);
        if (val6)
        { // 如果val6不是null
            if (res6 == false)
            {
                val6->FlowXOR ^= combined_k6;
                val6->FlowCount++;
            }
            val6->PacketCount++;
        }
    }
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
    bool res4 = true;
    __u64 len4 = sizeof(pkt);
    for (unsigned i = 0; i < bf_k; i++)
    {
        uint32_t hash4 = MurmurHash3_x86_32(&pkt, len4, i * i);
        __u32 target_idx4 = hash4 & (w_bf - 1);
        __u32 *val4 = bloomfilters4.lookup(&target_idx4);
        if (val4)
        { // 如果val4不是null
            if (*val4 == 0)
            {
                res4 = false;
                break;
            }
        }
    }

    if (res4 == false)
    {
        for (unsigned i = 0; i < bf_k; i++)
        {
            uint32_t hash4 = MurmurHash3_x86_32(&pkt, len4, i * i);
            __u32 target_idx4 = hash4 & (w_bf - 1);
            __u32 *val4 = bloomfilters4.lookup(&target_idx4);
            if (val4)
            { // 如果val4不是null
                (*val4) = 1;
            }
        }
    }

    uint64_t k14, k24;
    k14 = (uint64_t)pkt.src_ip;
    k24 = (uint64_t)pkt.dst_ip;
    uint64_t combined_k4 = (k14 << 32) + k24;

    for (unsigned i = 0; i < ct_k; i++)
    {
        uint32_t hash4 = MurmurHash3_x86_32(&pkt, len4, i * i);
        __u32 target_idx4 = hash4 & (w_ct - 1);
        struct FRBucket *val4 = countingtables4.lookup(&target_idx4);
        if (val4)
        { // 如果val4不是null
            if (res4 == false)
            {
                val4->FlowXOR ^= combined_k4;
                val4->FlowCount++;
            }
            val4->PacketCount++;
        }
    }
    bool res3 = true;
    __u64 len3 = sizeof(pkt);
    for (unsigned i = 0; i < bf_k; i++)
    {
        uint32_t hash3 = MurmurHash3_x86_32(&pkt, len3, i * i);
        __u32 target_idx3 = hash3 & (w_bf - 1);
        __u32 *val3 = bloomfilters3.lookup(&target_idx3);
        if (val3)
        { // 如果val3不是null
            if (*val3 == 0)
            {
                res3 = false;
                break;
            }
        }
    }

    if (res3 == false)
    {
        for (unsigned i = 0; i < bf_k; i++)
        {
            uint32_t hash3 = MurmurHash3_x86_32(&pkt, len3, i * i);
            __u32 target_idx3 = hash3 & (w_bf - 1);
            __u32 *val3 = bloomfilters3.lookup(&target_idx3);
            if (val3)
            { // 如果val3不是null
                (*val3) = 1;
            }
        }
    }

    uint64_t k13, k23;
    k13 = (uint64_t)pkt.src_ip;
    k23 = (uint64_t)pkt.dst_ip;
    uint64_t combined_k3 = (k13 << 32) + k23;

    for (unsigned i = 0; i < ct_k; i++)
    {
        uint32_t hash3 = MurmurHash3_x86_32(&pkt, len3, i * i);
        __u32 target_idx3 = hash3 & (w_ct - 1);
        struct FRBucket *val3 = countingtables3.lookup(&target_idx3);
        if (val3)
        { // 如果val3不是null
            if (res3 == false)
            {
                val3->FlowXOR ^= combined_k3;
                val3->FlowCount++;
            }
            val3->PacketCount++;
        }
    }

    bool res2 = true;
    __u64 len2 = sizeof(pkt);
    for (unsigned i = 0; i < bf_k; i++)
    {
        uint32_t hash2 = MurmurHash3_x86_32(&pkt, len2, i * i);
        __u32 target_idx2 = hash2 & (w_bf - 1);
        __u32 *val2 = bloomfilters2.lookup(&target_idx2);
        if (val2)
        { // 如果val2不是null
            if (*val2 == 0)
            {
                res2 = false;
                break;
            }
        }
    }

    if (res2 == false)
    {
        for (unsigned i = 0; i < bf_k; i++)
        {
            uint32_t hash2 = MurmurHash3_x86_32(&pkt, len2, i * i);
            __u32 target_idx2 = hash2 & (w_bf - 1);
            __u32 *val2 = bloomfilters2.lookup(&target_idx2);
            if (val2)
            { // 如果val2不是null
                (*val2) = 1;
            }
        }
    }

    uint64_t k12, k22;
    k12 = (uint64_t)pkt.src_ip;
    k22 = (uint64_t)pkt.dst_ip;
    uint64_t combined_k2 = (k12 << 32) + k22;

    for (unsigned i = 0; i < ct_k; i++)
    {
        uint32_t hash2 = MurmurHash3_x86_32(&pkt, len2, i * i);
        __u32 target_idx2 = hash2 & (w_ct - 1);
        struct FRBucket *val2 = countingtables2.lookup(&target_idx2);
        if (val2)
        { // 如果val2不是null
            if (res2 == false)
            {
                val2->FlowXOR ^= combined_k2;
                val2->FlowCount++;
            }
            val2->PacketCount++;
        }
    }
    bool res = true;
    __u64 len = sizeof(pkt);
    for (unsigned i = 0; i < bf_k; i++)
    {
        uint32_t hash = MurmurHash3_x86_32(&pkt, len, i * i);
        __u32 target_idx = hash & (w_bf - 1);
        __u32 *val = bloomfilters.lookup(&target_idx);
        if (val)
        { // 如果val不是null
            if (*val == 0)
            {
                res = false;
                break;
            }
        }
    }

    if (res == false)
    {
        for (unsigned i = 0; i < bf_k; i++)
        {
            uint32_t hash = MurmurHash3_x86_32(&pkt, len, i * i);
            __u32 target_idx = hash & (w_bf - 1);
            __u32 *val = bloomfilters.lookup(&target_idx);
            if (val)
            { // 如果val不是null
                (*val) = 1;
            }
        }
    }

    uint64_t k1, k2;
    k1 = (uint64_t)pkt.src_ip;
    k2 = (uint64_t)pkt.dst_ip;
    uint64_t combined_k = (k1 << 32) + k2;

    for (unsigned i = 0; i < ct_k; i++)
    {
        uint32_t hash = MurmurHash3_x86_32(&pkt, len, i * i);
        __u32 target_idx = hash & (w_ct - 1);
        struct FRBucket *val = countingtables.lookup(&target_idx);
        if (val)
        { // 如果val不是null
            if (res == false)
            {
                val->FlowXOR ^= combined_k;
                val->FlowCount++;
            }
            val->PacketCount++;
        }
    }

    uint32_t index = 0;
    md = metadata.lookup(&index);
    if (md)
    {
        NO_TEAR_INC(md->drop_cnt);
    }
    return bpf_redirect(5, 0);

DROP:;
    return XDP_DROP;
}

// This is only used when the action is redirect
int xdp_dummy(struct xdp_md *ctx)
{
    return XDP_PASS;
}
