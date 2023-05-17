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
#define UPDATE_PROBABILITY 0.5
#define ROWS 8
#define COLUMNS 327680

// _Static_assert((COLUMNS & (COLUMNS - 1)) == 0, "COLUMNS must be a power of two");

// struct countsketch
// {
//     __u32 values[ROWS][COLUMNS];
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


BPF_ARRAY(countsketch1, __u32, 327680);
BPF_ARRAY(countsketch2, __u32, 327680);
BPF_ARRAY(countsketch3, __u32, 327680);
BPF_ARRAY(countsketch4, __u32, 327680);
BPF_ARRAY(countsketch5, __u32, 327680);
BPF_ARRAY(countsketch6, __u32, 327680);
BPF_ARRAY(countsketch7, __u32, 327680);
BPF_ARRAY(countsketch8, __u32, 327680);
// BPF_PERCPU_ARRAY(countsketch, struct countsketch, 1);

// add element and determine count
// static void __always_inline nitrosketch_add(struct countsketch *cm, void *element, __u64 len, uint32_t row_to_update)
// {
//     // u32 layerhash = hashlittle(element, len, 0xffffffeee);
//     uint32_t hash;

//     if (row_to_update >= ROWS)
//     {
//         return;
//     }

//     hash = MurmurHash3_x86_32(element, len, row_to_update * row_to_update);
//     __u32 target_idx = hash & (COLUMNS - 1);
//     if (CHECK_BIT(hash, 31))
//     {
//         cm->values[row_to_update][target_idx]++;
//         // __sync_fetch_and_add(&cm->values[row_to_update][target_idx], 1);
//     }
//     else
//     {
//         cm->values[row_to_update][target_idx]--;
//         // __sync_fetch_and_sub(&cm->values[row_to_update][target_idx], 1);
//     }
// }

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

    // struct countsketch *cm;
    // cm = countsketch.lookup(&zero);

    // if (!cm)
    // {
    //     bpf_trace_printk("Invalid entry in the countsketch sketch");
    //     goto DROP;
    // }

    // for (int i = 0; i < ROWS; i++)
    // {
    //     u32 rand = bpf_get_prandom_u32();
    //     if (rand < UPDATE_PROBABILITY)
    //     {
    //         // Here we start updating the sketch
    //         nitrosketch_add(cm, &pkt, sizeof(pkt), i);
    //     }
    // }

    u32 rand1 = bpf_get_prandom_u32();
    if (rand1 < UPDATE_PROBABILITY)
    {
        // Here we start updating the sketch
        __u32 hash1 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 1);
        __u32 target_idx1 = hash1 & (COLUMNS - 1);
        // We should probably split the coin here to swap the sign for the countsketch implementation
        // 小于2^n的，CHECK_BIT(hash, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash, n)为0
        __u32 *val1 = countsketch1.lookup(&target_idx1);
        if (val1)
        {
            if (CHECK_BIT(hash1, 31))
            {

                (*val1)++;
            }
            else
            {
                (*val1)--;
            }
        }
    }
    u32 rand2 = bpf_get_prandom_u32();
    if (rand2 < UPDATE_PROBABILITY)
    {
        // Here we start updating the sketch
        __u32 hash2 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 2);
        __u32 target_idx2 = hash2 & (COLUMNS - 1);
        // We should probably split the coin here to swap the sign for the countsketch implementation
        // 小于2^n的，CHECK_BIT(hash, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash, n)为0
        __u32 *val2 = countsketch2.lookup(&target_idx2);
        if (val2)
        {
            if (CHECK_BIT(hash2, 31))
            {

                (*val2)++;
            }
            else
            {
                (*val2)--;
            }
        }
    }

    u32 rand3 = bpf_get_prandom_u32();
    if (rand3 < UPDATE_PROBABILITY)
    {
        // Here we start updating the sketch
        __u32 hash3 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 3);
        __u32 target_idx3 = hash3 & (COLUMNS - 1);
        // We should probably split the coin here to swap the sign for the countsketch implementation
        // 小于2^n的，CHECK_BIT(hash, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash, n)为0
        __u32 *val3 = countsketch3.lookup(&target_idx3);
        if (val3)
        {
            if (CHECK_BIT(hash3, 31))
            {

                (*val3)++;
            }
            else
            {
                (*val3)--;
            }
        }
    }

    u32 rand4 = bpf_get_prandom_u32();
    if (rand4 < UPDATE_PROBABILITY)
    {
        // Here we start updating the sketch
        __u32 hash4 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 4);
        __u32 target_idx4 = hash4 & (COLUMNS - 1);
        // We should probably split the coin here to swap the sign for the countsketch implementation
        // 小于2^n的，CHECK_BIT(hash, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash, n)为0
        __u32 *val4 = countsketch4.lookup(&target_idx4);
        if (val4)
        {
            if (CHECK_BIT(hash4, 31))
            {

                (*val4)++;
            }
            else
            {
                (*val4)--;
            }
        }
    }

    u32 rand5 = bpf_get_prandom_u32();
    if (rand5 < UPDATE_PROBABILITY)
    {
        // Here we start updating the sketch
        __u32 hash5 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 5);
        __u32 target_idx5 = hash5 & (COLUMNS - 1);
        // We should probably split the coin here to swap the sign for the countsketch implementation
        // 小于2^n的，CHECK_BIT(hash, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash, n)为0
        __u32 *val5 = countsketch5.lookup(&target_idx5);
        if (val5)
        {
            if (CHECK_BIT(hash5, 31))
            {

                (*val5)++;
            }
            else
            {
                (*val5)--;
            }
        }
    }


    u32 rand6 = bpf_get_prandom_u32();
    if (rand6 < UPDATE_PROBABILITY)
    {
        // Here we start updating the sketch
        __u32 hash6 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 6);
        __u32 target_idx6 = hash6 & (COLUMNS - 1);
        // We should probably split the coin here to swap the sign for the countsketch implementation
        // 小于2^n的，CHECK_BIT(hash, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash, n)为0
        __u32 *val6 = countsketch6.lookup(&target_idx6);
        if (val6)
        {
            if (CHECK_BIT(hash6, 31))
            {

                (*val6)++;
            }
            else
            {
                (*val6)--;
            }
        }
    }

    u32 rand7 = bpf_get_prandom_u32();
    if (rand7 < UPDATE_PROBABILITY)
    {
        // Here we start updating the sketch
        __u32 hash7 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 7);
        __u32 target_idx7 = hash7 & (COLUMNS - 1);
        // We should probably split the coin here to swap the sign for the countsketch implementation
        // 小于2^n的，CHECK_BIT(hash, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash, n)为0
        __u32 *val7 = countsketch7.lookup(&target_idx7);
        if (val7)
        {
            if (CHECK_BIT(hash7, 31))
            {

                (*val7)++;
            }
            else
            {
                (*val7)--;
            }
        }
    }
     u32 rand8 = bpf_get_prandom_u32();
    if (rand8 < UPDATE_PROBABILITY)
    {
        // Here we start updating the sketch
        __u32 hash8 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 8);
        __u32 target_idx8 = hash8 & (COLUMNS - 1);
        // We should probably split the coin here to swap the sign for the countsketch implementation
        // 小于2^n的，CHECK_BIT(hash, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash, n)为0
        __u32 *val8 = countsketch8.lookup(&target_idx8);
        if (val8)
        {
            if (CHECK_BIT(hash8, 31))
            {

                (*val8)++;
            }
            else
            {
                (*val8)--;
            }
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
