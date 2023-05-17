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
BPF_ARRAY(countsketch21, __u32, 327680);
BPF_ARRAY(countsketch22, __u32, 327680);
BPF_ARRAY(countsketch23, __u32, 327680);
BPF_ARRAY(countsketch24, __u32, 327680);
BPF_ARRAY(countsketch25, __u32, 327680);
BPF_ARRAY(countsketch26, __u32, 327680);
BPF_ARRAY(countsketch27, __u32, 327680);
BPF_ARRAY(countsketch28, __u32, 327680);
BPF_ARRAY(countsketch31, __u32, 327680);
BPF_ARRAY(countsketch32, __u32, 327680);
BPF_ARRAY(countsketch33, __u32, 327680);
BPF_ARRAY(countsketch34, __u32, 327680);
BPF_ARRAY(countsketch35, __u32, 327680);
BPF_ARRAY(countsketch36, __u32, 327680);
BPF_ARRAY(countsketch37, __u32, 327680);
BPF_ARRAY(countsketch38, __u32, 327680);

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

    u32 rand31 = bpf_get_prandom_u32();
    if (rand31 < UPDATE_PROBABILITY)
    {
        // Here we start updating the sketch
        __u32 hash31 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 1);
        __u32 target_idx31 = hash31 & (COLUMNS - 1);
        // We should probably split the coin here to swap the sign for the countsketch3 implementation
        // 小于2^n的，CHECK_BIT(hash3, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash3, n)为0
        __u32 *val31 = countsketch31.lookup(&target_idx31);
        if (val31)
        {
            if (CHECK_BIT(hash31, 31))
            {

                (*val31)++;
            }
            else
            {
                (*val31)--;
            }
        }
    }
    u32 rand32 = bpf_get_prandom_u32();
    if (rand32 < UPDATE_PROBABILITY)
    {
        // Here we start updating the sketch
        __u32 hash32 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 2);
        __u32 target_idx32 = hash32 & (COLUMNS - 1);
        // We should probably split the coin here to swap the sign for the countsketch3 implementation
        // 小于2^n的，CHECK_BIT(hash3, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash3, n)为0
        __u32 *val32 = countsketch32.lookup(&target_idx32);
        if (val32)
        {
            if (CHECK_BIT(hash32, 31))
            {

                (*val32)++;
            }
            else
            {
                (*val32)--;
            }
        }
    }

    u32 rand33 = bpf_get_prandom_u32();
    if (rand33 < UPDATE_PROBABILITY)
    {
        // Here we start updating the sketch
        __u32 hash33 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 3);
        __u32 target_idx33 = hash33 & (COLUMNS - 1);
        // We should probably split the coin here to swap the sign for the countsketch3 implementation
        // 小于2^n的，CHECK_BIT(hash3, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash3, n)为0
        __u32 *val33 = countsketch33.lookup(&target_idx33);
        if (val33)
        {
            if (CHECK_BIT(hash33, 31))
            {

                (*val33)++;
            }
            else
            {
                (*val33)--;
            }
        }
    }

    u32 rand34 = bpf_get_prandom_u32();
    if (rand34 < UPDATE_PROBABILITY)
    {
        // Here we start updating the sketch
        __u32 hash34 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 4);
        __u32 target_idx34 = hash34 & (COLUMNS - 1);
        // We should probably split the coin here to swap the sign for the countsketch3 implementation
        // 小于2^n的，CHECK_BIT(hash3, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash3, n)为0
        __u32 *val34 = countsketch34.lookup(&target_idx34);
        if (val34)
        {
            if (CHECK_BIT(hash34, 31))
            {

                (*val34)++;
            }
            else
            {
                (*val34)--;
            }
        }
    }

    u32 rand35 = bpf_get_prandom_u32();
    if (rand35 < UPDATE_PROBABILITY)
    {
        // Here we start updating the sketch
        __u32 hash35 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 5);
        __u32 target_idx35 = hash35 & (COLUMNS - 1);
        // We should probably split the coin here to swap the sign for the countsketch3 implementation
        // 小于2^n的，CHECK_BIT(hash3, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash3, n)为0
        __u32 *val35 = countsketch35.lookup(&target_idx35);
        if (val35)
        {
            if (CHECK_BIT(hash35, 31))
            {

                (*val35)++;
            }
            else
            {
                (*val35)--;
            }
        }
    }


    u32 rand36 = bpf_get_prandom_u32();
    if (rand36 < UPDATE_PROBABILITY)
    {
        // Here we start updating the sketch
        __u32 hash36 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 6);
        __u32 target_idx36 = hash36 & (COLUMNS - 1);
        // We should probably split the coin here to swap the sign for the countsketch3 implementation
        // 小于2^n的，CHECK_BIT(hash3, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash3, n)为0
        __u32 *val36 = countsketch36.lookup(&target_idx36);
        if (val36)
        {
            if (CHECK_BIT(hash36, 31))
            {

                (*val36)++;
            }
            else
            {
                (*val36)--;
            }
        }
    }

    u32 rand37 = bpf_get_prandom_u32();
    if (rand37 < UPDATE_PROBABILITY)
    {
        // Here we start updating the sketch
        __u32 hash37 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 7);
        __u32 target_idx37 = hash37 & (COLUMNS - 1);
        // We should probably split the coin here to swap the sign for the countsketch3 implementation
        // 小于2^n的，CHECK_BIT(hash3, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash3, n)为0
        __u32 *val37 = countsketch37.lookup(&target_idx37);
        if (val37)
        {
            if (CHECK_BIT(hash37, 31))
            {

                (*val37)++;
            }
            else
            {
                (*val37)--;
            }
        }
    }
     u32 rand38 = bpf_get_prandom_u32();
    if (rand38 < UPDATE_PROBABILITY)
    {
        // Here we start updating the sketch
        __u32 hash38 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 8);
        __u32 target_idx38 = hash38 & (COLUMNS - 1);
        // We should probably split the coin here to swap the sign for the countsketch3 implementation
        // 小于2^n的，CHECK_BIT(hash3, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash3, n)为0
        __u32 *val38 = countsketch38.lookup(&target_idx38);
        if (val38)
        {
            if (CHECK_BIT(hash38, 31))
            {

                (*val38)++;
            }
            else
            {
                (*val38)--;
            }
        }
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
    u32 rand21 = bpf_get_prandom_u32();
    if (rand21 < UPDATE_PROBABILITY)
    {
        // Here we start updating the sketch
        __u32 hash21 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 1);
        __u32 target_idx21 = hash21 & (COLUMNS - 1);
        // We should probably split the coin here to swap the sign for the countsketch2 implementation
        // 小于2^n的，CHECK_BIT(hash2, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash2, n)为0
        __u32 *val21 = countsketch21.lookup(&target_idx21);
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
    }
    u32 rand22 = bpf_get_prandom_u32();
    if (rand22 < UPDATE_PROBABILITY)
    {
        // Here we start updating the sketch
        __u32 hash22 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 2);
        __u32 target_idx22 = hash22 & (COLUMNS - 1);
        // We should probably split the coin here to swap the sign for the countsketch2 implementation
        // 小于2^n的，CHECK_BIT(hash2, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash2, n)为0
        __u32 *val22 = countsketch22.lookup(&target_idx22);
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
    }

    u32 rand23 = bpf_get_prandom_u32();
    if (rand23 < UPDATE_PROBABILITY)
    {
        // Here we start updating the sketch
        __u32 hash23 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 3);
        __u32 target_idx23 = hash23 & (COLUMNS - 1);
        // We should probably split the coin here to swap the sign for the countsketch2 implementation
        // 小于2^n的，CHECK_BIT(hash2, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash2, n)为0
        __u32 *val23 = countsketch23.lookup(&target_idx23);
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
    }

    u32 rand24 = bpf_get_prandom_u32();
    if (rand24 < UPDATE_PROBABILITY)
    {
        // Here we start updating the sketch
        __u32 hash24 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 4);
        __u32 target_idx24 = hash24 & (COLUMNS - 1);
        // We should probably split the coin here to swap the sign for the countsketch2 implementation
        // 小于2^n的，CHECK_BIT(hash2, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash2, n)为0
        __u32 *val24 = countsketch24.lookup(&target_idx24);
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
    }

    u32 rand25 = bpf_get_prandom_u32();
    if (rand25 < UPDATE_PROBABILITY)
    {
        // Here we start updating the sketch
        __u32 hash25 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 5);
        __u32 target_idx25 = hash25 & (COLUMNS - 1);
        // We should probably split the coin here to swap the sign for the countsketch2 implementation
        // 小于2^n的，CHECK_BIT(hash2, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash2, n)为0
        __u32 *val25 = countsketch25.lookup(&target_idx25);
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
    }


    u32 rand26 = bpf_get_prandom_u32();
    if (rand26 < UPDATE_PROBABILITY)
    {
        // Here we start updating the sketch
        __u32 hash26 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 6);
        __u32 target_idx26 = hash26 & (COLUMNS - 1);
        // We should probably split the coin here to swap the sign for the countsketch2 implementation
        // 小于2^n的，CHECK_BIT(hash2, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash2, n)为0
        __u32 *val26 = countsketch26.lookup(&target_idx26);
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
    }

    u32 rand27 = bpf_get_prandom_u32();
    if (rand27 < UPDATE_PROBABILITY)
    {
        // Here we start updating the sketch
        __u32 hash27 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 7);
        __u32 target_idx27 = hash27 & (COLUMNS - 1);
        // We should probably split the coin here to swap the sign for the countsketch2 implementation
        // 小于2^n的，CHECK_BIT(hash2, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash2, n)为0
        __u32 *val27 = countsketch27.lookup(&target_idx27);
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
    }
     u32 rand28 = bpf_get_prandom_u32();
    if (rand28 < UPDATE_PROBABILITY)
    {
        // Here we start updating the sketch
        __u32 hash28 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 8);
        __u32 target_idx28 = hash28 & (COLUMNS - 1);
        // We should probably split the coin here to swap the sign for the countsketch2 implementation
        // 小于2^n的，CHECK_BIT(hash2, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash2, n)为0
        __u32 *val28 = countsketch28.lookup(&target_idx28);
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
