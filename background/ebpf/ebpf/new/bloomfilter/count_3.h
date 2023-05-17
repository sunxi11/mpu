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

#define ROWS 8
#define COLUMNS 327680

// _Static_assert((COLUMNS & (COLUMNS - 1)) == 0, "COLUMNS must be a power of two");

// struct countSketch
// {
//     __u32 values[ROWS][COLUMNS];
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
// BPF_ARRAY(count, struct countSketch, 1);
BPF_ARRAY(countSketch1, __u32, 327680);
BPF_ARRAY(countSketch2, __u32, 327680);
BPF_ARRAY(countSketch3, __u32, 327680);
BPF_ARRAY(countSketch4, __u32, 327680);
BPF_ARRAY(countSketch5, __u32, 327680);
BPF_ARRAY(countSketch6, __u32, 327680);
BPF_ARRAY(countSketch7, __u32, 327680);
BPF_ARRAY(countSketch8, __u32, 327680);

BPF_ARRAY(countSketch21, __u32, 327680);
BPF_ARRAY(countSketch22, __u32, 327680);
BPF_ARRAY(countSketch23, __u32, 327680);
BPF_ARRAY(countSketch24, __u32, 327680);
BPF_ARRAY(countSketch25, __u32, 327680);
BPF_ARRAY(countSketch26, __u32, 327680);
BPF_ARRAY(countSketch27, __u32, 327680);
BPF_ARRAY(countSketch28, __u32, 327680);


BPF_ARRAY(countSketch31, __u32, 327680);
BPF_ARRAY(countSketch32, __u32, 327680);
BPF_ARRAY(countSketch33, __u32, 327680);
BPF_ARRAY(countSketch34, __u32, 327680);
BPF_ARRAY(countSketch35, __u32, 327680);
BPF_ARRAY(countSketch36, __u32, 327680);
BPF_ARRAY(countSketch37, __u32, 327680);
BPF_ARRAY(countSketch38, __u32, 327680);
// static void FORCE_INLINE count_add(struct countSketch *cs, void *element, __u64 len)
// {
//     // Calculate just a single hash and re-use it to update and query the sketch

//     for (int i = 0; i < ROWS; i++)
//     {
//         uint32_t hash = MurmurHash3_x86_32(element, len, i * i);
//         __u32 target_idx = hash & (COLUMNS - 1);

//         if (CHECK_BIT(hash, 31))
//         {
//             NO_TEAR_ADD(cs->values[i][target_idx], 1);
//         }
//         else
//         {
//             NO_TEAR_ADD(cs->values[i][target_idx], -1);
//         }
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

    __u32 hash31 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 0x12345678);
    __u32 target_idx31 = hash31 & (COLUMNS - 1);
    // We should probably split the coin here to swap the sign for the countsketch implementation
    // 小于2^n的，CHECK_BIT(hash3, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash3, n)为0
    __u32 *val31 = countSketch31.lookup(&target_idx31);
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

    __u32 hash32 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 0x6ad611c4);
    __u32 target_idx32 = hash32 & (COLUMNS - 1);
    // We should probably split the coin here to swap the sign for the countsketch implementation
    // 小于2^n的，CHECK_BIT(hash3, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash3, n)为0
    __u32 *val32 = countSketch32.lookup(&target_idx32);
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
    __u32 hash33 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 3333);
    __u32 target_idx33 = hash33 & (COLUMNS - 1);
    // We should probably split the coin here to swap the sign for the countsketch implementation
    // 小于2^n的，CHECK_BIT(hash3, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash3, n)为0
    __u32 *val33 = countSketch33.lookup(&target_idx33);
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

    __u32 hash34 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 444);
    __u32 target_idx34 = hash34 & (COLUMNS - 1);
    // We should probably split the coin here to swap the sign for the countsketch implementation
    // 小于2^n的，CHECK_BIT(hash3, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash3, n)为0
    __u32 *val34 = countSketch34.lookup(&target_idx34);
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

    __u32 hash35 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 555);
    __u32 target_idx35 = hash35 & (COLUMNS - 1);
    // We should probably split the coin here to swap the sign for the countsketch implementation
    // 小于2^n的，CHECK_BIT(hash3, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash3, n)为0
    __u32 *val35 = countSketch35.lookup(&target_idx35);
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

    __u32 hash36 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 666);
    __u32 target_idx36 = hash36 & (COLUMNS - 1);
    // We should probably split the coin here to swap the sign for the countsketch implementation
    // 小于2^n的，CHECK_BIT(hash3, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash3, n)为0
    __u32 *val36 = countSketch36.lookup(&target_idx36);
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

    __u32 hash37 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 777);
    __u32 target_idx37 = hash37 & (COLUMNS - 1);
    // We should probably split the coin here to swap the sign for the countsketch implementation
    // 小于2^n的，CHECK_BIT(hash3, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash3, n)为0
    __u32 *val37 = countSketch37.lookup(&target_idx37);
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

    __u32 hash38 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 888);
    __u32 target_idx38 = hash38 & (COLUMNS - 1);
    // We should probably split the coin here to swap the sign for the countsketch implementation
    // 小于2^n的，CHECK_BIT(hash3, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash3, n)为0
    __u32 *val38 = countSketch38.lookup(&target_idx38);
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

    __u32 hash1 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 0x12345678);
    __u32 target_idx1 = hash1 & (COLUMNS - 1);
    // We should probably split the coin here to swap the sign for the countsketch implementation
    // 小于2^n的，CHECK_BIT(hash, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash, n)为0
    __u32 *val1 = countSketch1.lookup(&target_idx1);
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

    __u32 hash2 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 0x6ad611c4);
    __u32 target_idx2 = hash2 & (COLUMNS - 1);
    // We should probably split the coin here to swap the sign for the countsketch implementation
    // 小于2^n的，CHECK_BIT(hash, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash, n)为0
    __u32 *val2 = countSketch2.lookup(&target_idx2);
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
    __u32 hash3 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 3333);
    __u32 target_idx3 = hash3 & (COLUMNS - 1);
    // We should probably split the coin here to swap the sign for the countsketch implementation
    // 小于2^n的，CHECK_BIT(hash, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash, n)为0
    __u32 *val3 = countSketch3.lookup(&target_idx3);
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

    __u32 hash4 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 444);
    __u32 target_idx4 = hash4 & (COLUMNS - 1);
    // We should probably split the coin here to swap the sign for the countsketch implementation
    // 小于2^n的，CHECK_BIT(hash, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash, n)为0
    __u32 *val4 = countSketch4.lookup(&target_idx4);
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

    __u32 hash5 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 555);
    __u32 target_idx5 = hash5 & (COLUMNS - 1);
    // We should probably split the coin here to swap the sign for the countsketch implementation
    // 小于2^n的，CHECK_BIT(hash, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash, n)为0
    __u32 *val5 = countSketch5.lookup(&target_idx5);
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

    __u32 hash6 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 666);
    __u32 target_idx6 = hash6 & (COLUMNS - 1);
    // We should probably split the coin here to swap the sign for the countsketch implementation
    // 小于2^n的，CHECK_BIT(hash, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash, n)为0
    __u32 *val6 = countSketch6.lookup(&target_idx6);
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

    __u32 hash7 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 777);
    __u32 target_idx7 = hash7 & (COLUMNS - 1);
    // We should probably split the coin here to swap the sign for the countsketch implementation
    // 小于2^n的，CHECK_BIT(hash, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash, n)为0
    __u32 *val7 = countSketch7.lookup(&target_idx7);
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

    __u32 hash8 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 888);
    __u32 target_idx8 = hash8 & (COLUMNS - 1);
    // We should probably split the coin here to swap the sign for the countsketch implementation
    // 小于2^n的，CHECK_BIT(hash, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash, n)为0
    __u32 *val8 = countSketch8.lookup(&target_idx8);
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
