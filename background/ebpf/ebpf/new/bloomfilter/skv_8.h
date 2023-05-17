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

#define ROWS 5
#define COLUMNS 2621440

// _Static_assert((COLUMNS & (COLUMNS - 1)) == 0, "COLUMNS must be a power of two");

// struct countSketch
// {
//     __u32 values[ROWS][COLUMNS];
// };

BPF_ARRAY(countSketch1, __u32, 2621440);
BPF_ARRAY(countSketch2, __u32, 2621440);
BPF_ARRAY(countSketch3, __u32, 2621440);
BPF_ARRAY(countSketch4, __u32, 2621440);
BPF_ARRAY(countSketch5, __u32, 2621440);

struct pkt_5tuple
{
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    uint8_t proto;
} __attribute__((packed));
BPF_HASH(fastpath, struct pkt_5tuple, __u64, 10000);

BPF_ARRAY(countSketch21, __u32, 2621440);
BPF_ARRAY(countSketch22, __u32, 2621440);
BPF_ARRAY(countSketch23, __u32, 2621440);
BPF_ARRAY(countSketch24, __u32, 2621440);
BPF_ARRAY(countSketch25, __u32, 2621440);
BPF_HASH(fastpath2, struct pkt_5tuple, __u64, 10000);
BPF_ARRAY(countSketch31, __u32, 2621440);
BPF_ARRAY(countSketch32, __u32, 2621440);
BPF_ARRAY(countSketch33, __u32, 2621440);
BPF_ARRAY(countSketch34, __u32, 2621440);
BPF_ARRAY(countSketch35, __u32, 2621440);
BPF_HASH(fastpath3, struct pkt_5tuple, __u64, 10000);
BPF_ARRAY(countSketch41, __u32, 2621440);
BPF_ARRAY(countSketch42, __u32, 2621440);
BPF_ARRAY(countSketch43, __u32, 2621440);
BPF_ARRAY(countSketch44, __u32, 2621440);
BPF_ARRAY(countSketch45, __u32, 2621440);
BPF_HASH(fastpath4, struct pkt_5tuple, __u64, 10000);
BPF_ARRAY(countSketch51, __u32, 2621440);
BPF_ARRAY(countSketch52, __u32, 2621440);
BPF_ARRAY(countSketch53, __u32, 2621440);
BPF_ARRAY(countSketch54, __u32, 2621440);
BPF_ARRAY(countSketch55, __u32, 2621440);
BPF_HASH(fastpath5, struct pkt_5tuple, __u64, 10000);
BPF_ARRAY(countSketch61, __u32, 2621440);
BPF_ARRAY(countSketch62, __u32, 2621440);
BPF_ARRAY(countSketch63, __u32, 2621440);
BPF_ARRAY(countSketch64, __u32, 2621440);
BPF_ARRAY(countSketch65, __u32, 2621440);
BPF_HASH(fastpath6, struct pkt_5tuple, __u64, 10000);
BPF_ARRAY(countSketch71, __u32, 2621440);
BPF_ARRAY(countSketch72, __u32, 2621440);
BPF_ARRAY(countSketch73, __u32, 2621440);
BPF_ARRAY(countSketch74, __u32, 2621440);
BPF_ARRAY(countSketch75, __u32, 2621440);
BPF_HASH(fastpath7, struct pkt_5tuple, __u64, 10000);
BPF_ARRAY(countSketch81, __u32, 2621440);
BPF_ARRAY(countSketch82, __u32, 2621440);
BPF_ARRAY(countSketch83, __u32, 2621440);
BPF_ARRAY(countSketch84, __u32, 2621440);
BPF_ARRAY(countSketch85, __u32, 2621440);
BPF_HASH(fastpath8, struct pkt_5tuple, __u64, 10000);

struct pkt_md
{
    uint64_t drop_cnt;
};

BPF_PERCPU_ARRAY(dropcnt, struct pkt_md, 1);

// static void FORCE_INLINE count_add(struct countSketch *cs, void *element, __u64 len)
// {
//     // Calculate just a single hash and re-use it to update and query the sketch

//     for (int i = 0; i < ROWS; i++)
//     {
//         uint32_t hash = MurmurHash3_x86_32(element, len, id * id);
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
      uint32_t zero8 = 0;
    bool update_cm8 = false;
    __u64 hpp8 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 0x1234) % 4;
    if (hpp8 <= 1)
        update_cm8 = false; // p(goto fastpath8) = 0.4
    else
        update_cm8 = true; // p(goto normal path) = 0.6

    if (update_cm8)
    {
        uint32_t hash81 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 11);
        uint32_t hash82 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 22);
        uint32_t hash83 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 33);
        uint32_t hash84 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 44);
        uint32_t hash85 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 55);
        __u32 target_idx81 = hash81 & (COLUMNS - 1);
        __u32 target_idx82 = hash82 & (COLUMNS - 1);
        __u32 target_idx83 = hash83 & (COLUMNS - 1);
        __u32 target_idx84 = hash84 & (COLUMNS - 1);
        __u32 target_idx85 = hash85 & (COLUMNS - 1);

        __u32 *val81 = countSketch81.lookup(&target_idx81);
        if (val81)
            (*val81) += 1;

        __u32 *val82 = countSketch82.lookup(&target_idx82);
        if (val82)
            (*val82) += 1;

        __u32 *val83 = countSketch83.lookup(&target_idx83);
        if (val83)
            (*val83) += 1;
         __u32 *val84 = countSketch84.lookup(&target_idx84);
        if (val84)
            (*val84) += 1;
         __u32 *val85 = countSketch85.lookup(&target_idx85);
        if (val85)
            (*val85) += 1;
    }
    else
    {
        __u64 *zero8 = 0, *val8;
        val8 = fastpath8.lookup_or_try_init(&pkt, &zero8);
        if (val8)
        {
            (*val8) += 1;
        }
    }
     uint32_t zero7 = 0;
    bool update_cm7 = false;
    __u64 hpp7 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 0x1234) % 4;
    if (hpp7 <= 1)
        update_cm7 = false; // p(goto fastpath7) = 0.4
    else
        update_cm7 = true; // p(goto normal path) = 0.6

    if (update_cm7)
    {
        uint32_t hash71 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 11);
        uint32_t hash72 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 22);
        uint32_t hash73 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 33);
        uint32_t hash74 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 44);
        uint32_t hash75 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 55);
        __u32 target_idx71 = hash71 & (COLUMNS - 1);
        __u32 target_idx72 = hash72 & (COLUMNS - 1);
        __u32 target_idx73 = hash73 & (COLUMNS - 1);
        __u32 target_idx74 = hash74 & (COLUMNS - 1);
        __u32 target_idx75 = hash75 & (COLUMNS - 1);

        __u32 *val71 = countSketch71.lookup(&target_idx71);
        if (val71)
            (*val71) += 1;

        __u32 *val72 = countSketch72.lookup(&target_idx72);
        if (val72)
            (*val72) += 1;

        __u32 *val73 = countSketch73.lookup(&target_idx73);
        if (val73)
            (*val73) += 1;
         __u32 *val74 = countSketch74.lookup(&target_idx74);
        if (val74)
            (*val74) += 1;
         __u32 *val75 = countSketch75.lookup(&target_idx75);
        if (val75)
            (*val75) += 1;
    }
    else
    {
        __u64 *zero7 = 0, *val7;
        val7 = fastpath7.lookup_or_try_init(&pkt, &zero7);
        if (val7)
        {
            (*val7) += 1;
        }
    }
      uint32_t zero5 = 0;
    bool update_cm5 = false;
    __u64 hpp5 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 0x1234) % 4;
    if (hpp5 <= 1)
        update_cm5 = false; // p(goto fastpath5) = 0.4
    else
        update_cm5 = true; // p(goto normal path) = 0.6

    if (update_cm5)
    {
        uint32_t hash51 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 11);
        uint32_t hash52 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 22);
        uint32_t hash53 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 33);
        uint32_t hash54 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 44);
        uint32_t hash55 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 55);
        __u32 target_idx51 = hash51 & (COLUMNS - 1);
        __u32 target_idx52 = hash52 & (COLUMNS - 1);
        __u32 target_idx53 = hash53 & (COLUMNS - 1);
        __u32 target_idx54 = hash54 & (COLUMNS - 1);
        __u32 target_idx55 = hash55 & (COLUMNS - 1);

        __u32 *val51 = countSketch51.lookup(&target_idx51);
        if (val51)
            (*val51) += 1;

        __u32 *val52 = countSketch52.lookup(&target_idx52);
        if (val52)
            (*val52) += 1;

        __u32 *val53 = countSketch53.lookup(&target_idx53);
        if (val53)
            (*val53) += 1;
         __u32 *val54 = countSketch54.lookup(&target_idx54);
        if (val54)
            (*val54) += 1;
         __u32 *val55 = countSketch55.lookup(&target_idx55);
        if (val55)
            (*val55) += 1;
    }
    else
    {
        __u64 *zero5 = 0, *val5;
        val5 = fastpath5.lookup_or_try_init(&pkt, &zero5);
        if (val5)
        {
            (*val5) += 1;
        }
    }
       uint32_t zero4 = 0;
    bool update_cm4 = false;
    __u64 hpp4 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 0x1234) % 4;
    if (hpp4 <= 1)
        update_cm4 = false; // p(goto fastpath4) = 0.4
    else
        update_cm4 = true; // p(goto normal path) = 0.6

    if (update_cm4)
    {
        uint32_t hash41 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 11);
        uint32_t hash42 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 22);
        uint32_t hash43 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 33);
        uint32_t hash44 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 44);
        uint32_t hash45 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 55);
        __u32 target_idx41 = hash41 & (COLUMNS - 1);
        __u32 target_idx42 = hash42 & (COLUMNS - 1);
        __u32 target_idx43 = hash43 & (COLUMNS - 1);
        __u32 target_idx44 = hash44 & (COLUMNS - 1);
        __u32 target_idx45 = hash45 & (COLUMNS - 1);

        __u32 *val41 = countSketch41.lookup(&target_idx41);
        if (val41)
            (*val41) += 1;

        __u32 *val42 = countSketch42.lookup(&target_idx42);
        if (val42)
            (*val42) += 1;

        __u32 *val43 = countSketch43.lookup(&target_idx43);
        if (val43)
            (*val43) += 1;
         __u32 *val44 = countSketch44.lookup(&target_idx44);
        if (val44)
            (*val44) += 1;
         __u32 *val45 = countSketch45.lookup(&target_idx45);
        if (val45)
            (*val45) += 1;
    }
    else
    {
        __u64 *zero4 = 0, *val4;
        val4 = fastpath4.lookup_or_try_init(&pkt, &zero4);
        if (val4)
        {
            (*val4) += 1;
        }
    }

       uint32_t zero3 = 0;
    bool update_cm3 = false;
    __u64 hpp3 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 0x1234) % 4;
    if (hpp3 <= 1)
        update_cm3 = false; // p(goto fastpath3) = 0.4
    else
        update_cm3 = true; // p(goto normal path) = 0.6

    if (update_cm3)
    {
        uint32_t hash31 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 11);
        uint32_t hash32 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 22);
        uint32_t hash33 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 33);
        uint32_t hash34 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 44);
        uint32_t hash35 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 55);
        __u32 target_idx31 = hash31 & (COLUMNS - 1);
        __u32 target_idx32 = hash32 & (COLUMNS - 1);
        __u32 target_idx33 = hash33 & (COLUMNS - 1);
        __u32 target_idx34 = hash34 & (COLUMNS - 1);
        __u32 target_idx35 = hash35 & (COLUMNS - 1);

        __u32 *val31 = countSketch31.lookup(&target_idx31);
        if (val31)
            (*val31) += 1;

        __u32 *val32 = countSketch32.lookup(&target_idx32);
        if (val32)
            (*val32) += 1;

        __u32 *val33 = countSketch33.lookup(&target_idx33);
        if (val33)
            (*val33) += 1;
         __u32 *val34 = countSketch34.lookup(&target_idx34);
        if (val34)
            (*val34) += 1;
         __u32 *val35 = countSketch35.lookup(&target_idx35);
        if (val35)
            (*val35) += 1;
    }
    else
    {
        __u64 *zero3 = 0, *val3;
        val3 = fastpath3.lookup_or_try_init(&pkt, &zero3);
        if (val3)
        {
            (*val3) += 1;
        }
    }

       uint32_t zero2 = 0;
    bool update_cm2 = false;
    __u64 hpp2 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 0x1234) % 4;
    if (hpp2 <= 1)
        update_cm2 = false; // p(goto fastpath2) = 0.4
    else
        update_cm2 = true; // p(goto normal path) = 0.6

    if (update_cm2)
    {
        uint32_t hash21 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 11);
        uint32_t hash22 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 22);
        uint32_t hash23 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 33);
        uint32_t hash24 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 44);
        uint32_t hash25 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 55);
        __u32 target_idx21 = hash21 & (COLUMNS - 1);
        __u32 target_idx22 = hash22 & (COLUMNS - 1);
        __u32 target_idx23 = hash23 & (COLUMNS - 1);
        __u32 target_idx24 = hash24 & (COLUMNS - 1);
        __u32 target_idx25 = hash25 & (COLUMNS - 1);

        __u32 *val21 = countSketch21.lookup(&target_idx21);
        if (val21)
            (*val21) += 1;

        __u32 *val22 = countSketch22.lookup(&target_idx22);
        if (val22)
            (*val22) += 1;

        __u32 *val23 = countSketch23.lookup(&target_idx23);
        if (val23)
            (*val23) += 1;
         __u32 *val24 = countSketch24.lookup(&target_idx24);
        if (val24)
            (*val24) += 1;
         __u32 *val25 = countSketch25.lookup(&target_idx25);
        if (val25)
            (*val25) += 1;
    }
    else
    {
        __u64 *zero2 = 0, *val2;
        val2 = fastpath2.lookup_or_try_init(&pkt, &zero2);
        if (val2)
        {
            (*val2) += 1;
        }
    }

    uint32_t zero = 0;
    bool update_cm = false;
    __u64 h = MurmurHash3_x86_32(&pkt, sizeof(pkt), 0x1234) % 4;
    if (h <= 1)
        update_cm = false; // p(goto fastpath) = 0.4
    else
        update_cm = true; // p(goto normal path) = 0.6

    if (update_cm)
    {
        uint32_t hash1 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 11);
        uint32_t hash2 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 22);
        uint32_t hash3 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 33);
        uint32_t hash4 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 44);
        uint32_t hash5 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 55);
        __u32 target_idx1 = hash1 & (COLUMNS - 1);
        __u32 target_idx2 = hash2 & (COLUMNS - 1);
        __u32 target_idx3 = hash3 & (COLUMNS - 1);
        __u32 target_idx4 = hash4 & (COLUMNS - 1);
        __u32 target_idx5 = hash5 & (COLUMNS - 1);

        __u32 *val1 = countSketch1.lookup(&target_idx1);
        if (val1)
            (*val1) += 1;

        __u32 *val2 = countSketch2.lookup(&target_idx2);
        if (val2)
            (*val2) += 1;

        __u32 *val3 = countSketch3.lookup(&target_idx3);
        if (val3)
            (*val3) += 1;
         __u32 *val4 = countSketch4.lookup(&target_idx4);
        if (val4)
            (*val4) += 1;
         __u32 *val5 = countSketch5.lookup(&target_idx5);
        if (val5)
            (*val5) += 1;
    }
    else
    {
        __u64 *zero = 0, *val;
        val = fastpath.lookup_or_try_init(&pkt, &zero);
        if (val)
        {
            (*val) += 1;
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
