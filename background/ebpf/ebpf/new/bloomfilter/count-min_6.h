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

BPF_ARRAY(countmin21, __u32, 327680);
BPF_ARRAY(countmin22, __u32, 327680);
BPF_ARRAY(countmin23, __u32, 327680);
BPF_ARRAY(countmin24, __u32, 327680);
BPF_ARRAY(countmin25, __u32, 327680);
BPF_ARRAY(countmin26, __u32, 327680);
BPF_ARRAY(countmin27, __u32, 327680);
BPF_ARRAY(countmin28, __u32, 327680);

BPF_ARRAY(countmin31, __u32, 327680);
BPF_ARRAY(countmin32, __u32, 327680);
BPF_ARRAY(countmin33, __u32, 327680);
BPF_ARRAY(countmin34, __u32, 327680);
BPF_ARRAY(countmin35, __u32, 327680);
BPF_ARRAY(countmin36, __u32, 327680);
BPF_ARRAY(countmin37, __u32, 327680);
BPF_ARRAY(countmin38, __u32, 327680);
BPF_ARRAY(countmin41, __u32, 327680);
BPF_ARRAY(countmin42, __u32, 327680);
BPF_ARRAY(countmin43, __u32, 327680);
BPF_ARRAY(countmin44, __u32, 327680);
BPF_ARRAY(countmin45, __u32, 327680);
BPF_ARRAY(countmin46, __u32, 327680);
BPF_ARRAY(countmin47, __u32, 327680);
BPF_ARRAY(countmin48, __u32, 327680);

BPF_ARRAY(countmin51, __u32, 327680);
BPF_ARRAY(countmin52, __u32, 327680);
BPF_ARRAY(countmin53, __u32, 327680);
BPF_ARRAY(countmin54, __u32, 327680);
BPF_ARRAY(countmin55, __u32, 327680);
BPF_ARRAY(countmin56, __u32, 327680);
BPF_ARRAY(countmin57, __u32, 327680);
BPF_ARRAY(countmin58, __u32, 327680);

BPF_ARRAY(countmin61, __u32, 327680);
BPF_ARRAY(countmin62, __u32, 327680);
BPF_ARRAY(countmin63, __u32, 327680);
BPF_ARRAY(countmin64, __u32, 327680);
BPF_ARRAY(countmin65, __u32, 327680);
BPF_ARRAY(countmin66, __u32, 327680);
BPF_ARRAY(countmin67, __u32, 327680);
BPF_ARRAY(countmin68, __u32, 327680);

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

    uint32_t hash61 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 11);
    uint32_t hash62 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 22);
    uint32_t hash63 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 33);
    uint32_t hash64 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 44);
    uint32_t hash65 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 55);
    uint32_t hash66 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 66);
    uint32_t hash67 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 77);
    uint32_t hash68 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 88);
    __u32 target_idx61 = hash61 & (COLUMNS - 1);
    __u32 target_idx62 = hash62 & (COLUMNS - 1);
    __u32 target_idx63 = hash63 & (COLUMNS - 1);
    __u32 target_idx64 = hash64 & (COLUMNS - 1);
    __u32 target_idx65 = hash65 & (COLUMNS - 1);
    __u32 target_idx66 = hash66 & (COLUMNS - 1);
    __u32 target_idx67 = hash67 & (COLUMNS - 1);
    __u32 target_idx68 = hash68 & (COLUMNS - 1);

    __u32 *val61 = countmin61.lookup(&target_idx61);
    if (val61)
        lock_xadd(val61, 1);

    __u32 *val62 = countmin62.lookup(&target_idx62);
    if (val62)
        lock_xadd(val62, 1);

    __u32 *val63 = countmin63.lookup(&target_idx63);
    if (val63)
        lock_xadd(val63, 1);
    __u32 *val64 = countmin64.lookup(&target_idx64);
    if (val64)
        lock_xadd(val64, 1);
    __u32 *val65 = countmin65.lookup(&target_idx65);
    if (val65)
        lock_xadd(val65, 1);
    __u32 *val66 = countmin66.lookup(&target_idx66);
    if (val66)
        lock_xadd(val66, 1);
    __u32 *val67 = countmin67.lookup(&target_idx67);
    if (val67)
        lock_xadd(val67, 1);
    __u32 *val68 = countmin68.lookup(&target_idx68);
    if (val68)
        lock_xadd(val68, 1);
    uint32_t hash51 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 11);
    uint32_t hash52 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 22);
    uint32_t hash53 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 33);
    uint32_t hash54 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 44);
    uint32_t hash55 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 55);
    uint32_t hash56 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 66);
    uint32_t hash57 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 77);
    uint32_t hash58 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 88);
    __u32 target_idx51 = hash51 & (COLUMNS - 1);
    __u32 target_idx52 = hash52 & (COLUMNS - 1);
    __u32 target_idx53 = hash53 & (COLUMNS - 1);
    __u32 target_idx54 = hash54 & (COLUMNS - 1);
    __u32 target_idx55 = hash55 & (COLUMNS - 1);
    __u32 target_idx56 = hash56 & (COLUMNS - 1);
    __u32 target_idx57 = hash57 & (COLUMNS - 1);
    __u32 target_idx58 = hash58 & (COLUMNS - 1);

    __u32 *val51 = countmin51.lookup(&target_idx51);
    if (val51)
        lock_xadd(val51, 1);

    __u32 *val52 = countmin52.lookup(&target_idx52);
    if (val52)
        lock_xadd(val52, 1);

    __u32 *val53 = countmin53.lookup(&target_idx53);
    if (val53)
        lock_xadd(val53, 1);
    __u32 *val54 = countmin54.lookup(&target_idx54);
    if (val54)
        lock_xadd(val54, 1);
    __u32 *val55 = countmin55.lookup(&target_idx55);
    if (val55)
        lock_xadd(val55, 1);
    __u32 *val56 = countmin56.lookup(&target_idx56);
    if (val56)
        lock_xadd(val56, 1);
    __u32 *val57 = countmin57.lookup(&target_idx57);
    if (val57)
        lock_xadd(val57, 1);
    __u32 *val58 = countmin58.lookup(&target_idx58);
    if (val58)
        lock_xadd(val58, 1);

    // countmin51.update(&target_idx51, 1);
    // countmin52.update(&target_idx52, 1);
    // countmin53.update(&target_idx53, 1);

    // cm1 = countmin5.lookup(&zero);
    // cm2 = countmin5.lookup(&one);
    // cm3 = countmin5.lookup(&two);
    uint32_t hash41 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 11);
    uint32_t hash42 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 22);
    uint32_t hash43 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 33);
    uint32_t hash44 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 44);
    uint32_t hash45 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 55);
    uint32_t hash46 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 66);
    uint32_t hash47 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 77);
    uint32_t hash48 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 88);
    __u32 target_idx41 = hash41 & (COLUMNS - 1);
    __u32 target_idx42 = hash42 & (COLUMNS - 1);
    __u32 target_idx43 = hash43 & (COLUMNS - 1);
    __u32 target_idx44 = hash44 & (COLUMNS - 1);
    __u32 target_idx45 = hash45 & (COLUMNS - 1);
    __u32 target_idx46 = hash46 & (COLUMNS - 1);
    __u32 target_idx47 = hash47 & (COLUMNS - 1);
    __u32 target_idx48 = hash48 & (COLUMNS - 1);

    __u32 *val41 = countmin41.lookup(&target_idx41);
    if (val41)
        lock_xadd(val41, 1);

    __u32 *val42 = countmin42.lookup(&target_idx42);
    if (val42)
        lock_xadd(val42, 1);

    __u32 *val43 = countmin43.lookup(&target_idx43);
    if (val43)
        lock_xadd(val43, 1);
    __u32 *val44 = countmin44.lookup(&target_idx44);
    if (val44)
        lock_xadd(val44, 1);
    __u32 *val45 = countmin45.lookup(&target_idx45);
    if (val45)
        lock_xadd(val45, 1);
    __u32 *val46 = countmin46.lookup(&target_idx46);
    if (val46)
        lock_xadd(val46, 1);
    __u32 *val47 = countmin47.lookup(&target_idx47);
    if (val47)
        lock_xadd(val47, 1);
    __u32 *val48 = countmin48.lookup(&target_idx48);
    if (val48)
        lock_xadd(val48, 1);
    // struct countmin *cm1, *cm3, *cm2;
    uint32_t hash31 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 11);
    uint32_t hash32 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 22);
    uint32_t hash33 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 33);
    uint32_t hash34 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 44);
    uint32_t hash35 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 55);
    uint32_t hash36 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 66);
    uint32_t hash37 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 77);
    uint32_t hash38 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 88);
    __u32 target_idx31 = hash31 & (COLUMNS - 1);
    __u32 target_idx32 = hash32 & (COLUMNS - 1);
    __u32 target_idx33 = hash33 & (COLUMNS - 1);
    __u32 target_idx34 = hash34 & (COLUMNS - 1);
    __u32 target_idx35 = hash35 & (COLUMNS - 1);
    __u32 target_idx36 = hash36 & (COLUMNS - 1);
    __u32 target_idx37 = hash37 & (COLUMNS - 1);
    __u32 target_idx38 = hash38 & (COLUMNS - 1);

    __u32 *val31 = countmin31.lookup(&target_idx31);
    if (val31)
        lock_xadd(val31, 1);

    __u32 *val32 = countmin32.lookup(&target_idx32);
    if (val32)
        lock_xadd(val32, 1);

    __u32 *val33 = countmin33.lookup(&target_idx33);
    if (val33)
        lock_xadd(val33, 1);
    __u32 *val34 = countmin34.lookup(&target_idx34);
    if (val34)
        lock_xadd(val34, 1);
    __u32 *val35 = countmin35.lookup(&target_idx35);
    if (val35)
        lock_xadd(val35, 1);
    __u32 *val36 = countmin36.lookup(&target_idx36);
    if (val36)
        lock_xadd(val36, 1);
    __u32 *val37 = countmin37.lookup(&target_idx37);
    if (val37)
        lock_xadd(val37, 1);
    __u32 *val38 = countmin38.lookup(&target_idx38);
    if (val38)
        lock_xadd(val38, 1);

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

    uint32_t hash21 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 11);
    uint32_t hash22 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 22);
    uint32_t hash23 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 33);
    uint32_t hash24 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 44);
    uint32_t hash25 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 55);
    uint32_t hash26 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 66);
    uint32_t hash27 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 77);
    uint32_t hash28 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 88);
    __u32 target_idx21 = hash21 & (COLUMNS - 1);
    __u32 target_idx22 = hash22 & (COLUMNS - 1);
    __u32 target_idx23 = hash23 & (COLUMNS - 1);
    __u32 target_idx24 = hash24 & (COLUMNS - 1);
    __u32 target_idx25 = hash25 & (COLUMNS - 1);
    __u32 target_idx26 = hash26 & (COLUMNS - 1);
    __u32 target_idx27 = hash27 & (COLUMNS - 1);
    __u32 target_idx28 = hash28 & (COLUMNS - 1);

    __u32 *val21 = countmin21.lookup(&target_idx21);
    if (val21)
        lock_xadd(val21, 1);

    __u32 *val22 = countmin22.lookup(&target_idx22);
    if (val22)
        lock_xadd(val22, 1);

    __u32 *val23 = countmin23.lookup(&target_idx23);
    if (val23)
        lock_xadd(val23, 1);
    __u32 *val24 = countmin24.lookup(&target_idx24);
    if (val24)
        lock_xadd(val24, 1);
    __u32 *val25 = countmin25.lookup(&target_idx25);
    if (val25)
        lock_xadd(val25, 1);
    __u32 *val26 = countmin26.lookup(&target_idx26);
    if (val26)
        lock_xadd(val26, 1);
    __u32 *val27 = countmin27.lookup(&target_idx27);
    if (val27)
        lock_xadd(val27, 1);
    __u32 *val28 = countmin28.lookup(&target_idx28);
    if (val28)
        lock_xadd(val28, 1);


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
