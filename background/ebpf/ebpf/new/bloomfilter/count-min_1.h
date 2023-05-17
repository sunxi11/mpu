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
    return XDP_PASS;
}

// This is only used when the action is redirect
int xdp_dummy(struct xdp_md *ctx)
{
    return XDP_PASS;
}
