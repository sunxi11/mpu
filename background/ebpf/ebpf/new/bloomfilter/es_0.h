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

#define heavy_size 100000
#define light_size _LIGHT_SIZE
#define light_size_m 3
#define light_size_n 2000000
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

//用于第一次sketch的数据结构
BPF_ARRAY(LightPart1_1, __u32, 2000000);
BPF_ARRAY(LightPart1_2, __u32, 2000000);
BPF_ARRAY(LightPart1_3, __u32, 2000000);
BPF_ARRAY(HeavyParts_flag_1, __u32, 100000);
BPF_ARRAY(HeavyParts_buckets_1, struct Bucket, 100000);

//用于第二次sketch的数据结构
BPF_ARRAY(LightPart2_1, __u32, 2000000);
BPF_ARRAY(LightPart2_2, __u32, 2000000);
BPF_ARRAY(LightPart2_3, __u32, 2000000);
BPF_ARRAY(HeavyParts_flag_2, __u32, 100000);
BPF_ARRAY(HeavyParts_buckets_2, struct Bucket, 100000);



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

   

    uint32_t srcIP = pkt.src_ip;
    uint32_t dstIP = pkt.dst_ip;

//以下是要修改的部分


//-----------------------第一次sketch----------------------------------------
    uint32_t hash_1 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 1234);
    __u32 pos_1 = hash_1 & (heavy_size - 1);

    struct Bucket *hpb_1;
		struct Bucket *hpb_init_1;
    // hpb_init->posvote = 1;
    // hpb_init->negvote = 0;
    // hpb_init->flag == false;
    // hpb_init->flow_id.dstIP = dstIP;
    // hpb_init->flow_id.srcIP = srcIP;
    __u32 *hpf_1;
    hpf_1 = HeavyParts_flag_1.lookup(&pos_1);
    hpb_1 = HeavyParts_buckets_1.lookup(&pos_1);

  

    // bpf_probe_read_kernel();
    __u32 res_1 = 0;
    if (hpf_1)
    {
        if (hpb_1)
        {
            if (*hpf_1 == 0)
            {
                // hpf = HeavyParts_flag.lookup_or_try_init(&pos_1, &one);
                *hpf_1 = 1;
                // hpb = HeavyParts_buckets.lookup_or_try_init(&pos_1, &hpb_init);
                hpb_1->posvote = 1;
                hpb_1->negvote = 0;
                hpb_1->flag == false;
                hpb_1->flow_id.dstIP = dstIP;
                hpb_1->flow_id.srcIP = srcIP;
            }
            else if (*hpf_1 != 0)
            {
                if (hpb_1->flow_id.srcIP == srcIP && hpb_1->flow_id.dstIP == dstIP)
                {
                    hpb_1->posvote++;
                }
                else
                {
                    hpb_1->negvote++;
                    u_int64_t temp = hpb_1->negvote / hpb_1->posvote;
                    if (temp < lamda)
                    {
                        res_1 = 1;
                    }
                    else
                    {
                        res_1 = hpb_1->posvote;
                        (*hpf_1) = true;
                        hpb_1->negvote = 1;
                        hpb_1->posvote = 1;
                        uint32_t tmp = srcIP;
                        srcIP = hpb_1->flow_id.srcIP;
                        hpb_1->flow_id.srcIP = tmp;
                        tmp = dstIP;
                        dstIP = hpb_1->flow_id.dstIP;
                        hpb_1->flow_id.dstIP = tmp;
                    }
                }
            }
            if (res_1 > 0)
            {
                // lp->update(srcIP, dstIP, status);

                uint32_t hash1 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 11);
                __u32 pos1 = hash1 & (light_size_n - 1);

                uint32_t hash2 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 22);
                __u32 pos2 = hash2 & (light_size_n - 1);

                uint32_t hash3 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 33);
                __u32 pos3 = hash3 & (light_size_n - 1);

                // uint64_t j = two_tuple_sketch_hash(srcIP, dstIP, i, n); // crc32(buf, i + 1) % n;

                __u32 *val1 = LightPart1_1.lookup(&hash1);
                if (val1)
                    (*val1) += 1;

                __u32 *val2 = LightPart1_2.lookup(&hash2);
                if (val2)
                    (*val2) += 1;

                __u32 *val3 = LightPart1_3.lookup(&hash3);
                if (val3)
                    (*val3) += 1;
            }
           
        }
    }

//-----------------------第二次sketch----------------------------------------
    uint32_t hash_2 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 1234);
    __u32 pos_2 = hash_2 & (heavy_size - 1);
    struct Bucket *hpb_2;
 
    struct Bucket *hpb_init_2;

    __u32 *hpf_2;
    hpf_2 = HeavyParts_flag_1.lookup(&pos_2);
    hpb_2 = HeavyParts_buckets_1.lookup(&pos_2);

 

    // bpf_probe_read_kernel();
    __u32 res_2 = 0;
    if (hpf_2)
    {
        if (hpb_2)
        {
            if (*hpf_2 == 0)
            {
                // hpf = HeavyParts_flag.lookup_or_try_init(&pos, &one);
                *hpf_2 = 1;
                // hpb = HeavyParts_buckets.lookup_or_try_init(&pos, &hpb_init);
                hpb_2->posvote = 1;
                hpb_2->negvote = 0;
                hpb_2->flag == false;
                hpb_2->flow_id.dstIP = dstIP;
                hpb_1->flow_id.srcIP = srcIP;
            }
            else if (*hpf_2 != 0)
            {
                if (hpb_2->flow_id.srcIP == srcIP && hpb_2->flow_id.dstIP == dstIP)
                {
                    hpb_2->posvote++;
                }
                else
                {
                    hpb_2->negvote++;
                    u_int64_t temp = hpb_2->negvote / hpb_2->posvote;
                    if (temp < lamda)
                    {
                        res_2 = 1;
                    }
                    else
                    {
                        res_2 = hpb_2->posvote;
                        (*hpf_1) = true;
                        hpb_2->negvote = 1;
                        hpb_2->posvote = 1;
                        uint32_t tmp = srcIP;
                        srcIP = hpb_1->flow_id.srcIP;
                        hpb_2->flow_id.srcIP = tmp;
                        tmp = dstIP;
                        dstIP = hpb_2->flow_id.dstIP;
                        hpb_2->flow_id.dstIP = tmp;
                    }
                }
            }
            if (res_2 > 0)
            {
                // lp->update(srcIP, dstIP, status);

                uint32_t hash1 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 11);
                __u32 pos1 = hash1 & (light_size_n - 1);

                uint32_t hash2 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 22);
                __u32 pos2 = hash2 & (light_size_n - 1);

                uint32_t hash3 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 33);
                __u32 pos3 = hash3 & (light_size_n - 1);

                // uint64_t j = two_tuple_sketch_hash(srcIP, dstIP, i, n); // crc32(buf, i + 1) % n;

                __u32 *val1 = LightPart2_1.lookup(&hash1);
                if (val1)
                    (*val1) += 1;

                __u32 *val2 = LightPart2_2.lookup(&hash2);
                if (val2)
                    (*val2) += 1;

                __u32 *val3 = LightPart2_3.lookup(&hash3);
                if (val3)
                    (*val3) += 1;
            }
           
        }
    }


//以下的就不用修改了
    struct pkt_md *md;
    uint32_t index = 0;
    md = dropcnt.lookup(&index);
    if (md)
    {
        NO_TEAR_INC(md->drop_cnt);
    }
    return XDP_PASS;

DROP:;
    bpf_trace_printk("Error. Dropping packet\n");
    return XDP_DROP;
}

// This is only used when the action is redirect
int xdp_dummy(struct xdp_md *ctx)
{
    return XDP_PASS;
}
