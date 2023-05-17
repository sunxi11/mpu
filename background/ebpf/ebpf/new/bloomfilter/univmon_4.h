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
#include <linux/jhash.h>
#include <uapi/linux/types.h>
#include <stddef.h>

#include "common.h"

#include "murmurhash3.h"

struct pkt_5tuple
{
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    uint8_t proto;
} __attribute__((packed));

struct topk_entry
{
    int value;
    struct pkt_5tuple tuple;
};

struct pkt_md
{
    uint64_t drop_cnt;
};
#define HASHFN_N 2
#define ROWS 2
#define COLUMNS 26042
#define _NM_LAYERS 12

//_Static_assert((COLUMNS & (COLUMNS - 1)) == 0, "COLUMNS must be a power of two");

// struct countsketch
// {
//     __u32 values[ROWS][COLUMNS];
//     struct topk_entry topks[_HEAP_SIZE];
// };

// BPF_PERCPU_ARRAY(ns_um, struct countsketch, _NM_LAYERS);
BPF_PERCPU_ARRAY(metadata, struct pkt_md, 1);
BPF_PERCPU_ARRAY(countsketch1, __u32, 26042);
BPF_PERCPU_ARRAY(countsketch2, __u32, 26042);

BPF_PERCPU_ARRAY(countsketch21, __u32, 26042);
BPF_PERCPU_ARRAY(countsketch22, __u32, 26042);
BPF_PERCPU_ARRAY(countsketch31, __u32, 26042);
BPF_PERCPU_ARRAY(countsketch32, __u32, 26042);
BPF_PERCPU_ARRAY(countsketch41, __u32, 26042);
BPF_PERCPU_ARRAY(countsketch42, __u32, 26042);

// BPF_PERCPU_ARRAY(topks, struct topk_entry, 62500000);

// 该函数主要是为了对命中的sketch hash二维表做改动
// static void __always_inline ns_um_add(struct countsketch *cs, void *element, __u64 len, uint32_t row_to_update)
// {
//     uint32_t hash;

//     if (row_to_update >= HASHFN_N)
//     {
//         return;
//     }
//     hash = MurmurHash3_x86_32(element, len, row_to_update * row_to_update);
//     __u32 target_idx = hash & (COLUMNS - 1);
//     // We should probably split the coin here to swap the sign for the countsketch implementation
//     // 小于2^n的，CHECK_BIT(hash, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash, n)为0
//     if (CHECK_BIT(hash, 31))
//     {
//         cs->values[row_to_update][target_idx]++;
//     }
//     else
//     {
//         cs->values[row_to_update][target_idx]--;
//     }
// }

// static int __always_inline query_sketch(struct countsketch *cs, void *element, __u64 len)
// {
//     // const __u32 hashes[] = {
//     //	xxhash32(element, len, 0x2d31e867),
//     //	xxhash32(element, len, 0x6ad611c4),
//     //	xxhash32(element, len, 0x00000000),
//     //	xxhash32(element, len, 0xffffffff)
//     // };

//     //_Static_assert(ARRAY_SIZE(hashes) == HASHFN_N, "Missing hash function");

//     int value[ROWS];
//     for (int i = 0; i < ROWS; i++)
//     {
//         __u32 hash = MurmurHash3_x86_32(element, len, i * i);
//         __u32 target_idx = hash & (COLUMNS - 1);
//         if (CHECK_BIT(hash, 31))
//         {
//             value[i] = cs->values[i][target_idx];
//         }
//         else
//         {
//             value[i] = -cs->values[i][target_idx];
//         }
//     }
//     // value这个数组储存了查询结果
//     // 找到value这个数组的中位数
//     // 返回value数组的中位数作为此时查询的结果
//     return median(value, ARRAY_SIZE(value));
// }

// static int __always_inline compare_pkt_struct(struct pkt_5tuple *origin_pkt, struct pkt_5tuple *new_pkt)
// {
//     if (origin_pkt->dst_ip == new_pkt->dst_ip &&
//         origin_pkt->src_ip == new_pkt->dst_ip &&
//         origin_pkt->proto == new_pkt->proto &&
//         origin_pkt->dst_port == new_pkt->dst_port &&
//         origin_pkt->src_port == new_pkt->src_port)
//         return 0;

//     return 1;
// }
// // 数组模拟堆，插入排序
// static void __always_inline insertionSort(struct countsketch *md)
// {
//     int i, j;
//     struct topk_entry key;

// #pragma clang loop unroll(full)
//     for (i = 1; i < _HEAP_SIZE; i++)
//     {
//         // __builtin_memcpy(&key, &arr[i], sizeof(struct topk_entry));
//         key = md->topks[i];
//         j = i - 1;
//         while (j >= 0 && md->topks[j].value < key.value)
//         {
//             md->topks[j + 1] = md->topks[j];
//             j = j - 1;
//         }
//         // __builtin_memcpy(&arr[j + 1], &key, sizeof(struct topk_entry));
//         md->topks[j + 1] = key;
//     }
// }

// static void __always_inline insert_into_heap(struct countsketch *md, int median, struct pkt_5tuple *pkt)
// {
//     int index = -1;

//     for (int i = 0; i < _HEAP_SIZE; i++)
//     {
//         struct pkt_5tuple origin_pkt = md->topks[i].tuple;
//         // bpf_probe_read_kernel(&origin, sizeof(origin), &md->topks[layer][i].tuple);
//         if (origin_pkt.dst_ip == pkt->dst_ip &&
//             origin_pkt.src_ip == pkt->src_ip &&
//             origin_pkt.proto == pkt->proto &&
//             origin_pkt.dst_port == pkt->dst_port &&
//             origin_pkt.src_port == pkt->src_port)
//         {
//             index = i;
//             break;
//         }
//     }

//     if (index >= 0)
//     {
//         if (md->topks[index].value < median)
//         {
//             md->topks[index].value = median;
//             md->topks[index].tuple = *pkt;
//         }
//         else
//         {
//             return;
//         }
//     }
//     else
//     {
//         // The element is not in the array, let's insert a new one.
//         // What I do is to insert in the last position, and then sort the array
//         // 如果查找不到对应的pkt,就将在最后的数组元素，赋中位数值（模拟堆）
//         if (md->topks[_HEAP_SIZE - 1].value < median)
//         {
//             md->topks[_HEAP_SIZE - 1].value = median;
//             md->topks[_HEAP_SIZE - 1].tuple = *pkt;
//         }
//         else
//         {
//             return;
//         }
//     }
//     insertionSort(md);
// }
// // 求末尾0的个数
// static uint32_t trailing_zeros(uint32_t V)
// {
//     V = V - (V & (V - 1));
//     return (((V & 0xFFFF0000) != 0 ? (V &= 0xFFFF0000, 16) : 0) | ((V & 0xFF00FF00) != 0 ? (V &= 0xFF00FF00, 8) : 0) | ((V & 0xF0F0F0F0) != 0 ? (V &= 0xF0F0F0F0, 4) : 0) | ((V & 0xCCCCCCCC) != 0 ? (V &= 0xCCCCCCCC, 2) : 0) | ((V & 0xAAAAAAAA) != 0));
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
        bpf_trace_printk("Error! Invalid metadata.\n");
        goto DROP;
    }

    uint32_t layerhash = MurmurHash3_x86_32(&pkt, sizeof(pkt), 0xdeadbeef) % _NM_LAYERS;
    // always insert into layer 0, set least significant bit to 0 (we count from right)
    // 设layerhash为0

    // struct countsketch *cm;
    // cm = ns_um.lookup(&max_l);
    // if (!cm)
    // {
    //     bpf_trace_printk("Invalid entry in the countsketch sketch\n");
    //     goto DROP;
    //
    struct pkt_5tuple pkt5;
    __u32 hash41 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 1);
    __u32 target_idx41 = hash41 & (COLUMNS - 1);
    // We should probably split the coin here to swap the sign for the countsketch4 implementation
    // 小于2^n的，CHECK_BIT(hash4, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash4, n)为0
    __u32 *val41 = countsketch41.lookup(&target_idx41);
    if (val41)
    {
        if (CHECK_BIT(hash41, 31))
        {

            (*val41)++;
        }
        else
        {
            (*val41)--;
        }
    }

    __u32 hash42 = MurmurHash3_x86_32(&pkt, sizeof(pkt), 2);
    __u32 target_idx42 = hash42 & (COLUMNS - 1);
    // We should probably split the coin here to swap the sign for the countsketch4 implementation
    // 小于2^n的，CHECK_BIT(hash4, n)为0，2*2^n ~ 3*2^n CHECK_BIT(hash4, n)为0
    __u32 *val42 = countsketch42.lookup(&target_idx42);
    if (val42)
    {
        if (CHECK_BIT(hash42, 31))
        {

            (*val42)++;
        }
        else
        {
            (*val42)--;
        }
    }
    // bpf_probe_read_kernel(&pkt, sizeof(pkt), &pkt5);
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
    // int median = query_sketch(cm, &pkt, sizeof(pkt));
    // int value = median;

    // insert_into_heap(cm, value, &pkt);


    NO_TEAR_INC(md->drop_cnt);

    return bpf_redirect(5, 0);

DROP:;
    return XDP_DROP;
}

// This is only used when the action is redirect
int xdp_dummy(struct xdp_md *ctx)
{
    return XDP_PASS;
}
