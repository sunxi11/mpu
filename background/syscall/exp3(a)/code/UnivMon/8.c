#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

#include <iostream>
#include <unordered_map>
#include <string>
#include <cstring>
#include <fstream>
#include <time.h>
#include <set>

#include <cinttypes>
#include "Univmon.h"

using namespace std;
/*
 *以太网帧的首部
 */
typedef struct ethernet
{
    u_char host1[6];
    u_char host2[6];
    u_short type;
} Ethernet;

/* IPv4 首部 */
typedef struct ip_header
{
    u_char ver_ihl;         // 版本 (4 bits) + 首部长度 (4 bits)
    u_char tos;             // 服务类型(Type of service)
    u_short tlen;           // 总长(Total length)
    u_short identification; // 标识(Identification)
    u_short flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
    u_char ttl;             // 存活时间(Time to live)
    u_char proto;           // 协议(Protocol)
    u_short crc;            // 首部校验和(Header checksum)
    u_int saddr;            // 源地址(Source address)
    u_int daddr;            // 目的地址(Destination address)
} Ip_Header;

typedef struct iphdr
{
    unsigned char version;
    unsigned char tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char ttl;
    unsigned char proto;
    unsigned short check;
    unsigned int saddr;
    unsigned int daddr;
    /*The options start here. */
} Ip_header;

/* UDP 首部*/
typedef struct udp_header
{
    unsigned short sport; // 源端口(Source port)
    unsigned short dport; // 目的端口(Destination port)
    unsigned short len;   // UDP数据包长度(Datagram length),the minimum is 8
    unsigned short crc;   // 校验和(Checksum)
} Udp_header;

/*TCP首部*/
typedef struct tcp_header
{

    u_short sport;
    u_short dPort;
    unsigned int uiSequNum;
    unsigned int uiAcknowledgeNum;
    u_short sHeaderLenAndFlag;
    u_short sWindowSize;
    u_short sCheckSum;
    u_short surgentPointer;
} Tcp_header;

struct fivetuple
{
    unsigned int saddr; // 源地址(Source address)
    unsigned int daddr; // 目的地址(Destination address)
    unsigned short sport;
    unsigned short dport;
    unsigned char proto; // 协议(Protocol)
} __attribute__((packed, aligned(1)));

int pkt_cnt = 10000;
int pkt_total = 10000;
long long time_total_ns = 0;
long long cycle_total = 0;

static inline uint64_t rdtsc()
{
    unsigned int lo, hi;
    __asm__ __volatile__("rdtsc"
                         : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t get_time()
{
    struct timespec time1 = {0, 0};
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &time1);
    uint64_t ns = time1.tv_sec * 1000000000 + time1.tv_nsec;
    return ns;
}

// void *runner(void *param)
// {
//     time_t temp;
//     while (1)
//     {
//         time(&temp);
//         if (temp - begin_time > 0)
//         {
//             printf("---------------------------------------------\n");
//             printf("当前总网速：%.2f kb/s \n", count_of_bytes / 1024.0);
//             printf("TCP协议占用网速：%.2f kb/s \n", tcp_count / 1024.0);
//             printf("UDP协议占用网速：%.2f kb/s \n", udp_count / 1024.0);
//             printf("---------------------------------------------\n");
//             count_of_bytes = 0;
//             tcp_count = 0;
//             udp_count = 0;
//             begin_time = temp;
//         }
//     }
// }
fivetuple *ft = (fivetuple *)malloc(sizeof(fivetuple));

UnivMon um1 = UnivMon(873812);
UnivMon um2 = UnivMon(873812);
UnivMon um3 = UnivMon(873812);
UnivMon um4 = UnivMon(873812);
UnivMon um5 = UnivMon(873812);
UnivMon um6 = UnivMon(873812);
UnivMon um7 = UnivMon(873812);
UnivMon um8 = UnivMon(873812);

void got_packet(u_char *argv, const struct pcap_pkthdr *header, const u_char *packet)
{

    int start_cycle = rdtsc();
    uint64_t time_start = get_time();
    Ethernet *ethernet = (Ethernet *)(packet);

    Ip_header *ip = (Ip_header *)(packet + sizeof(Ethernet));
    udp_header *udp = (udp_header *)(packet + sizeof(Ip_header));
    // 需要malloc,否则会有segment fault

    memset(ft, 0, sizeof(fivetuple));
    ft->saddr = ip->saddr;
    ft->daddr = ip->daddr;
    ft->sport = udp->sport;
    ft->dport = udp->dport;
    ft->proto = ip->proto;

    // Nitrosketch ns = Nitrosketch(65536, 0.5);
    // ns.insert(ft, sizeof(fivetuple));

    um1.insert(ft, sizeof(fivetuple));
    um2.insert(ft, sizeof(fivetuple));
    um3.insert(ft, sizeof(fivetuple));
    um4.insert(ft, sizeof(fivetuple));
    um5.insert(ft, sizeof(fivetuple));
    um6.insert(ft, sizeof(fivetuple));
    um7.insert(ft, sizeof(fivetuple));
    um8.insert(ft, sizeof(fivetuple));

    uint64_t time_end = get_time();
    int end_cycle = rdtsc();

    time_total_ns += (time_end - time_start);
    cycle_total += (end_cycle - start_cycle);
    if (pkt_cnt)
        pkt_cnt--;
    else
    {
        printf("%lld\n", time_total_ns);
        long long res = 10000000000000 / time_total_ns;
        long long cycle_res = cycle_total / pkt_total;
        printf("throughoutput:%lld \n", res);
        printf("avg cycles/packet:%lld \n", cycle_res);
        exit(0);
    }

    // printf("%d ns/packet\n", time_end - time_start);
}

int main()
{

    pthread_t tid;
    pthread_attr_t attr;

    /*get our device name*/
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    // dev = pcap_lookupdev(errbuf);
    dev = "ens4f0";
    printf("Device: %s\n", dev); /*print our device name*/

    /*open device and sniff
     *pcap_t *pcap_open_dev(char*device,int snaplen,int promisc,int to_ms,char*errbuf);
     *
     */
    pcap_t *open_dev = pcap_open_live(dev, 65535, 1, 0, errbuf);
    if (!open_dev)
    {
        printf("open device failed: %s", errbuf);
    }

    /*filter communication
     *pcap_compile(pcap_t *p,struct bpf_program *fp,char *str,int optimize,bpf_u_int32 netmask)
     *int pcap_setfilter(pcap_t *p, struct bpf_program *fp)
     */

    struct bpf_program filter;
    // char filter_exp[] = "port 80"; /*filter expressiong*/
    char filter_exp[] = ""; /*filter expressiong*/
    bpf_u_int32 mask;       /*net mask*/
    pcap_compile(open_dev, &filter, filter_exp, 0, mask);
    pcap_setfilter(open_dev, &filter);

    /*sniff
     *u_char *pcap_next(pcap_t *p,pcap_pkthdr *h)
     *int pcap_loop(pcap_t *p,int cnt,pcap_hander callback,u_char *user)
     */

    // pthread_attr_init(&attr);
    // pthread_create(&tid, &attr, runner, NULL);

    int id = 0;

    pcap_loop(open_dev, -1, got_packet, (u_char *)&id);

    pcap_close(open_dev);
    // pthread_join(tid, NULL);

    return 0;
}
