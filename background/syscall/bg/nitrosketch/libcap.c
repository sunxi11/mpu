#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

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
    int saddr;              // 源地址(Source address)
    int daddr;              // 目的地址(Destination address)
} Ip_header;

/* UDP 首部*/
typedef struct udp_header
{
    u_short sport; // 源端口(Source port)
    u_short dport; // 目的端口(Destination port)
    u_short len;   // UDP数据包长度(Datagram length),the minimum is 8
    u_short crc;   // 校验和(Checksum)
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

int count = 0, tcp_count = 0, udp_count = 0;
time_t begin;
void *runner(void *param)
{
    time_t temp;
    while (1)
    {
        time(&temp);
        if (temp - begin > 0)
        {
            printf("---------------------------------------------\n");
            printf("当前总网速：%.2f kb/s \n", count / 1024.0);
            printf("TCP协议占用网速：%.2f kb/s \n", tcp_count / 1024.0);
            printf("UDP协议占用网速：%.2f kb/s \n", udp_count / 1024.0);
            printf("---------------------------------------------\n");
            count = 0;
            tcp_count = 0;
            udp_count = 0;
            begin = temp;
        }
    }
}
void got_packet(u_char *argv, const struct pcap_pkthdr *header, const u_char *packet)
{

    int len2 = (int)header->caplen;
    Ethernet *ethernet = (Ethernet *)(packet);
    Ip_header *ip = (Ip_header *)(packet + sizeof(Ethernet));
    if (ip->proto == (u_char)6)
    {
        tcp_count += len2;
    }
    else if (ip->proto == (u_char)17)
    {
        udp_count += len2;
    }
    count += len2;
}

int main()
{

    time(&begin);
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

    pthread_attr_init(&attr);
    pthread_create(&tid, &attr, runner, NULL);

    int id = 0;
    pcap_loop(open_dev, -1, got_packet, (u_char *)&id);
    pcap_close(open_dev);
    pthread_join(tid, NULL);

    return 0;
}
