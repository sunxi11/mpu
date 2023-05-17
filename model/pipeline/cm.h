#ifndef CM_H_
#define CM_H_

#include <stdint.h>
#include <pthread.h>

#define _WRS_PACK_ALIGN(x) __attribute__((packed, aligned(x)))

#define M 4
#define N 65536
#define cache_size 1000000

struct ipv4_5tuple
{
    uint32_t ip_dst;
    uint32_t ip_src;
    uint16_t port_dst;
    uint16_t port_src;
    uint8_t proto;
}_WRS_PACK_ALIGN(1);

struct ipv4_5tuple_hash
{
    struct ipv4_5tuple ft;
    uint32_t hash[M];
};

struct ipv4_hash
{
    uint32_t index[M];
    uint32_t sign[M];
};






extern uint32_t counters[M][N];

extern struct ipv4_5tuple_hash table_cache[cache_size+10];
extern uint32_t cache_index;

extern struct ipv4_5tuple ft_cache[cache_size+10];
extern uint32_t ft_index;

extern struct ipv4_hash hash_cache[cache_size+10];
extern uint32_t hash_index;

extern pthread_mutex_t mutex;
uint32_t murmur3(const void *key, int len, uint32_t seed);



#endif