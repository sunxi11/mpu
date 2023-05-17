#include <iostream>
#include <cstring>
#include <vector>
#include <string.h>
#include <algorithm>

#include "murmur3.h"

using namespace std;

struct fivetuple
{
    unsigned int saddr; // 源地址(Source address)
    unsigned int daddr; // 目的地址(Destination address)
    unsigned short sport;
    unsigned short dport;
    unsigned char proto; // 协议(Protocol)
} __attribute__((packed, aligned(1)));

template <u_int64_t keylen, int level> // keylen in bytes
class CountSketch
{
private:
    int memory_in_bytes = 0;

    int w = 0;
    int *counters[level] = {NULL};

    // BOBHash32* hash[level] = {NULL};
    // BOBHash32* sign_hash[level] = {NULL};

public:
    CountSketch(int memory_in_bytes)
    {
        this->memory_in_bytes = memory_in_bytes;

        w = memory_in_bytes / level / 4;

        srand(time(0));

        for (int i = 0; i < level; i++)
        {
            counters[i] = new int[w];
            // hash[i] = new BOBHash32(rand() % MAX_PRIME32);
            // sign_hash[i] = new BOBHash32(rand() % MAX_PRIME32);
            memset(counters[i], 0, sizeof(int) * w);
        }
    }

    void insert(struct fivetuple *key, int f = 1) //(uint8_t *key, int f = 1)
    {
        for (int i = 0; i < level; ++i)
        {
            // int index = (hash[i]->run((const char*)key, keylen)) % w;
            // int sign = (sign_hash[i]->run((const char*)key, keylen)) % 2;

            int index = MurmurHash3_x86_32((const void *)key, sizeof(key), i * i) % w;
            int sign = MurmurHash3_x86_32((const void *)key, sizeof(key), i * i) % 2;

            counters[i][index] += sign ? f : -f;
        }
    }

    int query(struct fivetuple *key) //(uint8_t *key)
    {
        int result[level] = {0};
        for (int i = 0; i < level; i++)
        {
            // int index = (hash[i]->run((const char*)key, keylen)) % w;
            // int sign = (sign_hash[i]->run((const char*)key, keylen)) % 2;

            int index = MurmurHash3_x86_32((const void *)key, sizeof(key), i * i) % w;
            int sign = MurmurHash3_x86_32((const void *)key, sizeof(key), i * i) % 2;

            result[i] = sign ? counters[i][index] : -counters[i][index];
        }

        sort(result, result + level);

        int mid = level / 2;
        int ret;
        if (level % 2 == 0)
            ret = (result[mid] + result[mid - 1]) / 2;
        else
            ret = result[mid];

        return ret;
    }
};
