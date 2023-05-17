#ifndef BloomFilter_h
#define BloomFilter_h

#include "hash.h"
#include "murmur3.h"
#include <string.h>

struct fivetuple
{
    unsigned int saddr; // 源地址(Source address)
    unsigned int daddr; // 目的地址(Destination address)
    unsigned short sport;
    unsigned short dport;
    unsigned char proto; // 协议(Protocol)
} __attribute__((packed, aligned(1)));

class BloomFilter
{
private:
    vector<u_int8_t> bitArray;
    u_int32_t m; // The number of bit Array for BloomFilter
    u_int32_t k; // The number of Hash Function
    // Hashfamily * hf;
public:
    BloomFilter(u_int32_t m, u_int32_t k)
    {
        this->m = m;
        this->k = k;
        // hf = new Hashfamily(k);
        bitArray = vector<u_int8_t>(m, 0);
    }
    void insert(struct fivetuple *key)
    {
        for (unsigned i = 0; i < k; i++)
        {
            // u_int64_t index = hf->getihashval((const u_char *) &data, 4, i) % m;
            // u_int64_t index = crc32(buf, i + 1) % m;
            uint32_t index = MurmurHash3_x86_32((const void *)key, sizeof(key), i * i) % m;
            // printf("insert:%d\n", index);
            bitArray[index] = 1;
        }
    }
    bool query(struct fivetuple *key)
    {
        bool res = true;

        for (unsigned i = 0; i < k; i++)
        {
            // u_int64_t index = hf->getihashval((const u_char *) &data, 4, i) % m;
            // u_int64_t index = crc32(buf, i + 1) % m;
            // u_int64_t index = MurmurHash3_x86_32(key, i, m);
            uint32_t index = MurmurHash3_x86_32((const void *)key, sizeof(key), i * i) % m;
            // printf("query:%d\n", index);
            if (bitArray[index] == 0)
            {
                res = false;
                break;
            }
        }
        return res;
    }
};

#endif /* BloomFilter_h */
