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
class CountBloomFilter
{
private:
    int k;
    int size;
    vector<uint32_t> counters;

public:
    CountBloomFilter(int size, int k)
    {
        this->size = size;
        this->k = k;
        this->counters.reserve(this->size);
        std::fill(this->counters.begin(), this->counters.end(), 0);
    }

    void insert(struct fivetuple *key)
    {
        for (int i = 0; i < k; i++)
        {
            int index = MurmurHash3_x86_32((const void *)key, sizeof(key), i * i) % this->size;
            this->counters[index] += 1;
        }
    }

    uint32_t query(struct fivetuple *key)
    {
        uint32_t res = 0;
        bool visit = false;
        for (int i = 0; i < this->k; i++)
        {
            int index = MurmurHash3_x86_32((const void *)key, sizeof(key), i * i) % this->size;
            if (!visit)
            {
                visit = true;
                res = this->counters[index];
            }
            else if (res > this->counters[index])
                res = this->counters[index];
        }
        return res;
    }
};
