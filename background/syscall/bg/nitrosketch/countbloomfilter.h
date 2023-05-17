#include <iostream>
#include <cstring>
#include <vector>
#include <string.h>
#include <algorithm>

#include "hash.h"
#include "murmur3.h"

using namespace std;

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

    void insert(uint32_t srcIP, uint32_t dstIP)
    {
        for (int i = 0; i < k; i++)
        {
            int index = two_tuple_sketch_hash(srcIP, dstIP, i, this->size);
            this->counters[index] += 1;
        }
    }

    uint32_t query(uint32_t srcIP, uint32_t dstIP)
    {
        uint32_t res = 0;
        bool visit = false;
        for (int i = 0; i < this->k; i++)
        {
            int index = two_tuple_sketch_hash(srcIP, dstIP, i, this->size);
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
