#ifndef BloomFilter_h
#define BloomFilter_h

#include "hash.h"
#include "murmur3.h"
#include <string.h>

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
    void insert(u_int32_t srcIP, u_int32_t dstIP);
    bool query(u_int32_t srcIP, u_int32_t dstIP);
};

#endif /* BloomFilter_h */
