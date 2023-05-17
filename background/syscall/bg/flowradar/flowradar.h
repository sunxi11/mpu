#ifndef FlowRadar_h
#define FlowRadar_h

#include <iostream>
#include <map>
#include <vector>
#include <algorithm>
#include <cstring>
#include <string>
#include <string.h>

#include "bloomfilter.h"
#include "murmur3.h"

using namespace std;

struct FRBucket
{
    uint64_t FlowXOR;
    uint32_t FlowCount;
    uint32_t PacketCount;
    FRBucket()
    {
        FlowXOR = 0;
        FlowCount = 0;
        PacketCount = 0;
    }
};

class FlowRadar
{
private:
    int bf_k, ct_k;
    u_int32_t bf_size_in_bytes;
    u_int32_t ct_size_in_bytes;

    uint32_t w_bf;
    uint32_t w_ct;
    // Hashfamily * hf;
    BloomFilter *bloomfilter;
    vector<FRBucket> countingtable;

public:
    int num_flow = 0;
    FlowRadar(u_int32_t tot_mem, u_int32_t bf_k, u_int32_t ct_k, double bf_size_percentage)
    {
        this->bf_k = bf_k;
        this->ct_k = ct_k;

        // hf = new Hashfamily(ct_k);

        bf_size_in_bytes = tot_mem * bf_size_percentage;
        ct_size_in_bytes = tot_mem * (1 - bf_size_percentage);

        w_bf = bf_size_in_bytes * 8;
        w_ct = ct_size_in_bytes / sizeof(FRBucket);

        bloomfilter = new BloomFilter(w_bf, bf_k);
        countingtable = vector<FRBucket>(w_ct, FRBucket());
        // printf("flowradar init done!:w_ct:%ld\n", countingtable.size());
    }
    void update(struct fivetuple *key)
    {

        bool flag = bloomfilter->query(key);
        if (flag == false)
            bloomfilter->insert(key);
        // printf("%d\n", flag);
        for (unsigned i = 0; i < ct_k; i++)
        {
            unsigned int index = MurmurHash3_x86_32((const void *)key, sizeof(key), i * i);
            index = index % w_ct;
            uint64_t k1, k2;
            k1 = key->saddr;
            k2 = key->daddr;
            uint64_t combined_k = (k1 << 32) + k2;
            // k1 = 1;
            // k2 = 2;

            // printf("%ld -----\n", combined_k);
            // printf("index after mod:%d -----\n", index);
            // int n = countingtable.size();
            // printf("sizeof(key):%ld\n", sizeof(key));

            if (flag == false)
            {

                countingtable[index].FlowXOR ^= combined_k;
                countingtable[index].FlowCount++;
            }
            countingtable[index].PacketCount++;
        }
    }
};

#endif /* FlowRadar_hpp */
