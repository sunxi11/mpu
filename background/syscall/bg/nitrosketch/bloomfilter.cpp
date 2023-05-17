#include "bloomfilter.h"

void BloomFilter::insert(u_int32_t srcIP, u_int32_t dstIP)
{
    // u_char * buf = new u_char[k];
    // u_char * p = (u_char * )&data;
    // for (unsigned i = 0; i < k; i ++)
    // {
    //     buf[i] = p[i % 4];
    //     // printf("%d\n", buf[i]);
    // }
    
    for (unsigned i = 0; i < k; i ++)
    {
        // u_int64_t index = hf->getihashval((const u_char *) &data, 4, i) % m;
        //u_int64_t index = crc32(buf, i + 1) % m;
        u_int64_t index = two_tuple_sketch_hash(srcIP, dstIP, i, m);
        bitArray[index] = 1;
    }
}

bool BloomFilter::query(u_int32_t srcIP, u_int32_t dstIP)
{
    bool res = true;
    
    // u_char * buf = new u_char[k];
    // u_char * p = (u_char * )&data;
    // for (unsigned i = 0; i < k; i ++)
    // {
    //     buf[i] = p[i % 4];
    //     // printf("%d\n", buf[i]);
    // }
    
    
    for (unsigned i = 0; i < k; i ++)
    {
        // u_int64_t index = hf->getihashval((const u_char *) &data, 4, i) % m;
        // u_int64_t index = crc32(buf, i + 1) % m;
        u_int64_t index = two_tuple_sketch_hash(srcIP, dstIP, i, m);
        
        if (bitArray[index] == 0)
        {
            res = false;
            break;
        }
    }
    return res;
}
