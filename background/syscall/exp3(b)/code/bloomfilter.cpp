#include "bloomfilter.h"

void BloomFilter::insert(void *key)
{
    for (unsigned i = 0; i < k; i++)
    {
        // u_int64_t index = hf->getihashval((const u_char *) &data, 4, i) % m;
        // u_int64_t index = crc32(buf, i + 1) % m;
        unsigned int index = MurmurHash3_x86_32(key, sizeof(key), i);
        index = index % m;
        bitArray[index] = 1;
    }
}

bool BloomFilter::query(void *key)
{
    bool res = true;

    // u_char * buf = new u_char[k];
    // u_char * p = (u_char * )&data;
    // for (unsigned i = 0; i < k; i ++)
    // {
    //     buf[i] = p[i % 4];
    //     // printf("%d\n", buf[i]);
    // }

    for (unsigned i = 0; i < k; i++)
    {
        // u_int64_t index = hf->getihashval((const u_char *) &data, 4, i) % m;
        // u_int64_t index = crc32(buf, i + 1) % m;
        // u_int64_t index = MurmurHash3_x86_32(key, i, m);
        unsigned int index = MurmurHash3_x86_32(key, sizeof(key), i);
        index = index % m;
        if (bitArray[index] == 0)
        {
            res = false;
            break;
        }
    }
    return res;
}
