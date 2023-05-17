#include "flowradar.h"

void FlowRadar::update(struct fivetuple *key, int val)
{
    bool flag = bloomfilter->query(key);
    if (flag == false)
        bloomfilter->insert(key);

    // u_char * buf = new u_char[ct_k];
    // u_char * p = (u_char * )&key;
    // for (unsigned i = 0; i < ct_k; i ++)
    // {
    //     buf[i] = p[i % 4];
    //     // printf("%d\n", buf[i]);
    // }

    for (unsigned i = 0; i < ct_k; i++)
    {
        // u_int64_t index = hf->getihashval((const u_char*) &key, 4, i) % w_ct;
        // u_int64_t index = crc32(buf, i + 1) % w_ct;
        unsigned int index = MurmurHash3_x86_32((void *)key, sizeof(key), i);
        index = index % w_bf;
        uint64_t k1, k2;
        // key = (struct fivetuple *)key;
        k1 = (uint64_t)key->saddr;
        k2 = (uint64_t)key->daddr;
        uint64_t combined_k = (k1 << 32) + k2;

        if (flag == false)
        {
            countingtable[index].FlowXOR ^= combined_k;
            countingtable[index].FlowCount++;
        }
        countingtable[index].PacketCount++;
    }
}
