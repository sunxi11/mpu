#include "countmin.h"

void CountMin::update(u_int32_t srcIP, u_int32_t dstIP, int inc)
{
    // u_char * buf = new u_char[m];
    // u_char * p = (u_char * )&data;
    // for (unsigned i = 0; i < m; i ++)
    // {
    //     buf[i] = p[i % 4];
    //     // printf("%d\n", buf[i]);
    // }

    for (int i = 0; i < m; i ++) {
        u_int64_t j = two_tuple_sketch_hash(srcIP, dstIP, i, n); // crc32(buf, i + 1) % n;
        u_int64_t newval = counters[i][j] + inc;
        // TODO: resolve this limitation
        if (newval >= 0xffffffff) newval = 0xffffffff;
        counters[i][j] = (u_int32_t)newval;
    }
}

u_int32_t CountMin::query(u_int32_t srcIP, u_int32_t dstIP)
{
    // u_char * buf = new u_char[m];
    // u_char * p = (u_char * )&data;
    // for (unsigned i = 0; i < m; i ++)
    // {
    //     buf[i] = p[i % 4];
    //     // cout << buf[i] << endl;
    // }
    u_int32_t res = 0xffffffff;
    for (int i = 0; i < m; i ++)
    {
        u_int64_t j = two_tuple_sketch_hash(srcIP, dstIP, i, n); // crc32(buf, i + 1) % n;
//        cout << j << " ";
        res = min(res, counters[i][j]);
    }// cout << endl;
    return res;
}
