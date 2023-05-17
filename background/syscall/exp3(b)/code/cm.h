#ifndef CountMin_h
#define CountMin_h

#include <iostream>
#include <cstring>
#include <string>
#include <map>
#include <vector>
#include <algorithm>
#include <string.h>

#include "murmur3.h"

#define CMBUCKET_SIZE 4

using namespace std;
struct fivetuple
{
    unsigned int saddr; // 源地址(Source address)
    unsigned int daddr; // 目的地址(Destination address)
    unsigned short sport;
    unsigned short dport;
    unsigned char proto; // 协议(Protocol)
} __attribute__((packed, aligned(1)));
class CountMin
{
public:
    vector<vector<u_int32_t> > counters;
    u_int64_t m;
    u_int64_t n;
    CountMin(u_int64_t m, u_int64_t tot_mem)
    {
        this->m = m;
        this->n = tot_mem / m / CMBUCKET_SIZE;
//        cout << "m=" << this->m << " n=" << this->n << endl;
        counters = vector<vector<u_int32_t> >(m, vector<u_int32_t>(n, 0));
    }
    
    void update(struct fivetuple *key, int inc){
        for (int i = 0; i < m; i ++) {
            u_int64_t j = MurmurHash3_x86_32((const void *)key, sizeof(key), i * i) % n; // crc32(buf, i + 1) % n;
            u_int64_t newval = counters[i][j] + inc;
            if (newval >= 0xffffffff) newval = 0xffffffff;
            counters[i][j] = (u_int32_t)newval;
        }
    }
    u_int32_t query(struct fivetuple *key, u_int32_t dstIP){
        u_int32_t res = 0xffffffff;
        for (int i = 0; i < m; i ++)
        {
            u_int64_t j =  MurmurHash3_x86_32((const void *)key, sizeof(key), i * i) % n; // crc32(buf, i + 1) % n;
    //        cout << j << " ";
            res = min(res, counters[i][j]);
        }// cout << endl;
        return res;
    }
};

#endif /* CountMin_hpp */
