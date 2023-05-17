#ifndef SketchVisor_h
#define SketchVisor_h

#include <iostream>
#include <cstring>
#include <string>
#include <map>
#include <vector>
#include <algorithm>
#include <string.h>

// #include "hash.h"
// #include "twotuple.h"
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
    bool operator <(const fivetuple& other) const
    {
        if (sport < other.sport)        //src_port按升序排序
        {
            return true;
        }
        else if (sport == other.sport)  //src_port相同，按dst_port升序排序
        {
            if(dport < other.dport)
            {
                return true;
            }
            else if(dport == other.dport)//dst_port,src_port相同，比较src_ip
            {
                if(saddr!=other.saddr)
                {
                    return true;
                }
            }
 
        }
        return false;
    } 
} __attribute__((packed, aligned(1)));


class SketchVisor {
public:
    map<struct fivetuple, u_int32_t> fastpath_htbl;
    vector<vector<u_int32_t> > counters;
    u_int64_t m;
    u_int64_t n;
    u_int64_t fastpath_size;
    SketchVisor(u_int64_t m, u_int64_t size, u_int64_t tot_mem)
    {
        this->m = m;
        this->fastpath_size = size;
        this->n = (tot_mem-size*4) / m / CMBUCKET_SIZE;
//        cout << "m=" << this->m << " n=" << this->n << endl;
        counters = vector<vector<u_int32_t> >(m, vector<u_int32_t>(n, 0));
    }
    
    void update(struct fivetuple *key){
        // printf("111111111111111");
        bool update_cm = false;
        uint32_t h = MurmurHash3_x86_32((const void*)key, sizeof(key), 0x11111111);
        if (h <= 1) update_cm = false; // p(goto fastpath) = 0.4
        else update_cm = true; // p(goto normal path) = 0.6
        // printf("111111111111112");
        if (update_cm) {
            for (int i = 0; i < m; i ++) {
                u_int64_t j = MurmurHash3_x86_32((const void*)key, sizeof(key),i*i)%n;
                u_int64_t newval = counters[i][j] + 1;
                // TODO: resolve this limitation
                if (newval >= 0xffffffff) newval = 0xffffffff;
                counters[i][j] = (u_int32_t)newval;
            }
        } else {
            // uint64_t combined_IP = combine_IPs(srcIP, dstIP);
            // twoTuple_t* key = from_uint64_to_twotpl(combined_IP);
            std::map<struct fivetuple, u_int32_t>::iterator it = fastpath_htbl.find(*key);
            if (it != fastpath_htbl.end()) {
                it->second += 1;
            } else {
                fastpath_htbl.insert(std::make_pair(*key, 1));
            }
        }
    }
    // u_int32_t query(u_int32_t srcIP, u_int32_t dstIP);
};

#endif
