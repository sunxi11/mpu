#ifndef CountMin_h
#define CountMin_h

#include <iostream>
#include <cstring>
#include <string>
#include <map>
#include <vector>
#include <algorithm>
#include <string.h>

#include "hash.h"
#include "murmur3.h"

#define CMBUCKET_SIZE 4

using namespace std;

class CountMin
{
public:
    vector<vector<u_int32_t>> counters;
    u_int64_t m;
    u_int64_t n;
    CountMin(u_int64_t m, u_int64_t tot_mem)
    {
        this->m = m;
        this->n = tot_mem / m / CMBUCKET_SIZE;
        //        cout << "m=" << this->m << " n=" << this->n << endl;
        counters = vector<vector<u_int32_t>>(m, vector<u_int32_t>(n, 0));
    }

    void update(u_int32_t srcIP, u_int32_t dstIP, int inc);
    u_int32_t query(u_int32_t srcIP, u_int32_t dstIP);
};

#endif /* CountMin_hpp */
