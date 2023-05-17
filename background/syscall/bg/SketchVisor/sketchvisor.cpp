#include "sketchvisor.h"

void SketchVisor::update(u_int32_t srcIP, u_int32_t dstIP) {
    bool update_cm = false;
    u_int64_t h = two_tuple_sketch_hash(srcIP, dstIP, 0, 4);
    if (h <= 1) update_cm = false; // p(goto fastpath) = 0.4
    else update_cm = true; // p(goto normal path) = 0.6

    if (update_cm) {
        for (int i = 0; i < m; i ++) {
            u_int64_t j = two_tuple_sketch_hash(srcIP, dstIP, i, n);
            u_int64_t newval = counters[i][j] + 1;
            // TODO: resolve this limitation
            if (newval >= 0xffffffff) newval = 0xffffffff;
            counters[i][j] = (u_int32_t)newval;
        }
    } else {
        uint64_t combined_IP = combine_IPs(srcIP, dstIP);
        twoTuple_t* key = from_uint64_to_twotpl(combined_IP);
        std::map<twoTuple_t, u_int32_t>::iterator it = fastpath_htbl.find(*key);
        if (it != fastpath_htbl.end()) {
            it->second += 1;
        } else {
            fastpath_htbl.insert(std::make_pair(*key, 1));
        }
    }
}

u_int32_t SketchVisor::query(u_int32_t srcIP, u_int32_t dstIP) {
    // find fastpath
    uint64_t combined_IP = combine_IPs(srcIP, dstIP);
    twoTuple_t* key = from_uint64_to_twotpl(combined_IP);
    std::map<twoTuple_t, u_int32_t>::iterator it = fastpath_htbl.find(*key);
    if (it != fastpath_htbl.end()) {
        return it->second;
    }

    // find normal path
    u_int32_t res = 0xffffffff;
    for (int i = 0; i < m; i ++) {
        u_int64_t j = two_tuple_sketch_hash(srcIP, dstIP, i, n); 
        res = min(res, counters[i][j]);
    }
    return res;
}
