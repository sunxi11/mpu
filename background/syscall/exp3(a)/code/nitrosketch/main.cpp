#include <iostream>
#include <unordered_map>
#include <string>
#include <cstring>
#include <fstream>
#include <time.h>
#include <set>

#include "ideal.h"
#include "countmin.h"
#include "elasticsketch.h"
#include "flowradar.h"
#include "mvsketch.h"
#include "hashpipe.h"
#include "univmon.h"
#include "countsketch.h"
#include "countbloomfilter.h"
#include "sketchvisor.h"
//#include "sketchlearn.h"

#include <cinttypes>
#include "twotuple.h" // which includes "Pktextract.h"
#include "parameter.h"
#include "MurmurHash3.h"

using namespace std;

fiveTuple_t Pktbuf_fivetpl[MAX_PKT_CNT];
twoTuple_t Pktbuf_twotpl[MAX_PKT_CNT];
int Pktcnt = -1;

struct testNode {
    int tp, tn, fp ,fn;
    testNode() { tp = 0; tn = 0; fp = 0; fn = 0; }
    void printFP() {
        cout << "FP : " << fp << endl;
    }
    void printFPR() {
        printf("FPR : %.2lf%%\n", 1.0 * fp / (fp + tn) * 100);
    }
    void printFN() {
        cout << "FN : " << fn << endl;
    }
    void printFNR() {
        printf("FNR : %.2lf%%\n", 1.0 * fn / (fn + tp) * 100);
    }
    void printPrecision() {
        printf("Precision : %.2lf%%\n", 1.0 * tp / (tp + fp) * 100);
    }
    void printRecall() {
        printf("Recall : %.2lf%%\n", 1.0 * tp / (tp + fn) * 100);
    }
    void printfF1score() {
        double Precision = 1.0 * tp / (tp + fp);
        double Recall = 1.0 * tp / (tp + fn);
        printf("F1 Score : %.2lf\n", 2 * Precision * Recall / (Precision + Recall));
    }
};

double calculate_relative_error(uint64_t measure, uint64_t actual) {
    if (actual == 0) {
        printf("Error: actual==0\n");
        return -1;
    }
    uint64_t delta = 0;
    if (measure > actual) delta = measure-actual;
    else delta = actual-measure;
    double ans = (delta*1.0/actual*1.0)*1.0;
    return ans;
}

double calculate_mean_relative_error(std::vector<uint64_t>& measure_arr, std::vector<uint64_t>& actual_arr) {
    double ans = 0;
    if (measure_arr.size() != actual_arr.size()) {
        printf("Error: measure_arr.size() != actual_arr.size()\n");
        return -1;
    }
    double accumulator = 0;
    for (int i = 0; i < measure_arr.size(); i++) {
        accumulator += calculate_relative_error(measure_arr[i], actual_arr[i]);
    }
    ans = (accumulator*1.0/measure_arr.size()*1.0)*1.0;
    return ans;
}

int main() {
    srand((int)time(0));

    int cnt = 0;

    std::set<uint32_t> ip_addresses;

    if (method == 0) {
        Pktextracter pe;
        pe.extract_form_file(pcap_file_path, Pktbuf_fivetpl, Pktcnt);

        for (int i = 0; i < pe.pktCounter; i++) {
            twoTuple_t* twotpl_p = convert_fivetpl_to_twotpl(&Pktbuf_fivetpl[i]);
            Pktbuf_twotpl[i] = *twotpl_p;
            ip_addresses.insert(Pktbuf_twotpl[i].srcIP);
            ip_addresses.insert(Pktbuf_twotpl[i].dstIP);
            //printf("%" PRIu32 "=>%" PRIu32 "\n", Pktbuf_twotpl[i].srcIP, Pktbuf_twotpl[i].dstIP);
        }
        
        cnt = pe.pktCounter;

    } else if (method == 1) {
        vector<twoTuple_t> arr;
        cnt = extract_twotpl_from_file(twotpl_file_path, arr);
        printf("Packet number: %d\n", cnt);
        for (int i = 0; i < cnt; i++) {
            Pktbuf_twotpl[i] = arr[i];
            ip_addresses.insert(Pktbuf_twotpl[i].srcIP);
            ip_addresses.insert(Pktbuf_twotpl[i].dstIP);
        }
    }

    // parameters for testing MTP

    double loss_rate = 0.5535;
    int cnt_with_loss = cnt-int(cnt*loss_rate);

    // ss
    H = int(ip_addresses.size()*0.005);
    // ddos
    //H = int(cnt*0.005);
    // hh
    //H = 0.0002*cnt;
    //H = H/3;
    // gi
    // H = 3333;

    printf("Threshold:%d, cnt_with_loss:%d\n",H,cnt_with_loss);

    // creat sketches

    Ideal ideal;
    set<twoTuple_t> realAns;

    // CountMin Sketch with 12 rows
    CountMin cm = CountMin(36, TOTAL_MEM);
    testNode cmTestNode = testNode();
    set<twoTuple_t> cmAns;

    CountMin cm2 = CountMin(36, TOTAL_MEM);
    testNode cmTestNode2 = testNode();
    set<twoTuple_t> cmAns2;

    // FlowRadar has 6 hash functions in both bloomfilter and countingtable
    // Bloom Filter 3 hash, Sketch 3 hash, Bloom Filter 20% memory
    FlowRadar fr = FlowRadar(TOTAL_MEM, 3, 3, 0.2);
    testNode frTestNode = testNode();
    map<twoTuple_t, uint32_t> frDict;
    set<twoTuple_t> frAns;

    FlowRadar fr2 = FlowRadar(TOTAL_MEM, 3, 3, 0.2);
    testNode frTestNode2 = testNode();
    map<twoTuple_t, uint32_t> frDict2;
    set<twoTuple_t> frAns2;

    // ElasticSketch with 10 HeavyBuckets (size_HeavyPart/tot_mem = 1/4 in their demo)
    ElasticSketch es(1000, 8, TOTAL_MEM);
    testNode esTestNode = testNode();
    set<twoTuple_t> esAns;

    ElasticSketch es2(1000, 8, TOTAL_MEM);
    testNode esTestNode2 = testNode();
    set<twoTuple_t> esAns2;

    // Count Sketch with 8 rows
    CountSketch<8, 8> cs(TOTAL_MEM);
    testNode csTestNode = testNode();
    set<twoTuple_t> csAns;

    CountSketch<8, 8> cs2(TOTAL_MEM);
    testNode csTestNode2 = testNode();
    set<twoTuple_t> csAns2;

    // Univmon with 12 CountHeaps
    // param : <key length in bytes, total memary in bytes, count of CountHeap deafult 14>
    // for modifying k, see "Univmon.h" line 29
    // there will raise an error when the size of CountHeaps is larger than total memory, choose k carefully

    UnivMon<8, TOTAL_MEM, 12> um;
    testNode umTestNode = testNode();
    map<twoTuple_t, int> umDict;
    set<twoTuple_t> umAns;

    UnivMon<8, TOTAL_MEM, 12> um2;
    testNode umTestNode2 = testNode();
    map<twoTuple_t, int> umDict2;
    set<twoTuple_t> umAns2;

    // inject traffic into sketches

    for (int i = 0; i < cnt; i ++) {
        ideal.update(Pktbuf_twotpl[i].srcIP, Pktbuf_twotpl[i].dstIP, 1);
        cm.update(Pktbuf_twotpl[i].srcIP, Pktbuf_twotpl[i].dstIP, 1);
        fr.update(Pktbuf_twotpl[i].srcIP, Pktbuf_twotpl[i].dstIP, 1);
        es.update(Pktbuf_twotpl[i].srcIP, Pktbuf_twotpl[i].dstIP);
        cs.insert(Pktbuf_twotpl[i].srcIP, Pktbuf_twotpl[i].dstIP, 1);
        um.insert(Pktbuf_twotpl[i].srcIP, Pktbuf_twotpl[i].dstIP);
    }
    
    for (int i = 0; i < cnt-cnt_with_loss; i ++) {
        cm2.update(Pktbuf_twotpl[i].srcIP, Pktbuf_twotpl[i].dstIP, 1);
        fr2.update(Pktbuf_twotpl[i].srcIP, Pktbuf_twotpl[i].dstIP, 1);
        es2.update(Pktbuf_twotpl[i].srcIP, Pktbuf_twotpl[i].dstIP);
        cs2.insert(Pktbuf_twotpl[i].srcIP, Pktbuf_twotpl[i].dstIP, 1);
        um2.insert(Pktbuf_twotpl[i].srcIP, Pktbuf_twotpl[i].dstIP);
    }

    for (auto item : ideal.dict) {
        if (item.second >= H) realAns.insert(item.first);
    }


    int total_keynum = realAns.size();
    set<twoTuple_t>::iterator realAns_it;

    // CM

    for (auto item : ideal.dict) {
        uint32_t srcIP = item.first.srcIP;
        uint32_t dstIP = item.first.dstIP;
        if (cm.query(srcIP, dstIP) >= H) cmAns.insert(item.first);
    }

    for (auto item : ideal.dict) {
        uint32_t srcIP = item.first.srcIP;
        uint32_t dstIP = item.first.dstIP;
        if (cm2.query(srcIP, dstIP) >= H) cmAns2.insert(item.first);
    }

    // FR

    fr.dump(frDict);
    for (auto item : frDict)
    {
        if (item.second >= H) frAns.insert(item.first);
    }

    fr2.dump(frDict2);
    for (auto item : frDict2)
    {   
        if (item.second >= H) frAns2.insert(item.first);
    }


    // ES

    for (auto item : ideal.dict)
    {
        uint32_t srcIP = item.first.srcIP;
        uint32_t dstIP = item.first.dstIP;
        if (es.query(srcIP, dstIP) >= H) esAns.insert(item.first);
    }

    // elasticsketch extract flowkeys
    vector<pair<uint64_t, int> > es_keyval_pairs;
    int threshold = 1;
    es.get_heavy_hitters(threshold, es_keyval_pairs);
    vector<pair<uint64_t, int> >::iterator it;
    ofstream es_file;
    es_file.open("elasticsketch_output.txt", ios::out | ios::trunc);
    int es_fp=0, es_tp=0;
    for (it = es_keyval_pairs.begin(); it != es_keyval_pairs.end(); it++) {
        pair<uint64_t, int> kv_pair = *it;
        uint64_t key_uint64 = kv_pair.first;
        twoTuple_t* key_twotpl = from_uint64_to_twotpl(key_uint64);
        es_file << key_twotpl->srcIP << " " << key_twotpl->dstIP << endl;

        if (realAns.find(*key_twotpl) != realAns.end()) es_tp++;
        else es_fp++;
    }
    es_file.close();

    int es_fn = 0;
    for (realAns_it = realAns.begin(); realAns_it != realAns.end(); realAns_it++) {
        twoTuple_t flowkey = *realAns_it;
        if (esAns.find(flowkey) == esAns.end()) {
            es_fn = es_fn+1;
        }
    }

    //cout << "ES False Positive Rate: " << es_fp*1.0/total_keynum*1.0 << endl;
    //cout << "ES False Negative Rate: " << es_fn*1.0/(es_tp+es_fn)*1.0 << endl;    

    for (auto item : ideal.dict)
    {
        uint32_t srcIP = item.first.srcIP;
        uint32_t dstIP = item.first.dstIP;
        if (es2.query(srcIP, dstIP) >= H) esAns2.insert(item.first);
    }

    // CS

    for (auto item : ideal.dict)
    {
        uint32_t srcIP = item.first.srcIP;
        uint32_t dstIP = item.first.dstIP;
        // if (cs.query((u_char *)&item.first) >= H) csAns.insert(item.first);
        if (cs.query(srcIP, dstIP) >= H) csAns.insert(item.first);
    }

    for (auto item : ideal.dict)
    {
        uint32_t srcIP = item.first.srcIP;
        uint32_t dstIP = item.first.dstIP;
        if (cs2.query(srcIP, dstIP) >= H) csAns2.insert(item.first);
    }

    // UM

    um.dump(umDict);
    for (auto item : umDict)
    {
        if (item.second >= H) umAns.insert(item.first);
    }

    um2.dump(umDict2);
    for (auto item : umDict2)
    {
        if (item.second >= H) umAns2.insert(item.first);
    }

    // calculate accuracy

    for (auto item : ideal.dict) {
        twoTuple_t flow = item.first;
        if (realAns.find(flow) != realAns.end()) {
            // CountMin
            if (cmAns.find(flow) != cmAns.end())
                cmTestNode.tp ++;
            else cmTestNode.fn ++;

            // FlowRadar
            if (frAns.find(flow) != frAns.end())
                frTestNode.tp ++;
            else frTestNode.fn ++;

            // ElasticSketch
            if (esAns.find(flow) != esAns.end())
                esTestNode.tp ++;
            else esTestNode.fn ++;

            // CountSketch
            if (csAns.find(flow) != csAns.end())
                csTestNode.tp ++;
            else csTestNode.fn ++;

            // Univmon
            if (umAns.find(flow) != umAns.end())
                umTestNode.tp ++;
            else umTestNode.fn ++;

        } else {
            // CountMin
            if (cmAns.find(flow) != cmAns.end())
                cmTestNode.fp ++;
            else cmTestNode.tn ++;

            // FlowRadar
            if (frAns.find(flow) != frAns.end())
                frTestNode.fp ++;
            else frTestNode.tn ++;

            // ElasticSketch
            if (esAns.find(flow) != esAns.end())
                esTestNode.fp ++;
            else esTestNode.tn ++;

            // CountSketch
            if (csAns.find(flow) != csAns.end())
                csTestNode.fp ++;
            else csTestNode.tn ++;

            // Univmon
            if (umAns.find(flow) != umAns.end())
                umTestNode.fp ++;
            else umTestNode.tn ++;

        }
    }

    for (auto item : ideal.dict) {
        twoTuple_t flow = item.first;
        if (realAns.find(flow) != realAns.end()) {
            // CountMin
            if (cmAns2.find(flow) != cmAns2.end())
                cmTestNode2.tp ++;
            else cmTestNode2.fn ++;

            // FlowRadar
            if (frAns2.find(flow) != frAns2.end())
                frTestNode2.tp ++;
            else frTestNode2.fn ++;

            // ElasticSketch
            if (esAns2.find(flow) != esAns2.end())
                esTestNode2.tp ++;
            else esTestNode2.fn ++;

            // CountSketch
            if (csAns2.find(flow) != csAns2.end())
                csTestNode2.tp ++;
            else csTestNode2.fn ++;

            // Univmon
            if (umAns2.find(flow) != umAns2.end())
                umTestNode2.tp ++;
            else umTestNode2.fn ++;

        } else {
            // CountMin
            if (cmAns2.find(flow) != cmAns2.end())
                cmTestNode2.fp ++;
            else cmTestNode2.tn ++;

            // FlowRadar
            if (frAns2.find(flow) != frAns2.end())
                frTestNode2.fp ++;
            else frTestNode2.tn ++;

            // ElasticSketch
            if (esAns2.find(flow) != esAns2.end())
                esTestNode2.fp ++;
            else esTestNode2.tn ++;

            // CountSketch
            if (csAns2.find(flow) != csAns2.end())
                csTestNode2.fp ++;
            else csTestNode2.tn ++;

            // Univmon
            if (umAns2.find(flow) != umAns2.end())
                umTestNode2.fp ++;
            else umTestNode2.tn ++;

        }
    }


    // output result

    printf("CountMin Statistics:\n");
    cmTestNode.printFN();
    cmTestNode.printFNR();
    cmTestNode.printFP();
    cmTestNode.printFPR();
    cmTestNode.printPrecision();
    cmTestNode.printRecall();
    cmTestNode.printfF1score();
    printf("Relative Error : %.2lf%%\n", (1.0 * realAns.size() - cmTestNode.tp) / realAns.size() * 100);
    printf("\n");

    printf("CountMin2 Statistics:\n");
    cmTestNode2.printFN();
    cmTestNode2.printFNR();
    cmTestNode2.printFP();
    cmTestNode2.printFPR();
    cmTestNode2.printPrecision();
    cmTestNode2.printRecall();
    cmTestNode2.printfF1score();
    printf("Relative Error : %.2lf%%\n", (1.0 * realAns.size() - cmTestNode.tp) / realAns.size() * 100);
    printf("\n");

    printf("FlowRadar Statistics:\n");
    frTestNode.printFN();
    frTestNode.printFNR();
    frTestNode.printFP();
    frTestNode.printFPR();
    frTestNode.printPrecision();
    frTestNode.printRecall();
    frTestNode.printfF1score();
    printf("Relative Error : %.2lf%%\n", (1.0 * realAns.size() - frTestNode.tp) / realAns.size() * 100);
    printf("\n");

    printf("FlowRadar2 Statistics:\n");
    frTestNode2.printFN();
    frTestNode2.printFNR();
    frTestNode2.printFP();
    frTestNode2.printFPR();
    frTestNode2.printPrecision();
    frTestNode2.printRecall();
    frTestNode2.printfF1score();
    printf("Relative Error : %.2lf%%\n", (1.0 * realAns.size() - frTestNode2.tp) / realAns.size() * 100);
    printf("\n");

    printf("ElasticSketch Statistics:\n");
    esTestNode.printFN();
    esTestNode.printFNR();
    esTestNode.printFP();
    esTestNode.printFPR();
    esTestNode.printPrecision();
    esTestNode.printRecall();
    esTestNode.printfF1score();
    printf("Relative Error : %.2lf%%\n", (1.0 * realAns.size() - esTestNode.tp) / realAns.size() * 100);
    printf("\n");

    printf("ElasticSketch2 Statistics:\n");
    esTestNode2.printFN();
    esTestNode2.printFNR();
    esTestNode2.printFP();
    esTestNode2.printFPR();
    esTestNode2.printPrecision();
    esTestNode2.printRecall();
    esTestNode2.printfF1score();
    printf("Relative Error : %.2lf%%\n", (1.0 * realAns.size() - esTestNode2.tp) / realAns.size() * 100);
    printf("\n");

    printf("CountSketch Statistics:\n");
    csTestNode.printFN();
    csTestNode.printFNR();
    csTestNode.printFP();
    csTestNode.printFPR();
    csTestNode.printPrecision();
    csTestNode.printRecall();
    csTestNode.printfF1score();
    printf("Relative Error : %.2lf%%\n", (1.0 * realAns.size() - csTestNode.tp) / realAns.size() * 100);
    printf("\n");

    printf("CountSketch2 Statistics:\n");
    csTestNode2.printFN();
    csTestNode2.printFNR();
    csTestNode2.printFP();
    csTestNode2.printFPR();
    csTestNode2.printPrecision();
    csTestNode2.printRecall();
    csTestNode2.printfF1score();
    printf("Relative Error : %.2lf%%\n", (1.0 * realAns.size() - csTestNode2.tp) / realAns.size() * 100);
    printf("\n");

    printf("Univmon Statistics:\n");
    umTestNode.printFN();
    umTestNode.printFNR();
    umTestNode.printFP();
    umTestNode.printFPR();
    umTestNode.printPrecision();
    umTestNode.printRecall();
    umTestNode.printfF1score();
    printf("Relative Error : %.2lf%%\n", (1.0 * realAns.size() - umTestNode.tp) / realAns.size() * 100);
    printf("\n");

    printf("Univmon2 Statistics:\n");
    umTestNode2.printFN();
    umTestNode2.printFNR();
    umTestNode2.printFP();
    umTestNode2.printFPR();
    umTestNode2.printPrecision();
    umTestNode2.printRecall();
    umTestNode2.printfF1score();
    printf("Relative Error : %.2lf%%\n", (1.0 * realAns.size() - umTestNode2.tp) / realAns.size() * 100);
    printf("\n");

    return 0;
}
