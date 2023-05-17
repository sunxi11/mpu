import ctypes
from bcc import BPF
from bcc import libbcc
import numpy as np
import pyroute2
import time
import sys
import argparse
import resource
from ctypes import *
import socket
import heapq
import ipaddress
import copy
from multiprocessing import Process 
import os

FAST_HASH_FILE = f"{sys.path[0]}/../src/hash_lib/libfasthash.so"
LOOKUP3_HASH_FILE = f"{sys.path[0]}/../src/hash_lib/liblookup3.so"

SEED_HASHFN1 = 0x2d31e867
SEED_HASHFN2 = 0x6ad611c4
SEED_HASHFN3 = 0x00000000
SEED_HASHFN4 = 0xffffffff

CS_ROWS = 4
CS_COLUMNS = 65536
hash_k = 3
# This should be a power of two to avoid the module operation on the data plane
# MAX_GEOSAMPLING_SIZE = 1048576
# MAX_GEOSAMPLING_SIZE = 32768
MAX_GEOSAMPLING_SIZE = 4096

MAX_HEAP_ENTRIES = 3000000

flags = 0

class Pkt5Tuple(ctypes.Structure):
    """ creates a struct to match pkt_5tuple """
    _pack_ = 1
    _fields_ = [('src_ip', ctypes.c_uint32),
                ('dst_ip', ctypes.c_uint32),
                ('src_port', ctypes.c_uint16),
                ('dst_port', ctypes.c_uint16),
                ('proto', ctypes.c_uint8)]

    def __str__(self):
        str = f"Source IP: {ipaddress.IPv4Address(socket.ntohl(self.src_ip))}\n"
        str += f"Dest IP: {ipaddress.IPv4Address(socket.ntohl(self.dst_ip))}\n"
        str += f"Source Port: {socket.ntohs(self.src_port)}\n"
        str += f"Dst Port: {socket.ntohs(self.dst_port)}\n"
        str += f"Proto: {self.proto}\n"
        return str
def get_cycles():
    cmd = "sudo bpftool prog profile name xdp_prog1 duration 10 cycles"
    str_1 = os.popen(cmd).read()
    str_1 = str_1.replace('\n','')
    str_1 = str_1.replace('\r','')
    str_1 = str_1.split(' ')
    num = []
    for i in str_1:
        if i!='' and i[0]>='0' and i[0]<='9':
            num.append(int(i))
    outputfn="cycles/mix_5.log"
    with open(outputfn, 'a+') as f:
            f.write(str(int(num[1]/num[0]))+'\n')



def print_dropcnt(cmd):
    dropcnt = b.get_table("dropcnt")
    prev = [0]

    if len(cmd) < 2 or not cmd[1].isdigit():
        print("Second argument should be a number")
        return

    rates = []
    final_count = int(cmd[1])
    count = 0
    print("Reading dropcount")
    while count < final_count:
        for k in dropcnt.keys():
            array_val = dropcnt.getvalue(k)
            val = 0
            for elem in array_val:
                val += elem.drop_cnt
            i = k.value
            if val:
                delta = val - prev[i]
                prev[i] = val
                rates.append(delta)
                print("{}: {} pkt/s".format(i, delta))
        count+=1
        time.sleep(1)
    return max(rates)

def print_help():
    print("\nFull list of commands")
    print("read <N>: \tread the dropcount value for N seconds")
    print("quit: \t\texit and detach the eBPF program from the XDP hook")
    print("help: \t\tprint this help")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='eBPF Nitrosketch implementation')
    parser.add_argument("-i", "--interface", required=True, type=str, help="The name of the interface where to attach the program")
    #parser.add_argument("-m", "--mode", choices=["NATIVE", "SKB", "TC"], default="NATIVE", type=str,
    #                    help="The default mode where to attach the XDP program")
    #parser.add_argument("-p", "--probability", required=True, type=float, help="The update probability of the sketch")
    parser.add_argument("-a", "--action", choices=["DROP", "REDIRECT"], default="DROP", type=str, help="Final action to apply")
    parser.add_argument("-o", "--output-iface", type=str, help="The output interface where to redirect packets. Valid only if action is REDIRECT")
    parser.add_argument("-r", "--read", type=int, default=12,help="Read throughput after X time and print result")
    parser.add_argument("-s", "--seed", type=int, help="Set a specific seed to use")
    #parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("-m", "--rows", required=False, default=CS_ROWS,type=int, help="The rows of the sketch")
    parser.add_argument("-n", "--colomns", required=False, default=CS_COLUMNS ,type=int,help="The colomns of the sketch")
    
    args = parser.parse_args()

    mode = "NATIVE"
    device = args.interface
    #probability = args.probability
    action = args.action

    if action == "REDIRECT":
        if hasattr(args, "output_iface"):
            ip = pyroute2.IPRoute()
            out_idx = ip.link_lookup(ifname=args.output_iface)[0]
        else:
            print("When the action is REDIRECT you need to set the output interface")
            exit()

    fasthash_functions = CDLL(FAST_HASH_FILE)
    lookup3_functions = CDLL(LOOKUP3_HASH_FILE)

    fasthash_functions.fasthash32.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32]
    fasthash_functions.fasthash32.restype = ctypes.c_uint32
    lookup3_functions.hashlittle.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32]
    lookup3_functions.hashlittle.restype = ctypes.c_uint32

    maptype = "percpu_array"
    if mode == "TC":
        hook = BPF.SCHED_CLS
    elif mode == "SKB":
        hook = BPF.XDP
        flags |= (1 << 1)
    else:
        hook = BPF.XDP

    if hook == BPF.XDP:
        ret = "XDP_DROP"
        ctxtype = "xdp_md"
    else:
        ret = "TC_ACT_SHOT"
        ctxtype = "__sk_buff"

    custom_cflags = ["-w", f"-DRETURNCODE={ret}", f"-DCTXTYPE={ctxtype}", f"-DMAPTYPE=\"{maptype}\""]
    custom_cflags.append(f"-I{sys.path[0]}/ebpf/")
    custom_cflags.append(f"-I{sys.path[0]}/ebpf/nitrosketch")
    custom_cflags.append("-I/usr/include/linux")

    #update_probability = np.uint32((np.iinfo(np.uint32).max * probability))

    #custom_cflags.append(f"-DUPDATE_PROBABILITY={update_probability}")
    custom_cflags.append(f"-DMAX_GEOSAMPLING_SIZE={MAX_GEOSAMPLING_SIZE}")
    custom_cflags.append(f"-D_CS_ROWS={args.rows}")
    custom_cflags.append(f"-D_CS_COLUMNS={args.colomns}")
    custom_cflags.append(f"-D_MAX_HEAP_ENTRIES={MAX_HEAP_ENTRIES}")
    custom_cflags.append(f"-D_K={hash_k}")
    
    if action == "DROP":
        custom_cflags.append("-D_ACTION_DROP=1")
    else:
        custom_cflags.append("-D_ACTION_DROP=0")
        custom_cflags.append(f"-D_OUTPUT_INTERFACE_IFINDEX={out_idx}")

    # load BPF program
    b = BPF(src_file=f"{sys.path[0]}/ebpf/new/bloomfilter/mix_5.h", cflags=custom_cflags, device=None)

    # Initialization should be always done before the program is loaded on the interface
    # otherwise the geo sampling could have wrong values
    if args.seed is not None:
        np.random.seed(seed=args.seed)
    fn = b.load_func("xdp_prog1", hook, None)
   
    b.attach_xdp(device, fn, flags)
    p = Process(target=get_cycles)
    # 启动子进程
    p.start()

    try:
        line = f"read {args.read}"
        line = line.rstrip("\n").split(" ")
        time.sleep(5)
        res = print_dropcnt(line)
        print(res)
    except KeyboardInterrupt:
        print("Keyboard interrupt")

    print("Removing filter from device")
   
    b.remove_xdp(device, flags)
    b.cleanup()

