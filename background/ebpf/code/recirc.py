from bcc import BPF #1
from bcc.utils import printb

device = "ens4f0" #2
b = BPF(src_file="recirc.h") #3
# b = BPF(src_file="drop.h")
fn = b.load_func("xdp_prog1", BPF.XDP) #4
#fn = b.load_func("xdp_drop_the_world", BPF.XDP)
b.attach_xdp(device, fn, 0) #5

device2 = "ens4f1"
fn2 = b.load_func("xdp_dummy", BPF.XDP)
b.attach_xdp(device2, fn2, 0)

try:
    b.trace_print() #6
except KeyboardInterrupt: #7
    b.remove_xdp(device, 0) #11
    b.remove_xdp(device2, 0)
