import os
import time
a = dict()
b = dict()
# times_of_run = 5
app_list = ['./nitro','./um','./skv','./es','./fr','./cbf','./cm','./cs']
num_threads_cmd = ['-l 0-1 -n 2 -- -P -p 1 --rx="(0,0,0,0)(0,1,1,1)" ','-l 0-2 -n 2 -- -P -p 1 --rx="(0,0,0,0)(0,1,1,1)(0,2,2,2)"','-l 0-3 -n 2 -- -P -p 1 --rx="(0,0,0,0)(0,1,1,1)(0,2,2,2)(0,3,3,3)"','-l 0-4 -n 2 -- -P -p 1 --rx="(0,0,0,0)(0,1,1,1)(0,2,2,2)(0,3,3,3)(0,4,4,4)"','-l 0-5 -n 2 -- -P -p 1 --rx="(0,0,0,0)(0,1,1,1)(0,2,2,2)(0,3,3,3)(0,4,4,4)(0,5,5,5)"','-l 0-6 -n 2 -- -P -p 1 --rx="(0,0,0,0)(0,1,1,1)(0,2,2,2)(0,3,3,3)(0,4,4,4)(0,5,5,5)(0,6,6,6)"','-l 0-7 -n 2 -- -P -p 1 --rx="(0,0,0,0)(0,1,1,1)(0,2,2,2)(0,3,3,3)(0,4,4,4)(0,5,5,5)(0,6,6,6)(0,7,7,7)"','-l 0-8 -n 2 -- -P -p 1 --rx="(0,0,0,0)(0,1,1,1)(0,2,2,2)(0,3,3,3)(0,4,4,4)(0,5,5,5)(0,6,6,6)(0,7,7,7)(0,8,8,8)"','-l 0-9 -n 2 -- -P -p 1 --rx="(0,0,0,0)(0,1,1,1)(0,2,2,2)(0,3,3,3)(0,4,4,4)(0,5,5,5)(0,6,6,6)(0,7,7,7)(0,8,8,8)(0,9,9,9)"']
cmd = []
for i in app_list:
    for j in num_threads_cmd:
        tmp_cmd = i+' '+j
        cmd.append(tmp_cmd)
t1 = time.time()

# for i in file_list:
#     res_1 = 0
#     res_2 = 0
    
#     cmd = './'+i+'/'+'1'
#     str_1 = os.popen(cmd).read()
#     str_1 = str_1.replace('\n','')
#     str_1 = str_1.replace('\r','')
#     str_1 = str_1.split(' ')
#     throughoutput = str_1[1].split(':')[1]
#     cycles_per_packet = str_1[3].split(':')[1]
#     throughoutput = int(throughoutput)
#     cycles_per_packet = int(cycles_per_packet)
#     res_1+= throughoutput
#     res_2+= cycles_per_packet
#     time.sleep(2)

for i in cmd:
    str_1 = os.popen('./build'+i).read()
    str_1 = str_1.replace('\n','')
    str_1 = str_1.replace('\r','')
    str_1 = str_1.split(' ')
    # throughoutput = str_1[2].split(':')[1]
    # cycles_per_packet = str_1[3].split(':')[1]
    # print(i+' '+'throughoutput:'+throughoutput + ' cycles_per_packet: '+cycles_per_packet+'\n')
    print(str_1)
    time.sleep(3)
    break;

t2 = time.time()
# print(a)
# print(b)
print(t2-t1)