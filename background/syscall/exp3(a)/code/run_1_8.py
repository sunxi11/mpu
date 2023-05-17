import os
import time
file_list = ['CM','CS','CBF','elastic','flowradar', 'SketchVisor','UnivMon' , 'nitrosketch']
a = dict()
b = dict()
times_of_run = 2
times_of_sketch = 9
# file_list = os.listdir()
print(file_list)
# print(100,128)
t1 = time.time()
for i in file_list:
    if i!='run.py' and i!='common' and i!='run_1_8.py' and i!='libcap_res.xlsx':
        for k in range(1,times_of_sketch):
            res_1 = 0
            res_2 = 0
            for j in range(times_of_run):
                cmd = './'+i+'/'+str(k)
                str_1 = os.popen(cmd).read()
                str_1 = str_1.replace('\n','')
                str_1 = str_1.replace('\r','')
                str_1 = str_1.split(' ')
                throughoutput = str_1[1].split(':')[1]
                cycles_per_packet = str_1[3].split(':')[1]
                throughoutput = int(throughoutput)
                cycles_per_packet = int(cycles_per_packet)
                res_1+= throughoutput
                res_2+= cycles_per_packet
                time.sleep(1)
            print(i+'  '+str(k)+'  cycles:'+str(int(res_2/times_of_run))+'  '+'throughput:'+str(int(res_1/times_of_run)))
            with open('res_2.txt','a') as f:
                f.write(i+'  '+str(k)+'  cycles:'+str(res_2/times_of_run)+'  '+'throughput:'+str(int(res_1/times_of_run))+'\n')
    with open('res_2.txt','a') as f:
        f.write('\n')
t2 = time.time()
print(a)
print(b)
print(t2-t1)
            