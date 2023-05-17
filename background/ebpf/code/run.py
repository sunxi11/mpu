import subprocess 


# 8个sketch的名称
sketchs=['count-min','count','counting-bloom-filter','es','flowradar','nitrosketch','skv','univmon', 'mix']
test = sketchs

# para
device='ens4f0'
read_time='15'

output_list=[]


# for sketch in sketchs:
#     for i in range(8):
#         src_file = str(sketch) + '_' + str(i+1)+'.py'
#         output_file= "throughout/" + str(sketch) + '_' + str(i+1) + '.txt'
#         # 每个.py跑三次，并将其输出存入output_list
#         for i in range(3):
#             output_list.append(src_file+'\n')
#             result=subprocess.run(['python3',sketch,'-i',device,'-r',read_time],stdout=subprocess.PIPE,text=True)
#             output_list.append(result.stdout)
#             print(str(i)+': '+sketch+' Done')
#         # 将输出写入文件，供后续处理
#         with open(output_file,'a+') as f:
#             for output in output_list:
#                 f.write(output)
#             f.write('========\n')
#         output_list=[]


for sketch in test:
    for i in range(8):
        src_file = str(sketch) + '_' + str(i+1)+'.py'
        output_file= "throughout/" + str(sketch) + '_' + str(i+1) + '.txt'
        print(src_file, output_file)
        # 每个.py跑三次，并将其输出存入output_list
        for i in range(1):
            output_list.append(src_file+'\n')
            result=subprocess.run(['python3',src_file,'-i',device,'-r',read_time],stdout=subprocess.PIPE,text=True)
            output_list.append(result.stdout)
            print(str(i)+': '+sketch+' Done')
        # 将输出写入文件，供后续处理
        with open(output_file,'a+') as f:
            for output in output_list:
                f.write(output)
            f.write('========\n')
        output_list=[]