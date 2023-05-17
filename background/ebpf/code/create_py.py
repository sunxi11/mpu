import os

# 8个sketch的名称
sketchs=['es','counting-bloom-filter','count-min','count','univmon','nitrosketch','flowradar','es2','skv']

# 定义要复制的源文件名和目标文件名前缀
# src_file = '1.py'
cnt=0

# 打开目标文件并修改指定的行
def replace_line(file_path, line_number1, new_line1, line_number2, new_line2):
    # 读取文件中所有行
    with open(file_path, 'r') as file:
        lines = file.readlines()

    # 修改需要替换的行
    lines[line_number1-1] = new_line1 + '\n'
    lines[line_number2-1] = new_line2 + '\n'

    # 将修改后的行重新写回文件中
    with open(file_path, 'w') as file:
        file.writelines(lines)

for sketch in sketchs:
    cnt+=1
    for i in range(8):
        src_file = str(cnt)+'.py'
        new_file      = str(sketch) + '_' + str(i+1)
        dest_file_name = new_file + '.py'
        
        # 定义要添加的行
        outputfn        = '"cycles/' + new_file + '.log"'  # line 64
        output_line = '    outputfn='+outputfn # 注意缩进
    
        load_line = '    b = BPF(src_file=f"{sys.path[0]}/ebpf/new/bloomfilter/'+new_file+'.h", cflags=custom_cflags, device=None)' # line 178
        print(src_file,'==>',dest_file_name)
        # 复制源文件到目标文件
        os.system(f'cp {src_file} {dest_file_name}')  

        replace_line(dest_file_name, 64, output_line, 178, load_line)



for i in range(8):
    new_file      =  'mix_' + str(i+1)
    dest_file_name = new_file + '.py'
    
    # 定义要添加的行
    outputfn        = '"cycles/' + new_file + '.log"'  # line 64
    output_line = '    outputfn='+outputfn # 注意缩进

    load_line = '    b = BPF(src_file=f"{sys.path[0]}/ebpf/new/bloomfilter/'+new_file+'.h", cflags=custom_cflags, device=None)' # line 178

    # 复制源文件到目标文件
    os.system(f'cp {src_file} {dest_file_name}')  

    replace_line(dest_file_name, 64, output_line, 178, load_line)


print('Done')