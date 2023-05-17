import psutil
import time

# 获取逻辑CPU核心数量
num_cores = psutil.cpu_count(logical=True)

while True:
    # 获取每个核心的利用率
    core_utilization = psutil.cpu_percent(interval=1, percpu=True)

    # 打印每个核心的利用率
    for i in range(num_cores):
        print(f"CPU Core {i}: {core_utilization[i]}%")

    # 等待一秒钟
    time.sleep(1)

