import dns.resolver
import dns.reversename
from concurrent.futures import ThreadPoolExecutor
import pandas as pd
import time
import argparse
import pickle
from load_config import load_config
config = load_config()

# load previous file
suspicious_domain_ip_file = config['2_1_get_cdn']['suspicious_domain_ip_file']
ptr_output_file = config['2_1_get_cdn']['ptr_output_file']


with open(suspicious_domain_ip_file, 'rb') as f:
    suspicious_domain_ip = pickle.load(f)
unique_ip = set([item.split('/')[1] for item in list(suspicious_domain_ip)])


# 查询函数
global_counter = 0
def query_ptr(ip):
    global global_counter
    global_counter += 1
    if global_counter % 1000 == 0 or global_counter == 1:
        from datetime import datetime
        # 获取当前时间
        current_time = datetime.now()
        # 将时间格式化为字符串
        formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
        print(global_counter, formatted_time)
        
    resolver = dns.resolver.Resolver()
    try:
        # 获取IP地址的反向DNS名称
        reverse_name = dns.reversename.from_address(ip)
        # 解析PTR记录
        answers = resolver.resolve(reverse_name, 'PTR')
        return ip, [answer.to_text() for answer in answers]
    except Exception as e:
        return ip, str(e)

# 使用 ThreadPoolExecutor 来并行执行查询
def perform_queries(ips, max_workers=50):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(query_ptr, ips)
        return list(results)

#read ip list
ips = unique_ip

# 执行查询并打印结果
start = time.time()
results = perform_queries(ips)


end = time.time()
df=pd.DataFrame(results, columns=['IP', 'PTR'])
import pickle
with open(ptr_output_file, 'wb') as f:
    pickle.dump(df, f)
print("Done! Spend ", end-start, " seconds.")
