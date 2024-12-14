from load_config import load_config
import pickle
config = load_config()

domain_file =  config['global']['domain_file']

rb_file = config['1_rbline_ip']['rb_file']
test_file = config['1_rbline_ip']['test_file']

output_suspicious_name = config['1_rbline_ip']['output_suspicious_name']
output_white_name = config['1_rbline_ip']['output_white_name']
output_reverse_name = config['1_rbline_ip']['output_reverse_name']

def load_domain_list(domain_file = domain_file):
    tmp = pd.read_csv(domain_file, header=None)
    domain_list = list(tmp[0])
    domain_list = [f'{item}.' for item in domain_list]
    return domain_list


import os
from LightTree import LTree
import numpy as np
import pandas as pd
from collections import defaultdict, Counter

def produce_rbline(file=rb_file, domain_list = load_domain_list()):

    # produce rbline based on ns sets
    total_a_sets = defaultdict(set)
    
    ltrees = {}
    df = pd.read_csv(file)
    
    native_name = file.split('/')[-1].split('.')[0][2:]
    ltree = LTree()
    ltree.construct_rrp(df)

    for domain in domain_list:
        bl_result = set(ltree.get_final_a_by_query(domain))
        total_a_sets[domain] = bl_result
    return total_a_sets

bl_set = produce_rbline()

# import pickle
# with open(f'{tmp_file}/pickle_white_a_set', 'wb') as f:
#     pickle.dump(bl_set, f)
    
    
# 结构：{resolver: {domain: {date: set(answers)}}}

from collections import defaultdict
import json

def load_test(file=test_file):
    resolver_results = defaultdict(lambda: defaultdict(set))
    sum_line = 0
    date = file.split('_')[-1]  # 从文件名中提取日期
    with open(file, 'r') as f:
        for line in f:
            sum_line += 1
            data = json.loads(line)
            resolver = data['data']['resolver'][:-3]
            domain = data['name']
            answers = data['data'].get('answers', [])
            for answer in answers:
                if answer['type'] == 'A':
                    resolver_results[resolver][domain].add(answer['answer'])
    return resolver_results

resolver_results = load_test()

import pdb
import maxmind
import pdb
import maxmind
def rbline_compare(bl_sets, test_sets, domain_list=load_domain_list()):

    # 1. A record compare
    same_domain = []
    cv1 = [] # baseline is subset of test
    cv2 = [] # test is subset of baseline
    cv3 = [] # baseline & subset != empty
    cv4 = [] # baseline & subset == empty

    ip_suspicious = defaultdict(set)
    ip_ensured = defaultdict(set)
    suspicious_ip_counter = 0
    ensured_ip_counter = 0
    for domain in domain_list:
        # try:
        bl_result = bl_sets[domain]
        test_result = test_sets[domain[:-1]]

        # if bl_result == test_result:
        #     same_domain.append(domain)
        # elif bl_result < test_result:
        #     cv1.append(domain)
        # elif test_result < bl_result:
        #     cv2.append(domain)
        # elif len(bl_result & test_result) != 0:
        #     cv3.append(domain)
        # elif len(bl_result & test_result) == 0:
        #     cv4.append(domain)

        for item in test_result:
            if item not in bl_result:
                ip_suspicious[domain].add(item)
                suspicious_ip_counter += 1
            else:
                ip_ensured[domain].add(item)
                ensured_ip_counter += 1

    print(f'''1. rbline a sets compared results: 
        ensured domain:{len(ip_ensured)}, suspicious domain: {len(ip_suspicious)}
        ensured ip: {ensured_ip_counter}, suspicious ip: {suspicious_ip_counter}''')
    
    
    # 2. maxmind compare 
    maxmind_suspicious = defaultdict(set)
    maxmind_ensured = defaultdict(set)
    maxmind_ensured_counter = 0
    maxmind_suspicious_counter = 0
    for key, item in ip_suspicious.items():
        domain = key
        bl_ips = bl_sets[domain]
        test = item
        bl_props = set()
        for bl_item in list(bl_ips):
            ip_props = maxmind.query_asn(bl_item)
            bl_props.add(ip_props)
        for test_item in list(test):
            test_item_ip_props = maxmind.query_asn(test_item)
            if test_item_ip_props not in bl_props:
                maxmind_suspicious[domain].add(test_item)
                maxmind_suspicious_counter += 1
            else:
                maxmind_ensured[domain].add(test_item)
                maxmind_ensured_counter += 1
                
    print(f'''2. Maxmind compared results: 
            ensured domain:{len(maxmind_ensured)},      suspicious domain:{len(maxmind_suspicious)}
            ensured ip: {maxmind_suspicious_counter},    suspicious ip: {maxmind_ensured_counter}''')
    
    return maxmind_suspicious

def differential_compare(suspicious_domain_ip):
    diff_suspicious_domain_dip = defaultdict(set)
    diff_ensured_domain_dip = defaultdict(set)
    diff_suspicious_counter = 0
    diff_ensured_counter = 0
    for domain, ips in suspicious_domain_ip.items():
        c = Counter(ips)
        c_total = c.total()
        c_most_common = c.most_common()

        if c_total == 1:
            # 把只有一个的元组加入到suspicious中
            diff_suspicious_domain_dip[domain] |= ips
            diff_suspicious_counter += 1
        
        elif len(c_most_common) > 1:
            # 把多数的元组加入到ensured中
            diff_ensured_domain_dip[domain].add(c_most_common[0][0])
            diff_ensured_counter += 1
            # 把少数的元组加入到suspicious中
            for i in range(1, len(c_most_common)):
                diff_suspicious_domain_dip[domain].add(c_most_common[i][0])
                diff_suspicious_counter += 1
                
        else:
            # 把单一多数的元组加入到ensured中
            diff_ensured_domain_dip[domain].add(c_most_common[0][0])
            diff_ensured_counter += 1
    print(f'''3. diff compared results:
                ensured name: {len(diff_ensured_domain_dip)}, suspicious name: {len(diff_suspicious_domain_dip)},
                ensured ip: {diff_ensured_counter},           suspicious ip: {diff_suspicious_counter}''')
    return diff_suspicious_domain_dip


suspicious_unique_domain_ip = set()
reverse_suspicious_map = defaultdict(set)
for key in resolver_results.keys():
    print(key)
    test_set = resolver_results[key]
    remained_suspicious_name_ip = rbline_compare(bl_set, test_set)
    # print(statistics(remained_suspicious_name_ip))
    remained_suspicious_name_ip = differential_compare(remained_suspicious_name_ip)
    print('-'*20)
    
    # save the suspicious unique domain_ip to set for further cert and hcontent acquire
    for domain, ips in remained_suspicious_name_ip.items():
        for ip in ips:
            domain_ip = f'{domain}/{ip}'
            suspicious_unique_domain_ip.add(domain_ip)
            reverse_suspicious_map[domain_ip].add(key)

unique_domain = [item.split('/')[0] for item in list(suspicious_unique_domain_ip)]
print(f'remained unique domain: {len(set(unique_domain))}, remained unique ip: {len(suspicious_unique_domain_ip)}')


with open(output_suspicious_name, 'wb') as f:
    pickle.dump(suspicious_unique_domain_ip, f)
len(suspicious_unique_domain_ip)

white_domain_ip = set()
for domain in load_domain_list():
    for ip in bl_set[domain]:
        domain_ip = f'{domain}/{ip}'
        white_domain_ip.add(domain_ip)
        
with open(output_white_name, 'wb') as f:
    pickle.dump(white_domain_ip, f)
len(white_domain_ip)

with open(output_reverse_name, 'wb') as f:
    pickle.dump(reverse_suspicious_map, f)