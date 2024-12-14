import dns.resolver
import dns.reversename
from concurrent.futures import ThreadPoolExecutor
import pandas as pd
import time
import argparse
import pickle
from load_config import load_config
config = load_config()

suspicious_domain_ip_file = config['2_2_get_cdn']['suspicious_domain_ip_file']
ptr_output_file = config['2_2_get_cdn']['ptr_output_file']
save_suspicious_domain_ip_file = config['2_2_get_cdn']['save_suspicious_domain_ip_file']

with open(suspicious_domain_ip_file, 'rb') as f:
    suspicious_domain_ip = pickle.load(f)
unique_ip = set([item.split('/')[1] for item in list(suspicious_domain_ip)])

with open(ptr_output_file, 'rb') as f:
    df = pickle.load(f)

df['Valid_PTR'] = df.apply(lambda row: ('does not exist' not in row['PTR']), axis=1)
valid_df = df[df['Valid_PTR']]
invalid_df = df[~df['Valid_PTR']]
valid_df['Base_Domain'] =  ['.'.join(x[0].split('.')[-3:]) for x in valid_df['PTR'].tolist()]

cdn_condition = (valid_df['Base_Domain'] == 'cloudfront.net.') | (valid_df['Base_Domain'] == 'akamaitechnologies.com.') | (valid_df['Base_Domain'] == 'amazonaws.com.')
cdn_df = valid_df[cdn_condition].reset_index(drop=True)
nocdn_df = valid_df[~cdn_condition].reset_index(drop=True)
len(cdn_df), len(nocdn_df), len(invalid_df)

require_further_ips = set(nocdn_df['IP'].tolist() + invalid_df['IP'].tolist())
len(require_further_ips)

filtered_suspicious_domain_ip = []
for item in list(suspicious_domain_ip):
    domain, ip = item.split('/')
    if ip in require_further_ips:
        filtered_suspicious_domain_ip.append(item)

with open(save_suspicious_domain_ip_file, 'wb') as f:
    pickle.dump(filtered_suspicious_domain_ip, f)