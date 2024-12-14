import pickle
from load_config import load_config
config = load_config()

# load previous file
suspicious_domain_ip_file = config['3_rbline_certs']['suspicious_domain_ip_file']
white_domain_ip_file = config['3_rbline_certs']['white_domain_ip_file']
white_cert = config['3_rbline_certs']['white_cert']
test_cert = config['3_rbline_certs']['test_cert']

# save current results
suspicious_certs_ip_file = config['3_rbline_certs']['suspicious_certs_ip_file']
suspicious_certs_pickle = config['3_rbline_certs']['suspicious_certs_pickle']
white_certs_pickle = config['3_rbline_certs']['white_certs_pickle']

with open(suspicious_domain_ip_file, 'rb') as f:
    domain_ips = pickle.load(f)
    
counter = 0
suspicious_domain_dip = []
suspicious_domains = set()
for item in domain_ips:
    domain, ip = item.split('/')
    key = f'{domain}-{ip}'
    
    suspicious_domain_dip.append(item)
    suspicious_domains.add(domain)
    counter += 1


import pickle

def load_white_hc_bline(loc=white_cert):
    with open(loc, 'rb') as f:
        htmls, certs = pickle.load(f)
    return certs, htmls
        
def load_test_hc_bline(loc=test_cert):
    with open(loc, 'rb') as f:
        htmls, certs = pickle.load(f)
    return certs, htmls

wch = load_white_hc_bline()
tch = load_test_hc_bline()

bl_certs = wch[0]
test_certs = tch[0]


from collections import defaultdict
import hashlib
base_certsmd5 = defaultdict(set)
test_certsmd5 = defaultdict(set)
base_cts = defaultdict(list)
test_cts = defaultdict(list)
diff_domain_cert_set = defaultdict(set)
trace_suspicious_cert_ips = defaultdict(set)
for key, value in bl_certs.items():
    tmp = key.split('/')
    domain, ip = tmp[0], tmp[1]
    if value != None:
        cert_info = value['Serial Number']
        # cert_info = value['Subject']
        base_certsmd5[domain].add(cert_info)
        base_cts[domain].append(value)

# onlye use the differential test results instead of all ip resolved of the domain
# 此处的key是domain/ip
# test_certs 中的key是domain/ip，value是 certs证书信息

for key in suspicious_domain_dip:
    value = test_certs[key]
    tmp = key.split('/')
    domain, ip = tmp[0], tmp[1]
    if value != None:
        # cert_info = value['Serial Number']
        # cert_info = value['Subject']
        cert_info = value['Serial Number']
        test_certsmd5[domain].add(cert_info)
        test_cts[domain].append(value)
        trace_suspicious_cert_ips[f'{domain}/{cert_info}'].add(ip)
        
suspicious_domain_dip = []
suspicious_certs = []
ensured_domain_dip = []

# for key in base_certsmd5.keys():  # raw judge
# key is domain
counter = 0
for key in suspicious_domains:
    base_cert = base_certsmd5[key]
    test_cert = test_certsmd5[key]
    
    # if len(test_cert) == 0 and len(base_cert) != 0:
    #     suspicious_domain_dip.append(domain)
    #     continue
    
    for item in test_cert:
        counter += 1
        domain = key
        ips = trace_suspicious_cert_ips[f'{domain}/{item}'] 
        if item not in base_cert:
            suspicious_domain_dip.extend([f'{domain}/{ip}' for ip in ips])
        else:
            ensured_domain_dip.extend([f'{domain}/{ip}' for ip in ips])

unique_suspicious_domain = set([item.split('/')[0] for item in list(suspicious_domain_dip)])
print(f'rbline: suspicious ip {len(suspicious_domain_dip)}, ensured ip {len(ensured_domain_dip)}, suspicious domain {len(unique_suspicious_domain)}')

counter = 0
unique_certs = set()
for key in base_certsmd5.keys():
    if len(base_certsmd5[key]) != 0:
        counter += 1
        unique_certs |= (base_certsmd5[key])


from collections import Counter
diff_results = defaultdict(set)
diff_domain_certs = defaultdict(list)
diff_domain_counter = {}
trace_dc2ip = defaultdict(set)
trace_ip2dc = defaultdict(set)
diff_suspicious_domain_dip = []
diff_ensured_domain_dip = []

# 遍历一遍把剩余的domain/ip按照domain对cert进行统计
for domain_dip in suspicious_domain_dip:
    domain, dip = domain_dip.split('/')
    cert_info = test_certs[domain_dip]['Serial Number']
    cert_info = test_certs[domain_dip]['Subject']
    diff_domain_certs[domain].append(cert_info)
    trace_dc2ip[f'{domain}/{cert_info}'].add(dip)
    
for domain in diff_domain_certs.keys():
    c = Counter(diff_domain_certs[domain])
    c_total = c.total()
    c_most_common = c.most_common()
    # most_common is [('a', 5), ('b', 2), ('r', 2)]
    # 选取少数的为异常
    
    if c_total == 1:
        # 把只有一个的元组加入到suspicious中
        domain_ips = trace_dc2ip[f'{domain}/{c_most_common[0][0]}']
        diff_suspicious_domain_dip.extend([f'{domain}/{domain_ip}' for domain_ip in domain_ips])
    
    elif len(c_most_common) > 1:
        # 把多数的元组加入到ensured中
        domain_ips = trace_dc2ip[f'{domain}/{c_most_common[0][0]}']
        diff_ensured_domain_dip.extend([f'{domain}/{domain_ip}' for domain_ip in domain_ips])
        # 把少数的元组加入到suspicious中
        for i in range(1, len(c_most_common)):
            domain_ips = trace_dc2ip[f'{domain}/{c_most_common[i][0]}']
            diff_suspicious_domain_dip.extend([f'{domain}/{domain_ip}/' for domain_ip in domain_ips])
            
    else:
        # 把单一多数的元组加入到ensured中
        domain_ips = trace_dc2ip[f'{domain}/{c_most_common[0][0]}']
        diff_ensured_domain_dip.extend([f'{domain}/{domain_ip}' for domain_ip in domain_ips])
        
unique_suspicious_domain = set([item.split('/')[0] for item in list(diff_ensured_domain_dip)])
print(f'differential: suspicious ip {len(diff_suspicious_domain_dip)}, ensured ip {len(diff_ensured_domain_dip)}, suspicious domain {len(unique_suspicious_domain)}')

# save domain ip seperately for direct threatbook query
results = []
for item in diff_suspicious_domain_dip:
    results.append(item.split('/')[1])
    
with open(suspicious_certs_ip_file, 'w') as f:
    f.write('\n'.join(list(set(results))))

# generate white domain ip
unique_suspicious_domain = set(item.split('/')[0] for item in diff_suspicious_domain_dip)
with open(white_domain_ip_file, 'rb') as f:
    white_domain_dip = pickle.load(f)
diff_white_domain_dip = []
for item in white_domain_dip:
    _d, _ip = item.split('/')
    if _d in unique_suspicious_domain:
        diff_white_domain_dip.append(item)

# save white domain ip 
with open(suspicious_certs_pickle, 'wb') as f:
    pickle.dump(diff_suspicious_domain_dip, f)

with open(white_certs_pickle, 'wb') as f:
    pickle.dump(diff_white_domain_dip, f)

# save suspicious domain ip

print(len(diff_white_domain_dip),len(unique_suspicious_domain), len(diff_suspicious_domain_dip))