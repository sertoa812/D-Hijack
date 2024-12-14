import pickle
import pickle
from load_config import load_config
config = load_config()

suspicious_certs_pickle = config['3_rbline_certs']['suspicious_certs_pickle']
reverse_map_name = config['1_rbline_ip']['output_reverse_name']
result_output_name = config['6_result']['result_output']

with open(suspicious_certs_pickle, 'rb') as f:
    diff_suspicious_domain_dip = pickle.load(f)
diff_suspicious_domain_dip

with open(reverse_map_name, 'rb') as f:
    reverse_map = pickle.load(f)

result = []
for item in diff_suspicious_domain_dip:
    result.append((item, reverse_map[item]))
with open(result_output_name, 'wb') as f:
    pickle.dump(result, f)