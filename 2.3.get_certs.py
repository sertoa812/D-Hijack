import pickle
from srequest import get_certs
from multiprocessing import Pool
from concurrent import futures
from load_config import load_config
config = load_config()

pickle_load_white_file = config['2_3_get_certs']['pickle_load_white_file']
pickle_save_white_file = config['2_3_get_certs']['pickle_save_white_file']

pickle_load_suspicious_file = config['2_3_get_certs']['pickle_load_suspicious_file']
pickle_save_suspicious_file = config['2_3_get_certs']['pickle_save_suspicious_file']

def multi_execute(keys):
    with futures.ThreadPoolExecutor(30) as p:
        result_generator = p.map(get_certs, keys)
    print('done')
    return result_generator

def get_white_cert_file():
    with open(pickle_load_white_file, 'rb') as f:
        domain_ips = pickle.load(f)
    print('white crawling...')
    keys = list(domain_ips)
    print(len(keys))
    
    result_generator = multi_execute(keys)
    
    certs = {}
    htmls = {}
    for bl_item in result_generator:
        domain, ip, content, cert = bl_item
        key = f'{domain}/{ip}'
        htmls[key] = content
        certs[key] = cert

    with open(pickle_save_white_file, 'wb') as f:
        pickle.dump([htmls, certs], f)

def get_suspicious_cert_file():
    with open(pickle_load_suspicious_file, 'rb') as f:
        domain_ips = pickle.load(f)
    print('suspicious crawling...')
    keys = list(domain_ips)
    print(len(keys))
    
    result_generator = multi_execute(keys)
    
    certs = {}
    htmls = {}
    for bl_item in result_generator:
        domain, ip, content, cert = bl_item
        key = f'{domain}/{ip}'
        htmls[key] = content
        certs[key] = cert

    with open(pickle_save_suspicious_file, 'wb') as f:
        pickle.dump([htmls, certs], f)

if __name__ == '__main__':
    get_white_cert_file()
    get_suspicious_cert_file()
    