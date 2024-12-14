import datetime
import os
import pickle
from collections import defaultdict
from urllib.parse import urlparse
from collections import Counter
import os
from bs4 import BeautifulSoup
import argparse

from load_config import load_config
config = load_config()

suspicious_pickle_file = config['5_rbline_html']['suspicious_pickle_file']
save_pure_ip_file = config['5_rbline_html']['save_pure_ip_file']
save_domain_ip_file = config['5_rbline_html']['save_domain_ip_file']
tmp_file = config['global']['tmp_folder']

def extract_html_info(html):
    soup = BeautifulSoup(html, 'html.parser')
    title = soup.title.string if soup.title else ''
    meta_desc = soup.find("meta", attrs={"name": "description"})
    description = meta_desc['content'] if meta_desc and 'content' in meta_desc.attrs else ''
    meta_keywords = soup.find("meta", attrs={"name": "keywords"})
    keywords = meta_keywords['content'] if meta_keywords and 'content' in meta_keywords.attrs else ''
    links = {link.get('href') for link in soup.find_all('a', href=True)}
    return title, description, keywords, links


def check_tkd_discrepancies(tkd_info):
    """检查TKD信息是否存在差异，并返回差异的详细信息
       添加可疑IP的逻辑是，将除了出现次数最多的TKD之外的其他TKD对应的IP添加到可疑ip列表中
    """
    titles = {info[0] for info in tkd_info.values() if info[0]}
    descriptions = {info[1] for info in tkd_info.values() if info[1]}
    keywords = {info[2] for info in tkd_info.values() if info[2]}
    has_discrepancy = len(titles) > 1 or len(descriptions) > 1 or len(keywords) > 1
    tkd_discrepancies_ips = []

    if has_discrepancy:
        # 生成各个IP的TKD字符串
        tkd_strings = ['|'.join(map(str, tkd)) for tkd in tkd_info.values()]
        tkd_counter = Counter(tkd_strings)
        # 找出出现次数最多的组合
        most_common_count = max(tkd_counter.values())
        most_common_tkd_strings = [tkd_string for tkd_string, count in tkd_counter.items() if
                                   count == most_common_count]

        # 找出除了出现次数最多的组合之外的所有IP
        for ip, tkd in tkd_info.items():
            if '|'.join(map(str, tkd)) != most_common_tkd_strings:
                tkd_discrepancies_ips.append(ip)

    has_discrepancy = len(tkd_discrepancies_ips) > 0
    return has_discrepancy, tkd_discrepancies_ips


def check_links_discrepancies(links_info, current_domain):
    """检查外链信息是否存在差异，并返回差异的详细信息
       添加可疑ip的逻辑是，将除了出现次数最多的links组之外的其他links组对应的IP添加到可疑ip列表中
       (判断依据：links in max_count_links)
    """
    domain_links_map = {}
    for ip, links in links_info.items():
        # 对每个IP的所有links进行域名提取
        domain_links = set()
        for link in links:
            parsed_link = urlparse(link)
            # 仅考虑完整的链接且域名不等于当前域名的情况
            if parsed_link.scheme and current_domain not in parsed_link.netloc:
                domain_links.add(f"{parsed_link.scheme}://{parsed_link.netloc}")
        domain_links_map[ip] = frozenset(domain_links)  # 使用不可变集合以便进行计数

    # 计算所有域名集合的出现频率
    domain_sets_count = Counter(domain_links_map.values())
    # 找出出现次数最多的域名集合
    max_count = max(domain_sets_count.values(), default=0)
    most_common_domain_sets = {domain_set for domain_set, count in domain_sets_count.items() if count == max_count}

    # 确定可疑IP列表
    discrepant_ip_list = []
    for ip, domains_set in domain_links_map.items():
        if domains_set not in most_common_domain_sets:
            discrepant_ip_list.append(ip)

    # 检查是否有差异
    has_discrepancy = len(discrepant_ip_list) > 0

    return has_discrepancy, discrepant_ip_list


""" 数据示例 """


# data = {
#     'domain1': {
#         'ip1': 'content1',
#         'ip2': 'content2'
#     },
#     'domain2': {
#         'ip3': 'content3',
#         'ip4': 'content4'
#     }
# }
def baseline_TKD_links(html_info):
    suspicious_ip_list_tkd = defaultdict(list)
    suspicious_ip_list_links = defaultdict(list)
    for domain, ip_content in html_info.items():
        print(f'Cur Domain:{domain}')
        """  TKD & links  """
        tkd_info = {}
        links_info = defaultdict(set)
        for ip, content in ip_content.items():
            # html相关信息提取
            title, description, keywords, links = extract_html_info(content)
            if title or description or keywords:
                tkd_info[ip] = (title, description, keywords)
            if links:
                links_info[ip] = links

        # TKD
        has_discrepancy, tkd_discrepancies_ips = check_tkd_discrepancies(tkd_info)
        if has_discrepancy:
            suspicious_ip_list_tkd[domain] = tkd_discrepancies_ips

        # links
        current_domain = domain.replace('www.', '')
        has_discrepancy, links_discrepant_ips = check_links_discrepancies(links_info, current_domain)
        if has_discrepancy:
            suspicious_ip_list_links[domain] = tkd_discrepancies_ips
    return dict(suspicious_ip_list_tkd), dict(suspicious_ip_list_links)


def process_pickle_file(input_file_path, output_file_path):
    # 尝试以分批方式加载pickle文件
    try:
        with open(input_file_path, 'rb') as f:
            data = pickle.load(f)[0]  # 只考虑列表的第一个元素
    except Exception as e:
        print(f"Error loading pickle file: {e}")
        return

    # 转换数据格式
    domain_ip_content_map = {}
    for domain_ip, content in data.items():
        domain, ip = domain_ip.split('/')
        if domain not in domain_ip_content_map:
            domain_ip_content_map[domain] = {}
        domain_ip_content_map[domain][ip] = content

    # 保存转换后的数据到新的pickle文件
    try:
        with open(output_file_path, 'wb') as f:
            pickle.dump(domain_ip_content_map, f)
        print(f"Data successfully saved to {output_file_path}")
    except Exception as e:
        print(f"Error saving new pickle file: {e}")


def extract_ip(suspicious_ip_list_files, suspicious_ip_list_output_file):
    links_list = []
    # suspicious_ip_list_files = ['./suspicious_ip_list_links', 'suspicious_ip_list_tkd']
    # suspicious_ip_list_output_file = './suspicious_ip_list.csv'
    for suspicious_ip_list_file in suspicious_ip_list_files:
        with open(suspicious_ip_list_file, 'rb') as f:
            links = dict(pickle.load(f))
            links_list += list(links.values())

    with open(suspicious_ip_list_output_file, 'w') as f:
        links_output = []
        for links in links_list:
            for link in links:
                links_output.append(link)

        links_output = list(set(links_output))
        print(links_output)
        print(len(links_output))
        f.write('\n'.join(links_output))


# suspicious_pickle_file = f'{tmp_file}/2.pickle_suspicious_html'

# save_pure_ip_file = f'{tmp_file}/3.suspicious_html_ip'
# save_domain_ip_file = f'{tmp_file}/2.suspicious_html_domain_ip'

def main():
    suspicious_dealed_file = f'{suspicious_pickle_file}'
    process_pickle_file(suspicious_pickle_file, suspicious_dealed_file)

    formatted_date = config['1_rbline_ip']['rb_file'].split('/')[-1][2:-4]
    os.makedirs(f'{tmp_file}/suspicious_ip_list/{formatted_date}', exist_ok=True)

    # suspicious_ip_list_files tkd/links的可疑IP列表输出文件
    suspicious_ip_list_files = [f'{tmp_file}/suspicious_ip_list/{formatted_date}/suspicious_ip_list_tkd',
                                f'{tmp_file}/suspicious_ip_list/{formatted_date}/suspicious_ip_list_links']
    suspicious_ip_list_output_file = f'{tmp_file}/suspicious_ip_list/{formatted_date}/suspicious_ip_list.csv'

    data = pickle.load(open(suspicious_dealed_file, 'rb'))
    link1, link2 = baseline_TKD_links(data)

    with open(suspicious_ip_list_files[0], 'wb') as f:
        pickle.dump(link1, f)
    with open(suspicious_ip_list_files[1], 'wb') as f:
        pickle.dump(link2, f)

    # 输出域名/解析IP数量
    print(f'domain num: {len(data)}')
    print(f'ip num: {sum(len(ips) for ips in data.values())}')
    extract_ip(suspicious_ip_list_files, suspicious_ip_list_output_file)


if __name__ == '__main__':
    # parser = argparse.ArgumentParser(description='Process a pickle file and extract suspicious IP addresses.')
    # parser.add_argument('input_pickle_file_path', type=str, help='Path to the input pickle file')
    # args = parser.parse_args()
    main()
