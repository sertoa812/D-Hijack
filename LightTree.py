''' ## RRSets and Packet Definition '''
# packet_index, source_ip, dest_ip, raw_query, raw_query_type, section_type, query, value, dns_type, ttl
class Packet:
    def __init__(self, index, trans_id, source_ip, dest_ip, raw_query, raw_query_type, rrsets, ind_answers, ind_query_names, query_or_response):
        self.index = index
        self.query_or_response = query_or_response
        self.trans_id = trans_id
        self.query_ip = ""
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.raw_query = raw_query
        self.raw_query_type = raw_query_type
        self.rrsets = rrsets
        self.ind_answers = ind_answers
        self.ind_query_names = ind_query_names
        self.parent_links = set()
        self.sibling_links = set()
        self.child_links = set()
        self.response_links = set()
        self.query_links = set()

        # 根据source_ip和dest_ip判断哪个是公网地址
        if source_ip.startswith('10.') or source_ip.startswith('192.168') or source_ip.startswith('172.16'):
            self.query_ip = dest_ip
        else:
            self.query_ip = source_ip
        
    def __str__(self):
        return (f'''
index: {self.index}; 
trans_id: {self.trans_id};
query_or_response: {self.query_or_response}; 
source_ip: {self.source_ip}; 
dest_ip: {self.dest_ip};
query_ip: {self.query_ip};
raw_query: {self.raw_query}; 
raw_query_type: {self.raw_query_type}; 
rrsets: {self.rrsets}; 
ind_answers: {self.ind_answers}; 
ind_query_names: {self.ind_query_names}; 
parent_links: {self.parent_links}; 
sibling_links: {self.sibling_links}; 
child_links: {self.child_links}; 
response_links: {self.response_links};
query_links: {self.query_links};
                ''')    
class RRSets:
    def __init__(self, packet_index, dns_id, source_ip, dest_ip, raw_query, raw_query_type, section_type, query, value, dns_type, ttl):
        self.packet_index = packet_index
        self.dns_id = dns_id
        self.query_ip = ""
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.raw_query = raw_query
        self.raw_query_type = raw_query_type
        self.section_type = section_type
        self.dns_type = dns_type
        self.query = query
        if type(value) == float:
            self.value = ''
        else:
            self.value = value
        self.ttl = ttl
        self.authority_links = set()
        self.parent_links = set()
        self.sibling_links = set()
        self.child_links = set()

        # 根据source_ip和dest_ip判断哪个是公网地址
        if source_ip.startswith('10.') or source_ip.startswith('192.168') or source_ip.startswith('172.16'):
            self.query_ip = dest_ip
        else:
            self.query_ip = source_ip

        self.history_ips = set([self.query_ip])
        

    def __str__(self):
        return (f'''
packet_index: {self.packet_index}; 
source_ip: {self.source_ip}; 
dest_ip: {self.dest_ip};
query_ip: {self.query_ip};
raw_query: {self.raw_query}; 
raw_query_type: {self.raw_query_type}; 
query: {self.query}; 
value: {self.value}; 
section_type: {self.section_type}; 
dns_type: {self.dns_type}; 
ttl: {self.ttl}; 
authority_links: {self.authority_links}; 
parent_links: {self.parent_links}; 
sibling_links: {self.sibling_links}; 
child_links: {self.child_links}; 
history_ips: {self.history_ips}; 
                ''')
    
            
            
''' 总体构建的数据结构 '''

from matplotlib.lines import Line2D
import networkx as nx
import matplotlib.pyplot as plt

class LTree:  
    def __init__(self):
        self.total_pkts = {}
        self.total_rrs = []

        self.pkts_name_index = {}
        self.pkts_query_raw_query_index = {}
        self.pkts_response_raw_query_index = {}
        self.pkts_transid_index = {}

        self.query_name_rrs_index = {}
        self.raw_query_rrs_index = {}
        self.values_rrs_index = {}
        self.query_ip_rrs_index = {}
    
    def get_final_a_by_query(self, key):
        direct_response = self.get_node_by_query(key)
        result = []
        for item in direct_response:
            if item.dns_type == 'CNAME':
                result.extend(self.get_final_a_by_query(item.value))
            if item.dns_type == 'A':
                result.append(item.value)
        return result
    
    def get_cname_by_query(self, key):
        direct_response = self.get_node_by_query(key)
        result = []
        for item in direct_response:
            if item.dns_type == 'CNAME':
                result.append(item.value)
        return result
    
    def get_direct_ns_by_query(self, key):
        direct_response = self.get_node_by_query(key)
        result = []
        for item in direct_response:
            if item.dns_type == 'NS':
                result.append(item.value)
        return result
    
    def get_final_ns_by_query(self, key):
        direct_response = self.get_node_by_query(key)
        result = []
        for item in direct_response:
            if item.dns_type == 'CNAME':
                result = self.get_final_ns_by_query(item.value)
                return result
            if item.dns_type == 'NS':
                result.append(item.value)
        return result
    
    def get_node_by_query(self, key):
        results = []
        for item in self.get_rrs(key, 'query'):
            results.append(self.total_rrs[item])
        return results
    
    def get_rrs(self, key, collection):
        try:
            if collection == 'query':
                tmp_rrs = self.query_name_rrs_index[key]
                return tmp_rrs

            if collection == 'value':
                tmp_rrs = self.values_rrs_index[key]
                return tmp_rrs

            if collection == 'query_ip':
                tmp_rrs = self.query_ip_rrs_index[key]
                return tmp_rrs

            if collection == 'raw_query':
                tmp_rrs = self.raw_query_rrs_index[key]
                return tmp_rrs
        except KeyError:
            return []
        
    def construct_rrp(self, df):
        rr_index = 0
        for grouped in df.groupby('packet_index'):
            index, grouped_list = grouped[0], grouped[1].values.tolist()
            rrsets = []
            raw_query = None
            ind_answers = set()
            ind_query_names= set()
            query_or_response = None
            for item in grouped_list:
                # init rr object, 
                rr = RRSets(item[0], item[1], item[2], item[3], item[4], item[5], item[6], item[7], item[8], item[9], item[10])
                # init packet 
                rrsets.append(rr_index)
                packet_index, trans_id, source_ip, dest_ip, raw_query, raw_query_type, section_type, query, value, dns_type, ttl \
                = item[0], item[1], item[2], item[3], item[4], item[5], item[6], item[7], item[8], item[9], item[10]
                if section_type == 'query':
                    query_or_response = 'query'
                else:
                    query_or_response = 'response'
                ind_query_names.add(query)
                ind_answers.add(value)
                # append rr to rr management
                self.total_rrs.append(rr)

                if value in self.values_rrs_index.keys():
                    self.values_rrs_index[value].append(rr_index)
                else:
                    self.values_rrs_index[value] = [rr_index]

                query_ip = rr.query_ip
                if query_ip in self.query_ip_rrs_index.keys():
                    self.query_ip_rrs_index[query_ip].append(rr_index)
                else:
                    self.query_ip_rrs_index[query_ip] = [rr_index]

                if query in self.query_name_rrs_index.keys():
                    self.query_name_rrs_index[query].append(rr_index)
                else:
                    self.query_name_rrs_index[query] = [rr_index]

                if raw_query in self.raw_query_rrs_index.keys():
                    self.raw_query_rrs_index[raw_query].append(rr_index)
                else:
                    self.raw_query_rrs_index[raw_query] = [rr_index]
                rr_index += 1

            pkt = Packet(index, trans_id, source_ip, dest_ip, raw_query, raw_query_type, rrsets, 
                         ind_answers, ind_query_names,query_or_response)
            self.total_pkts[index] = (pkt)

            if raw_query in self.pkts_name_index.keys():
                self.pkts_name_index[raw_query].append(index)
            else:
                self.pkts_name_index[raw_query] = [index]

            if raw_query in self.pkts_transid_index.keys():
                self.pkts_transid_index[raw_query].append(index)
            else:
                self.pkts_transid_index[raw_query] = [index]
                