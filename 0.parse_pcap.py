import os
source_directory = "../aboard-DATASET/ite_data"
dest_directory = "../aboard-DATASET/ite_data_dealed"
files_list = []
# 遍历指定目录及其子目录中的所有文件
for root, directories, files in os.walk(source_directory):
    for file_name in files:
        if file_name[-5:] == '.pcap':
            file_path = os.path.join(root, file_name)
            files_list.append(file_path)
            
from scapy.all import *
import datetime

# DNS 记录类型与其对应名称的映射字典
type_map = {
    1: 'A',
    5: 'CNAME',
    6: 'SOA',
    2: 'NS',
    41: 'OPT',
    28: 'AAAA'
}

IP_DF = 0x02  # Don't fragment flag
IP_MF = 0x01  # More fragments flag


def parse_packet(packet, packet_index):
    """Print out information about each packet in a pcap.
        Args:
            packet: scapy.plist.PacketList
    """
    csvs = []

    # Unpack the Ethernet frame (mac src/dst, ethertype)
    eth = packet.getlayer(Ether)

    # Make sure the Ethernet data contains an IP packet\
    if not packet.haslayer(IP):
        return
    
    # Now unpack the data within the Ethernet frame 
    # (the IP packet)
    ip = packet.getlayer(IP)

    # Pull out fragment information 
    # (flags and offset all packed into off field, 
    # so use bitmasks)
    do_not_fragment = bool(ip.flags & IP_DF)
    more_fragments = bool(ip.flags & IP_MF)
    fragment_offset = ip.frag
    
    # Check for UDP in the transport layer
    if packet.haslayer(UDP):
        # Set the UDP data
        udp = packet.getlayer(UDP)
        
        # Now see if we can parse the contents of the truncated DNS request
        try:
            dns = packet.getlayer(DNS)
        except Exception as e:
            print('\nError Parsing DNS, Might be a truncated packet...')
            print(e)
            return
        if dns == None:
            return


        '''
        query,depth,layer.query_level,section_type,dns_type,answer,class,raw_query,ttl
        '''
        query_ip = ip.src
        response_ip = ip.dst
        dns_id = dns.id
        raw_query = dns.qd.qname.decode()
        raw_query_type = dns.qd.qtype
        if raw_query_type in type_map.keys():
            raw_query_type = type_map[raw_query_type]
        else:
            raw_query_type = raw_query_type
        depth = 0
        layer = 0
        query_level = ''
        
        # queries
        if dns.qr == 0:
            # 将查询类型映射为字符串
            section_type = 'query'
            csvs.append([packet_index, dns_id, query_ip, response_ip, raw_query, raw_query_type, section_type, "No", "No", "No", 0])

        # answers
        if dns.qr == 1 and dns.ancount > 0: #  DNS response
            for rindex in range(dns.ancount):
                answer = dns.an[rindex]
                if isinstance(answer, scapy.layers.dns.DNSRR):
                    query = answer.rrname.decode()
                    section_type = 'answers'
                    if answer.type in type_map.keys():
                        dns_type = type_map[answer.type]
                    else:
                        dns_type = answer.type
                    value = answer.rdata
                    if isinstance(value, bytes):
                        value = value.decode()
                    ttl = answer.ttl
                    csvs.append([packet_index, dns_id, query_ip, response_ip, raw_query, raw_query_type, section_type, query, value, dns_type, ttl])
                    #print(csvs[-1])

        #ns
        if dns.qr == 1 and dns.nscount > 0:
            for rindex in range(dns.nscount):
                ns = dns.ns[rindex]
                if isinstance(ns, scapy.layers.dns.DNSRR):
                    query = ns.rrname.decode()
                    section_type = 'authority'
                    if ns.type in type_map.keys():
                        dns_type = type_map[ns.type]
                    else:
                        dns_type = ns.type
                    value = ns.rdata
                    if isinstance(value, bytes):
                        value = value.decode()
                    ttl = ns.ttl
                    csvs.append([packet_index, dns_id, query_ip, response_ip, raw_query, raw_query_type, section_type, query, value, dns_type, ttl])
                    #print(csvs[-1])

        # additional
        if dns.qr == 1 and dns.arcount > 0:
            for rindex in range(dns.arcount):
                ar = dns.ar[rindex]
                if isinstance(ar, scapy.layers.dns.DNSRR):
                    query = ar.rrname.decode()
                    section_type = 'additional'
                    if ar.type in type_map.keys():
                        dns_type = type_map[ar.type]
                    else:
                        dns_type = ar.type
                    value = ar.rdata
                    if isinstance(value, bytes):
                        value = value.decode()
                    ttl = ar.ttl
                    csvs.append([packet_index, dns_id, query_ip, response_ip, raw_query, raw_query_type, section_type, query, value, dns_type, ttl])
                    #print(csvs[-1])
        return csvs
    


def parse_pcaps(filename):
    """Open up a test pcap file and print out the packets"""
    count = 0
    total_csvs = [] 
    with open(filename, 'rb') as f:
        packets = rdpcap(f)
        print('read done')
        """Process each packet i a pcap
         Args: pcap: scapy.plist.PacketList """
        for index, packet in enumerate(packets):
            # if index % 1000 == 0:
            #     print(index)
            # Print out the timestamp in UTC
            timestamp = str(datetime.datetime.utcfromtimestamp(float(packet.time)))
            # print(f"Timestamp: {timestamp}")
            csvs = parse_packet(packet, index)
            if csvs != None:
                total_csvs.extend(csvs)
        return total_csvs

import pandas as pd

for filename in files_list:
    print(filename)
    # filename = './test.pcap'
    # filename = './Parse_pcap/test_pcap/20240219.pcap'
    total_csvs = parse_pcaps(filename)
    total_frame = pd.DataFrame(total_csvs)
    total_frame.columns = ['packet_index', 'dns_id', 'query_ip', 'response_ip', 'raw_query', 'raw_query_type', 
                           'section_type', 'query', 'value', 'dns_type', 'ttl']
    native_name = filename.split('/')[-1].split('.')[0]
    changed_native_name = native_name.replace('-', '')
    total_frame.to_csv(f'{dest_directory}/{changed_native_name}.csv', index=False)
    print(len(total_frame))