import requests
import ssl
import chardet
import requests
import OpenSSL
import urllib3
import socket
from cryptography.hazmat.primitives import serialization
socket.setdefaulttimeout(5)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from cryptography import x509
from cryptography.hazmat.backends import default_backend

global_counter = 0
def parse_pem_certificate(cert_data):
    # 使用 cryptography 加载证书
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    
    # 解析证书版本
    version = cert.version.value
    
    # 解析序列号
    serial_number = cert.serial_number
    
    # 解析签名算法
    signature_algorithm = cert.signature_algorithm_oid._name
    
    # 解析颁发者信息
    issuer = cert.issuer.rfc4514_string()

    signature = cert.signature
    
    # 解析有效期
    valid_from = cert.not_valid_before_utc.isoformat()
    valid_to = cert.not_valid_after_utc.isoformat()
    
    # 解析主题信息
    subject = cert.subject.rfc4514_string()
    
    # 解析公钥信息
    public_key = cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    # 解析扩展信息
    extensions = {}
    for ext in cert.extensions:
        extensions[ext.oid._name] = ext.value.public_bytes()
        
    return {
        'Version': version,
        'Serial Number': serial_number,
        'Signature Algorithm': signature_algorithm,
        'Signature': signature,
        'Issuer': issuer,
        'Validity': {'Not Before': valid_from, 'Not After': valid_to},
        'Subject': subject,
        'Public Key': public_key,
        'Extensions': extensions
    }


# deprecated
def parse_pem_certificate_openssl(pem_data):
    # 使用 OpenSSL 库加载 PEM 格式的证书
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_data)
    
    # 解析证书的版本信息
    version = cert.get_version()
    
    # 解析证书的序列号
    serial_number = cert.get_serial_number()
    
    # 解析证书的签名算法
    signature_algorithm = cert.get_signature_algorithm()
    
    # 解析证书的颁发者信息
    issuer = dict(cert.get_issuer().get_components())
    
    # 解析证书的有效期
    not_before = cert.get_notBefore().decode('ascii')
    not_after = cert.get_notAfter().decode('ascii')
    
    # 解析证书的主题信息
    subject = dict(cert.get_subject().get_components())
    
    # 解析证书的公钥信息
    public_key = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, cert.get_pubkey()).decode('ascii')

    subject_name_hash = cert.subject_name_hash()
    
    # 解析证书的扩展信息
    extensions = {}
    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        extensions[ext.get_short_name().decode()] = ext.get_data()
    
    return {
        'Version': version,
        'Serial Number': serial_number,
        'Signature Algorithm': signature_algorithm,
        'Issuer': issuer,
        'Validity': {'Not Before': not_before, 'Not After': not_after},
        'Subject': subject,
        'Public Key': public_key,
        'Subject Hash': subject_name_hash,
        'Extensions': extensions
    }

def get_certs(key):
    global global_counter
    global_counter += 1
    if global_counter % 1000 == 0 or global_counter == 1:
        from datetime import datetime
        # 获取当前时间
        current_time = datetime.now()
        # 将时间格式化为字符串
        formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
        print(global_counter, formatted_time)
    domain, ip = key.split('/')
    # print(domain, ip)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Referer': 'https://www.google.com/',
    }
    headers['Host'] = domain
    urls_to_try = [f'https://{ip}', f'http://{ip}']
    content = ''
    cert = None
    hostname = ip
    port = 443
    # get certificate

    try:
        conn = ssl.create_connection((hostname, port))
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = context.wrap_socket(conn, server_hostname=hostname)
        certificate = ssl.DER_cert_to_PEM_cert(sock.getpeercert(True))
        cert = parse_pem_certificate(certificate.encode())
        cert['IP'] = ip
        cert['Domain'] = domain
    except :
        pass
    # get html content
    # for url in urls_to_try:
    #     try:
    #         response = requests.get(url, timeout=5, verify=False, headers=headers)  # 忽略SSL证书验证
    #         encoding = chardet.detect(response.content)['encoding']
    #         if response.status_code == 200:
    #             if encoding:
    #                 # print(encoding)
    #                 content = response.content.decode(encoding)
    #             else:
    #                 content = response.text  # 如果chardet也无法确定编码，回退到使用response.text
    #             break
    #     except:
    #         continue
    return [domain, ip, content, cert] 

def get_htmls(key):
    global global_counter
    global_counter += 1
    if global_counter % 1000 == 0 or global_counter == 1:
        from datetime import datetime
        # 获取当前时间
        current_time = datetime.now()
        # 将时间格式化为字符串
        formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
        print(global_counter, formatted_time)
    domain, ip = key.split('/')
    # print(domain, ip)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Referer': 'https://www.google.com/',
    }
    headers['Host'] = domain
    urls_to_try = [f'https://{ip}', f'http://{ip}']
    content = ''
    cert = None
    hostname = ip
    port = 443
    # get certificate

    # try:
    #     conn = ssl.create_connection((hostname, port))
    #     context = ssl.create_default_context()
    #     context.check_hostname = False
    #     context.verify_mode = ssl.CERT_NONE
    #     sock = context.wrap_socket(conn, server_hostname=hostname)
    #     certificate = ssl.DER_cert_to_PEM_cert(sock.getpeercert(True))
    #     cert = parse_pem_certificate(certificate.encode())
    #     cert['IP'] = ip
    #     cert['Domain'] = domain
    # except :
    #     pass
    # get html content
    for url in urls_to_try:
        try:
            response = requests.get(url, timeout=10, verify=False, headers=headers)  # 忽略SSL证书验证
            encoding = chardet.detect(response.content)['encoding']
            if response.status_code == 200:
                if encoding:
                    # print(encoding)
                    content = response.content.decode(encoding)
                else:
                    content = response.text  # 如果chardet也无法确定编码，回退到使用response.text
                break
        except:
            continue
    return [domain, ip, content, cert] 