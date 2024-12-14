import configparser
import os
def load_config(path = './config'):
# 创建一个ConfigParser对象
    config = configparser.ConfigParser()
    
    # 读取配置文件
    config.read(path)
    
    tmp_folder = config['global']['tmp_folder']
    dataset = config['global']['dataset']
    domain_file = config['global']['domain_file']
    result_folder = config['global']['result_folder']
    
    
    for section in config:
        for item in config[section]:
            config[section][item] = config[section][item].replace('{dataset}', dataset)
            config[section][item] = config[section][item].replace('{tmp_folder}', tmp_folder)
            config[section][item] = config[section][item].replace('{result_folder}', result_folder)
            print(section, item, config[section][item])

    if not os.path.exists(tmp_folder):
        os.mkdir(tmp_folder)
    return config