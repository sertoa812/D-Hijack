# Efficient Detection for DoH service

This tool is used for Domain Hijack detection based on behavior line of the resolvers.


# Usage

1. First change the corresponding file name in config file.  
* It requires the test resolver file, recurisive resolver file and the monitored domain name. *

2. Execute the execute.sh by bash execute.sh

# Output
Python pickle files with the suspicious domain and their IPs.  
The pickle file is a list of three tuple [domain, domain_ip, resolver_ip]