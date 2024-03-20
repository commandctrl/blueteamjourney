import ipaddress
import socket
import time
import csv

def defang(domain):
    return domain.replace('.','[.]')

cidr_block = '77.90.185.0/24'

ip_addresses = [str(ip) for ip in ipaddress.ip_network(cidr_block)]

csv_file = '/Users/austinpham/Documents/rDNS_lookup_results.csv'
with open(csv_file, mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(['IP address','Defanged Domain'])

    for ip in ip_addresses:
        try:
            domain = socket.gethostbyaddr(ip)[0]
            defanged_domain = defang(domain)
            print(f"{ip}: {defanged_domain}")
            writer.writerow([ip, defanged_domain])
        except socket.herror:
            print(f"{ip}: No reverse DNS record found")
        time.sleep(30)
print(f"Results have been savd to {csv_file}")
