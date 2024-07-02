import socket

# Path to your file containing IP addresses, one per line
file_path = '/Users/austinpham/Documents/ips.txt'

def nslookup_ips(file_path):
    with open(file_path, 'r') as file:
        for line in file:
            ip_address = line.strip()
            try:
                # Attempt to perform a reverse lookup
                hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(ip_address)
                print(f"IP Address: {ip_address} resolves to Hostname: {hostname}")
            except socket.herror:
                # Handle error if the host could not be looked up
                print(f"IP Address: {ip_address} could not be resolved.")

if __name__ == "__main__":
    nslookup_ips(file_path)
