import socket

# Paths to your input and output files
input_file_path = '/Users/<user>/Documents/ips.txt'
resolved_output_file_path = '/Users/<user>/Documents/resolved_ips.txt'
unresolved_output_file_path = '/Users/<user>/Documents/unresolved_ips.txt'
master_output_file_path = '/Users/<user>/Documents/master_list_ips.txt'


def nslookup_ips(input_file_path, resolved_output_file_path, unresolved_output_file_path, master_output_file_path):
    with open(input_file_path, 'r') as file, \
            open(resolved_output_file_path, 'w') as resolved_file, \
            open(unresolved_output_file_path, 'w') as unresolved_file, \
            open(master_output_file_path, 'w') as master_file:

        for line in file:
            ip_address = line.strip()
            try:
                # Attempt to perform a reverse lookup
                hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(
                    ip_address)
                resolved_file.write(f"{ip_address}, {hostname}\n")
                master_file.write(f"Resolved: {ip_address} -> {hostname}\n")
                print(f"Resolved: {ip_address} -> {hostname}")
            except socket.herror:
                # Handle error if the host could not be looked up
                unresolved_file.write(f"{ip_address}\n")
                master_file.write(f"Unresolved: {ip_address}\n")
                print(f"Unresolved: {ip_address}")


if __name__ == "__main__":
    nslookup_ips(input_file_path, resolved_output_file_path,
                 unresolved_output_file_path, master_output_file_path)
