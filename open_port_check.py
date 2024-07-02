# This script uses a simple connection attempt to check if port 22 is open. It does not perform any actual SSH login or negotiation.
# The timeout is set to 1 second to avoid long waits for each IP address. You may adjust this value based on your network speed and reliability.
# Running this script against IP addresses you do not own or have permission to scan may violate terms of service or laws. Always obtain permission before scanning networks.

import socket

# File containing the list of IP addresses, one per line
input_file_path = '/Users/<user>/Documents/ips.txt'
# New output file path for the results
output_file_path = '/Users/<user>/Documents/port_22_scan_results.txt'


def scan_port_22(ip_address):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # Set a timeout of 1 second for the connection attempt
            sock.settimeout(1)
            # Attempt to connect to port 22
            result = sock.connect_ex((ip_address, 22))
            if result == 0:
                return True  # The port is open
            else:
                return False  # The port is closed or filtered
    except socket.error as e:
        print(f"Socket error: {e}")
        return False


def main(input_file_path, output_file_path):
    with open(input_file_path, 'r') as file, open(output_file_path, 'w') as output_file:
        for line in file:
            ip_address = line.strip()
            if scan_port_22(ip_address):
                result = f"Port 22 is open on {ip_address}"
            else:
                result = f"Port 22 is closed on {ip_address}"
            print(result)  # Show progress by printing the result
            # Write the result to the output file
            output_file.write(result + '\n')


if __name__ == "__main__":
    main(input_file_path, output_file_path)
