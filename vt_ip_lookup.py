import requests
import csv
import os

# If you run into a homebrew python link problem with the local env, install requests in a python venv before running this script.

# Retrieve the API key from an environment variable
API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

if not API_KEY:
    raise ValueError("Please set the VIRUSTOTAL_API_KEY environment variable with your API key")

# The file containing the list of IPs
IP_LIST_FILE = '/Users/<user>/Documents/ips_to_vt.txt'

# The CSV file where the results will be saved
OUTPUT_CSV_FILE = '/Users/<user>/Documents/ip_reputation_results.csv'

def check_ip_reputation(ip):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {
        'x-apikey': API_KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def main():
    with open(IP_LIST_FILE, 'r') as file:
        ips = file.read().splitlines()
    
    with open(OUTPUT_CSV_FILE, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['IP', 'Harmless', 'Malicious', 'Suspicious', 'Undetected', 'Timeout'])
        
        for ip in ips:
            result = check_ip_reputation(ip)
            if result:
                attributes = result['data']['attributes']
                last_analysis_stats = attributes['last_analysis_stats']
                writer.writerow([
                    ip,
                    last_analysis_stats.get('harmless', 0),
                    last_analysis_stats.get('malicious', 0),
                    last_analysis_stats.get('suspicious', 0),
                    last_analysis_stats.get('undetected', 0),
                    last_analysis_stats.get('timeout', 0),
                    vt_link  # Add the VT link to the row
                ])
            else:
                writer.writerow([ip, 'Error', 'Error', 'Error', 'Error', 'Error',''])

if __name__ == '__main__':
    main()
