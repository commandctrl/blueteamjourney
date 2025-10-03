import requests
import csv
import os

# Retrieve the API key from an environment variable
API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

if not API_KEY:
    raise ValueError("Please set the VIRUSTOTAL_API_KEY environment variable with your API key")

# The file containing the list of SHA-256 hashes
DOMAIN_LIST_FILE = '/Users/<user>/Documents/domains_to_vt.txt'

# The CSV file where the results will be saved
OUTPUT_CSV_FILE = '/Users/<user>/Documents/domain_reputation_results.csv'

def check_hash_reputation(domain_value):
    url = f'https://www.virustotal.com/api/v3/domain/{domain}'
    headers = {
        'x-apikey': API_KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def main():
    with open(DOMAIN_LIST_FILE, 'r') as file:
        hashes = file.read().splitlines()
    
    with open(OUTPUT_CSV_FILE, 'w', newline='') as file:
        writer = csv.writer(file)
        # Include a column for the VT Link
        writer.writerow(['SHA-256', 'Harmless', 'Malicious', 'Suspicious', 'Undetected', 'Timeout', 'VT Link'])
        
        for hash_value in hashes:
            result = check_hash_reputation(domain_value)
            if result:
                attributes = result['data']['attributes']
                last_analysis_stats = attributes['last_analysis_stats']
                # Check if there are any malicious hits
                malicious_hits = last_analysis_stats.get('malicious', 0)
                vt_link = f"https://www.virustotal.com/gui/domain/{domain}" if malicious_hits > 0 else ""
                writer.writerow([
                    hash_value,
                    last_analysis_stats.get('harmless', 0),
                    last_analysis_stats.get('malicious', 0),
                    last_analysis_stats.get('suspicious', 0),
                    last_analysis_stats.get('undetected', 0),
                    last_analysis_stats.get('timeout', 0),
                    vt_link  # Now vt_link is defined and can be used here
                ])
            else:
                # Make sure to handle the case where vt_link would be used but no result is available
                writer.writerow([ip, 'Error', 'Error', 'Error', 'Error', 'Error', ''])

if __name__ == '__main__':
    main()
