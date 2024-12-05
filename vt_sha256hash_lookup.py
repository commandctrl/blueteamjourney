import requests
import csv
import os

# Retrieve the API key from an environment variable
API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

if not API_KEY:
    raise ValueError("Please set the VIRUSTOTAL_API_KEY environment variable with your API key")

# The file containing the list of SHA-256 hashes
HASH_LIST_FILE = '/Users/austinpham/Documents/hashes_to_vt.txt'

# The CSV file where the results will be saved
OUTPUT_CSV_FILE = '/Users/austinpham/Documents/hash_reputation_results.csv'

def check_hash_reputation(hash_value):
    url = f'https://www.virustotal.com/api/v3/files/{hash_value}'
    headers = {
        'x-apikey': API_KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def main():
    with open(HASH_LIST_FILE, 'r') as file:
        hashes = file.read().splitlines()
    
    with open(OUTPUT_CSV_FILE, 'w', newline='') as file:
        writer = csv.writer(file)
        # Adjust the column headers based on the information you want from the hash lookup
        writer.writerow(['SHA-256', 'Harmless', 'Malicious', 'Suspicious', 'Undetected', 'Timeout'])
        
        for hash_value in hashes:
            result = check_hash_reputation(hash_value)
            if result:
                attributes = result['data']['attributes']
                last_analysis_stats = attributes['last_analysis_stats']
                writer.writerow([
                    hash_value,
                    last_analysis_stats.get('harmless', 0),
                    last_analysis_stats.get('malicious', 0),
                    last_analysis_stats.get('suspicious', 0),
                    last_analysis_stats.get('undetected', 0),
                    last_analysis_stats.get('timeout', 0)
                ])
            else:
                writer.writerow([hash_value, 'Error', 'Error', 'Error', 'Error', 'Error'])

if __name__ == '__main__':
    main()
