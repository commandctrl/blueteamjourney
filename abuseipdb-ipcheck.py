import requests
import os
import csv

# Load the API key from an environment variable
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')

# Define the function to check an IP address
def check_ip(ip):
    url = f"https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90',
        'verbose': True
    }
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        return None

# Read a list of IP addresses from a file (assuming a file named 'ips.txt')
ips = []
with open('ips.txt', 'r') as file:
    ips = [line.strip() for line in file if line.strip()]

# Check each IP and collect the results
results = []
for ip in ips:
    result = check_ip(ip)
    if result:
        ip_data = result['data']
        results.append({
            'IP': ip,
            'Abuse Confidence Score': ip_data['abuseConfidenceScore'],
            'Country': ip_data['countryCode'],
            'Usage Type': ip_data['usageType'],
            'Link': f"https://www.abuseipdb.com/check/{ip}"
        })

# Write the results to a CSV file
with open('ip_check_results.csv', 'w', newline='') as csvfile:
    fieldnames = ['IP', 'Abuse Confidence Score', 'Country', 'Usage Type', 'Link']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for result in results:
        writer.writerow(result)

print("Completed checking IPs and results are saved to 'ip_check_results.csv'.")
