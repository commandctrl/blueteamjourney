# This python script takes a csv file with a column containing executables and searches the Hybrid Analysis API endpoint api/v2 /search/terms for hits and outputs the json 200 response https://www.hybrid-analysis.com/docs/api/v2 . This is useful for gathering sha256 hashes, etc. 

# Load the required modules

import requests
import csv
import os

# Load the API Key from the env variable path. for macOS, in terminal cmdline: echo 'export HA_API_KEY="<api-key>"' >> ~/.zshrc then source ~/.zshrc

api_key = os.getenv('HA_API_KEY')

# The Hybrid Analysis API endpoint.
api_endpoint = 'https://www.hybrid-analysis.com/api/v2'

# Path to csv file containing executables to lookup.
csv_file = '/Users/<user>/Documents/<file>.csv'

# Building the executables array
executables = []
with open(csv_file, newline='') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        executables.append(row[0])

# Setting the headers in the HTTP requests
headers = {
    'accept': 'application/json',
    'api-key': api_key,
    'Content-Type': 'application/x-www-form-urlencoded'
}

# Building the results array
results = []

for exe in executables:
    api_request = f'{api_endpoint}/search/terms'
    data = {'filename': exe}

    response = requests.post(api_request, headers=headers, data=data)
    if response.status_code == 200:
        search_results = response.json()
        results.append((exe, search_results))
    else:
        print(f"Failed to search for {exe}: HTTP {response.status_code}")
        results.append([exe, 'Search Failed'])

# Outputting the csv file
output_file = 'results.csv'
with open(output_file, 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['Executable','search_results'])
    writer.writerows(results)
  
# Printing that the job is done.
print('Results have been written to', output_file)
