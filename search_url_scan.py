import os
import requests
from urllib.parse import urlparse
from tld import get_tld

# Get your API key from an environment variable
api_key = os.getenv('URLSCAN_API_KEY')

# Ensure the API key is present
if not api_key:
    print("URLSCAN_API_KEY environment variable not set.")
    exit(1)

# The search query
query = "YOUR_QUERY_HERE"

# URLscan.io search API endpoint
search_url = "https://urlscan.io/api/v1/search/"

# Headers for authentication
headers = {
    'API-Key': api_key,
    'Content-Type': 'application/json'
}

# Parameters for the search
params = {
    'q': query,
    'size': 100  # Adjust the size as needed
}

def get_tlds_from_redirects(search_url, params, headers):
    try:
        response = requests.get(search_url, headers=headers, params=params)
        response.raise_for_status()  # Raise an error for bad responses
        results = response.json()['results']
        
        tlds = set()
        for result in results:
            page_url = result.get('page', {}).get('url')
            if page_url:
                try:
                    # Extract the TLD from the URL
                    tld = get_tld(page_url, as_object=True).suffix
                    tlds.add(tld)
                except Exception as e:
                    print(f"Error extracting TLD from {page_url}: {e}")
        
        return tlds
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return set()

# Call the function and print the TLDs
tlds = get_tlds_from_redirects(search_url, params, headers)
print("Extracted TLDs:", tlds)
