import requests
import os
from os.path import join, dirname
from dotenv import load_dotenv

dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)

def vuln_scanning(service):
    api_key = os.environ.get("SHODAN_KEY")
    url = f'https://api.shodan.io/shodan/host/search?key={api_key}&query={service}'
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        return data['matches']
    except requests.exceptions.RequestException as e:
        print(f"Error fetching vulnerabilities: {e}")
        return []
