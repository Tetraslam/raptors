import requests
import logging
from time import sleep

def vuln_scanning(service, retries=3, backoff=5):
    logging.info(f"Scanning vulnerabilities for service: {service}...")
    vulns = []
    api_key = 'YOUR_VULNERS_API_KEY'
    headers = {'Authorization': f'Bearer {api_key}'}
    
    for attempt in range(retries):
        try:
            response = requests.get(
                f'https://vulners.com/api/v3/search/lucene/?query=service:{service}',
                headers=headers,
                timeout=10
            )
            response.raise_for_status()  # Raise exception for HTTP errors
            data = response.json()
            for item in data.get('data', {}).get('Search', []):
                vulns.append(item['id'])
            logging.info(f"Vulnerabilities for {service}: {vulns}")
            return vulns
        except requests.exceptions.ConnectionError as e:
            logging.warning(f"Connection error: {e}. Retrying in {backoff} seconds...")
            sleep(backoff)
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed: {e}")
            return []
    
    logging.error(f"Failed to fetch vulnerabilities for {service} after {retries} retries.")
    return []

if __name__ == "__main__":
    from initialize import load_config, setup_logging
    setup_logging()
    config = load_config()
    target = config['targets'][0]
    services = {
        22: "ssh",
        80: "http",
    }  # Replace with the actual services from your enumeration step
    vulnerabilities = {port: vuln_scanning(service) for port, service in services.items()}
    print(f"Vulnerabilities: {vulnerabilities}")
