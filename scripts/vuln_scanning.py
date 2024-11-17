import requests
import os
from os.path import join, dirname
from dotenv import load_dotenv
import logging
import shodan

dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)

def vuln_scanning(service):
    logging.info(f"Scanning vulnerabilities for service: {service}...")
    vulns = []
    api_key = os.environ.get("SHODAN_KEY")  # Replace with your Shodan API key
    client = shodan.Shodan(api_key)

    try:
        # Perform a Shodan search
        query = f"{service}"
        results = client.search(query)

        # Parse and store vulnerabilities
        for result in results['matches']:
            vulns.append({
                'ip': result.get('ip_str', 'N/A'),
                'port': result.get('port', 'N/A'),
                'data': result.get('data', 'N/A'),
                'vulns': result.get('vulns', [])
            })

        logging.info(f"Vulnerabilities found for {service}: {len(vulns)}")
    except shodan.APIError as e:
        logging.error(f"Shodan API error: {e}")
        return []

    return vulns


if __name__ == "__main__":
    from initialize import load_config, setup_logging
    setup_logging()
    config = load_config()

    # Replace with actual services from your service enumeration step
    services = {
        22: "ssh",
        80: "http",
    }

    vulnerabilities = {port: vuln_scanning(service) for port, service in services.items()}
    for port, vulns in vulnerabilities.items():
        print(f"Port {port}:")
        for vuln in vulns:
            print(f"  IP: {vuln['ip']}, Port: {vuln['port']}, Vulnerabilities: {vuln['vulns']}")