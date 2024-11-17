import subprocess
import re
import logging

def scan_vulnerabilities(ip, ports):
    """
    Scans the target IP for vulnerabilities using nmap and searchsploit.
    """
    logging.info(f"Starting vulnerability scan on {ip} for ports {ports}...")
    vulnerabilities = {}

    # Step 1: Perform nmap scan with version detection and vulnerability scripts
    try:
        logging.info("Running nmap vulnerability scan...")
        nmap_command = [
            "nmap",
            "-sV",  # Service/version detection
            "--script", "vuln",  # Vulnerability scripts
            "-p", ",".join(map(str, ports)),  # Target ports
            ip,
        ]
        nmap_result = subprocess.check_output(nmap_command, text=True)
        logging.info("Nmap scan completed successfully.")
        vulnerabilities["nmap"] = parse_nmap_vulns(nmap_result)
    except subprocess.CalledProcessError as e:
        logging.error(f"Nmap scan failed: {e}")
        vulnerabilities["nmap"] = []

    # Step 2: Use searchsploit for additional vulnerabilities
    try:
        logging.info("Running searchsploit scan...")
        for port, service_info in vulnerabilities["nmap"].items():
            if "service" in service_info:
                service = service_info["service"]
                searchsploit_result = search_exploit(service)
                vulnerabilities.setdefault("searchsploit", {})[port] = searchsploit_result
    except Exception as e:
        logging.error(f"Searchsploit scan failed: {e}")

    return vulnerabilities


def parse_nmap_vulns(nmap_result):
    """
    Parses the output of nmap's vulnerability scan.
    """
    vulns = {}
    lines = nmap_result.splitlines()
    current_port = None

    for line in lines:
        port_match = re.match(r"(\d+)/tcp\s+open\s+\S+\s+(.*)", line)
        if port_match:
            current_port = int(port_match.group(1))
            vulns[current_port] = {"service": port_match.group(2), "vulns": []}
        elif current_port and re.search(r"CVE-\d{4}-\d+", line):
            cve = re.search(r"(CVE-\d{4}-\d+)", line).group(1)
            vulns[current_port]["vulns"].append(cve)

    return vulns


def search_exploit(service_name):
    """
    Searches for exploits using searchsploit.
    """
    try:
        result = subprocess.check_output(["searchsploit", service_name], text=True)
        exploits = parse_searchsploit_output(result)
        return exploits
    except subprocess.CalledProcessError as e:
        logging.error(f"Searchsploit failed for {service_name}: {e}")
        return []


def parse_searchsploit_output(output):
    """
    Parses searchsploit's output for exploit details.
    """
    exploits = []
    lines = output.splitlines()
    for line in lines:
        if line.strip() and not line.startswith("Exploit Title"):
            exploits.append(line.strip())
    return exploits


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    target_ip = "192.168.56.101"
    target_ports = [22, 80, 445]  # Common ports to scan
    vulnerabilities = scan_vulnerabilities(target_ip, target_ports)

    # Print the vulnerabilities
    for tool, results in vulnerabilities.items():
        print(f"\n--- {tool.upper()} RESULTS ---")
        for port, data in results.items():
            print(f"Port {port}:")
            if isinstance(data, dict):
                print(f"  Service: {data.get('service', 'Unknown')}")
                print(f"  Vulnerabilities: {', '.join(data.get('vulns', []))}")
            else:
                print(f"  {data}")
