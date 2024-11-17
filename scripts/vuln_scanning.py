import subprocess
import re
import logging


def scan_vulnerabilities(ip, ports):
    """
    Scans the target IP for vulnerabilities using nmap, searchsploit, and integrates manual lookup.
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
        nmap_vulns = parse_nmap_vulns(nmap_result)
        vulnerabilities["nmap"] = nmap_vulns
    except subprocess.CalledProcessError as e:
        logging.error(f"Nmap scan failed: {e}")
        vulnerabilities["nmap"] = {}

    # Step 2: Use searchsploit for additional vulnerabilities
    vulnerabilities["searchsploit"] = {}
    for port, service_info in nmap_vulns.items():
        service_name = service_info.get("service", "unknown")
        logging.info(f"Running searchsploit for service on port {port}: {service_name}")
        exploits = search_exploit(service_name)
        vulnerabilities["searchsploit"][port] = exploits

    # Step 3: Manual vulnerabilities lookup
    vulnerabilities["manual"] = manual_vuln_lookup(nmap_vulns)

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
        return ["No results found"]


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


def manual_vuln_lookup(nmap_vulns):
    """
    Adds manual lookup for common vulnerabilities (e.g., Metasploitable 2).
    """
    manual_vulns = {
        "22": ["CVE-2008-0166: OpenSSH key compromise via weak random number generator"],
        "80": ["CVE-2007-6750: Apache 2.2.8 directory traversal"],
        "445": ["CVE-2007-2447: Samba command injection"],
    }

    matched_vulns = {}
    for port, service_info in nmap_vulns.items():
        if str(port) in manual_vulns:
            matched_vulns[port] = manual_vulns[str(port)]

    return matched_vulns


def generate_report(vulnerabilities):
    """
    Generates a simple vulnerability report.
    """
    with open("vulnerability_report.txt", "w") as report:
        for tool, results in vulnerabilities.items():
            report.write(f"\n--- {tool.upper()} RESULTS ---\n")
            for port, data in results.items():
                report.write(f"Port {port}:\n")
                if isinstance(data, dict):
                    report.write(f"  Service: {data.get('service', 'Unknown')}\n")
                    report.write(f"  Vulnerabilities: {', '.join(data.get('vulns', []))}\n")
                elif isinstance(data, list):
                    report.write(f"  {', '.join(data)}\n")


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
            elif isinstance(data, list):
                print(f"  {', '.join(data)}")

    # Generate the report
    generate_report(vulnerabilities)
    logging.info("Vulnerability report generated: vulnerability_report.txt")
