import nmap
import logging

def port_scanning(target_ip, ports):
    logging.info(f"Starting port scan on {target_ip}...")
    nm = nmap.PortScanner()
    nm.scan(target_ip, ','.join(map(str, ports)))
    open_ports = []
    for proto in nm[target_ip].all_protocols():
        lport = nm[target_ip][proto].keys()
        for port in lport:
            if nm[target_ip][proto][port]['state'] == 'open':
                open_ports.append(port)
    logging.info(f"Open ports discovered: {open_ports}")
    return open_ports

if __name__ == "__main__":
    from initialize import load_config, setup_logging
    setup_logging()
    config = load_config()
    target = config['targets'][0]
    open_ports = port_scanning(target['ip'], config['scanning']['ports'])
    print(f"Open ports: {open_ports}")
