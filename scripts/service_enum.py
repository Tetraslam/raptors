import nmap
import logging

def service_enumeration(target_ip, open_ports):
    logging.info(f"Starting service enumeration on {target_ip}...")
    nm = nmap.PortScanner()
    nm.scan(target_ip, ','.join(map(str, open_ports)), '-sV')
    services = {}
    for port in open_ports:
        service = nm[target_ip]['tcp'][port]['name']
        services[port] = service
    logging.info(f"Services discovered: {services}")
    return services

if __name__ == "__main__":
    from initialize import load_config, setup_logging
    from port_scanning import port_scanning
    setup_logging()
    config = load_config()
    target = config['targets'][0]
    open_ports = port_scanning(target['ip'], config['scanning']['ports'])
    services = service_enumeration(target['ip'], open_ports)
    print(f"Services: {services}")
