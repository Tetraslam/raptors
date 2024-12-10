import nmap
import asyncio
from typing import List, Dict, Tuple, Optional
from ..models import Service, Vulnerability, ScanReport
import logging
import sys
import os
import ctypes
import socket
from .vulnerability_scanner import VulnerabilityScanner

logger = logging.getLogger(__name__)

# Common ports to scan first
COMMON_PORTS = [
    80,    # HTTP
    443,   # HTTPS
    22,    # SSH
    3389,  # RDP
    8080,  # HTTP Proxy
    21,    # FTP
    3000,  # Added 3000 to the list
]

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

class PortScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.vuln_scanner = VulnerabilityScanner()
        self.loop = asyncio.get_event_loop()
        if not is_admin():
            logger.warning("Scanner is not running with administrator privileges. Some features may not work correctly.")

    async def scan_target(self, host: str, port_range: Optional[str] = None) -> Tuple[List[Service], List[Vulnerability]]:
        """Scan a target host for open ports and vulnerabilities"""
        logger.info(f"Starting target scan for {host}")
        
        services = await self.scan_ports(host, port_range)
        if not services:
            logger.warning("No services found to scan for vulnerabilities")
            return [], []

        logger.info(f"Found {len(services)} services, checking for vulnerabilities")
        all_vulnerabilities = []

        for service in services:
            try:
                vulnerabilities = await self.vuln_scanner.scan_service(service)
                if vulnerabilities:
                    logger.info(f"Found {len(vulnerabilities)} vulnerabilities for {service.name} on port {service.port}")
                    all_vulnerabilities.extend(vulnerabilities)
                else:
                    logger.info(f"No vulnerabilities found for {service.name} on port {service.port}")
            except Exception as e:
                logger.error(f"Error scanning service {service.name} on port {service.port}: {str(e)}")

        return services, all_vulnerabilities

    async def scan_ports(self, host: str, port_range: Optional[str] = None) -> List[Service]:
        """
        Scan ports on the target host using nmap
        """
        try:
            # Sanitize host input
            host = host.strip()  # Remove leading/trailing whitespace
            if not host:
                raise ValueError("Empty host provided")
            
            # Validate host format
            try:
                socket.inet_aton(host)  # Validate IPv4 address format
            except socket.error:
                raise ValueError(f"Invalid IP address format: {host}")

            logger.info(f"Starting port scan on {host} with range {port_range or 'common ports'}")
            
            # Test multiple common ports for connectivity
            test_ports = [8080, 80, 443, 22]
            connected = False
            for test_port in test_ports:
                try:
                    socket_test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    socket_test.settimeout(1)
                    result = socket_test.connect_ex((host, test_port))
                    socket_test.close()
                    if result == 0:
                        logger.info(f"Found responsive port at {test_port}")
                        connected = True
                        break
                except Exception as e:
                    logger.warning(f"Connectivity test failed for port {test_port}: {str(e)}")
                finally:
                    socket_test.close()
            
            if not connected:
                logger.warning(f"No responsive ports found during initial test on {host}")
            
            # Use a smaller set of most common ports for faster scanning
            common_ports = "8080,80,443,22,3389,3000"
            ports = port_range or common_ports
            
            def run_scan():
                try:
                    logger.info(f"Starting nmap scan on {host} with ports {ports}")
                    args = '-sV -sS -Pn' if is_admin() else '-sV -sT -Pn'
                    scan_result = self.nm.scan(host, ports, arguments=args)
                    
                    if not scan_result or not scan_result.get('scan'):
                        logger.error("Nmap scan failed - no results returned")
                        return None
                    return scan_result
                except Exception as e:
                    logger.error(f"Unexpected error during scan: {str(e)}")
                    return None

            scan_task = self.loop.run_in_executor(None, run_scan)
            result = await asyncio.wait_for(scan_task, timeout=180)  # 3 minute timeout
            
            if not result:
                raise Exception("Nmap scan failed to return results")

            services: List[Service] = []
            
            try:
                if host not in self.nm.all_hosts():
                    raise KeyError(f"No scan results found for host {host}")
                    
                scan_data = self.nm[host]
                logger.debug(f"Scan data for {host}: {scan_data}")
                
                if 'tcp' in scan_data:
                    for port, data in scan_data['tcp'].items():
                        if data['state'] == 'open':
                            service = Service(
                                port=port,
                                name=data.get('name', 'unknown'),
                                version=data.get('version', ''),
                                protocol='tcp'
                            )
                            services.append(service)
                            logger.info(f"Found open port {port} running {service.name}")
                else:
                    logger.warning("No TCP ports found in scan data")
                    logger.debug(f"Available protocols: {list(scan_data.keys())}")

            except KeyError as e:
                logger.error(f"Error parsing nmap results: {str(e)}")
                raise Exception(f"Failed to parse nmap results for host {host}")

            logger.info(f"Scan completed. Found {len(services)} open ports/services")
            return services

        except ValueError as e:
            logger.error(f"Invalid input: {str(e)}")
            raise
        except asyncio.TimeoutError:
            logger.error("Scan timed out")
            raise Exception("Scan timed out after 3 minutes")
        except Exception as e:
            logger.error(f"Error during port scanning: {str(e)}")
            raise

    async def _ping_sweep(self, host: str):
        """Perform a simple ping sweep to check if host is up"""
        try:
            sweep_task = asyncio.get_event_loop().run_in_executor(
                None,
                self.nm.scan,
                host,
                '',
                '-sn -T4 -n --max-retries 1'  # Fast ping scan with limited retries
            )
            await asyncio.wait_for(sweep_task, timeout=5)  # 5 second timeout
        except asyncio.TimeoutError:
            logger.warning("Ping sweep timed out")
            raise

    def get_service_details(self, service: Service) -> Dict:
        """
        Get detailed information about a service
        """
        try:
            service_info = {
                'name': service.name,
                'version': service.version,
                'cpe': self.nm[service.name]['cpe'] if 'cpe' in self.nm[service.name] else None
            }
            return service_info
        except Exception as e:
            logger.error(f"Error getting service details: {str(e)}")
            return {
                'name': service.name,
                'version': service.version,
                'cpe': None
            }
