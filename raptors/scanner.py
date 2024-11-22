import asyncio
import nmap
import json
import logging
import re
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path
import aiohttp
from rich.progress import Progress, SpinnerColumn, TextColumn
from pydantic import BaseModel
import os
from dotenv import load_dotenv

load_dotenv()

class ScanTarget(BaseModel):
    host: str
    ports: str = os.getenv("DEFAULT_PORTS", "21-443")
    scan_type: str = "intense"

class VulnerabilitySource(BaseModel):
    name: str
    cve_id: str
    cvss_score: float
    description: str
    references: List[str]
    recommendations: List[str]
    source: str  # e.g., 'NVD', 'ExploitDB', 'Vulners'

class ServiceInfo(BaseModel):
    port: str
    service: str
    version: str
    product: str
    os_type: Optional[str]
    scripts: Dict[str, str] = {}  # Script name -> output
    vulnerabilities: List[VulnerabilitySource] = []

class ScanResult(BaseModel):
    target: str
    timestamp: datetime
    services: List[Dict]
    os_info: Dict[str, str] = {}
    vulnerabilities: List[VulnerabilitySource]
    scan_duration: float
    risk_score: float = 0.0
    raw_data: Dict = {}

    def calculate_risk_score(self) -> float:
        if not self.vulnerabilities:
            return 0.0
        
        # Weight factors
        weights = {
            'critical': 1.0,   # CVSS 9.0-10.0
            'high': 0.8,       # CVSS 7.0-8.9
            'medium': 0.5,     # CVSS 4.0-6.9
            'low': 0.2         # CVSS 0.1-3.9
        }
        
        total_score = 0
        max_score = 0
        
        for vuln in self.vulnerabilities:
            if vuln.cvss_score >= 9.0:
                weight = weights['critical']
            elif vuln.cvss_score >= 7.0:
                weight = weights['high']
            elif vuln.cvss_score >= 4.0:
                weight = weights['medium']
            else:
                weight = weights['low']
            
            total_score += vuln.cvss_score * weight
            max_score += 10.0 * weight
        
        return (total_score / max_score) * 10.0 if max_score > 0 else 0.0

class Scanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.scan_timeout = int(os.getenv("SCAN_TIMEOUT", 300))
        
    async def scan_target(self, target: ScanTarget, progress_callback=None) -> ScanResult:
        start_time = datetime.now()
        all_vulnerabilities = []
        
        try:
            if progress_callback:
                await progress_callback("init", 0.0, f"Initializing comprehensive scan of {target.host}")
            
            # Phase 1: Initial port scan and service detection
            if progress_callback:
                await progress_callback("port_scan", 0.1, "Running initial port scan")
            
            # Comprehensive port scan with service detection, OS detection, and default scripts
            arguments = (
                "-sS -sV -O -A -T4 "  # Basic scan options
                "--script=vuln,exploit,auth,default "  # Vulnerability scripts
                "--script-args=vulns.showall=on "  # Show all vulnerabilities
                f"--host-timeout {self.scan_timeout}"
            )
            
            self.nm.scan(
                target.host,
                target.ports,
                arguments=arguments
            )
            
            if progress_callback:
                await progress_callback("processing", 0.3, "Processing initial scan results")
            
            scan_data = self.nm[target.host] if target.host in self.nm.all_hosts() else {}
            services = []
            
            # Phase 2: Process service information and run targeted scripts
            if 'tcp' in scan_data:
                total_ports = len(scan_data['tcp'])
                processed_ports = 0
                
                for port, data in scan_data['tcp'].items():
                    if data['state'] == 'open':
                        if progress_callback:
                            processed_ports += 1
                            progress = 0.3 + (0.2 * (processed_ports / total_ports))
                            await progress_callback(
                                "service_scan",
                                progress,
                                f"Analyzing service on port {port}"
                            )
                        
                        service_info = ServiceInfo(
                            port=str(port),
                            service=data.get('name', 'unknown'),
                            version=data.get('version', 'unknown'),
                            product=data.get('product', 'unknown'),
                            os_type=data.get('ostype', None),
                            scripts={} if 'script' not in data else data['script']
                        )
                        
                        # Process script vulnerabilities for this service
                        if 'script' in data:
                            for script_name, output in data['script'].items():
                                if any(vuln_indicator in output.upper() for vuln_indicator in [
                                    'VULNERABLE',
                                    'CVE-',
                                    'SECURITY HOLE',
                                    'EXPLOIT',
                                    'VULNERABILITY',
                                    'AFFECTED'
                                ]):
                                    cve_matches = re.findall(r'CVE-\d{4}-\d{4,7}', output)
                                    state = "Vulnerable"
                                    
                                    # Extract severity if available
                                    severity = "Medium"  # Default
                                    if 'CRITICAL' in output.upper():
                                        severity = "Critical"
                                    elif 'HIGH' in output.upper():
                                        severity = "High"
                                    elif 'LOW' in output.upper():
                                        severity = "Low"
                                    
                                    # Set CVSS score based on severity
                                    cvss_score = {
                                        "Critical": 9.0,
                                        "High": 7.5,
                                        "Medium": 5.0,
                                        "Low": 2.5
                                    }.get(severity, 5.0)
                                    
                                    # Add vulnerability
                                    vuln = VulnerabilitySource(
                                        name=f"{script_name} ({severity})",
                                        cve_id=cve_matches[0] if cve_matches else f"NMAP-{script_name.upper()}",
                                        cvss_score=cvss_score,
                                        description=output,
                                        references=[],
                                        recommendations=[
                                            f"Address {script_name} findings",
                                            "Update the affected service",
                                            "Apply security patches",
                                            "Review service configuration"
                                        ],
                                        source="Nmap Script"
                                    )
                                    all_vulnerabilities.append(vuln)
                                    service_info.vulnerabilities.append(vuln)
                        
                        services.append(service_info)
            
            # Phase 3: OS Detection
            os_info = {}
            if 'osmatch' in scan_data:
                os_info = {
                    'os_match': scan_data['osmatch'][0]['name'] if scan_data['osmatch'] else 'Unknown',
                    'accuracy': scan_data['osmatch'][0]['accuracy'] if scan_data['osmatch'] else '0',
                    'os_class': scan_data['osmatch'][0]['osclass'][0]['osfamily'] if scan_data['osmatch'] and scan_data['osmatch'][0]['osclass'] else 'Unknown'
                }
            
            # Phase 4: Vulnerability Analysis
            if progress_callback:
                await progress_callback("vuln_check", 0.5, "Starting comprehensive vulnerability analysis")
            
            async with aiohttp.ClientSession() as session:
                # Check NVD
                nvd_vulns = await self._query_nvd(session, services, progress_callback)
                all_vulnerabilities.extend(nvd_vulns)
                
                # Check ExploitDB (if available)
                try:
                    exploit_vulns = await self._check_exploitdb_vulnerabilities(services, session, progress_callback)
                    all_vulnerabilities.extend(exploit_vulns)
                except Exception as e:
                    logging.warning(f"ExploitDB check failed: {str(e)}")
                
                # Process script outputs for additional vulnerabilities
                script_vulns = self._process_script_vulnerabilities(services)
                all_vulnerabilities.extend(script_vulns)
            
            # Create final result
            if progress_callback:
                await progress_callback("finalizing", 0.9, "Compiling final report")
            
            duration = (datetime.now() - start_time).total_seconds()
            
            # Convert services to dict format for JSON serialization
            services_data = []
            for service in services:
                service_dict = {
                    'port': service.port,
                    'service': service.service,
                    'version': service.version,
                    'product': service.product,
                    'os_type': service.os_type,
                    'scripts': service.scripts,
                    'vulnerabilities': [vuln.dict() for vuln in service.vulnerabilities]
                }
                services_data.append(service_dict)
            
            result = ScanResult(
                target=target.host,
                timestamp=start_time,
                services=services_data,
                os_info=os_info,
                vulnerabilities=all_vulnerabilities,
                scan_duration=duration,
                raw_data=scan_data,
                risk_score=0.0
            )
            
            # Calculate final risk score
            result.risk_score = result.calculate_risk_score()
            
            if progress_callback:
                await progress_callback(
                    "complete",
                    1.0,
                    f"Scan completed in {duration:.1f}s. Found {len(all_vulnerabilities)} vulnerabilities. "
                    f"Risk Score: {result.risk_score:.1f}/10"
                )
            
            return result
            
        except Exception as e:
            if progress_callback:
                await progress_callback("error", 0.0, f"Scan error: {str(e)}")
            raise

    async def _check_nvd_vulnerabilities(
        self,
        services: List[ServiceInfo],
        session: aiohttp.ClientSession,
        progress_callback=None
    ) -> List[VulnerabilitySource]:
        vulnerabilities = []
        total_services = len(services)
        
        for idx, service in enumerate(services):
            if progress_callback:
                progress = 0.5 + (0.2 * (idx / total_services))
                await progress_callback(
                    "vuln_check",
                    progress,
                    f"Checking NVD for {service.product} {service.version}"
                )
            
            if service.product != 'unknown' and service.version != 'unknown':
                query = f"{service.product} {service.version}"
                vulns = await self._query_nvd(session, query, progress_callback)
                
                for vuln in vulns:
                    vulnerabilities.append(
                        VulnerabilitySource(
                            name=f"{service.product} Vulnerability",
                            cve_id=vuln.cve_id,
                            cvss_score=vuln.cvss_score,
                            description=vuln.description,
                            references=vuln.references,
                            recommendations=vuln.recommendations,
                            source="NVD"
                        )
                    )
        
        return vulnerabilities

    async def _check_exploitdb_vulnerabilities(
        self,
        services: List[ServiceInfo],
        session: aiohttp.ClientSession,
        progress_callback=None
    ) -> List[VulnerabilitySource]:
        # This is a placeholder for ExploitDB integration
        # You would implement actual ExploitDB API calls here
        return []

    async def _query_nvd(self, session: aiohttp.ClientSession, query: str, progress_callback=None) -> List[VulnerabilitySource]:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        api_key = os.getenv("NVD_API_KEY", "")
        
        headers = {
            "apiKey": api_key
        } if api_key else {}
        
        params = {
            "keywordSearch": query,
            "resultsPerPage": "20"
        }
        
        max_retries = 3
        retry_delay = 10
        
        for attempt in range(max_retries):
            try:
                async with session.get(url, params=params, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_nvd_response(data)
                    elif response.status == 429:  # Rate limit
                        if attempt < max_retries - 1:
                            logging.warning(f"NVD rate limit reached. Waiting {retry_delay}s before retry {attempt + 1}/{max_retries}")
                            await asyncio.sleep(retry_delay)
                            retry_delay *= 2  # Exponential backoff
                            continue
                    elif response.status == 503:  # Service unavailable
                        if attempt < max_retries - 1:
                            logging.warning(f"NVD service unavailable. Waiting {retry_delay}s before retry {attempt + 1}/{max_retries}")
                            await asyncio.sleep(retry_delay)
                            retry_delay *= 2  # Exponential backoff
                            continue
                        else:
                            logging.error("NVD service unavailable after all retries")
                    else:
                        logging.error(f"NVD API error: Status {response.status}")
                        if attempt < max_retries - 1:
                            await asyncio.sleep(retry_delay)
                            continue
            except aiohttp.ClientError as e:
                logging.error(f"NVD API connection error: {str(e)}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
                    continue
            except Exception as e:
                logging.error(f"Error querying NVD: {str(e)}")
                break
        
        # If we get here, we failed to get data from NVD
        if progress_callback:
            await progress_callback(
                "warning",
                0.0,
                "Could not fetch data from NVD. Continuing with local vulnerability checks."
            )
        return []

    def _parse_nvd_response(self, data: Dict) -> List[VulnerabilitySource]:
        vulnerabilities = []
        
        try:
            for vuln in data.get('vulnerabilities', []):
                cve = vuln.get('cve', {})
                
                # Get CVSS score
                metrics = cve.get('metrics', {})
                cvss_score = 0.0
                
                # Try V31 first, then V30, then V2
                if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                    cvss_score = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseScore', 0.0)
                elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                    cvss_score = metrics['cvssMetricV30'][0].get('cvssData', {}).get('baseScore', 0.0)
                elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                    cvss_score = metrics['cvssMetricV2'][0].get('cvssData', {}).get('baseScore', 0.0)
                
                # Get references
                references = []
                for ref in cve.get('references', []):
                    url = ref.get('url', '')
                    if url:
                        references.append(url)
                
                # Get recommendations from descriptions
                descriptions = cve.get('descriptions', [])
                description = next((d['value'] for d in descriptions if d.get('lang') == 'en'), '')
                
                recommendations = [
                    "Update the affected software to the latest version",
                    "Apply security patches as recommended by the vendor",
                    "Monitor vendor's security advisories"
                ]
                
                vulnerabilities.append(
                    VulnerabilitySource(
                        name=cve.get('id', ''),
                        cve_id=cve.get('id', ''),
                        cvss_score=cvss_score,
                        description=description,
                        references=references,
                        recommendations=recommendations,
                        source="NVD"
                    )
                )
        except Exception as e:
            logging.error(f"Error parsing NVD response: {str(e)}")
        
        return vulnerabilities

    def _process_script_vulnerabilities(self, services: List[ServiceInfo]) -> List[VulnerabilitySource]:
        vulnerabilities = []
        
        for service in services:
            for script_name, output in service.scripts.items():
                # Check for various vulnerability indicators in script output
                indicators = [
                    'VULNERABLE',
                    'CVE-',
                    'SECURITY HOLE',
                    'EXPLOIT',
                    'VULNERABILITY'
                ]
                
                if any(indicator in output.upper() for indicator in indicators):
                    # Try to extract CVE IDs
                    cve_matches = re.findall(r'CVE-\d{4}-\d{4,7}', output)
                    
                    # Extract state information
                    state_match = re.search(r'State: (.*?)\n', output)
                    state = state_match.group(1) if state_match else "Unknown"
                    
                    # Extract additional details
                    details_match = re.search(r'\|\s*(.*?)\n', output)
                    details = details_match.group(1) if details_match else output
                    
                    # Determine CVSS score based on script output
                    cvss_score = 7.5  # Default score
                    if 'CRITICAL' in output.upper():
                        cvss_score = 9.0
                    elif 'HIGH' in output.upper():
                        cvss_score = 7.5
                    elif 'MEDIUM' in output.upper():
                        cvss_score = 5.0
                    elif 'LOW' in output.upper():
                        cvss_score = 2.5
                    
                    for cve_id in (cve_matches or ['NMAP-' + script_name.upper()]):
                        vulnerabilities.append(
                            VulnerabilitySource(
                                name=f"{script_name} - {state}",
                                cve_id=cve_id,
                                cvss_score=cvss_score,
                                description=details,
                                references=[],
                                recommendations=[
                                    f"Address {script_name} findings",
                                    "Update the affected service",
                                    "Apply security patches",
                                    "Review service configuration"
                                ],
                                source="Nmap Script"
                            )
                        )
        
        return vulnerabilities
