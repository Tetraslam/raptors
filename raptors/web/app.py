from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
import asyncio
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from ..scanner import Scanner, ScanTarget
import aiofiles
import os
from rich.console import Console
from collections import defaultdict
from datetime import timezone
import logging

app = FastAPI(title="Raptors Security Scanner", version="2.0.0")
console = Console()

# Mount static files
static_path = Path(__file__).parent / "static"
templates_path = Path(__file__).parent / "templates"
app.mount("/static", StaticFiles(directory=str(static_path)), name="static")
templates = Jinja2Templates(directory=str(templates_path))

# WebSocket manager for real-time updates
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.scan_tasks = {}

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except WebSocketDisconnect:
                await self.disconnect(connection)

manager = ConnectionManager()

# Routes
@app.get("/", response_class=HTMLResponse)
async def get_dashboard(request: Request):
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request}
    )

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_json()
            if data["action"] == "start_scan":
                asyncio.create_task(run_scan(data["target"], websocket))
            elif data["action"] == "get_reports":
                await send_report_data(websocket)
    except WebSocketDisconnect:
        manager.disconnect(websocket)

async def run_scan(target: str, websocket: WebSocket):
    scanner = Scanner()
    scan_target = ScanTarget(host=target)
    
    try:
        # Send initial status
        await websocket.send_json({
            "type": "scan_status",
            "status": "scanning",
            "message": f"Starting comprehensive scan of {target}",
            "progress": 0.0
        })

        # Track scan progress
        async def progress_callback(stage: str, progress: float, message: str):
            try:
                await websocket.send_json({
                    "type": "scan_status",
                    "status": "scanning",
                    "stage": stage,
                    "progress": progress,
                    "message": f"[{stage.upper()}] {message}"
                })
            except Exception as e:
                logging.error(f"Error sending progress update: {str(e)}")

        # Perform the scan with progress tracking
        result = await scanner.scan_target(scan_target, progress_callback=progress_callback)

        # Process and save the scan results
        timestamp = datetime.now(timezone.utc)
        
        report_dir = Path(os.getenv("SCAN_REPORTS_DIR", "scan_reports"))
        year_dir = report_dir / str(timestamp.year)
        month_dir = year_dir / f"{timestamp.month:02d}"
        day_dir = month_dir / f"{timestamp.day:02d}"
        day_dir.mkdir(parents=True, exist_ok=True)
        
        # Save scan results
        report_file = day_dir / f"report_{timestamp.strftime('%H%M%S')}.json"
        
        # Convert Pydantic models to dict for JSON serialization
        services_data = []
        for service in result.services:
            service_dict = {
                "port": service.port,
                "service": service.service,
                "version": service.version,
                "product": service.product,
                "os_type": service.os_type,
                "scripts": service.scripts,
                "vulnerabilities": [vuln.dict() for vuln in service.vulnerabilities]
            }
            services_data.append(service_dict)
        
        report_data = {
            "timestamp": timestamp.isoformat(),  # This will include timezone info
            "target": target,
            "scan_duration": result.scan_duration,
            "services": services_data,
            "os_info": result.os_info,
            "vulnerabilities": [vuln.dict() for vuln in result.vulnerabilities],
            "risk_score": result.risk_score,
            "raw_data": result.raw_data,
            "open_ports": {
                service.port: {
                    "service": service.service,
                    "version": service.version,
                    "product": service.product
                }
                for service in result.services
            }
        }
        
        async with aiofiles.open(report_file, mode='w') as f:
            await f.write(json.dumps(report_data, indent=2))

        # Send completion status with summary
        await websocket.send_json({
            "type": "scan_status",
            "status": "completed",
            "message": (
                f"Scan completed in {result.scan_duration:.1f}s\n"
                f"Found {len(result.vulnerabilities)} vulnerabilities\n"
                f"Risk Score: {result.risk_score:.1f}/10\n"
                f"OS: {result.os_info.get('os_match', 'Unknown')} "
                f"({result.os_info.get('accuracy', '0')}% confidence)"
            ),
            "data": report_data
        })

        # Update all connected clients with new data
        await send_report_data(websocket)

    except Exception as e:
        console.print_exception()
        await websocket.send_json({
            "type": "scan_status",
            "status": "error",
            "message": f"Scan failed: {str(e)}"
        })

async def send_report_data(websocket: WebSocket):
    reports_dir = Path(os.getenv("SCAN_REPORTS_DIR", "scan_reports"))
    all_reports = []
    
    try:
        for year_dir in sorted(reports_dir.glob("*"), reverse=True):
            if not year_dir.is_dir():
                continue
            for month_dir in sorted(year_dir.glob("*"), reverse=True):
                if not month_dir.is_dir():
                    continue
                for day_dir in sorted(month_dir.glob("*"), reverse=True):
                    if not day_dir.is_dir():
                        continue
                    # Look for both old and new report formats
                    for report_file in sorted(day_dir.glob("*report_*.json"), reverse=True):
                        try:
                            async with aiofiles.open(report_file, mode='r') as f:
                                content = await f.read()
                                report_data = json.loads(content)
                                all_reports.append(report_data)
                        except Exception as e:
                            console.print(f"Error reading report {report_file}: {str(e)}")
                            continue

        # Process reports for visualization
        vulnerability_trends = defaultdict(int)
        risk_distribution = defaultdict(int)
        service_stats = defaultdict(int)
        os_distribution = defaultdict(int)
        topology_data = {
            "nodes": [],
            "links": []
        }
        recent_scans = []  # Store processed recent scans
        
        # Get data from the last 30 days
        thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
        
        for report in all_reports:
            try:
                # Parse timestamp handling various formats
                timestamp = report.get('timestamp', '')
                if not timestamp:
                    continue
                
                # Clean up timestamp format - handle all possible cases
                if '+00:00+00:00' in timestamp:
                    timestamp = timestamp.replace('+00:00+00:00', '+00:00')
                elif timestamp.endswith('Z'):
                    timestamp = timestamp[:-1] + '+00:00'
                elif timestamp.endswith('+00:00Z'):
                    timestamp = timestamp[:-1]  # Remove trailing Z
                
                try:
                    date = datetime.fromisoformat(timestamp)
                except ValueError as e:
                    logging.error(f"Invalid timestamp format: {timestamp}")
                    continue
                
                # Ensure date is timezone-aware
                if date.tzinfo is None:
                    date = date.replace(tzinfo=timezone.utc)
                
                if date < thirty_days_ago:
                    continue
                
                date_str = date.strftime('%Y-%m-%d')
                
                # Get target from report
                target = report.get('target', 'unknown')
                
                # Add target node if not exists
                target_exists = any(node['id'] == target for node in topology_data['nodes'])
                if not target_exists:
                    topology_data['nodes'].append({
                        'id': target,
                        'group': 1,
                        'type': 'host'
                    })
                
                # Process services and add to topology
                services = []
                if 'services' in report:
                    services = report['services']
                elif 'open_ports' in report:
                    # Convert old format to new format
                    for port, info in report['open_ports'].items():
                        services.append({
                            'port': port,
                            'service': info.get('service', 'unknown'),
                            'version': info.get('version', 'unknown'),
                            'product': info.get('product', 'unknown'),
                            'vulnerabilities': []
                        })
                
                for service in services:
                    if isinstance(service, dict):
                        service_name = service.get('service', 'unknown')
                        port = service.get('port', 'unknown')
                        product = service.get('product', 'unknown')
                        version = service.get('version', 'unknown')
                        
                        # Add to service stats with more detailed info
                        if service_name.lower() != 'unknown':
                            service_key = f"{service_name}"
                            if product.lower() != 'unknown':
                                service_key += f" ({product}"
                                if version.lower() != 'unknown':
                                    service_key += f" {version}"
                                service_key += ")"
                            service_key += f" on port {port}"
                            service_stats[service_key] += 1
                            
                            # Add to topology data
                            service_id = f"{service_name}:{port}"
                            service_exists = any(node['id'] == service_id for node in topology_data['nodes'])
                            if not service_exists:
                                topology_data['nodes'].append({
                                    'id': service_id,
                                    'group': 2,
                                    'type': 'service',
                                    'name': service_key,
                                    'port': port,
                                    'product': product,
                                    'version': version,
                                    'vulnerabilities': len(service.get('vulnerabilities', []))
                                })
                                topology_data['links'].append({
                                    'source': target,
                                    'target': service_id,
                                    'value': 1
                                })
                
                # Process vulnerabilities
                vulnerabilities = report.get('vulnerabilities', [])
                vulnerability_trends[date_str] += len(vulnerabilities)
                
                # Process risk distribution
                for vuln in vulnerabilities:
                    cvss_score = vuln.get('cvss_score', 0.0) if isinstance(vuln, dict) else 0.0
                    
                    if cvss_score >= 9.0:
                        risk_distribution['Critical'] += 1
                    elif cvss_score >= 7.0:
                        risk_distribution['High'] += 1
                    elif cvss_score >= 4.0:
                        risk_distribution['Medium'] += 1
                    else:
                        risk_distribution['Low'] += 1
                
                # Process OS info
                os_info = report.get('os_info', {})
                os_match = os_info.get('os_match', 'Unknown') if isinstance(os_info, dict) else 'Unknown'
                os_distribution[os_match] += 1
                
                # Add to recent scans
                recent_scans.append({
                    'timestamp': timestamp,
                    'target': target,
                    'vulnerabilities': vulnerabilities,
                    'services': services,
                    'risk_score': report.get('risk_score', 0.0),
                    'scan_duration': report.get('scan_duration', 0.0)
                })
            
            except Exception as e:
                logging.error(f"Error processing report: {str(e)}")
                continue
        
        # Sort recent scans by timestamp (newest first)
        recent_scans.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Sort and prepare final data
        vulnerability_trends = dict(sorted(vulnerability_trends.items())[-30:])
        service_stats = dict(sorted(service_stats.items(), key=lambda x: x[1], reverse=True)[:10])
        os_distribution = dict(sorted(os_distribution.items(), key=lambda x: x[1], reverse=True))
        
        # Send the data
        await websocket.send_json({
            "type": "visualization_data",
            "data": {
                "vulnerability_trends": vulnerability_trends,
                "risk_distribution": risk_distribution,
                "service_stats": service_stats,
                "os_distribution": os_distribution,
                "topology": topology_data,
                "recent_scans": recent_scans[:10]  # Only send the 10 most recent scans
            }
        })
    except Exception as e:
        console.print_exception()
        await websocket.send_json({
            "type": "error",
            "message": f"Failed to load report data: {str(e)}"
        })
