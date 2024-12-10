from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from .services.scanner import PortScanner
from .models import ScanReport, Service, Vulnerability
import logging
import uuid
from typing import Dict, List, Optional
import asyncio

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scanner = PortScanner()
active_scans: Dict[str, ScanReport] = {}

@app.get("/")
async def root():
    """Raptors Vulnerability Scanner API"""
    return {"message": "Raptors Vulnerability Scanner API"}

@app.post("/scan")
async def start_scan(background_tasks: BackgroundTasks, target: str = "127.0.0.1", port_range: Optional[str] = None):
    """Start a new vulnerability scan"""
    scan_id = str(uuid.uuid4())
    active_scans[scan_id] = ScanReport(
        id=scan_id,
        target=target,
        status="running",
        services=[],
        vulnerabilities=[]
    )
    
    background_tasks.add_task(perform_scan, scan_id, target, port_range)
    return {"scan_id": scan_id}

@app.get("/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get the status of a scan"""
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return active_scans[scan_id]

@app.get("/reports")
async def get_reports():
    """Get all scan reports"""
    return list(active_scans.values())

async def perform_scan(scan_id: str, target: str, port_range: Optional[str] = None):
    """Perform the actual scan and save results"""
    try:
        services, vulnerabilities = await scanner.scan_target(target, port_range)
        
        active_scans[scan_id].services = services
        active_scans[scan_id].vulnerabilities = vulnerabilities
        active_scans[scan_id].status = "completed"
        
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        active_scans[scan_id].status = "error"
        active_scans[scan_id].error = str(e)
