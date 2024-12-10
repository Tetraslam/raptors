from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from typing import List, Dict
import asyncio

from .models import ScanReport, ScanRequest, RiskLevel
from .services.scanner import PortScanner
from .services.database import DatabaseService
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()
scanner = PortScanner()
db_service = DatabaseService()

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Next.js development server
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
    expose_headers=["*"]
)

@app.get("/reports", response_model=List[ScanReport])
async def get_reports():
    """
    Get all scan reports
    """
    try:
        reports = await db_service.get_all_reports()
        return reports
    except Exception as e:
        logger.error(f"Error retrieving reports: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve reports")

@app.post("/scan")
async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Start a new vulnerability scan
    """
    try:
        # Validate host
        if not scan_request.host:
            raise HTTPException(status_code=400, detail="Host is required")
        
        # Basic IP/hostname validation
        host = scan_request.host.strip()
        if not host or host.count('.') != 3 or not all(part.isdigit() and 0 <= int(part) <= 255 for part in host.split('.')):
            if host != "localhost":
                raise HTTPException(status_code=400, detail="Invalid IP address format")
        
        logger.info(f"Received scan request for host: {host}")
        background_tasks.add_task(perform_scan, scan_request)
        return {"message": f"Scan started for host: {host}"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

async def perform_scan(scan_request: ScanRequest):
    """
    Perform the actual scan and save results
    """
    try:
        logger.info(f"Starting scan for host: {scan_request.host}")
        
        try:
            services, vulnerabilities = await scanner.scan_target(
                scan_request.host,
                scan_request.port_range
            )
        except Exception as e:
            logger.error(f"Scan operation failed: {str(e)}")
            raise
        
        logger.info(f"Scan completed. Found {len(services)} services and {len(vulnerabilities)} vulnerabilities")
        logger.debug(f"Services found: {[f'{s.name}:{s.port}' for s in services]}")
        
        if not services:
            logger.warning("No services found during scan")
        
        if not vulnerabilities:
            logger.warning("No vulnerabilities found during scan")

        # Calculate risk summary
        risk_summary = {
            RiskLevel.CRITICAL: len([v for v in vulnerabilities if v.risk_level == RiskLevel.CRITICAL]),
            RiskLevel.MEDIUM: len([v for v in vulnerabilities if v.risk_level == RiskLevel.MEDIUM]),
            RiskLevel.LOW: len([v for v in vulnerabilities if v.risk_level == RiskLevel.LOW])
        }
        
        logger.info(f"Risk summary: {risk_summary}")

        # Create scan report
        report = ScanReport(
            scan_timestamp=datetime.utcnow(),
            host=scan_request.host,
            services=services,
            vulnerabilities=vulnerabilities,
            total_vulnerabilities=len(vulnerabilities),
            risk_summary=risk_summary
        )

        # Save report to database
        report_id = await db_service.save_report(report)
        logger.info(f"Scan completed and saved with ID: {report_id}")

    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        raise

@app.get("/reports/{report_id}", response_model=ScanReport)
async def get_report(report_id: str):
    """
    Get a specific scan report
    """
    try:
        report = await db_service.get_report(report_id)
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        return report
    except Exception as e:
        logger.error(f"Error retrieving report: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve report")

@app.delete("/reports/{report_id}")
async def delete_report(report_id: str):
    """
    Delete a specific scan report
    """
    try:
        await db_service.delete_report(report_id)
        return {"message": "Report deleted"}
    except Exception as e:
        logger.error(f"Error deleting report: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to delete report")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
