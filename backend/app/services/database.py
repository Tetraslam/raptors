from supabase import create_client
from ..config import get_settings
from ..models import ScanReport, Service, Vulnerability
import logging
from typing import List, Optional
import uuid

logger = logging.getLogger(__name__)
settings = get_settings()

class DatabaseService:
    def __init__(self):
        self.supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)

    async def save_report(self, report: ScanReport) -> str:
        """
        Save scan report and its related data to Supabase
        """
        try:
            # Generate UUIDs for the report and its components
            report_id = str(uuid.uuid4())
            
            # 1. Save services
            service_ids = []
            for service in report.services:
                service_data = service.model_dump()
                response = self.supabase.table('services').insert(service_data).execute()
                service_ids.append(response.data[0]['id'])

            # 2. Save vulnerabilities
            vulnerability_ids = []
            for vuln in report.vulnerabilities:
                vuln_data = vuln.model_dump()
                response = self.supabase.table('vulnerabilities').insert(vuln_data).execute()
                vulnerability_ids.append(response.data[0]['id'])

            # 3. Save the main report
            report_data = {
                'id': report_id,
                'scan_timestamp': report.scan_timestamp.isoformat(),
                'host': report.host,
                'total_vulnerabilities': report.total_vulnerabilities,
                'risk_summary': report.risk_summary
            }
            self.supabase.table('scan_reports').insert(report_data).execute()

            # 4. Create relationships
            for service_id in service_ids:
                self.supabase.table('scan_report_services').insert({
                    'scan_report_id': report_id,
                    'service_id': service_id
                }).execute()

            for vuln_id in vulnerability_ids:
                self.supabase.table('scan_report_vulnerabilities').insert({
                    'scan_report_id': report_id,
                    'vulnerability_id': vuln_id
                }).execute()

            logger.info(f"Successfully saved report with ID: {report_id}")
            return report_id

        except Exception as e:
            logger.error(f"Error saving report to database: {str(e)}")
            raise

    async def get_report(self, report_id: str) -> Optional[ScanReport]:
        """
        Retrieve a specific report with all related data from Supabase
        """
        try:
            # Use the custom function to get report details
            response = self.supabase.rpc(
                'get_scan_report_details',
                {'report_id': report_id}
            ).execute()

            if response.data and len(response.data) > 0:
                report_data = response.data[0]
                
                # Convert the data back to our models
                services = [Service(**service) for service in report_data['services']]
                vulnerabilities = [Vulnerability(**vuln) for vuln in report_data['vulnerabilities']]
                
                return ScanReport(
                    id=report_data['id'],
                    scan_timestamp=report_data['scan_timestamp'],
                    host=report_data['host'],
                    total_vulnerabilities=report_data['total_vulnerabilities'],
                    risk_summary=report_data['risk_summary'],
                    services=services,
                    vulnerabilities=vulnerabilities
                )
            return None

        except Exception as e:
            logger.error(f"Error retrieving report from database: {str(e)}")
            raise

    async def get_all_reports(self) -> List[ScanReport]:
        """
        Retrieve all reports with their related data from Supabase
        """
        try:
            # Get all report IDs first
            response = self.supabase.table('scan_reports').select('id').order('scan_timestamp', desc=True).execute()
            
            # Get full details for each report
            reports = []
            for report_data in response.data:
                report = await self.get_report(report_data['id'])
                if report:
                    reports.append(report)
            
            return reports

        except Exception as e:
            logger.error(f"Error retrieving reports from database: {str(e)}")
            raise

    async def delete_report(self, report_id: str) -> bool:
        """
        Delete a specific report and its related data from Supabase
        """
        try:
            # Due to foreign key constraints with cascade delete,
            # we only need to delete the main report
            response = self.supabase.table('scan_reports').delete().eq('id', report_id).execute()
            return bool(response.data)

        except Exception as e:
            logger.error(f"Error deleting report from database: {str(e)}")
            raise
