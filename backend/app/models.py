from enum import Enum
from pydantic import BaseModel
from typing import List, Dict, Optional

class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class Service(BaseModel):
    port: int
    name: str
    version: str = ""
    protocol: str

class Vulnerability(BaseModel):
    cve_id: str
    description: str
    cvss_score: float
    risk_level: RiskLevel
    affected_versions: List[str]
    reference_urls: List[str]
    fix_suggestions: str

class ScanReport(BaseModel):
    id: str
    target: str
    status: str
    services: List[Service]
    vulnerabilities: List[Vulnerability]
    error: Optional[str] = None
