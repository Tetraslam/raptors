from pydantic import BaseModel, Field
from typing import List, Optional, Dict
from datetime import datetime
from enum import Enum

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    CRITICAL = "critical"

class Service(BaseModel):
    port: int
    name: str
    version: Optional[str] = None
    protocol: str = "tcp"

class Vulnerability(BaseModel):
    cve_id: str
    description: str
    cvss_score: float
    risk_level: RiskLevel
    affected_versions: List[str]
    fix_suggestions: Optional[str] = None
    reference_urls: List[str]

class ScanReport(BaseModel):
    id: Optional[str] = None
    scan_timestamp: datetime = Field(default_factory=datetime.utcnow)
    host: str
    services: List[Service]
    vulnerabilities: List[Vulnerability]
    total_vulnerabilities: int = 0
    risk_summary: Dict[RiskLevel, int] = Field(default_factory=lambda: {
        RiskLevel.LOW: 0,
        RiskLevel.MEDIUM: 0,
        RiskLevel.CRITICAL: 0
    })

class ScanRequest(BaseModel):
    host: str = "localhost"
    port_range: Optional[str] = None
