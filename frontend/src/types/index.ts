export type RiskLevel = 'low' | 'medium' | 'critical';

export interface Service {
  id?: string;
  port: number;
  name: string;
  version?: string;
  protocol: string;
}

export interface Vulnerability {
  id?: string;
  cve_id: string;
  description: string;
  cvss_score: number;
  risk_level: RiskLevel;
  affected_versions: string[];
  fix_suggestions?: string;
  reference_urls: string[];
}

export interface ScanReport {
  id?: string;
  scan_timestamp: string;
  host: string;
  services: Service[];
  vulnerabilities: Vulnerability[];
  total_vulnerabilities: number;
  risk_summary: Record<RiskLevel, number>;
}

export interface ScanRequest {
  host: string;
  port_range?: string;  // Optional, will use common ports if not specified
}
