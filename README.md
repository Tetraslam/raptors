# Raptors 🦖

A real-time vulnerability scanner with AI-powered fix suggestions. Raptors scans your system for open ports, identifies potential vulnerabilities, and provides actionable remediation steps using GPT-4.

## Features

- **Port Scanning**: Detects open ports and running services using Nmap
- **Vulnerability Detection**: 
  - Checks against common vulnerability database
  - Integrates with National Vulnerability Database (NVD)
  - Assigns CVSS scores and risk levels
- **AI-Powered Analysis**: 
  - Uses GPT-4 to analyze vulnerabilities
  - Provides specific, actionable fix suggestions
  - Includes immediate actions, long-term fixes, and verification steps
- **Modern Dashboard**:
  - Real-time scan progress updates
  - Detailed vulnerability reports
  - Risk level categorization

## Prerequisites

- Python 3.9+
- Node.js 16+
- Nmap installed on your system
- Administrator privileges (for certain scan features)
- OpenAI API key
- NVD API key (optional, improves rate limits)

## Environment Setup

1. Create a `.env` file in the root directory:
```env
OPENAI_API_KEY=your_openai_api_key
NVD_API_KEY=your_nvd_api_key  # Optional
```

2. Install Nmap:
   - Windows: Download from [nmap.org](https://nmap.org/download.html)
   - Linux: `sudo apt-get install nmap`
   - macOS: `brew install nmap`

## Installation

1. Clone and set up the backend:
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

2. Set up the frontend:
```bash
cd frontend
npm install
```

## Running the Application

1. Start the backend server:
```bash
cd backend
uvicorn app.main:app --reload
```

2. Start the frontend development server:
```bash
cd frontend
npm run dev
```

3. Open http://localhost:3000 in your browser

## Usage Guide

### Starting a Scan
1. Enter the target IP address (e.g., 127.0.0.1 for local system)
2. Click "Start Scan"
3. The scanner will:
   - Detect open ports
   - Identify running services
   - Check for known vulnerabilities
   - Generate AI-powered fix suggestions

### Understanding Results
- **Services**: List of detected open ports and running services
- **Vulnerabilities**: 
  - Risk Level (Critical/Medium/Low based on CVSS score)
  - Description of the vulnerability
  - AI-generated fix suggestions
  - Reference links to NVD and other security resources

### Fix Suggestions
Each vulnerability includes:
1. Immediate Actions
2. Long-term Fixes
3. Verification Steps
4. Additional Security Measures

## API Endpoints

### Scan Operations
- `POST /scan` - Start a new vulnerability scan
  - Body: `{ "target": "127.0.0.1" }`
- `GET /scan/{scan_id}` - Get scan status
- `GET /reports` - List all scan reports

### Response Format
```typescript
interface ScanResponse {
  scan_id: string;
  services: Array<{
    port: number;
    name: string;
    version: string;
    protocol: string;
  }>;
  vulnerabilities: Array<{
    cve_id: string;
    description: string;
    cvss_score: number;
    risk_level: "CRITICAL" | "MEDIUM" | "LOW";
    fix_suggestions: string;
    reference_urls: string[];
  }>;
}
```

## Security Notes

- Run with administrator privileges for full scanning capabilities
- The scanner performs active port scanning which may be detected by security systems
- Some fix suggestions require system modifications - review carefully before implementing
- Default scan is configured for common ports to balance speed and coverage

## Troubleshooting

### Common Issues
1. "Scanner is not running with administrator privileges"
   - Run the application with admin rights
   - Some scan features may be limited without admin access

2. "No responsive ports found"
   - Check if target system is reachable
   - Verify no firewall is blocking the scan

3. "Failed to parse nmap results"
   - Ensure Nmap is properly installed
   - Check if target IP is valid

### Getting Help
- Check the logs in the backend terminal for detailed error messages
- Ensure all environment variables are properly set
- Verify network connectivity to target system
