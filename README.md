# Raptors 🦖

A powerful vulnerability scanner and dashboard that helps identify, analyze, and track system vulnerabilities in real-time.

## Features

- **Real-time System Scanning**: Automatically detects open ports and running services on your system
- **Vulnerability Analysis**: Integrates with the National Vulnerability Database (NVD) to identify potential security risks
- **AI-Powered Fix Suggestions**: Utilizes GPT-4 to provide structured, actionable fix recommendations
- **CVSS Scoring**: Calculates and categorizes vulnerabilities based on CVSS scores into Low, Medium, and Critical risks
- **Beautiful Dashboard**: Modern, responsive interface built with Shadcn/UI components
- **Report Management**: Stores and manages vulnerability reports using Supabase
- **Data Visualization**: Presents vulnerability data through intuitive and interactive visualizations

## Tech Stack

### Backend
- [FastAPI](https://fastapi.tiangolo.com/) - High-performance Python web framework
- OpenAI GPT-4 - AI-powered vulnerability analysis
- NVD API - Vulnerability database integration

### Frontend
- [Next.js](https://nextjs.org/) - React framework
- [Shadcn/UI](https://ui.shadcn.com/) - Beautiful UI components
- Data visualization libraries

### Database
- [Supabase](https://supabase.com/) - Open source Firebase alternative

## Prerequisites

- Python 3.8+
- Node.js 16+
- OpenAI API key
- Supabase account and project keys

## Environment Variables

Create a `.env` file in the root directory with the following variables:

```env
OPENAI_API_KEY=your_openai_api_key
SUPABASE_PUBLIC_KEY=your_supabase_public_key
SUPABASE_PRIVATE_KEY=your_supabase_private_key
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/raptors.git
cd raptors
```

2. Install backend dependencies:
```bash
cd backend
pip install -r requirements.txt
```

3. Install frontend dependencies:
```bash
cd frontend
npm install
```

## Running the Application

1. Start the backend server:
```bash
cd backend
uvicorn main:app --reload
```

2. Start the frontend development server:
```bash
cd frontend
npm run dev
```

3. Access the dashboard at `http://localhost:3000`

## Usage

1. Open the Raptors dashboard in your browser
2. Click "Start New Scan" to initiate a system vulnerability scan
3. Wait for the scan to complete - the system will:
   - Detect open ports and services
   - Check for known vulnerabilities
   - Generate CVSS scores
   - Provide AI-powered fix suggestions
4. View the generated report in the dashboard with detailed visualizations
5. Access historical reports at any time through the dashboard interface

## API and Database Structure

### Supabase Schema

The database schema consists of the following main tables:

#### Services Table
- `id`: UUID (Primary Key)
- `port`: Integer - Port number of the detected service
- `name`: Text - Service name
- `version`: Text - Service version (optional)
- `protocol`: Text - Service protocol
- `created_at`: Timestamp with timezone

#### Vulnerabilities Table
- `id`: UUID (Primary Key)
- `cve_id`: Text - CVE identifier
- `description`: Text - Vulnerability description
- `cvss_score`: Float - CVSS score
- `risk_level`: Enum ('low', 'medium', 'critical')
- `affected_versions`: Text Array - List of affected versions
- `fix_suggestions`: Text - AI-generated fix suggestions
- `reference_urls`: Text Array - Reference URLs
- `created_at`: Timestamp with timezone

#### Scan Reports Table
- `id`: UUID (Primary Key)
- `timestamp`: Timestamp - Scan execution time
- `host`: Text - Scanned host
- `total_vulnerabilities`: Integer
- `risk_summary`: JSONB - Summary of vulnerabilities by risk level
- `created_at`: Timestamp with timezone

Junction tables `scan_report_services` and `scan_report_vulnerabilities` maintain many-to-many relationships between scan reports and their associated services/vulnerabilities.

### API Responses

#### Scan Report Response
```json
{
  "id": "uuid",
  "scan_timestamp": "ISO-8601 timestamp",
  "host": "hostname",
  "total_vulnerabilities": 10,
  "risk_summary": {
    "low": 3,
    "medium": 5,
    "critical": 2
  },
  "services": [
    {
      "id": "uuid",
      "port": 80,
      "name": "nginx",
      "version": "1.18.0",
      "protocol": "tcp"
    }
  ],
  "vulnerabilities": [
    {
      "id": "uuid",
      "cve_id": "CVE-2023-XXXX",
      "description": "Vulnerability description",
      "cvss_score": 7.5,
      "risk_level": "critical",
      "affected_versions": ["1.18.0", "1.17.0"],
      "fix_suggestions": "Upgrade to version 1.18.1 or apply patch...",
      "reference_urls": ["https://nvd.nist.gov/..."]
    }
  ]
}

## API Usage

The Raptors API provides the following endpoints:

### Start a Scan
```http
POST /scan
Content-Type: application/json

{
    "host": "localhost",
    "port_range": "1-65535",
    "scan_type": "full"
}
```

Response:
```json
"Scan started successfully"
```

### Get All Reports
```http
GET /reports
```

Response:
```json
[
    {
        "id": "uuid",
        "scan_timestamp": "ISO-8601 timestamp",
        "host": "hostname",
        "total_vulnerabilities": 10,
        "risk_summary": {
            "low": 3,
            "medium": 5,
            "critical": 2
        },
        "services": [...],
        "vulnerabilities": [...]
    }
]
```

### Get Specific Report
```http
GET /reports/{report_id}
```

Response: Same as individual report object above.

### Delete Report
```http
DELETE /reports/{report_id}
```

Response:
```json
{
    "message": "Report deleted successfully"
}
```

### Error Responses

- `404 Not Found`: Resource not found
- `405 Method Not Allowed`: Wrong HTTP method used
- `500 Internal Server Error`: Server-side error

## Security Features

- Row Level Security (RLS) is enabled on all tables
- Authenticated users have read-only access to all data
- Service role has full CRUD permissions
- All timestamps are automatically set to UTC
- UUIDs are automatically generated for new records

## Security Considerations

- Ensure your `.env` file is included in `.gitignore`
- Regularly update your API keys
- Follow the principle of least privilege when configuring Supabase access

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
