# Raptors Vulnerability Scanner 🦖

A powerful, modern, and interactive vulnerability scanner that uses the National Vulnerability Database (NVD) API to identify potential security issues in your system. No API key required!

![Raptors Banner](https://raw.githubusercontent.com/yourusername/raptors/main/docs/banner.png)

## ✨ Features

- 🔍 Advanced port scanning and service detection using nmap
- 🛡️ Real-time vulnerability checking using NVD API (no key required)
- 📊 Beautiful interactive dashboard with real-time visualizations
- 📈 Detailed vulnerability reports with CVSS scores and recommendations
- 🎯 Risk-based prioritization of vulnerabilities
- 🚀 Fast and concurrent scanning capabilities
- 💻 Modern command-line interface with progress tracking
- 📱 Responsive web dashboard for viewing scan reports
- 🌈 Dark mode interface with beautiful animations
- 🔄 Automatic report generation in both text and JSON formats
- 📋 Comprehensive system information gathering
- 📂 Organized report storage with date-based directory structure

## 🚀 Installation

1. Ensure you have Python 3.7+ and nmap installed on your system:

   ```bash
   # Windows (using chocolatey)
   choco install nmap

   # Linux
   sudo apt-get install nmap

   # macOS
   brew install nmap
   ```

2. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/raptors.git
   cd raptors
   ```

3. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Create a `.env` file from the template:
   ```bash
   cp .env.example .env
   ```

## 🎮 Usage

### Command Line Interface

Run a new vulnerability scan:
```bash
# Basic scan
python -m raptors scan example.com

# Scan specific ports
python -m raptors scan example.com --ports 80,443,8080

# Different scan types
python -m raptors scan example.com --scan-type quick
python -m raptors scan example.com --scan-type thorough
```

Launch the interactive dashboard:
```bash
python -m raptors dashboard

# Specify custom port
python -m raptors dashboard --port 8080
```

### 📊 Interactive Dashboard

The dashboard provides a beautiful interface for:
- Viewing scan reports with interactive visualizations
- Analyzing vulnerability distributions
- Tracking risk levels and CVSS scores
- Exploring detailed port and service information
- Reviewing security recommendations

## 🎨 Features Showcase

### Modern Dark Theme
![Dark Theme](https://raw.githubusercontent.com/yourusername/raptors/main/docs/dark-theme.png)

### Interactive Visualizations
![Visualizations](https://raw.githubusercontent.com/yourusername/raptors/main/docs/visualizations.png)

### Real-time Scanning
![Scanning](https://raw.githubusercontent.com/yourusername/raptors/main/docs/scanning.png)

## 🛠️ Configuration

All configuration is done through environment variables in the `.env` file:

```ini
# Scanning Configuration
MAX_CONCURRENT_SCANS=5
SCAN_TIMEOUT=300
DEFAULT_PORTS=21,22,23,25,53,80,110,139,443,445,1433,3306,3389,5432,8080

# Report Configuration
REPORT_RETENTION_DAYS=30
SCAN_REPORTS_DIR=scan_reports
```

## 📁 Project Structure

```
raptors/
├── raptors/
│   ├── __init__.py        # Package initialization
│   ├── __main__.py        # CLI entry point
│   ├── scanner.py         # Core scanning functionality
│   ├── report.py          # Report generation and dashboard
│   └── assets/
│       └── styles.css     # Dashboard styling
├── scan_reports/          # Generated scan reports
│   └── YYYY/             # Year directory
│       └── MM/           # Month directory
│           └── DD/       # Day directory
│               ├── report_YYYYMMDD_HHMMSS.txt   # Human-readable report
│               └── report_YYYYMMDD_HHMMSS.json  # JSON report for dashboard
├── requirements.txt       # Python dependencies
├── .env.example          # Environment variables template
└── README.md             # Project documentation
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [National Vulnerability Database (NVD)](https://nvd.nist.gov/) for providing the vulnerability data
- [nmap](https://nmap.org/) for the powerful network scanning capabilities
- [Dash](https://plotly.com/dash/) for the interactive visualization framework
- [Rich](https://rich.readthedocs.io/) for beautiful terminal formatting