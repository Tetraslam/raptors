import json
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel
import dash
from dash import dcc, html
import dash_bootstrap_components as dbc
from dash.dependencies import Input, Output
import os
from dotenv import load_dotenv

load_dotenv()

class Report(BaseModel):
    scan_id: str
    timestamp: datetime
    target: str
    summary: Dict
    vulnerabilities: List[Dict]
    recommendations: List[str]
    raw_data: Dict

class ReportGenerator:
    def __init__(self):
        self.reports_dir = Path(os.getenv("SCAN_REPORTS_DIR", "scan_reports"))
        self.reports_dir.mkdir(exist_ok=True)
        
    def generate_report(self, scan_result: Dict) -> Report:
        timestamp = datetime.now()
        scan_id = timestamp.strftime("%Y%m%d_%H%M%S")
        
        # Create dated directory structure
        date_dir = self.reports_dir / timestamp.strftime("%Y/%m/%d")
        date_dir.mkdir(parents=True, exist_ok=True)
        
        summary = self._generate_summary(scan_result)
        report = Report(
            scan_id=scan_id,
            timestamp=timestamp,
            target=scan_result['target'],
            summary=summary,
            vulnerabilities=scan_result['vulnerabilities'],
            recommendations=self._generate_recommendations(scan_result),
            raw_data=scan_result
        )
        
        self._save_report(report, date_dir)
        return report
    
    def _generate_summary(self, scan_result: Dict) -> Dict:
        total_ports = len(scan_result['open_ports'])
        total_vulns = len(scan_result['vulnerabilities'])
        
        risk_levels = {
            'Critical': len([v for v in scan_result['vulnerabilities'] if v['cvss_score'] >= 9.0]),
            'High': len([v for v in scan_result['vulnerabilities'] if 7.0 <= v['cvss_score'] < 9.0]),
            'Medium': len([v for v in scan_result['vulnerabilities'] if 4.0 <= v['cvss_score'] < 7.0]),
            'Low': len([v for v in scan_result['vulnerabilities'] if v['cvss_score'] < 4.0])
        }
        
        return {
            'total_ports_scanned': total_ports,
            'total_vulnerabilities': total_vulns,
            'risk_levels': risk_levels,
            'scan_duration': scan_result['scan_duration']
        }
    
    def _generate_recommendations(self, scan_result: Dict) -> List[str]:
        recommendations = set()
        for vuln in scan_result['vulnerabilities']:
            recommendations.update(vuln['recommendations'])
        return list(recommendations)
    
    def _save_report(self, report: Report, date_dir: Path):
        # Save as readable text file
        report_text = f"""RAPTORS VULNERABILITY SCAN REPORT
================================
Scan ID: {report.scan_id}
Target: {report.target}
Timestamp: {report.timestamp}
Duration: {report.summary['scan_duration']:.2f} seconds

SUMMARY
-------
Total Ports Scanned: {report.summary['total_ports_scanned']}
Total Vulnerabilities: {report.summary['total_vulnerabilities']}

Risk Levels:
- Critical: {report.summary['risk_levels']['Critical']}
- High: {report.summary['risk_levels']['High']}
- Medium: {report.summary['risk_levels']['Medium']}
- Low: {report.summary['risk_levels']['Low']}

OPEN PORTS
----------
"""
        for port, data in report.raw_data['open_ports'].items():
            report_text += f"Port {port}:\n"
            report_text += f"  Service: {data['service']}\n"
            report_text += f"  Version: {data['version']}\n"
            report_text += f"  Product: {data['product']}\n\n"

        report_text += """VULNERABILITIES
---------------
"""
        for vuln in report.vulnerabilities:
            report_text += f"CVE: {vuln['cve_id']}\n"
            report_text += f"CVSS Score: {vuln['cvss_score']}\n"
            report_text += f"Description: {vuln['description']}\n"
            report_text += "References:\n"
            for ref in vuln['references']:
                report_text += f"  - {ref}\n"
            report_text += "Recommendations:\n"
            for rec in vuln['recommendations']:
                report_text += f"  - {rec}\n"
            report_text += "\n"

        # Save text report
        report_path = date_dir / f"report_{report.scan_id}.txt"
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_text)
            
        # Also save JSON for dashboard
        json_path = date_dir / f"report_{report.scan_id}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report.dict(), f, default=str, indent=2)

class DashboardApp:
    def __init__(self):
        self.app = dash.Dash(__name__, external_stylesheets=[dbc.themes.CYBORG])
        self.reports_dir = Path(os.getenv("SCAN_REPORTS_DIR", "scan_reports"))
        self._setup_layout()
        self._setup_callbacks()
        
    def _setup_layout(self):
        self.app.layout = dbc.Container([
            dbc.Row([
                dbc.Col(html.H1("Raptors Vulnerability Scanner Dashboard", 
                               className="text-center mb-4"), width=12)
            ]),
            
            dbc.Row([
                dbc.Col([
                    dcc.Dropdown(
                        id='report-selector',
                        options=self._get_report_options(),
                        placeholder="Select a scan report"
                    )
                ], width=6)
            ], className="mb-4"),
            
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Summary"),
                        dbc.CardBody(id='summary-stats')
                    ])
                ], width=12)
            ], className="mb-4"),
            
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Vulnerability Distribution"),
                        dbc.CardBody(dcc.Graph(id='vuln-distribution'))
                    ])
                ], width=6),
                
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("CVSS Score Distribution"),
                        dbc.CardBody(dcc.Graph(id='cvss-distribution'))
                    ])
                ], width=6)
            ], className="mb-4"),
            
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Open Ports"),
                        dbc.CardBody(id='ports-table')
                    ])
                ], width=12)
            ], className="mb-4"),
            
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Recommendations"),
                        dbc.CardBody(id='recommendations')
                    ])
                ], width=12)
            ])
        ], fluid=True)
    
    def _get_report_options(self):
        reports = []
        for year_dir in sorted(self.reports_dir.glob("*")):
            if not year_dir.is_dir():
                continue
            for month_dir in sorted(year_dir.glob("*")):
                if not month_dir.is_dir():
                    continue
                for day_dir in sorted(month_dir.glob("*")):
                    if not day_dir.is_dir():
                        continue
                    for report in sorted(day_dir.glob("report_*.json")):
                        date_str = f"{year_dir.name}-{month_dir.name}-{day_dir.name}"
                        label = f"{date_str} - {report.stem}"
                        reports.append({'label': label, 'value': str(report)})
        return reports
    
    def _setup_callbacks(self):
        @self.app.callback(
            [Output('summary-stats', 'children'),
             Output('vuln-distribution', 'figure'),
             Output('cvss-distribution', 'figure'),
             Output('ports-table', 'children'),
             Output('recommendations', 'children')],
            [Input('report-selector', 'value')]
        )
        def update_dashboard(selected_report):
            if not selected_report:
                return dash.no_update
                
            report = self._load_report(selected_report)
            
            summary_stats = self._create_summary_stats(report)
            vuln_dist = self._create_vulnerability_distribution(report)
            cvss_dist = self._create_cvss_distribution(report)
            ports_table = self._create_ports_table(report)
            recommendations = self._create_recommendations_list(report)
            
            return summary_stats, vuln_dist, cvss_dist, ports_table, recommendations
    
    def _load_report(self, report_path: str) -> Dict:
        with open(report_path, encoding='utf-8') as f:
            return json.load(f)
    
    def _create_summary_stats(self, report: Dict) -> html.Div:
        summary = report['summary']
        return html.Div([
            dbc.Row([
                dbc.Col([
                    html.H4(f"{summary['total_ports_scanned']} Ports Scanned"),
                    html.P("Open ports detected")
                ], width=3),
                dbc.Col([
                    html.H4(f"{summary['total_vulnerabilities']} Vulnerabilities"),
                    html.P("Total vulnerabilities found")
                ], width=3),
                dbc.Col([
                    html.H4(f"{summary['risk_levels']['Critical']} Critical"),
                    html.P("Critical vulnerabilities")
                ], width=3),
                dbc.Col([
                    html.H4(f"{summary['scan_duration']:.1f}s"),
                    html.P("Scan duration")
                ], width=3)
            ])
        ])
    
    def _create_vulnerability_distribution(self, report: Dict) -> go.Figure:
        risk_levels = report['summary']['risk_levels']
        fig = go.Figure(data=[
            go.Pie(
                labels=list(risk_levels.keys()),
                values=list(risk_levels.values()),
                hole=.3,
                marker_colors=['#ff0d0d', '#ff4e11', '#ff8e15', '#fab733']
            )
        ])
        fig.update_layout(
            title="Vulnerability Risk Levels",
            showlegend=True,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white')
        )
        return fig
    
    def _create_cvss_distribution(self, report: Dict) -> go.Figure:
        scores = [v['cvss_score'] for v in report['vulnerabilities']]
        fig = px.histogram(
            x=scores,
            nbins=20,
            labels={'x': 'CVSS Score', 'y': 'Count'},
            color_discrete_sequence=['#00ff00']
        )
        fig.update_layout(
            title="CVSS Score Distribution",
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white')
        )
        return fig
    
    def _create_ports_table(self, report: Dict) -> html.Table:
        ports_data = report['raw_data']['open_ports']
        return dbc.Table([
            html.Thead([
                html.Tr([
                    html.Th("Port"),
                    html.Th("Service"),
                    html.Th("Version"),
                    html.Th("Product")
                ])
            ]),
            html.Tbody([
                html.Tr([
                    html.Td(port),
                    html.Td(data['service']),
                    html.Td(data['version']),
                    html.Td(data['product'])
                ]) for port, data in ports_data.items()
            ])
        ], striped=True, bordered=True, hover=True)
    
    def _create_recommendations_list(self, report: Dict) -> html.Div:
        return html.Div([
            html.Ul([
                html.Li(rec) for rec in report['recommendations']
            ])
        ])
    
    def run_server(self, debug=True, port=8050):
        self.app.run_server(debug=debug, port=port)
