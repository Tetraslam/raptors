import asyncio
import typer
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress
import uvicorn
from .scanner import Scanner, ScanTarget
from .report import ReportGenerator, DashboardApp
import os
from dotenv import load_dotenv

load_dotenv()

app = typer.Typer(help="Raptors Vulnerability Scanner")
console = Console()

def display_banner():
    banner = """
    ██████╗  █████╗ ██████╗ ████████╗ ██████╗ ██████╗ ███████╗
    ██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝
    ██████╔╝███████║██████╔╝   ██║   ██║   ██║██████╔╝███████╗
    ██╔══██╗██╔══██║██╔═══╝    ██║   ██║   ██║██╔══██╗╚════██║
    ██║  ██║██║  ██║██║        ██║   ╚██████╔╝██║  ██║███████║
    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝
    """
    console.print(Panel(banner, title="[bold green]Vulnerability Scanner[/]", subtitle="[bold red]v1.0.0[/]"))

@app.command()
def scan(
    target: str = typer.Argument(..., help="Target host to scan"),
    ports: str = typer.Option(None, help="Port range to scan (e.g., '80,443' or '1-1000')"),
    scan_type: str = typer.Option("intense", help="Scan type: quick, intense, or thorough")
):
    """Run a vulnerability scan on a target host."""
    display_banner()
    
    scanner = Scanner()
    report_gen = ReportGenerator()
    
    scan_target = ScanTarget(
        host=target,
        ports=ports or os.getenv("DEFAULT_PORTS", "21-443"),
        scan_type=scan_type
    )
    
    try:
        console.print(f"\n[bold blue]Starting scan on {target}...[/]")
        result = asyncio.run(scanner.scan_target(scan_target))
        
        with Progress() as progress:
            task = progress.add_task("[green]Generating report...", total=None)
            report = report_gen.generate_report(result.dict())
            progress.update(task, completed=100)
        
        console.print(f"\n[bold green]Scan completed! Report saved as: report_{report.scan_id}.json[/]")
        
        # Display summary
        console.print("\n[bold yellow]Scan Summary:[/]")
        console.print(f"Total ports scanned: {report.summary['total_ports_scanned']}")
        console.print(f"Total vulnerabilities: {report.summary['total_vulnerabilities']}")
        console.print("\nRisk Levels:")
        for level, count in report.summary['risk_levels'].items():
            color = {
                'Critical': 'red',
                'High': 'yellow',
                'Medium': 'blue',
                'Low': 'green'
            }.get(level, 'white')
            console.print(f"  {level}: [bold {color}]{count}[/]")
            
    except Exception as e:
        console.print(f"\n[bold red]Error during scan: {str(e)}[/]")
        raise typer.Exit(1)

@app.command()
def dashboard(
    port: int = typer.Option(8050, help="Port to run the dashboard on"),
    debug: bool = typer.Option(False, help="Run in debug mode")
):
    """Launch the interactive dashboard to view scan reports."""
    display_banner()
    console.print(f"\n[bold green]Starting dashboard on http://localhost:{port}[/]")
    
    dashboard_app = DashboardApp()
    dashboard_app.run_server(debug=debug, port=port)

if __name__ == "__main__":
    app()
