from jinja2 import Environment, FileSystemLoader
import pdfkit
import logging

def generate_report(vulnerabilities, output_path='reports/vuln_report.pdf'):
    logging.info("Generating report...")
    env = Environment(loader=FileSystemLoader('./templates'))
    template = env.get_template('report_template.html')
    html_content = template.render(vulnerabilities=vulnerabilities)
    pdfkit.from_string(html_content, output_path)
    logging.info(f"Report generated: {output_path}")

if __name__ == "__main__":
    from initialize import load_config, setup_logging
    setup_logging()
    # Mock data for testing
    vulnerabilities = {
        22: ['CVE-2020-1234', 'CVE-2019-5678'],
        80: ['CVE-2021-8765'],
    }
    generate_report(vulnerabilities)
    print("Report generated.")
