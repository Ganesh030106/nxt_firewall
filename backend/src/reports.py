from fpdf import FPDF
import datetime
import os
from src.database import get_logs, get_stats

# Define Report Directory
REPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)

class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 16)
        self.cell(0, 10, 'Sentinel-X Security Audit Report', 0, 1, 'C')
        self.set_font('Arial', 'I', 10)
        self.cell(0, 10, f'Generated on: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_pdf_report():
    pdf = PDFReport()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    # 1. Executive Summary (Stats)
    stats = get_stats()
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(200, 10, "1. Executive Summary", ln=True)
    pdf.set_font("Arial", size=12)
    
    pdf.cell(0, 10, f"Total Packets Analyzed: {stats.get('total', 0)}", ln=True)
    pdf.cell(0, 10, f"Threats Blocked: {stats.get('blocked', 0)}", ln=True)
    
    # Calculate Threat Level
    blocked = stats.get('blocked', 0)
    level = "LOW"
    if blocked > 10: level = "MODERATE"
    if blocked > 100: level = "CRITICAL"
    
    pdf.cell(0, 10, f"Current Threat Level: {level}", ln=True)
    pdf.ln(10)

    # 2. Recent Incident Logs
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(200, 10, "2. Recent Critical Incidents (Last 20)", ln=True)
    pdf.set_font("Arial", size=10)

    # Table Header
    pdf.set_fill_color(200, 220, 255)
    pdf.cell(40, 10, "Time", 1, 0, 'C', 1)
    pdf.cell(35, 10, "Source IP", 1, 0, 'C', 1)
    pdf.cell(65, 10, "Threat Type", 1, 0, 'C', 1)
    pdf.cell(25, 10, "Action", 1, 0, 'C', 1)
    pdf.cell(20, 10, "Conf.", 1, 1, 'C', 1)

    # Table Rows
    logs = get_logs(limit=20)
    for log in logs:
        # Filter only bad stuff
        if log['action'] in ['BLOCKED', 'SINKHOLED', 'ALERT']:
            pdf.cell(40, 10, str(log['time'].split(' ')[1]), 1)
            pdf.cell(35, 10, str(log['src']), 1)
            pdf.cell(65, 10, str(log['reason'])[:25], 1) # Truncate long text
            pdf.cell(25, 10, str(log['action']), 1)
            pdf.cell(20, 10, f"{log['conf']*100:.0f}%", 1, 1)

    # Save
    filename = f"Sentinel_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(REPORT_DIR, filename)
    pdf.output(filepath)
    return filepath