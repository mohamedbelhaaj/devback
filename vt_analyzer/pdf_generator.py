from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet

def generate_pdf_report(report):
    """
    Generates a PDF file for the ThreatReport and returns the ContentFile or Path
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    elements.append(Paragraph(f"Threat Report: {report.input_value}", styles['Title']))
    elements.append(Spacer(1, 12))

    # Details
    data = [
        ["ID", str(report.id)],
        ["Type", report.input_type],
        ["Severity", report.severity],
        ["Status", report.status],
        ["Analyst", report.analyst.username if report.analyst else "N/A"],
        ["Threat Score", str(report.threat_score)],
    ]

    t = Table(data)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.grey),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(t)
    
    doc.build(elements)
    buffer.seek(0)
    
    # Save to the model field
    from django.core.files.base import ContentFile
    file_name = f"report_{report.id}.pdf"
    report.pdf_report.save(file_name, ContentFile(buffer.getvalue()), save=False)
    
    return report.pdf_report