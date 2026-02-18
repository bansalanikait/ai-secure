from io import BytesIO
from typing import Dict, Any
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from starlette.concurrency import run_in_threadpool


def _build_pdf_bytes(report: Dict[str, Any]) -> bytes:
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica-Bold", 16)
    c.drawString(40, height - 50, "SecureCode AI - Scan Report")

    c.setFont("Helvetica", 12)
    c.drawString(40, height - 80, f"Timestamp: {report.get('timestamp')}")
    c.drawString(40, height - 100, f"Score: {report.get('score')}")
    c.drawString(40, height - 120, f"Grade: {report.get('grade')}")

    y = height - 160
    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, y, "Vulnerabilities:")
    y -= 20

    c.setFont("Helvetica", 11)
    for v in report.get("vulnerabilities", []):
        text = f"- {v.get('issue')} ({v.get('severity')})"
        c.drawString(48, y, text)
        y -= 14
        fix = v.get('recommended_fix', '')
        if fix:
            c.drawString(64, y, f"Fix: {fix}")
            y -= 14
        if y < 80:
            c.showPage()
            y = height - 50

    c.showPage()
    c.save()
    buffer.seek(0)
    return buffer.read()


async def generate_pdf(report: Dict[str, Any]) -> bytes:
    # run CPU-bound PDF creation in threadpool to avoid blocking event loop
    return await run_in_threadpool(_build_pdf_bytes, report)
