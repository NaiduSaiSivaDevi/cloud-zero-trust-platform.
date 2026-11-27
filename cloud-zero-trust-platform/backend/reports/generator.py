import csv
import os
from datetime import datetime
from typing import List

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "generated_reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


def generate_csv_report(filename: str, headers: List[str], rows: List[List[str]]) -> str:
    path = os.path.join(REPORTS_DIR, filename)
    with open(path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for row in rows:
            writer.writerow(row)
    return path


def _escape_pdf_text(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def generate_pdf_report(filename: str, title: str, lines: List[str]) -> str:
    path = os.path.join(REPORTS_DIR, filename)
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas

        c = canvas.Canvas(path, pagesize=letter)
        width, height = letter
        y = height - 50
        c.setFont("Helvetica-Bold", 14)
        c.drawString(45, y, title)
        y -= 20
        c.setFont("Helvetica", 9)
        c.drawString(45, y, f"Generated: {datetime.utcnow().isoformat()} UTC")
        y -= 24

        for line in lines:
            if y < 50:
                c.showPage()
                c.setFont("Helvetica", 9)
                y = height - 50
            c.drawString(45, y, line[:105])
            y -= 14

        c.save()
        return path
    except ImportError:
        # Pure-Python valid PDF 1.4 fallback if reportlab is not installed
        content_lines = [f"BT /F1 13 Tf 45 750 Td ({_escape_pdf_text(title)}) Tj ET"]
        y = 725
        for line in lines[:42]:
            content_lines.append(f"BT /F1 9 Tf 45 {y} Td ({_escape_pdf_text(line[:95])}) Tj ET")
            y -= 15
        stream_data = "\n".join(content_lines).encode("latin-1", errors="replace")

        objects = []
        objects.append(b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n")
        objects.append(b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n")
        objects.append(
            b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n"
        )
        objects.append(b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n")
        objects.append(
            f"5 0 obj << /Length {len(stream_data)} >> stream\n".encode("ascii")
            + stream_data
            + b"\nendstream endobj\n"
        )

        pdf = bytearray(b"%PDF-1.4\n")
        offsets = [0]
        for obj in objects:
            offsets.append(len(pdf))
            pdf.extend(obj)
        xref_start = len(pdf)
        pdf.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode("ascii"))
        for off in offsets[1:]:
            pdf.extend(f"{off:010d} 00000 n \n".encode("ascii"))
        pdf.extend(
            f"trailer << /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_start}\n%%EOF\n".encode("ascii")
        )
        with open(path, "wb") as f:
            f.write(pdf)
        return path
