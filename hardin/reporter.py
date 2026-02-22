import os
from datetime import datetime
from pathlib import Path

from PyPDF2 import PdfMerger
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
)

from hardin.config import get_output_dir
from hardin.exceptions import ReporterError
from hardin.state import AnalysisResult

BRAND_RED = colors.HexColor("#DC2626")
BRAND_DARK = colors.HexColor("#1F2937")
BRAND_GRAY = colors.HexColor("#6B7280")
BRAND_LIGHT = colors.HexColor("#F3F4F6")


def _get_styles():
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        "HardinTitle",
        parent=styles["Title"],
        fontSize=28,
        textColor=BRAND_DARK,
        spaceAfter=20,
        fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        "HardinH1",
        parent=styles["Heading1"],
        fontSize=18,
        textColor=BRAND_RED,
        spaceBefore=20,
        spaceAfter=10,
        fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        "HardinH2",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=BRAND_DARK,
        spaceBefore=12,
        spaceAfter=6,
        fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        "HardinBody",
        parent=styles["Normal"],
        fontSize=10,
        textColor=BRAND_DARK,
        spaceAfter=6,
        leading=14,
    ))
    styles.add(ParagraphStyle(
        "HardinCode",
        parent=styles["Code"],
        fontSize=8,
        textColor=BRAND_DARK,
        backColor=BRAND_LIGHT,
        leftIndent=10,
        spaceAfter=6,
        leading=12,
    ))
    return styles


def _severity_color(text: str) -> colors.Color:
    t = text.lower()
    if "critical" in t:
        return colors.HexColor("#991B1B")
    if "high" in t:
        return colors.HexColor("#DC2626")
    if "medium" in t:
        return colors.HexColor("#D97706")
    if "low" in t:
        return colors.HexColor("#2563EB")
    return colors.HexColor("#6B7280")


def generate_service_pdf(result: AnalysisResult, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    filename = output_dir / f"hardin_{result.service_name}.pdf"
    styles = _get_styles()

    doc = SimpleDocTemplate(
        str(filename),
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=25 * mm,
        bottomMargin=20 * mm,
    )

    story = []
    story.append(Paragraph(f"Security Analysis: {result.service_name.upper()}", styles["HardinH1"]))
    story.append(HRFlowable(width="100%", thickness=2, color=BRAND_RED))
    story.append(Spacer(1, 12))

    if result.findings:
        for line in result.findings.strip().split("\n"):
            line = line.strip()
            if not line:
                story.append(Spacer(1, 6))
                continue
            if line.startswith("["):
                color = _severity_color(line)
                story.append(Paragraph(
                    f'<font color="{color.hexval()}">{_escape(line)}</font>',
                    styles["HardinBody"],
                ))
            elif line.startswith("  "):
                story.append(Paragraph(_escape(line), styles["HardinCode"]))
            else:
                story.append(Paragraph(_escape(line), styles["HardinBody"]))
    else:
        story.append(Paragraph("No findings for this service.", styles["HardinBody"]))

    if result.remediation_commands:
        story.append(Spacer(1, 12))
        story.append(Paragraph("Remediation Commands", styles["HardinH2"]))
        story.append(HRFlowable(width="100%", thickness=1, color=BRAND_GRAY))
        story.append(Spacer(1, 6))
        for cmd in result.remediation_commands:
            story.append(Paragraph(f"$ {_escape(cmd)}", styles["HardinCode"]))

    try:
        doc.build(story)
    except Exception as e:
        raise ReporterError(f"Failed to generate PDF for {result.service_name}: {e}") from e

    return filename


def merge_pdfs(pdf_files: list[Path], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    merger = PdfMerger()

    cover = _generate_cover_page(output_path.parent)
    merger.append(str(cover))

    for pdf in sorted(pdf_files):
        try:
            merger.append(str(pdf))
        except Exception as e:
            raise ReporterError(f"Failed to merge {pdf.name}: {e}") from e

    try:
        merger.write(str(output_path))
        merger.close()
    except Exception as e:
        raise ReporterError(f"Failed to write merged PDF: {e}") from e

    if cover.exists():
        cover.unlink()

    return output_path


def _generate_cover_page(output_dir: Path) -> Path:
    filename = output_dir / "_cover.pdf"
    styles = _get_styles()
    doc = SimpleDocTemplate(str(filename), pagesize=A4)

    story = []
    story.append(Spacer(1, 2 * inch))
    story.append(Paragraph("HARDIN PILOT", styles["HardinTitle"]))
    story.append(Paragraph("Security Configuration Audit Report", styles["HardinH2"]))
    story.append(Spacer(1, 0.5 * inch))
    story.append(HRFlowable(width="60%", thickness=3, color=BRAND_RED))
    story.append(Spacer(1, 0.5 * inch))

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    story.append(Paragraph(f"Generated: {now}", styles["HardinBody"]))
    story.append(Paragraph("Tool: Hardin Pilot v1.0.0", styles["HardinBody"]))
    story.append(Paragraph("AI Model: Gemini 2.5 Pro", styles["HardinBody"]))

    doc.build(story)
    return filename


def cleanup_temp_pdfs(pdf_files: list[Path]) -> None:
    for pdf in pdf_files:
        try:
            if pdf.exists():
                pdf.unlink()
        except OSError:
            pass


def build_remediation_script(results: list[AnalysisResult]) -> str:
    all_commands = []
    for result in results:
        if result.remediation_commands:
            all_commands.append(f"echo '=== Fixing: {result.service_name} ==='")
            all_commands.extend(result.remediation_commands)
    if not all_commands:
        return ""
    full_script = " && \\\n".join(all_commands)

    # Save the script to a constant location for later use
    script_path = get_output_dir().parent / ".hardin" / "last_remediation.sh"
    try:
        script_path.parent.mkdir(parents=True, exist_ok=True)
        with open(script_path, "w") as f:
            f.write("#!/bin/bash\nset -e\n\n" + full_script + "\n")
        # Ensure it's executable and only readable by the owner
        os.chmod(script_path, 0o700)
    except Exception:
        # We don't want to crash the whole run just because we couldn't save the convenience script
        pass

    return full_script


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
