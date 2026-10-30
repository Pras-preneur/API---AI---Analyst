"""PDF report generation engine for the API Security Testing Assistant.

Uses ReportLab to produce a structured, high-veracity, evidence-backed
PDF assessment report from an in-memory Report instance.
"""

import html
import io
from typing import List, Any
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from ..models import Report, FindingDetail, FindingStatus, AssessmentOutcome


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute total pages and render running headers and footers."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, total_pages: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(HexColor("#64748b"))

        # Running header (pages 2+)
        if self._pageNumber > 1:
            self.drawString(36, 756, "API Security Testing Assistant — Assessment Report")
            self.setStrokeColor(HexColor("#e2e8f0"))
            self.setLineWidth(0.5)
            self.line(36, 750, 576, 750)

        # Running footer (all pages)
        self.setStrokeColor(HexColor("#e2e8f0"))
        self.setLineWidth(0.5)
        self.line(36, 45, 576, 45)
        self.drawString(
            36,
            32,
            "Confidential • Automated Assessment with Human Verification • Sanitized Evidence",
        )
        page_str = f"Page {self._pageNumber} of {total_pages}"
        self.drawRightString(576, 32, page_str)
        self.restoreState()


def _escape(val: Any) -> str:
    """Safely escape text for inclusion in ReportLab Paragraph XML."""
    if val is None:
        return ""
    return html.escape(str(val))


def generate_pdf_report(report: Report) -> bytes:
    """Generate a high-veracity PDF report from a Report object.

    Returns the raw PDF bytes.
    Does not perform any network calls or alter report state.
    """
    buffer = io.BytesIO()

    # Document setup: 0.5 inch margins (36 pt), printable width = 540 pt
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=54,
        bottomMargin=54,
    )

    base_styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=base_styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=HexColor("#0f172a"),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=base_styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=HexColor("#64748b"),
        spaceAfter=12,
    )
    h2_style = ParagraphStyle(
        "SectionH2",
        parent=base_styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=HexColor("#1e293b"),
        spaceBefore=14,
        spaceAfter=6,
    )
    h3_style = ParagraphStyle(
        "SectionH3",
        parent=base_styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=13,
        textColor=HexColor("#334155"),
        spaceBefore=8,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "DocBody",
        parent=base_styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=HexColor("#334155"),
        spaceAfter=6,
    )
    mono_style = ParagraphStyle(
        "DocMono",
        parent=base_styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=10,
        textColor=HexColor("#1e293b"),
    )
    badge_style = ParagraphStyle(
        "BadgeText",
        parent=base_styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        alignment=1,  # Centered
    )

    story: List[Any] = []

    # 1. Title Banner
    story.append(Paragraph("API Security Assessment Report", title_style))
    story.append(
        Paragraph(
            "Evidence-Backed Vulnerability Assessment • Strict Human-in-the-Loop Governance",
            subtitle_style,
        )
    )
    story.append(
        HRFlowable(
            width="100%",
            thickness=1.5,
            color=HexColor("#0284c7"),
            spaceBefore=0,
            spaceAfter=10,
        )
    )

    # 2. Metadata Table
    meta_data = [
        [
            Paragraph("<b>Target Base URL:</b>", body_style),
            Paragraph(f"<code>{_escape(report.target_base_url)}</code>", mono_style),
            Paragraph("<b>Generated At:</b>", body_style),
            Paragraph(
                _escape(report.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")),
                body_style,
            ),
        ],
        [
            Paragraph("<b>Session ID:</b>", body_style),
            Paragraph(f"<code>{_escape(report.session_id)}</code>", mono_style),
            Paragraph("<b>Report ID:</b>", body_style),
            Paragraph(f"<code>{_escape(report.report_id)}</code>", mono_style),
        ],
    ]
    meta_table = Table(meta_data, colWidths=[95, 175, 85, 185])
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 0.5, HexColor("#e2e8f0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, HexColor("#f1f5f9")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(meta_table)
    story.append(Spacer(1, 10))

    # 3. Executive Summary
    story.append(Paragraph("1. Executive Summary", h2_style))
    story.append(Paragraph(_escape(report.assessment_summary), body_style))
    story.append(Spacer(1, 6))

    # Severity Counts Table
    sc = report.severity_counts
    sev_rows = [
        [
            Paragraph("<b>Severity Tier</b>", body_style),
            Paragraph("<b>Count</b>", body_style),
            Paragraph("<b>Assessment Status</b>", body_style),
        ],
        [
            Paragraph('<font color="#b91c1c"><b>CRITICAL</b></font>', body_style),
            Paragraph(str(sc.critical), body_style),
            Paragraph("Immediate remediation required", body_style),
        ],
        [
            Paragraph('<font color="#ea580c"><b>HIGH</b></font>', body_style),
            Paragraph(str(sc.high), body_style),
            Paragraph("High priority fix recommended", body_style),
        ],
        [
            Paragraph('<font color="#d97706"><b>MEDIUM</b></font>', body_style),
            Paragraph(str(sc.medium), body_style),
            Paragraph("Moderate risk exposure", body_style),
        ],
        [
            Paragraph('<font color="#059669"><b>LOW</b></font>', body_style),
            Paragraph(str(sc.low), body_style),
            Paragraph("Low risk / Informational hardening", body_style),
        ],
    ]
    if sc.unknown > 0:
        sev_rows.append(
            [
                Paragraph('<font color="#64748b"><b>UNKNOWN</b></font>', body_style),
                Paragraph(str(sc.unknown), body_style),
                Paragraph("Unclassified severity", body_style),
            ]
        )

    sev_table = Table(sev_rows, colWidths=[120, 70, 350])
    sev_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), HexColor("#f1f5f9")),
                ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#0f172a")),
                ("BOX", (0, 0), (-1, -1), 0.5, HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(sev_table)
    story.append(Spacer(1, 8))

    # Execution Statistics Table
    stats = report.execution_statistics or {}
    stat_rows = [
        [
            Paragraph("<b>Metric</b>", body_style),
            Paragraph("<b>Count</b>", body_style),
            Paragraph("<b>Metric</b>", body_style),
            Paragraph("<b>Count</b>", body_style),
        ],
        [
            Paragraph("Proposals Formulated:", body_style),
            Paragraph(str(stats.get("total_proposals", 0)), body_style),
            Paragraph("Tests Executed:", body_style),
            Paragraph(str(stats.get("executed_tests", 0)), body_style),
        ],
        [
            Paragraph("Completed Tests:", body_style),
            Paragraph(str(stats.get("completed_tests", 0)), body_style),
            Paragraph("Failed Tests:", body_style),
            Paragraph(str(stats.get("failed_tests", 0)), body_style),
        ],
        [
            Paragraph("Unexecuted Tests:", body_style),
            Paragraph(str(stats.get("not_executed_tests", len(report.not_executed_tests))), body_style),
            Paragraph("Total Findings:", body_style),
            Paragraph(str(stats.get("total_findings", len(report.finding_details))), body_style),
        ],
        [
            Paragraph("Confirmed Vulnerabilities:", body_style),
            Paragraph(str(stats.get("confirmed_findings", 0)), body_style),
            Paragraph("Suspected Findings:", body_style),
            Paragraph(str(stats.get("suspected_findings", 0)), body_style),
        ],
        [
            Paragraph("False Positives Identified:", body_style),
            Paragraph(str(stats.get("false_positive_findings", 0)), body_style),
            Paragraph("Awaiting Human Review:", body_style),
            Paragraph(str(stats.get("pending_review", report.pending_review_count)), body_style),
        ],
    ]
    stat_table = Table(stat_rows, colWidths=[150, 120, 150, 120])
    stat_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 0.5, HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(stat_table)
    story.append(Spacer(1, 10))

    # 4. Scope and Limitations
    story.append(Paragraph("2. Scope & Assessment Limitations", h2_style))
    story.append(Paragraph(_escape(report.scope_and_limitations), body_style))
    if hasattr(report, "endpoints_cataloged") and report.endpoints_cataloged:
        ep_text = ", ".join([f"{ep.get('method', '')} {ep.get('path', '')}" for ep in report.endpoints_cataloged[:20]])
        if len(report.endpoints_cataloged) > 20:
            ep_text += f" ... (+{len(report.endpoints_cataloged) - 20} more)"
        story.append(Paragraph(f"<b>Cataloged Endpoints ({len(report.endpoints_cataloged)}):</b> {ep_text}", body_style))
    story.append(Spacer(1, 10))

    # 5. Technical Findings Breakdown
    story.append(Paragraph("3. Detailed Vulnerability Findings", h2_style))
    if not report.finding_details:
        story.append(
            Paragraph(
                "<i>No vulnerability findings were identified or recorded for this assessment session.</i>",
                body_style,
            )
        )
    else:
        for idx, finding in enumerate(report.finding_details, 1):
            finding_blocks = []

            # Finding Header with Severity & Outcome
            outcome = finding.assessment_outcome or finding.status
            sev_color = "#b91c1c" if finding.severity.upper() in ("CRITICAL", "HIGH") else "#d97706"
            header_text = (
                f"<b>Finding {idx}: {finding.title}</b> "
                f"[<font color='{sev_color}'><b>{_escape(finding.severity)}</b></font> | "
                f"Outcome: <b>{_escape(outcome)}</b>]"
            )
            finding_blocks.append(Paragraph(header_text, h3_style))

            # Details mini-table
            f_table_data = [
                [
                    Paragraph("<b>Endpoint:</b>", body_style),
                    Paragraph(f"<code>{_escape(finding.endpoint_method or '')} {_escape(finding.endpoint_path)}</code>", mono_style),
                    Paragraph("<b>Category:</b>", body_style),
                    Paragraph(_escape(finding.test_category), body_style),
                ],
                [
                    Paragraph("<b>Finding ID:</b>", body_style),
                    Paragraph(f"<code>{_escape(finding.finding_id)}</code>", mono_style),
                    Paragraph("<b>Human Review:</b>", body_style),
                    Paragraph(
                        "<b>Confirmed by Human Review</b>"
                        if finding.is_human_reviewed and outcome == AssessmentOutcome.CONFIRMED
                        else (
                            "<b>False Positive (Human Reviewed)</b>"
                            if finding.is_human_reviewed and outcome == AssessmentOutcome.FALSE_POSITIVE
                            else "<i>Pending Human Review</i>"
                        ),
                        body_style,
                    ),
                ],
            ]
            f_table = Table(f_table_data, colWidths=[75, 205, 80, 180])
            f_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), HexColor("#f8fafc")),
                        ("BOX", (0, 0), (-1, -1), 0.5, HexColor("#cbd5e1")),
                        ("INNERGRID", (0, 0), (-1, -1), 0.5, HexColor("#e2e8f0")),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                        ("LEFTPADDING", (0, 0), (-1, -1), 5),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ]
                )
            )
            finding_blocks.append(f_table)
            finding_blocks.append(Spacer(1, 4))

            # Observed Behavior
            finding_blocks.append(Paragraph("<b>Observed Behavior:</b>", body_style))
            finding_blocks.append(Paragraph(_escape(finding.observed_behavior), body_style))

            # Sanitized Evidence Summary
            ev = finding.evidence_summary or {}
            ev_status = ev.get("status_code", "N/A")
            ev_body = "Yes" if ev.get("response_body_present") else "No"
            ev_summary_text = (
                f"HTTP Status: <b>{_escape(ev_status)}</b> | Body Present: <b>{_escape(ev_body)}</b>"
            )
            if finding.assessment_reason:
                # Truncate reason safely to avoid blowout
                reason_clean = _escape(str(finding.assessment_reason)[:400])
                ev_summary_text += f"<br/><b>Evidence Assessment Notes:</b> {reason_clean}"

            finding_blocks.append(Paragraph("<b>Sanitized Evidence Summary:</b>", body_style))
            finding_blocks.append(Paragraph(ev_summary_text, body_style))

            # Human Review Metadata
            if finding.is_human_reviewed:
                rev_text = (
                    f"Reviewed by: <b>{_escape(finding.reviewer_id or 'analyst')}</b>"
                )
                if finding.reviewed_at:
                    rev_text += f" on {_escape(finding.reviewed_at.strftime('%Y-%m-%d %H:%M:%S UTC'))}"
                if finding.reviewer_notes:
                    rev_text += f"<br/><b>Reviewer Notes:</b> {_escape(finding.reviewer_notes)}"
                finding_blocks.append(Paragraph("<b>Human Review Audit Record:</b>", body_style))
                finding_blocks.append(Paragraph(rev_text, body_style))
            elif finding.requires_re_review:
                finding_blocks.append(
                    Paragraph(
                        "<b>Review Status:</b> <font color='#c2410c'><b>Requires Re-Review</b></font> (Prior review invalidated by fresh execution run)",
                        body_style,
                    )
                )

            # Recommended Remediation
            finding_blocks.append(Paragraph("<b>Recommended Remediation:</b>", body_style))
            finding_blocks.append(Paragraph(_escape(finding.recommended_remediation), body_style))

            if finding.limitations:
                finding_blocks.append(Paragraph(f"<b>Limitations & Caveats:</b> <i>{_escape(finding.limitations)}</i>", body_style))

            finding_blocks.append(Spacer(1, 8))
            story.append(KeepTogether(finding_blocks))

    # 6. Retesting and Governance Guidance
    story.append(Spacer(1, 6))
    story.append(Paragraph("4. Retesting Guidance & Veracity Statement", h2_style))
    retest_text = (
        "<b>Verification Workflow:</b> Remediate the identified authorization or authentication flaw in the API codebase, "
        "redeploy the service, and re-execute approved test proposals. New executions generate fresh sanitized evidence and "
        "automatically trigger the re-review requirement while preserving the prior audit trail.<br/><br/>"
        "<b>Veracity Guarantee:</b> Automated scanners produce initial indicators (SUSPECTED); only explicit human review "
        "can mark a finding as CONFIRMED. All sensitive credentials, tokens, and authorization headers have been redacted."
    )
    story.append(Paragraph(retest_text, body_style))

    # Build document
    doc.build(story, canvasmaker=NumberedCanvas)
    return buffer.getvalue()
