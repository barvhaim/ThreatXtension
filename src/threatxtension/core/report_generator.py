"""
PDF Report Generator

This module generates professional PDF reports for Chrome extension security analysis.
Uses ReportLab for pure-Python PDF generation (no system dependencies).
"""

import io
import logging
from datetime import datetime
from typing import Dict, Optional, Any, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates professional PDF security reports for Chrome extension analysis.
    Uses ReportLab for pure-Python PDF generation.
    """

    def __init__(self):
        """Initialize the ReportGenerator."""
        self.enabled = True
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Setup custom paragraph styles."""
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#1e40af'),
        ))
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceBefore=20,
            spaceAfter=10,
            textColor=colors.HexColor('#1f2937'),
        ))
        self.styles.add(ParagraphStyle(
            name='BodyTextCustom',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=8,
            leading=14,
        ))
        self.styles.add(ParagraphStyle(
            name='SmallText',
            parent=self.styles['Normal'],
            fontSize=8,
            textColor=colors.HexColor('#6b7280'),
        ))

    def _get_risk_color(self, risk_level: str) -> colors.Color:
        """Get color for risk level."""
        risk_colors = {
            "high": colors.HexColor('#dc2626'),
            "medium": colors.HexColor('#f59e0b'),
            "low": colors.HexColor('#22c55e'),
            "normal": colors.HexColor('#22c55e'),
            "clean": colors.HexColor('#22c55e'),
            "suspicious": colors.HexColor('#f59e0b'),
            "malicious": colors.HexColor('#dc2626'),
        }
        return risk_colors.get(risk_level.lower(), colors.HexColor('#6b7280'))

    def _create_header(self, extension_name: str, extension_id: str, timestamp: str) -> List:
        """Create report header elements."""
        elements = []

        elements.append(Paragraph("ThreatXtension", self.styles['ReportTitle']))
        elements.append(Paragraph("Security Analysis Report", self.styles['Heading2']))
        elements.append(Spacer(1, 20))

        info_data = [
            ["Extension:", extension_name],
            ["ID:", extension_id],
            ["Generated:", timestamp],
        ]
        info_table = Table(info_data, colWidths=[1.5 * inch, 5 * inch])
        info_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#6b7280')),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(info_table)
        elements.append(Spacer(1, 30))

        return elements

    def _create_score_section(self, security_score: int, risk_level: str) -> List:
        """Create risk score section."""
        elements = []

        score_color = self._get_risk_color(risk_level)
        score_data = [
            [Paragraph(f"<b>{security_score}</b>/100", ParagraphStyle(
                'ScoreStyle',
                fontSize=28,
                textColor=score_color,
                alignment=TA_CENTER,
            ))],
            [Paragraph("Risk Score", self.styles['SmallText'])],
        ]

        risk_data = [
            [Paragraph(f"<b>{risk_level.upper()}</b>", ParagraphStyle(
                'RiskStyle',
                fontSize=18,
                textColor=score_color,
                alignment=TA_CENTER,
            ))],
            [Paragraph("Risk Level", self.styles['SmallText'])],
        ]

        combined_data = [[
            Table(score_data, colWidths=[2.5 * inch]),
            Table(risk_data, colWidths=[2.5 * inch]),
        ]]
        combined_table = Table(combined_data, colWidths=[3 * inch, 3 * inch])
        combined_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOX', (0, 0), (0, 0), 1, colors.HexColor('#e5e7eb')),
            ('BOX', (1, 0), (1, 0), 1, colors.HexColor('#e5e7eb')),
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f9fafb')),
            ('TOPPADDING', (0, 0), (-1, -1), 15),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
        ]))

        elements.append(combined_table)
        elements.append(Spacer(1, 20))

        return elements

    def _create_executive_summary(self, summary: Dict) -> List:
        """Create executive summary section."""
        elements = []
        elements.append(Paragraph("1. Executive Summary", self.styles['SectionHeader']))

        summary_text = summary.get("summary", "No executive summary available.")
        # ReportLab paragraphs take markup, not raw newlines
        summary_text = summary_text.replace('\n', '<br/>')
        elements.append(Paragraph(summary_text, self.styles['BodyTextCustom']))
        elements.append(Spacer(1, 15))

        return elements

    def _create_virustotal_section(self, vt_analysis: Dict) -> List:
        """Create VirusTotal section."""
        elements = []
        elements.append(Paragraph("2. VirusTotal Threat Intelligence", self.styles['SectionHeader']))

        if not vt_analysis or not vt_analysis.get("enabled", True):
            elements.append(Paragraph(
                "VirusTotal analysis not available or disabled.",
                self.styles['BodyTextCustom']
            ))
            return elements

        summary = vt_analysis.get("summary", {})
        threat_level = summary.get("threat_level", "unknown")

        stats_data = [
            ["Files Scanned", "With Detections", "Malicious", "Suspicious"],
            [
                str(vt_analysis.get("files_analyzed", 0)),
                str(vt_analysis.get("files_with_detections", 0)),
                str(vt_analysis.get("total_malicious", 0)),
                str(vt_analysis.get("total_suspicious", 0)),
            ],
        ]
        stats_table = Table(stats_data, colWidths=[1.5 * inch] * 4)
        stats_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f3f4f6')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(stats_table)
        elements.append(Spacer(1, 10))

        threat_color = self._get_risk_color(threat_level)
        elements.append(Paragraph(
            f"Threat Level: <b><font color='{threat_color.hexval()}'>{threat_level.upper()}</font></b>",
            self.styles['BodyTextCustom']
        ))

        families = summary.get("detected_families", [])
        if families:
            elements.append(Paragraph(
                f"Detected Families: {', '.join(families[:10])}",
                self.styles['BodyTextCustom']
            ))

        recommendation = summary.get("recommendation", "")
        if recommendation:
            elements.append(Spacer(1, 5))
            elements.append(Paragraph(recommendation, self.styles['SmallText']))

        elements.append(Spacer(1, 15))
        return elements

    def _create_entropy_section(self, entropy_analysis: Dict) -> List:
        """Create entropy/obfuscation section."""
        elements = []
        elements.append(Paragraph("3. Obfuscation Analysis", self.styles['SectionHeader']))

        if not entropy_analysis:
            elements.append(Paragraph(
                "Entropy analysis not available.",
                self.styles['BodyTextCustom']
            ))
            return elements

        summary = entropy_analysis.get("summary", {})
        overall_risk = summary.get("overall_risk", "normal")

        stats_data = [
            ["Files Analyzed", "Skipped", "Obfuscated", "Suspicious"],
            [
                str(entropy_analysis.get("files_analyzed", 0)),
                str(entropy_analysis.get("files_skipped", 0)),
                str(entropy_analysis.get("obfuscated_files", 0)),
                str(entropy_analysis.get("suspicious_files", 0)),
            ],
        ]
        stats_table = Table(stats_data, colWidths=[1.5 * inch] * 4)
        stats_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f3f4f6')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(stats_table)
        elements.append(Spacer(1, 10))

        risk_color = self._get_risk_color(overall_risk)
        elements.append(Paragraph(
            f"Obfuscation Risk: <b><font color='{risk_color.hexval()}'>{overall_risk.upper()}</font></b>",
            self.styles['BodyTextCustom']
        ))

        high_entropy_files = summary.get("high_entropy_files", [])
        if high_entropy_files:
            elements.append(Paragraph("High Entropy Files:", self.styles['BodyTextCustom']))
            for f in high_entropy_files[:5]:
                elements.append(Paragraph(
                    f"  - {f.get('file', 'Unknown')}: Entropy {f.get('entropy', 0):.2f}",
                    self.styles['SmallText']
                ))

        recommendation = summary.get("recommendation", "")
        if recommendation:
            elements.append(Spacer(1, 5))
            elements.append(Paragraph(recommendation, self.styles['SmallText']))

        elements.append(Spacer(1, 15))
        return elements

    def _create_permissions_section(self, permissions_analysis: Dict) -> List:
        """Create permissions section."""
        elements = []
        elements.append(Paragraph("4. Permissions Analysis", self.styles['SectionHeader']))

        details = permissions_analysis.get("permissions_details", {})
        if not details:
            elements.append(Paragraph(
                "No permissions data available.",
                self.styles['BodyTextCustom']
            ))
            return elements

        table_data = [["Permission", "Reasonable", "Risk"]]
        for perm_name, perm_info in list(details.items())[:15]:
            is_reasonable = perm_info.get("is_reasonable", True)
            risk = "Low" if is_reasonable else "High"
            table_data.append([perm_name, "Yes" if is_reasonable else "No", risk])

        perm_table = Table(table_data, colWidths=[3 * inch, 1.5 * inch, 1 * inch])
        perm_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f3f4f6')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(perm_table)

        if len(details) > 15:
            elements.append(Paragraph(
                f"... and {len(details) - 15} more permissions",
                self.styles['SmallText']
            ))

        elements.append(Spacer(1, 15))
        return elements

    def _create_chromestats_section(self, chromestats_analysis: Dict) -> List:
        """Create Chrome Stats behavioral analysis section."""
        elements = []
        elements.append(Paragraph("5. Chrome Stats Behavioral Analysis", self.styles['SectionHeader']))

        if not chromestats_analysis or not chromestats_analysis.get("enabled"):
            elements.append(Paragraph(
                "Chrome Stats analysis not available.",
                self.styles['BodyTextCustom']
            ))
            return elements

        overall_risk = chromestats_analysis.get("overall_risk_level", "unknown")
        total_risk_score = chromestats_analysis.get("total_risk_score", 0)
        
        risk_color = self._get_risk_color(overall_risk)
        elements.append(Paragraph(
            f"Overall Risk Level: <b><font color='{risk_color.hexval()}'>{overall_risk.upper()}</font></b> (Score: {total_risk_score})",
            self.styles['BodyTextCustom']
        ))
        elements.append(Spacer(1, 10))

        api_risk = chromestats_analysis.get("api_risk_analysis", {})
        if api_risk.get("has_api_risk_data"):
            elements.append(Paragraph("<b>API Risk Assessment:</b>", self.styles['BodyTextCustom']))
            
            risk_impact = api_risk.get("risk_impact", 0)
            risk_likelihood = api_risk.get("risk_likelihood", 0)
            
            stats_data = [
                ["Risk Impact", "Risk Likelihood", "API Risk Score"],
                [f"{risk_impact}/3", f"{risk_likelihood}/3", str(api_risk.get("risk_score", 0))],
            ]
            stats_table = Table(stats_data, colWidths=[2 * inch] * 3)
            stats_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f3f4f6')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ]))
            elements.append(stats_table)
            elements.append(Spacer(1, 10))

        risk_indicators = chromestats_analysis.get("risk_indicators", [])
        if risk_indicators:
            elements.append(Paragraph("<b>Risk Indicators:</b>", self.styles['BodyTextCustom']))
            for indicator in risk_indicators[:10]:
                clean_indicator = indicator.replace("[Critical]", "🔴").replace("[High]", "🟠").replace("[Medium]", "🟡").replace("[Low]", "🟢")
                elements.append(Paragraph(f"  • {clean_indicator}", self.styles['SmallText']))
            
            if len(risk_indicators) > 10:
                elements.append(Paragraph(
                    f"... and {len(risk_indicators) - 10} more indicators",
                    self.styles['SmallText']
                ))

        elements.append(Spacer(1, 15))
        return elements

    def _create_sast_section(self, sast_results: Dict) -> List:
        """Create SAST findings section."""
        elements = []
        elements.append(Paragraph("6. SAST Findings", self.styles['SectionHeader']))

        findings = sast_results.get("javascript_analysis", [])
        if not findings:
            findings = sast_results.get("findings", [])

        if not findings:
            elements.append(Paragraph(
                "No security findings detected.",
                self.styles['BodyTextCustom']
            ))
            return elements

        table_data = [["File", "Line", "Severity", "Rule"]]
        for finding in findings[:20]:
            severity = finding.get("risk_level", finding.get("severity", "medium"))
            table_data.append([
                finding.get("file", "Unknown")[:30],
                str(finding.get("line_number", finding.get("line", "-"))),
                severity.upper(),
                finding.get("pattern_name", finding.get("rule", "-"))[:25],
            ])

        findings_table = Table(table_data, colWidths=[2 * inch, 0.6 * inch, 0.8 * inch, 2 * inch])
        findings_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f3f4f6')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        elements.append(findings_table)

        if len(findings) > 20:
            elements.append(Paragraph(
                f"... and {len(findings) - 20} more findings",
                self.styles['SmallText']
            ))

        elements.append(Spacer(1, 15))
        return elements

    def _create_recommendations_section(self, summary: Dict) -> List:
        """Create recommendations section."""
        elements = []
        elements.append(Paragraph("7. Recommendations", self.styles['SectionHeader']))

        recommendations = summary.get("recommendations", [])
        if recommendations:
            for rec in recommendations:
                elements.append(Paragraph(f"- {rec}", self.styles['BodyTextCustom']))
        else:
            elements.append(Paragraph("- Review all high-risk findings before installation", self.styles['BodyTextCustom']))
            elements.append(Paragraph("- Verify the extension developer's reputation", self.styles['BodyTextCustom']))
            elements.append(Paragraph("- Monitor extension behavior after installation", self.styles['BodyTextCustom']))

        elements.append(Spacer(1, 30))
        return elements

    def _create_footer(self) -> List:
        """Create report footer."""
        elements = []
        elements.append(Paragraph(
            "Generated by ThreatXtension - Chrome Extension Security Analyzer",
            ParagraphStyle('Footer', fontSize=9, textColor=colors.HexColor('#9ca3af'), alignment=TA_CENTER)
        ))
        elements.append(Paragraph(
            "This report is for informational purposes only.",
            ParagraphStyle('Footer2', fontSize=8, textColor=colors.HexColor('#9ca3af'), alignment=TA_CENTER)
        ))
        return elements

    def generate_pdf(self, scan_results: Dict, output_path: Optional[str] = None) -> bytes:
        """
        Generate PDF report from scan results.

        Args:
            scan_results: Complete scan results dictionary
            output_path: Optional path to save the PDF file

        Returns:
            PDF content as bytes
        """
        extension_name = scan_results.get("extension_name", scan_results.get("metadata", {}).get("title", "Unknown Extension"))
        extension_id = scan_results.get("extension_id", "Unknown")
        timestamp = scan_results.get("timestamp", datetime.now().isoformat())
        security_score = scan_results.get("overall_security_score", scan_results.get("security_score", 0))
        risk_level = scan_results.get("risk_level", scan_results.get("overall_risk", "unknown"))

        permissions_analysis = scan_results.get("permissions_analysis", {})
        sast_results = scan_results.get("sast_results", scan_results.get("javascript_analysis", {}))
        vt_analysis = scan_results.get("virustotal_analysis", {})
        entropy_analysis = scan_results.get("entropy_analysis", {})
        chromestats_analysis = scan_results.get("chromestats_analysis", {})
        summary = scan_results.get("summary", {})

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
        )

        elements = []
        elements.extend(self._create_header(extension_name, extension_id, timestamp))
        elements.extend(self._create_score_section(security_score, risk_level))
        elements.extend(self._create_executive_summary(summary))
        elements.extend(self._create_virustotal_section(vt_analysis))
        elements.extend(self._create_entropy_section(entropy_analysis))
        elements.extend(self._create_permissions_section(permissions_analysis))
        elements.extend(self._create_chromestats_section(chromestats_analysis))
        elements.extend(self._create_sast_section(sast_results))
        elements.extend(self._create_recommendations_section(summary))
        elements.extend(self._create_footer())

        doc.build(elements)

        pdf_bytes = buffer.getvalue()
        buffer.close()

        if output_path:
            with open(output_path, "wb") as f:
                f.write(pdf_bytes)
            logger.info("PDF report saved to: %s", output_path)

        return pdf_bytes
