from fpdf import FPDF
from datetime import datetime
from pathlib import Path


class ForensicReport(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 13)
        self.set_fill_color(20, 20, 20)
        self.set_text_color(255, 255, 255)
        self.cell(0, 12, 'DIGITAL FORENSIC INVESTIGATION REPORT',
                  fill=True, align='C', new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)
        self.ln(3)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(120, 120, 120)
        self.cell(
            0, 10,
            f'Page {self.page_no()} | Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | CONFIDENTIAL',
            align='C'
        )

    def section_title(self, title):
        self.set_font('Helvetica', 'B', 11)
        self.set_fill_color(220, 220, 220)
        self.set_text_color(0, 0, 0)
        self.cell(0, 8, f'  {title}', fill=True,
                  new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def body_text(self, text):
        self.set_font('Helvetica', '', 9)
        self.set_text_color(30, 30, 30)
        # Clean non-latin chars
        clean = text.encode('latin-1', 'replace').decode('latin-1')
        self.multi_cell(0, 5.5, clean)
        self.ln(2)

    def key_value(self, key, value):
        self.set_font('Helvetica', 'B', 9)
        self.set_text_color(0, 0, 0)
        self.cell(45, 6, f'{key}:', new_x="RIGHT", new_y="TOP")
        self.set_font('Helvetica', '', 9)
        val_clean = str(value).encode('latin-1', 'replace').decode('latin-1')
        self.multi_cell(0, 6, val_clean)


def generate_pdf_report(case_id, ai_summary, all_evidence,
                         output_path="forensic_report.pdf"):
    pdf = ForensicReport()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # ── Case Info Banner ──
    pdf.set_font('Helvetica', 'B', 10)
    pdf.set_fill_color(240, 240, 240)
    pdf.cell(0, 7, f'  Case ID: {case_id}    |    Date: {datetime.now().strftime("%Y-%m-%d %H:%M")}    |    Files: {len(all_evidence)}    |    Status: UNDER INVESTIGATION',
             fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    # ── Evidence Files Table ──
    pdf.section_title('EVIDENCE FILES ANALYZED')
    pdf.set_font('Helvetica', 'B', 8)
    pdf.set_fill_color(60, 60, 60)
    pdf.set_text_color(255, 255, 255)

    # Table header
    col_widths = [55, 20, 40, 25, 50]
    headers = ['Filename', 'Type', 'Modified', 'Size', 'SHA256']
    for i, h in enumerate(headers):
        pdf.cell(col_widths[i], 6, h, fill=True, border=1)
    pdf.ln()

    pdf.set_font('Helvetica', '', 7)
    pdf.set_text_color(0, 0, 0)

    for ev in all_evidence:
        m = ev.get('metadata', {})
        h = ev.get('hashes', {})
        fill = False
        pdf.set_fill_color(248, 248, 248)
        vals = [
            m.get('filename', 'unknown')[:30],
            ev.get('file_type', 'doc')[:8],
            m.get('modified', '')[:19],
            f"{m.get('size_bytes', 0):,}",
            h.get('sha256', '')[:20] + '...'
        ]
        for i, v in enumerate(vals):
            pdf.cell(col_widths[i], 5, str(v), border=1, fill=fill)
        pdf.ln()

        # IOCs row
        iocs = ev.get('iocs', {})
        ioc_parts = []
        if iocs.get('ips'):
            ioc_parts.append(f"IPs: {', '.join(iocs['ips'][:3])}")
        if iocs.get('domains'):
            ioc_parts.append(f"Domains: {', '.join(iocs['domains'][:2])}")
        if iocs.get('emails'):
            ioc_parts.append(f"Emails: {', '.join(iocs['emails'][:2])}")
        if ioc_parts:
            pdf.set_font('Helvetica', 'I', 7)
            pdf.set_text_color(180, 0, 0)
            ioc_text = '  IOCs: ' + ' | '.join(ioc_parts)
            ioc_clean = ioc_text.encode('latin-1', 'replace').decode('latin-1')
            pdf.cell(0, 4, ioc_clean[:120], new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(0, 0, 0)

    pdf.ln(5)

    # ── AI Analysis ──
    pdf.section_title('AI FORENSIC ANALYSIS')
    pdf.body_text(ai_summary)

    # ── Consolidated IOCs ──
    pdf.add_page()
    pdf.section_title('CONSOLIDATED INDICATORS OF COMPROMISE')

    all_iocs = {
        "IP Addresses": [],
        "Domains": [],
        "URLs": [],
        "Email Addresses": [],
        "File Hashes": [],
        "File Paths": []
    }
    ioc_keys = {
        "IP Addresses": "ips",
        "Domains": "domains",
        "URLs": "urls",
        "Email Addresses": "emails",
        "File Hashes": "hashes",
        "File Paths": "filepaths"
    }
    for ev in all_evidence:
        for label, key in ioc_keys.items():
            all_iocs[label].extend(ev.get('iocs', {}).get(key, []))

    for label, values in all_iocs.items():
        unique_vals = list(set(values))
        if unique_vals:
            pdf.set_font('Helvetica', 'B', 9)
            pdf.set_text_color(0, 60, 120)
            pdf.cell(0, 6, f'{label} ({len(unique_vals)} found):',
                     new_x="LMARGIN", new_y="NEXT")
            pdf.set_font('Helvetica', '', 8)
            pdf.set_text_color(30, 30, 30)
            for v in unique_vals[:15]:
                v_clean = str(v).encode('latin-1', 'replace').decode('latin-1')
                pdf.cell(0, 5, f'  • {v_clean}',
                         new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)

    # ── Footer disclaimer ──
    pdf.ln(5)
    pdf.set_font('Helvetica', 'I', 8)
    pdf.set_text_color(100, 100, 100)
    pdf.multi_cell(0, 5,
        "DISCLAIMER: This report was generated by an AI-assisted forensic analysis system. "
        "All findings must be verified by a qualified digital forensic examiner before use "
        "in legal proceedings. Chain of custody documentation is maintained separately.")

    pdf.output(output_path)
    return output_path