#!/usr/bin/env python3
"""Render the team's CTF Markdown report to its required PDF deliverable."""
from html import escape
from pathlib import Path
import re

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

ROOT = Path(__file__).resolve().parents[1]


def inline(text):
    text = escape(text.replace(r'\|', '|')).replace('∧', 'AND').replace('→', '-&gt;').replace('≥', '&gt;=')
    text = text.replace('—', '-').replace('–', '-').replace('‑', '-')
    text = re.sub(r'`([^`]+)`', r'<font name="Courier">\1</font>', text)
    text = re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', text)
    return text


def build():
    styles = getSampleStyleSheet()
    styles['BodyText'].fontSize = 9
    styles['BodyText'].leading = 13
    styles['BodyText'].spaceAfter = 7
    styles.add(ParagraphStyle('Cell', parent=styles['BodyText'], fontSize=7.5,
                              leading=10, spaceAfter=0, wordWrap='CJK'))
    styles.add(ParagraphStyle('CodeLine', fontName='Courier', fontSize=7,
                              leading=9, wordWrap='CJK', spaceAfter=0))
    document = SimpleDocTemplate(str(ROOT / 'CTF_writeup.pdf'), pagesize=A4,
                                 rightMargin=42, leftMargin=42, topMargin=42,
                                 bottomMargin=42, title='SFTP CTF write-up')
    lines = (ROOT / 'docs/CTF_writeup.md').read_text().splitlines()
    story, paragraph = [], []
    def flush():
        if paragraph:
            story.append(Paragraph(inline(' '.join(paragraph)), styles['BodyText']))
            paragraph.clear()
    i, code = 0, False
    while i < len(lines):
        line = lines[i]
        if line.startswith('```'):
            flush()
            code = not code
            story.append(Spacer(1, 6))
        elif code:
            story.append(Paragraph(escape(line).replace(' ', '&nbsp;') or '&nbsp;', styles['CodeLine']))
        elif line.startswith('|'):
            flush()
            rows = []
            while i < len(lines) and lines[i].startswith('|'):
                cells = [x.strip() for x in re.split(r'(?<!\\)\|', lines[i].strip('|'))]
                if not all(re.fullmatch(r'[-: ]+', x) for x in cells):
                    rows.append(cells)
                i += 1
            count = len(rows[0])
            # Keep long attack-description columns wide and all text wrapped.
            weights = [1] * count
            if count == 4:
                weights = [0.6, 2, 1.3, 1.5]
            widths = [document.width * w / sum(weights) for w in weights]
            data = [[Paragraph(inline(cell), styles['Cell']) for cell in row] for row in rows]
            table = Table(data, colWidths=widths, repeatRows=1, hAlign='LEFT')
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e5edf5')),
                ('GRID', (0, 0), (-1, -1), 0.3, colors.HexColor('#b5c3d0')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ]))
            story.extend([table, Spacer(1, 10)])
            continue
        elif line.startswith('#'):
            flush()
            level = len(line) - len(line.lstrip('#'))
            style = 'Title' if level == 1 else 'Heading1' if level == 2 else 'Heading2'
            story.append(Paragraph(inline(line.lstrip('# ')), styles[style]))
        elif not line.strip():
            flush()
        elif line.startswith(('- ', '* ')):
            flush()
            story.append(Paragraph(inline(line[2:]), styles['BodyText'], bulletText='-'))
        else:
            paragraph.append(line)
        i += 1
    flush()
    def footer(canvas, doc):
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(colors.HexColor('#53677a'))
        canvas.drawString(42, 24, 'Computer Security | SFTP CTF')
        canvas.drawRightString(A4[0] - 42, 24, str(doc.page))
    document.build(story, onFirstPage=footer, onLaterPages=footer)


if __name__ == '__main__':
    build()
