#!/usr/bin/env python3
"""Builds a PDF from one of this project's Markdown documents (default: the demo guide).

    python3 -m venv /tmp/pdfenv && /tmp/pdfenv/bin/pip install fpdf2==2.8.3
    /tmp/pdfenv/bin/python docs/make_pdf.py [input.md] [output.pdf]

Renders the Markdown subset these documents use - headings, paragraphs,
**bold**, `code`, bullet and numbered lists, tables, fenced code blocks and
horizontal rules - directly with fpdf2's text, table and cell functions,
using the DejaVu fonts from Ubuntu's fonts-dejavu-core (Unicode arrows etc.).
Code blocks keep their spacing, so the ASCII diagrams stay aligned.
"""
import os
import re
import sys

from fpdf import FPDF
from fpdf.fonts import FontFace

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FONT_DIR = "/usr/share/fonts/truetype/dejavu"
ACCENT = (37, 99, 170)
INK = (20, 20, 20)
MUTED = (110, 110, 110)
LIST_RE = re.compile(r"^(\s*)([-*]|\d+\.)\s+(.*)$")


def md_inline(text):
    """Markdown inline -> fpdf2 'markdown=True' syntax (**bold** kept, `code` shown plainly)."""
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1", text)          # links -> text
    text = re.sub(r"`([^`]+)`", r"\1", text)
    return text


def plain(text):
    return md_inline(text).replace("**", "")


def write_rich(pdf, text, size, line_h, x_left=None):
    """Flow text with **bold** segments. Written segment by segment (fpdf2's own
    markdown mode would also treat '--' and '__' as markup, breaking '--control')."""
    old_margin = pdf.l_margin
    if x_left is not None:
        pdf.set_left_margin(x_left)
        pdf.set_x(x_left)
    for k, seg in enumerate(md_inline(text).split("**")):
        if seg:
            pdf.set_font("DejaVu", "B" if k % 2 else "", size)
            pdf.write(line_h, seg)
    pdf.ln(line_h)
    pdf.set_left_margin(old_margin)


class Doc(FPDF):
    title_text = ""

    def footer(self):
        self.set_y(-12)
        self.set_font("DejaVu", size=7)
        self.set_text_color(*MUTED)
        self.cell(0, 8, "%s   |   page %d" % (self.title_text, self.page_no()), align="C")


def render(pdf, md):
    lines = md.splitlines()
    i = 0
    para = []

    def flush():
        if para:
            pdf.set_text_color(*INK)
            write_rich(pdf, " ".join(para), 9.5, 5)
            pdf.ln(1.5)
            para.clear()

    def code_block(code):
        width = max([len(c) for c in code] + [1])
        size = 7.5 if width <= 95 else max(5.0, 7.5 * 95 / width)
        pdf.set_font("DejaVuMono", size=size)
        pdf.set_fill_color(244, 244, 241)
        pdf.set_text_color(*INK)
        pdf.multi_cell(0, size * 0.48, "\n".join(code) or " ", fill=True,
                       new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    while i < len(lines):
        line, s = lines[i], lines[i].strip()
        if s.startswith("```"):
            flush()
            i += 1
            code = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code.append(lines[i].rstrip())
                i += 1
            code_block(code)
        elif line.startswith("    ") and s and not para:
            # indented code block (4 spaces, after a blank line)
            code = []
            while i < len(lines) and (lines[i].startswith("    ") or not lines[i].strip()):
                if not lines[i].strip() and not (i + 1 < len(lines) and lines[i + 1].startswith("    ")):
                    break
                code.append(lines[i][4:].rstrip())
                i += 1
            i -= 1
            code_block(code)
        elif not s:
            flush()
        elif s.startswith("#"):
            flush()
            level = len(s) - len(s.lstrip("#"))
            size = {1: 18, 2: 14, 3: 11.5}.get(level, 10.5)
            if level <= 2 and pdf.get_y() > pdf.h - 60:
                pdf.add_page()
            pdf.ln(3 if level > 1 else 0)
            pdf.set_font("DejaVu", "B", size)
            pdf.set_text_color(*(ACCENT if level <= 2 else INK))
            pdf.multi_cell(0, size * 0.55, plain(s[level:].strip()), align="L", new_x="LMARGIN", new_y="NEXT")
            if level == 2:
                pdf.set_draw_color(*ACCENT)
                pdf.line(pdf.l_margin, pdf.get_y() + 0.5, pdf.w - pdf.r_margin, pdf.get_y() + 0.5)
            pdf.ln(2)
        elif s in ("---", "***"):
            flush()
            pdf.set_draw_color(200, 200, 200)
            pdf.line(pdf.l_margin, pdf.get_y() + 1, pdf.w - pdf.r_margin, pdf.get_y() + 1)
            pdf.ln(3)
        elif s.startswith("|"):
            flush()
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                # split on unescaped pipes; "\|" inside a cell is a literal pipe
                cells = [c.strip().replace("\\|", "|")
                         for c in re.split(r"(?<!\\)\|", lines[i].strip().strip("|"))]
                if not all(re.fullmatch(r":?-{2,}:?", c) for c in cells):
                    rows.append([plain(c) for c in cells])
                i += 1
            i -= 1
            if rows:
                ncol = max(len(r) for r in rows)
                rows = [r + [""] * (ncol - len(r)) for r in rows]
                pdf.set_font("DejaVu", size=7.5 if ncol <= 4 else 6.5)
                pdf.set_text_color(*INK)
                pdf.set_draw_color(200, 200, 200)
                with pdf.table(headings_style=FontFace(emphasis="BOLD", fill_color=(232, 238, 247)),
                               line_height=3.6, padding=1.2, text_align="LEFT",
                               first_row_as_headings=True) as table:
                    for r in rows:
                        row = table.row()
                        for c in r:
                            row.cell(c)
                pdf.ln(3)
        elif LIST_RE.match(line):
            flush()
            while i < len(lines) and LIST_RE.match(lines[i]):
                indent, marker, item = LIST_RE.match(lines[i]).groups()
                while i + 1 < len(lines) and lines[i + 1].startswith("  ") and lines[i + 1].strip() \
                        and not LIST_RE.match(lines[i + 1]):
                    i += 1
                    item += " " + lines[i].strip()
                depth = len(indent) // 2
                bullet = marker if marker[0].isdigit() else "•"
                pdf.set_font("DejaVu", size=9.5)
                pdf.set_text_color(*INK)
                x0 = pdf.l_margin + 3 + depth * 5
                pdf.set_x(x0)
                pdf.cell(6, 5, bullet)
                write_rich(pdf, item, 9.5, 5, x_left=x0 + 6)
                i += 1
            i -= 1
            pdf.ln(1.5)
        elif s.startswith(">"):
            flush()
            pdf.set_text_color(*MUTED)
            write_rich(pdf, s.lstrip("> "), 9, 4.6)
            pdf.ln(1.5)
        else:
            para.append(s)
        i += 1
    flush()


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "FRONTEND_EXPLANATION_AND_DEMO_GUIDE.md")
    dst = sys.argv[2] if len(sys.argv) > 2 else os.path.splitext(src)[0] + ".pdf"
    with open(src, encoding="utf-8") as f:
        md = f.read()
    pdf = Doc(format="A4")
    m = re.search(r"^#\s+(.+)$", md, re.M)
    pdf.title_text = plain(m.group(1)) if m else os.path.basename(src)
    pdf.add_font("DejaVu", "", os.path.join(FONT_DIR, "DejaVuSans.ttf"))
    pdf.add_font("DejaVu", "B", os.path.join(FONT_DIR, "DejaVuSans-Bold.ttf"))
    # fonts-dejavu-core has no oblique Sans: italic uses the upright faces.
    pdf.add_font("DejaVu", "I", os.path.join(FONT_DIR, "DejaVuSans.ttf"))
    pdf.add_font("DejaVu", "BI", os.path.join(FONT_DIR, "DejaVuSans-Bold.ttf"))
    pdf.add_font("DejaVuMono", "", os.path.join(FONT_DIR, "DejaVuSansMono.ttf"))
    pdf.set_margins(15, 15, 15)
    pdf.set_auto_page_break(True, margin=15)
    pdf.add_page()
    render(pdf, md)
    pdf.output(dst)
    print("written %s (%d pages)" % (dst, pdf.page_no()))


if __name__ == "__main__":
    main()
