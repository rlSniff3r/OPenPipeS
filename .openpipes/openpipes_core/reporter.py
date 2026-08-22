"""
reporter.py — DOCX Pentest Report Generator for OPenPipeS.

Uses docxtpl (python-docx + Jinja2) to render professional, customizable
pentest reports directly from the SQLite database.

Usage:
    openpipes-core report                                  # default template
    openpipes-core report --template ~/brand.docx          # custom template
    openpipes-core report --init-template                  # generate starter template
"""
import os
import json
import re
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Optional

from rich.console import Console

import db

console = Console()

HOME = str(Path.home())
DEFAULT_TEMPLATE = os.path.join(HOME, ".openpipes", ".templates", "pentest_report.docx")

# ── Severity chart colors ────────────────────────────────────────
SEVERITY_COLORS = {
    "Crítica": "#dc2626",
    "Alta": "#f97316",
    "Média": "#eab308",
    "Baixa": "#22c55e",
    "Info": "#6b7280",
}
SEVERITY_ORDER = ["Crítica", "Alta", "Média", "Baixa", "Info"]


# ── Chart generation ─────────────────────────────────────────────
def _generate_severity_chart(stats: dict, output_path: str) -> Optional[str]:
    """Render a severity pie chart as PNG. Returns path or None."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        console.print(" [yellow]⚠ matplotlib not installed — skipping severity chart.[/yellow]")
        return None

    labels, sizes, colors = [], [], []
    for sev in SEVERITY_ORDER:
        key = sev.lower().replace("á", "a").replace("í", "i")  # critical->crítica map
        mapping = {"crítica": "critical", "alta": "high", "média": "medium",
                   "baixa": "low", "info": "info"}
        count = stats.get(mapping.get(sev.lower(), sev.lower()), 0) or stats.get(sev, 0)
        if count > 0:
            labels.append(sev)
            sizes.append(count)
            colors.append(SEVERITY_COLORS[sev])

    if not sizes:
        return None

    fig, ax = plt.subplots(figsize=(5, 4))
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, colors=colors, autopct="%1.0f%%",
        startangle=90, textprops={"fontsize": 10},
    )
    for t in autotexts:
        t.set_fontweight("bold")
    ax.set_title("Vulnerabilities by Severity", fontsize=13, fontweight="bold", pad=15)
    fig.savefig(output_path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    return output_path


# ── Context builders ─────────────────────────────────────────────
def _build_host_context(conn, host_id: int, host_name: str,
                        proj_path: str, tpl_doc=None) -> Optional[dict]:
    """Build the full context dict for a single vulnerable host."""
    from docxtpl import InlineImage
    from docx.shared import Inches

    cur = conn.cursor()

    # Host row
    cur.execute("SELECT * FROM hosts WHERE id = ?", (host_id,))
    row = cur.fetchone()
    if not row:
        return None
    host = dict(row)
    host["ips"] = json.loads(host["ips"]) if host.get("ips") else []

    # Open ports
    cur.execute(
        "SELECT port, protocol, state, service, version "
        "FROM ports WHERE host_id = ? AND state = 'open' ORDER BY port",
        (host_id,),
    )
    open_ports = [dict(r) for r in cur.fetchall()]

    # All ports (for Appendix A)
    cur.execute(
        "SELECT port, protocol, state, service, version "
        "FROM ports WHERE host_id = ? ORDER BY port",
        (host_id,),
    )
    all_ports = [dict(r) for r in cur.fetchall()]

    # Endpoints
    cur.execute(
        "SELECT url, status_code, title, web_server, tech_stack, source_tool "
        "FROM endpoints WHERE host_id = ? ORDER BY url",
        (host_id,),
    )
    endpoints = [dict(r) for r in cur.fetchall()]

    # Vulnerabilities (open only)
    cur.execute("""
        SELECT id, title, severity, cvss_score, cvss_vector, cwe_id,
               cve_id, vuln_name, description, matched_at,
               curl_command, remediation, impact,
               reference_urls, source_tool, enriched_by, created_at
        FROM vulnerabilities WHERE host_id = ? AND status = 'open'
        ORDER BY CASE severity WHEN 'Crítica' THEN 0 WHEN 'Alta' THEN 1
                 WHEN 'Média' THEN 2 WHEN 'Baixa' THEN 3 ELSE 4 END
    """, (host_id,))
    vulns = []
    evidence_dir = os.path.join(proj_path, "Varreduras", f"nmap-{host_name}", "Evidencias")

    for r in cur.fetchall():
        v = dict(r)
        v["reference_urls"] = json.loads(v["reference_urls"]) if v.get("reference_urls") else []
        v["cvss_score"] = float(v["cvss_score"]) if v.get("cvss_score") else None
        v["severity_emoji"] = {"Crítica": "🔴", "Alta": "🟠", "Média": "🟡",
                                "Baixa": "🟢", "Info": "🔵"}.get(v["severity"], "⚪")

        cwe_match = re.match(r"CWE-(\d+)", v.get("cwe_id") or "")
        v["cwe_url"] = (
            f"https://cwe.mitre.org/data/definitions/{cwe_match.group(1)}.html"
            if cwe_match else ""
        )

        # Evidence images
        evidence_images = []
        if tpl_doc:
            cur.execute("SELECT stored_name FROM user_evidences WHERE vuln_id = ?",
                        (v["id"],))
            for er in cur.fetchall():
                img_path = os.path.join(evidence_dir, er["stored_name"])
                if os.path.exists(img_path):
                    try:
                        evidence_images.append(
                            InlineImage(tpl_doc, img_path, width=Inches(5.5))
                        )
                    except Exception:
                        pass
        v["evidence_images"] = evidence_images

        # Also grab screenshots matched_at if any
        vulns.append(v)

    # Screenshots (for appendix)
    cur.execute(
        "SELECT file_path, source_url, title FROM screenshots WHERE host_id = ?",
        (host_id,),
    )
    screenshots = []
    ss_dir = os.path.join(proj_path, "Varreduras", f"nmap-{host_name}", "Screenshots")
    for r in cur.fetchall():
        s = dict(r)
        full_path = os.path.join(ss_dir, s["file_path"])
        if tpl_doc and os.path.exists(full_path):
            try:
                s["image"] = InlineImage(tpl_doc, full_path, width=Inches(5))
            except Exception:
                s["image"] = None
        else:
            s["image"] = None
        screenshots.append(s)

    # Tech stack
    tech_set = set()
    cur.execute("SELECT tech_stack FROM endpoints WHERE host_id = ?", (host_id,))
    for r in cur.fetchall():
        try:
            tech_set.update(json.loads(r["tech_stack"] or "[]"))
        except Exception:
            pass
    try:
        tech_set.update(json.loads(host.get("manual_techs") or "[]"))
    except Exception:
        pass

    return {
        "name": host_name,
        "ip": host["ips"][0] if host["ips"] else "",
        "all_ips": host["ips"],
        "tech_summary": ", ".join(sorted(tech_set)) if tech_set else "N/D",
        "open_ports": open_ports,
        "all_ports": all_ports,       # ← ADD
        "endpoints": endpoints,       # ← ADD
        "vulnerabilities": vulns,
        "screenshots": screenshots,
        "narrative": host.get("narrative", "") or "",
    }


def _build_report_context(proj_path: str, client_name: str = "",
                          all_hosts: bool = False, tpl_doc=None) -> dict:
    """Build the complete Jinja2 context for the report template."""
    # Scope
    scope_domains = []
    domains_file = os.path.join(proj_path, "domains.txt")
    if os.path.exists(domains_file):
        with open(domains_file, "r", encoding="utf-8") as f:
            for line in f:
                d = line.strip().lower()
                if d and not d.startswith("#") and not re.match(r"^\d+\.", d):
                    scope_domains.append(d)

    stats = {
        "total_hosts": 0, "vulnerable_hosts": 0, "total_vulns": 0,
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
    }

    hosts_ctx = []

    with db.get_connection(proj_path) as conn:
        cur = conn.cursor()

        # Get hosts with open vulns (or all alive hosts if --all-hosts)
        if all_hosts:
            cur.execute("SELECT id, host FROM hosts WHERE is_alive = 1 AND in_scope = 1 ORDER BY host")
        else:
            cur.execute("""
                SELECT DISTINCT h.id, h.host
                FROM hosts h
                JOIN vulnerabilities v ON v.host_id = h.id
                WHERE v.status = 'open' AND h.is_alive = 1 AND h.in_scope = 1
                ORDER BY h.host
            """)

        host_rows = cur.fetchall()
        stats["total_hosts"] = len(host_rows)

        for hr in host_rows:
            hctx = _build_host_context(conn, hr["id"], hr["host"], proj_path, tpl_doc)
            if not hctx:
                continue
            hosts_ctx.append(hctx)
            if hctx["vulnerabilities"]:
                stats["vulnerable_hosts"] += 1
                stats["total_vulns"] += len(hctx["vulnerabilities"])
                for v in hctx["vulnerabilities"]:
                    sev = v["severity"]
                    if sev == "Crítica":   stats["critical"] += 1
                    elif sev == "Alta":    stats["high"] += 1
                    elif sev == "Média":   stats["medium"] += 1
                    elif sev == "Baixa":   stats["low"] += 1
                    elif sev == "Info":    stats["info"] += 1

        # Scope stats
        cur.execute("SELECT COUNT(*) FROM endpoints WHERE host_id IN "
                    "(SELECT id FROM hosts WHERE is_alive = 1 AND in_scope = 1)")
        total_endpoints = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM ports WHERE host_id IN "
                    "(SELECT id FROM hosts WHERE is_alive = 1 AND in_scope = 1) "
                    "AND state = 'open'")
        total_ports = cur.fetchone()[0]

    return {
        "project_name": os.path.basename(proj_path),
        "client_name": client_name or os.path.basename(proj_path),
        "report_date": datetime.now().strftime("%d/%m/%Y"),
        "classification": "CONFIDENCIAL",
        "stats": stats,
        "scope": {
            "domains": scope_domains,
            "total_endpoints": total_endpoints,
            "total_ports": total_ports,
        },
        "hosts": hosts_ctx,
        "methodology": (
            "A metodologia de teste seguiu as diretrizes do OWASP Testing Guide v4, "
            "combinada com técnicas de reconnaissance e exploração automatizadas e manuais. "
            "As ferramentas utilizadas incluíram Nmap, HTTPx, Katana, Feroxbuster, Nuclei, "
            "JSFinder e GF para cobertura abrangente de superfície de ataque e vulnerabilidades."
        ),
    }


# ── Default template generator ───────────────────────────────────
def create_default_template():
    """Generate a rich, pre-formatted default DOCX report template."""
    from docx import Document
    from docx.shared import Inches, Pt, Cm, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.enum.section import WD_ORIENT
    from docx.oxml.ns import qn

    os.makedirs(os.path.dirname(DEFAULT_TEMPLATE), exist_ok=True)
    doc = Document()

    # ── Page setup ────────────────────────────────────────────────
    section = doc.sections[0]
    section.page_height = Cm(29.7)
    section.page_width = Cm(21.0)
    section.top_margin = Cm(2.5)
    section.bottom_margin = Cm(2.5)
    section.left_margin = Cm(2.5)
    section.right_margin = Cm(2.5)

    # ── Styles ────────────────────────────────────────────────────
    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(11)
    style.paragraph_format.space_after = Pt(6)

    for level, size, color in [
        ("Heading 1", 20, RGBColor(0x1a, 0x56, 0x8e)),
        ("Heading 2", 16, RGBColor(0x1a, 0x56, 0x8e)),
        ("Heading 3", 13, RGBColor(0x2c, 0x3e, 0x50)),
    ]:
        h = doc.styles[level]
        h.font.name = "Calibri"
        h.font.size = Pt(size)
        h.font.color.rgb = color
        h.font.bold = True

    # ── Helper: add a styled table ────────────────────────────────
    def add_table(doc, headers, rows_data=None):
        """Create a table with header row + optional template rows."""
        ncols = len(headers)
        nrows = 1 + (len(rows_data) if rows_data else 1)
        tbl = doc.add_table(rows=nrows, cols=ncols)
        tbl.style = "Light Grid Accent 1"
        tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        # header
        for i, h in enumerate(headers):
            cell = tbl.rows[0].cells[i]
            cell.text = h
            for p in cell.paragraphs:
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                for run in p.runs:
                    run.bold = True
                    run.font.size = Pt(9)
        # data rows
        if rows_data:
            for r_idx, row_vals in enumerate(rows_data):
                for c_idx, val in enumerate(row_vals):
                    cell = tbl.rows[r_idx + 1].cells[c_idx]
                    cell.text = str(val)
                    for p in cell.paragraphs:
                        for run in p.runs:
                            run.font.size = Pt(9)
        return tbl

    # ══════════════════════════════════════════════════════════════
    #  COVER PAGE
    # ══════════════════════════════════════════════════════════════
    for _ in range(6):
        doc.add_paragraph("")

    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run("{{ project_name }}")
    run.font.size = Pt(36)
    run.font.color.rgb = RGBColor(0x1a, 0x56, 0x8e)
    run.bold = True

    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run("Relatório de Pentest")
    run.font.size = Pt(20)
    run.font.color.rgb = RGBColor(0x2c, 0x3e, 0x50)

    doc.add_paragraph("")

    # Cover details table
    cover_data = [
        ("Cliente:", "{{ client_name }}"),
        ("Data:", "{{ report_date }}"),
        ("Classificação:", "Confidencial"),
    ]
    tbl = doc.add_table(rows=3, cols=2)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, (label, value) in enumerate(cover_data):
        tbl.rows[i].cells[0].text = label
        tbl.rows[i].cells[1].text = value
        for p in tbl.rows[i].cells[0].paragraphs:
            for run in p.runs:
                run.bold = True
                run.font.size = Pt(12)
        for p in tbl.rows[i].cells[1].paragraphs:
            for run in p.runs:
                run.font.size = Pt(12)

    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════
    #  TABLE OF CONTENTS (Word auto-generated)
    # ══════════════════════════════════════════════════════════════
    doc.add_heading("Sumário", level=1)
    p = doc.add_paragraph()
    run = p.add_run()
    fld_char_begin = run._element.makeelement(qn("w:fldChar"), {qn("w:fldCharType"): "begin"})
    run._element.append(fld_char_begin)
    run2 = p.add_run()
    fld_code = run2._element.makeelement(qn("w:instrText"), {qn("xml:space"): "preserve"})
    fld_code.text = " TOC \\o \"1-3\" \\h \\z \\u "
    run2._element.append(fld_code)
    run3 = p.add_run()
    fld_char_end = run3._element.makeelement(qn("w:fldChar"), {qn("w:fldCharType"): "end"})
    run3._element.append(fld_char_end)
    p = doc.add_paragraph("(Atualize o campo no Word: clique → F9, ou Ctrl+A → F9)")
    p.runs[0].font.size = Pt(9)
    p.runs[0].font.color.rgb = RGBColor(0x99, 0x99, 0x99)

    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════
    #  1. EXECUTIVE SUMMARY
    # ══════════════════════════════════════════════════════════════
    doc.add_heading("1. Resumo Executivo", level=1)

    doc.add_paragraph(
        "Este relatório apresenta os resultados da avaliação de segurança realizada "
        "no projeto {{ project_name }}, conduzida entre {{ methodology.scope_summary }}."
    )
    doc.add_paragraph(
        "Foram avaliados {{ stats.total_hosts }} hosts, identificando-se "
        "{{ stats.total_vulns }} vulnerabilidades e mapeando {{ stats.total_endpoints }} "
        "endpoints web e {{ stats.total_ports }} portas abertas."
    )

    doc.add_heading("Visão Geral por Severidade", level=2)

    sev_headers = ["Severidade", "Quantidade"]
    sev_rows = [
        ("🔴 Crítica", "{{ stats.critical }}"),
        ("🟠 Alta", "{{ stats.high }}"),
        ("🟡 Média", "{{ stats.medium }}"),
        ("🟢 Baixa", "{{ stats.low }}"),
        ("🔵 Informativo", "{{ stats.info }}"),
    ]
    add_table(doc, sev_headers, sev_rows)

    doc.add_paragraph("")
    doc.add_paragraph("Distribuição visual:")
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run()
    p.add_run("{{ severity_chart }}")

    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════
    #  2. ESCOPO
    # ══════════════════════════════════════════════════════════════
    doc.add_heading("2. Escopo da Avaliação", level=1)

    doc.add_heading("2.1 Domínios em Escopo", level=2)
    doc.add_paragraph("{{ methodology.scope_summary }}")

    doc.add_heading("2.2 Hosts Avaliados", level=2)
    host_headers = ["Host", "IP", "Portas Abertas", "Endpoints", "Vulns"]
    host_rows_tmpl = (
        "{% for host in hosts %}"
        "{% raw %}<row>{% endraw %}"
        "{{ host.name }} | {{ host.ip }} | {{ host.open_ports | length }} | "
        "{{ host.endpoints | length }} | {{ host.vulnerabilities | length }}"
        "{% raw %}</row>{% endraw %}"
        "{% endfor %}"
    )
    # For docxtpl, we build the table with Jinja2 row tags:
    tbl = doc.add_table(rows=2, cols=5)
    tbl.style = "Light Grid Accent 1"
    for i, h in enumerate(host_headers):
        cell = tbl.rows[0].cells[i]
        cell.text = h
        for p in cell.paragraphs:
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            for run in p.runs:
                run.bold = True
                run.font.size = Pt(9)
    # Jinja2 tags in first cell, endfor in last cell
    tbl.rows[1].cells[0].text = "{{ host.name }}{% for host in hosts %}"
    tbl.rows[1].cells[1].text = "{{ host.ip }}"
    tbl.rows[1].cells[2].text = "{{ host.open_ports | length }}"
    tbl.rows[1].cells[3].text = "{{ host.endpoints | length }}"
    tbl.rows[1].cells[4].text = "{{ host.vulnerabilities | length }}{% endfor %}"

    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════
    #  3. METODOLOGIA
    # ══════════════════════════════════════════════════════════════
    doc.add_heading("3. Metodologia", level=1)

    doc.add_paragraph(
        "A avaliação foi conduzida seguindo as melhores práticas da OWASP e PTES "
        "(Penetration Testing Execution Standard), abrangendo as seguintes fases:"
    )

    doc.add_heading("3.1 Ferramentas Utilizadas", level=2)
    tools_headers = ["Ferramenta", "Finalidade"]
    tools_rows = [
        ("Nmap", "Varredura de portas e detecção de serviços"),
        ("HTTPx", "Probing HTTP/HTTPS e detecção de tecnologias"),
        ("Katana", "Crawling e descoberta de endpoints"),
        ("Feroxbuster", "Força bruta de diretórios e arquivos"),
        ("Nuclei", "Detecção de vulnerabilidades por templates"),
        ("JSFinder", "Análise de JavaScript e rotas ocultas"),
        ("GF (GrepFuzzable)", "Classificação de padrões vulneráveis"),
        ("Arjun", "Descoberta de parâmetros de entrada"),
    ]
    add_table(doc, tools_headers, tools_rows)

    doc.add_heading("3.2 Fases da Avaliação", level=2)
    doc.add_paragraph("{{ methodology.phases }}")

    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════
    #  4. DETAILED FINDINGS (per host)
    # ══════════════════════════════════════════════════════════════
    doc.add_heading("4. Análise Detalhada por Host", level=1)

    doc.add_paragraph(
        "Esta seção apresenta os achados detalhados para cada host que apresentou "
        "vulnerabilidades ou superfície de ataque relevante."
    )

    # ── Per-host block (Jinja2 loop) ──
    doc.add_paragraph("{% for host in hosts %}")

    doc.add_heading("{{ host.name }}", level=2)

    p = doc.add_paragraph()
    run = p.add_run("IP: ")
    run.bold = True
    p.add_run("{{ host.ip }}")

    p = doc.add_paragraph()
    run = p.add_run("Tecnologias Detectadas: ")
    run.bold = True
    p.add_run("{{ host.tech_summary }}")

    # ── Open Ports table ──
    doc.add_heading("Portas Abertas", level=3)
    doc.add_paragraph(
        "{% if host.open_ports %}"
    )
    port_tbl = doc.add_table(rows=2, cols=4)
    port_tbl.style = "Light Grid Accent 1"
    for i, h in enumerate(["Porta", "Protocolo", "Serviço", "Versão"]):
        cell = port_tbl.rows[0].cells[i]
        cell.text = h
        for p in cell.paragraphs:
            for run in p.runs:
                run.bold = True
                run.font.size = Pt(9)
    port_tbl.rows[1].cells[0].text = "{{ port.port }}{% for port in host.open_ports %}"
    port_tbl.rows[1].cells[1].text = "{{ port.protocol }}"
    port_tbl.rows[1].cells[2].text = "{{ port.service }}"
    port_tbl.rows[1].cells[3].text = "{{ port.version }}{% endfor %}"
    doc.add_paragraph(
        "{% else %}"
        "<i>Nenhuma porta aberta registrada.</i>"
        "{% endif %}"
    )

    # ── Endpoints table ──
    doc.add_heading("Endpoints Web", level=3)
    doc.add_paragraph(
        "{% if host.endpoints %}"
    )
    ep_tbl = doc.add_table(rows=2, cols=3)
    ep_tbl.style = "Light Grid Accent 1"
    for i, h in enumerate(["URL", "Status", "Servidor"]):
        cell = ep_tbl.rows[0].cells[i]
        cell.text = h
        for p in cell.paragraphs:
            for run in p.runs:
                run.bold = True
                run.font.size = Pt(9)
    ep_tbl.rows[1].cells[0].text = "{{ ep.url }}{% for ep in host.endpoints %}"
    ep_tbl.rows[1].cells[1].text = "{{ ep.status_code }}"
    ep_tbl.rows[1].cells[2].text = "{{ ep.web_server }}{% endfor %}"
    doc.add_paragraph(
        "{% else %}"
        "<i>Nenhum endpoint web descoberto.</i>"
        "{% endif %}"
    )

    # ── Vulnerabilities detail ──
    doc.add_heading("Vulnerabilidades", level=3)
    doc.add_paragraph(
        "{% if host.vulnerabilities %}"
    )

    # Per-vuln Jinja2 block
    doc.add_paragraph("{% for vuln in host.vulnerabilities %}")

    doc.add_heading("{{ vuln.severity_emoji }} {{ vuln.title }}", level=3)

    # Severity + CVSS line
    vuln_meta_tbl = doc.add_table(rows=1, cols=4)
    vuln_meta_tbl.style = "Light Grid Accent 1"
    meta_data = [
        ("Severidade", "{{ vuln.severity }}"),
        ("CVSS", "{{ vuln.cvss_score }}"),
        ("CWE", "{{ vuln.cwe_id }}"),
        ("CVE", "{{ vuln.cve_id }}"),
    ]
    for i, (label, val) in enumerate(meta_data):
        cell = vuln_meta_tbl.rows[0].cells[i]
        cell.text = f"{label}: {val}"
        for p in cell.paragraphs:
            for run in p.runs:
                run.font.size = Pt(9)
                run.bold = True

    doc.add_paragraph("")

    doc.add_heading("Descrição", level=4)
    doc.add_paragraph("{{ vuln.description }}")

    doc.add_heading("Evidência", level=4)
    doc.add_paragraph(
        "{% if vuln.matched_at %}"
        "**Localização:** {{ vuln.matched_at }}"
        "{% endif %}"
    )
    doc.add_paragraph(
        "{% if vuln.curl_command %}"
        "```bash\n{{ vuln.curl_command }}\n```"
        "{% endif %}"
    )
    # Embed evidence images
    doc.add_paragraph(
        "{% for img in vuln.evidence_images %}"
    )
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run()
    p.add_run("{{ img }}")
    doc.add_paragraph(
        "{% endfor %}"
    )

    doc.add_heading("Impacto", level=4)
    doc.add_paragraph("{{ vuln.impact }}")

    doc.add_heading("Recomendação", level=4)
    doc.add_paragraph("{{ vuln.remediation }}")

    doc.add_heading("Referências", level=4)
    doc.add_paragraph(
        "{% for ref in vuln.reference_urls %}"
        "- {{ ref }}"
        "{% endfor %}"
    )

    doc.add_paragraph("{% endfor %}")  # end vuln loop

    doc.add_paragraph(
        "{% else %}"
        "<i>Nenhuma vulnerabilidade encontrada para este host.</i>"
        "{% endif %}"
    )

    doc.add_paragraph("{% endfor %}")  # end hosts loop

    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════
    #  5. APPENDIX A — Full Port Scan
    # ══════════════════════════════════════════════════════════════
    doc.add_heading("Apêndice A — Varredura Completa de Portas", level=1)
    doc.add_paragraph(
        "{% for host in hosts %}"
        "**{{ host.name }} ({{ host.ip }})**"
    )

    full_port_tbl = doc.add_table(rows=2, cols=5)
    full_port_tbl.style = "Light Grid Accent 1"
    for i, h in enumerate(["Porta", "Proto", "Estado", "Serviço", "Versão"]):
        cell = full_port_tbl.rows[0].cells[i]
        cell.text = h
        for p in cell.paragraphs:
            for run in p.runs:
                run.bold = True
                run.font.size = Pt(8)
    full_port_tbl.rows[1].cells[0].text = "{{ port.port }}{% for port in host.all_ports %}"
    full_port_tbl.rows[1].cells[1].text = "{{ port.protocol }}"
    full_port_tbl.rows[1].cells[2].text = "{{ port.state }}"
    full_port_tbl.rows[1].cells[3].text = "{{ port.service }}"
    full_port_tbl.rows[1].cells[4].text = "{{ port.version }}{% endfor %}"
    doc.add_paragraph("")
    doc.add_paragraph(
        "{% endfor %}"
    )

    doc.add_page_break()

    # ══════════════════════════════════════════════════════════════
    #  6. APPENDIX B — Screenshots
    # ══════════════════════════════════════════════════════════════
    # ── 6. APPENDIX B — Screenshots ──
    doc.add_heading("Apêndice B — Capturas de Tela", level=1)

    doc.add_paragraph("{% for host in hosts %}")
    doc.add_paragraph("{% if host.screenshots %}")

    p = doc.add_paragraph()
    run = p.add_run("**{{ host.name }}**")
    run.bold = True

    doc.add_paragraph(
        "{% for shot in host.screenshots %}"
    )
    doc.add_paragraph(
        "- {{ shot.title if shot.title else shot.source_url }}"
    )
    doc.add_paragraph(
        "{% endfor %}"
    )
    doc.add_paragraph("{% endif %}")
    doc.add_paragraph("{% endfor %}")

    # ── Footer disclaimer ──
    doc.add_paragraph("")
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run(
        "Este documento é confidencial e destinado exclusivamente ao cliente. "
        "A reprodução ou distribuição não autorizada é proibida."
    )
    run.font.size = Pt(9)
    run.font.color.rgb = RGBColor(0x99, 0x99, 0x99)
    run.italic = True

    # ── Save ──────────────────────────────────────────────────────
    doc.save(DEFAULT_TEMPLATE)
    console.print(
        f"\n [bold green]✔[/bold green] Template padrão criado em:\n"
        f" [dim]{DEFAULT_TEMPLATE}[/dim]\n\n"
        f" [dim]Abra no Word, adicione seu logo, ajuste fontes/cores,[/dim]\n"
        f" [dim]e salve. Em seguida rode:[/dim]\n\n"
        f" [bold cyan]openpipes-core report --template {DEFAULT_TEMPLATE}[/bold cyan]\n"
    )


# ── Main entry point ─────────────────────────────────────────────
def generate_report(proj_path: str, template: str = None,
                    output: str = None, client_name: str = "",
                    all_hosts: bool = False):
    """Generate the DOCX pentest report."""
    try:
        from docxtpl import DocxTemplate
    except ImportError:
        console.print("[bold red]✖ docxtpl não instalado. Rode: pip install docxtpl[/bold red]")
        return

    template = template or DEFAULT_TEMPLATE
    if not os.path.exists(template):
        console.print(f"[yellow]⚠ Template não encontrado: {template}[/yellow]")
        console.print(" [dim]Gerando template padrão...[/dim]")
        create_default_template(template)

    output = output or os.path.join(
        proj_path, f"Relatorio_{os.path.basename(proj_path)}_"
        f"{datetime.now().strftime('%Y%m%d')}.docx"
    )

    console.print(f"\n[bold cyan]▶ Gerando relatório DOCX...[/bold cyan]")
    console.print(f" [dim]Template: {template}[/dim]")
    console.print(f" [dim]Output:   {output}[/dim]")

    # Load template
    tpl = DocxTemplate(template)

    # Generate severity chart
    ctx = _build_report_context(proj_path, client_name, all_hosts, tpl_doc=tpl)

    chart_path = os.path.join(tempfile.gettempdir(), "openpipes_severity_chart.png")
    chart_file = _generate_severity_chart(ctx["stats"], chart_path)

    if chart_file:
        from docxtpl import InlineImage
        from docx.shared import Inches
        ctx["severity_chart"] = InlineImage(tpl, chart_file, width=Inches(4.5))
    else:
        ctx["severity_chart"] = ""

    # Render
    try:
        tpl.render(ctx)
        tpl.save(output)
        file_size = os.path.getsize(output) / 1024
        console.print(f"\n[bold green]✔ Relatório gerado![/bold green]")
        console.print(f" [dim]{output} ({file_size:.0f} KB)[/dim]")
        console.print(f" [dim]{ctx['stats']['total_vulns']} vulnerabilidades em "
                      f"{ctx['stats']['vulnerable_hosts']} hosts.[/dim]")
    except Exception as e:
        console.print(f"[bold red]✖ Erro ao renderizar: {e}[/bold red]")
        raise
