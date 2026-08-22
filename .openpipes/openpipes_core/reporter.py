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
def create_default_template(output_path: str = None):
    """
    Generate a professional starter .docx template with Jinja2 placeholders.
    The analyst opens this in Word to customize branding, styles, and sections.
    """
    output_path = output_path or DEFAULT_TEMPLATE
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    from docx import Document
    from docx.shared import Inches, Pt, RGBColor, Cm
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.oxml.ns import qn

    doc = Document()

    # ── Style defaults ────────────────────────────────────────
    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(11)
    style.paragraph_format.space_after = Pt(6)

    for level in range(1, 4):
        hs = doc.styles[f"Heading {level}"]
        hs.font.color.rgb = RGBColor(0, 51, 102)

    # ── Cover Page ────────────────────────────────────────────
    for _ in range(6):
        doc.add_paragraph()

    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run("{{ project_name }}")
    run.bold = True
    run.font.size = Pt(32)
    run.font.color.rgb = RGBColor(0, 51, 102)

    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run("Relatório de Teste de Segurança")
    run.font.size = Pt(18)
    run.font.color.rgb = RGBColor(100, 100, 100)

    doc.add_paragraph()

    for label, var in [("Cliente", "{{ client_name }}"),
                       ("Data", "{{ report_date }}"),
                       ("Classificação", "{{ classification }}")]:
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run(f"{label}: ")
        run.font.size = Pt(12)
        run.font.color.rgb = RGBColor(100, 100, 100)
        run = p.add_run(var)
        run.bold = True
        run.font.size = Pt(12)

    doc.add_page_break()

    # ── Executive Summary ─────────────────────────────────────
    doc.add_heading("1. Resumo Executivo", level=1)
    doc.add_paragraph(
        "Este relatório apresenta os resultados do teste de segurança realizado "
        "contra a infraestrutura de {{ client_name }}. "
        "Foram identificadas {{ stats.total_vulns }} vulnerabilidades em "
        "{{ stats.vulnerable_hosts }} hosts de {{ stats.total_hosts }} analisados."
    )

    # Summary table
    table = doc.add_table(rows=3, cols=3)
    table.style = "Light Shading Accent 1"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    cells = [
        ("Métrica", "Valor", ""),
        ("Hosts analisados", "{{ stats.total_hosts }}", ""),
        ("Hosts com vulnerabilidades", "{{ stats.vulnerable_hosts }}", ""),
    ]
    for i, (a, b, _) in enumerate(cells):
        table.rows[i].cells[0].text = a
        table.rows[i].cells[1].text = b

    # Severity table
    doc.add_paragraph()
    p = doc.add_paragraph()
    run = p.add_run("Distribuição por Severidade:")
    run.bold = True
    table2 = doc.add_table(rows=6, cols=2)
    table2.style = "Light Shading Accent 1"
    table2.alignment = WD_TABLE_ALIGNMENT.CENTER
    severities = [("🔴 Crítica", "{{ stats.critical }}"),
                  ("🟠 Alta", "{{ stats.high }}"),
                  ("🟡 Média", "{{ stats.medium }}"),
                  ("🟢 Baixa", "{{ stats.low }}"),
                  ("🔵 Info", "{{ stats.info }}")]
    table2.rows[0].cells[0].text = "Severidade"
    table2.rows[0].cells[1].text = "Quantidade"
    for i, (sev, val) in enumerate(severities):
        table2.rows[i + 1].cells[0].text = sev
        table2.rows[i + 1].cells[1].text = val

    # Severity chart placeholder
    doc.add_paragraph()
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run("{{ severity_chart }}")
    run.font.size = Pt(10)

    doc.add_page_break()

    # ── Scope ─────────────────────────────────────────────────
    doc.add_heading("2. Escopo", level=1)
    doc.add_paragraph(
        "O teste de segurança foi realizado nos seguintes domínios e recursos:"
    )
    doc.add_paragraph("Domínios em escopo:")
    doc.add_paragraph(
        "{% for d in scope.domains %}\n• {{ d }}\n{% endfor %}"
    )
    doc.add_paragraph(
        "Total de endpoints identificados: {{ scope.total_endpoints }}\n"
        "Total de portas abertas: {{ scope.total_ports }}"
    )

    doc.add_page_break()

    # ── Methodology ───────────────────────────────────────────
    doc.add_heading("3. Metodologia", level=1)
    doc.add_paragraph("{{ methodology }}")

    doc.add_page_break()

    # ── Detailed Findings ─────────────────────────────────────
    doc.add_heading("4. Achados Detalhados", level=1)

    doc.add_paragraph(
        "{% for host in hosts %}"
    )
    doc.add_heading("{{ host.name }} ({{ host.ip }})", level=2)
    doc.add_paragraph("Stack tecnológica: {{ host.tech_summary }}")

    # Open ports table
    doc.add_paragraph()
    p = doc.add_paragraph()
    run = p.add_run("Portas abertas:")
    run.bold = True
    doc.add_paragraph(
        "{% for port in host.open_ports %}"
        "• {{ port.port }}/{{ port.protocol }} — {{ port.service }} {{ port.version }}\n"
        "{% endfor %}"
    )

    # Per-vulnerability
    doc.add_paragraph(
        "{% for vuln in host.vulnerabilities %}"
    )
    doc.add_heading("{{ vuln.severity_emoji }} {{ vuln.title }}", level=3)

    # Vuln metadata table
    t = doc.add_table(rows=4, cols=2)
    t.style = "Light Grid Accent 1"
    meta = [("Severidade", "{{ vuln.severity }}"),
            ("CVSS", "{{ vuln.cvss_score }}"),
            ("CVE", "{{ vuln.cve_id }}"),
            ("CWE", "{{ vuln.cwe_id }}")]
    for i, (k, v) in enumerate(meta):
        t.rows[i].cells[0].text = k
        t.rows[i].cells[1].text = v

    doc.add_paragraph()
    p = doc.add_paragraph()
    run = p.add_run("Descrição:")
    run.bold = True
    doc.add_paragraph("{{ vuln.description }}")

    p = doc.add_paragraph()
    run = p.add_run("Impacto:")
    run.bold = True
    doc.add_paragraph("{{ vuln.impact }}")

    p = doc.add_paragraph()
    run = p.add_run("Recomendação:")
    run.bold = True
    doc.add_paragraph("{{ vuln.remediation }}")

    if using curl_command:
        p = doc.add_paragraph()
        run = p.add_run("Comando de reprodução:")
        run.bold = True
        doc.add_paragraph("{{ vuln.curl_command }}")

    # Evidence images
    doc.add_paragraph(
        "{% for img in vuln.evidence_images %}"
    )
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run("{{ img }}")
    doc.add_paragraph(
        "{% endfor %}"
    )

    # References
    doc.add_paragraph(
        "{% if vuln.reference_urls %}"
    )
    p = doc.add_paragraph()
    run = p.add_run("Referências:")
    run.bold = True
    doc.add_paragraph(
        "{% for ref in vuln.reference_urls %}\n• {{ ref }}\n{% endfor %}"
    )
    doc.add_paragraph("{% endif %}")

    doc.add_paragraph(
        "{% endfor %}"  # end vulns loop
    )
    doc.add_paragraph(
        "{% endfor %}"  # end hosts loop
    )

    doc.add_page_break()

    # ── Appendix: Screenshots ─────────────────────────────────
    doc.add_heading("Apêndice A: Capturas de Tela", level=1)
    doc.add_paragraph(
        "{% for host in hosts %}"
    )
    doc.add_heading("{{ host.name }}", level=2)
    doc.add_paragraph(
        "{% for ss in host.screenshots %}"
    )
    doc.add_paragraph("{{ ss.title or ss.source_url or 'Screenshot' }}")
    doc.add_paragraph(
        "{% if ss.image %}{{ ss.image }}{% endif %}"
    )
    doc.add_paragraph(
        "{% endfor %}"
    )
    doc.add_paragraph(
        "{% endfor %}"
    )

    # ── Save ──────────────────────────────────────────────────
    doc.save(output_path)
    console.print(f" [bold green]✔ Template padrão criado:[/bold green] {output_path}")
    console.print(" [dim]Abra no Microsoft Word para personalizar layouts, logos e estilos.[/dim]")
    return output_path


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
        tpl.render(ctx, output)
        file_size = os.path.getsize(output) / 1024
        console.print(f"\n[bold green]✔ Relatório gerado![/bold green]")
        console.print(f" [dim]{output} ({file_size:.0f} KB)[/dim]")
        console.print(f" [dim]{ctx['stats']['total_vulns']} vulnerabilidades em "
                      f"{ctx['stats']['vulnerable_hosts']} hosts.[/dim]")
    except Exception as e:
        console.print(f"[bold red]✖ Erro ao renderizar: {e}[/bold red]")
        raise
