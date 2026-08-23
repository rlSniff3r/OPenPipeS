"""
reporter.py — DOCX Pentest Report Generator for OPenPipeS.

Uses docxtpl (python-docx + Jinja2) to render professional, customizable
pentest reports directly from the SQLite database using a Native Word Template.

Usage:
    openpipes-core report                                  # default template
    openpipes-core report --template ~/brand.docx          # custom template
"""
import os
import json
import re
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Optional
import shutil

from rich.console import Console

import db

console = Console()

HOME = str(Path.home())
DEFAULT_TEMPLATE_DIR = os.path.join(HOME, ".openpipes", ".templates")
DEFAULT_TEMPLATE = os.path.join(DEFAULT_TEMPLATE_DIR, "pentest_report.docx")

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
        key = sev.lower().replace("á", "a").replace("í", "i")
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
    ax.set_title("Vulnerabilidades por Severidade", fontsize=13, fontweight="bold", pad=15)
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

    cur.execute("SELECT * FROM hosts WHERE id = ?", (host_id,))
    row = cur.fetchone()
    if not row:
        return None
    host = dict(row)
    host["ips"] = json.loads(host["ips"]) if host.get("ips") else []

    cur.execute(
        "SELECT port, protocol, state, service, version "
        "FROM ports WHERE host_id = ? AND state = 'open' ORDER BY port",
        (host_id,),
    )
    open_ports = [dict(r) for r in cur.fetchall()]

    cur.execute(
        "SELECT port, protocol, state, service, version "
        "FROM ports WHERE host_id = ? ORDER BY port",
        (host_id,),
    )
    all_ports = [dict(r) for r in cur.fetchall()]

    cur.execute(
        "SELECT url, status_code, title, web_server, tech_stack, source_tool "
        "FROM endpoints WHERE host_id = ? ORDER BY url",
        (host_id,),
    )
    endpoints = [dict(r) for r in cur.fetchall()]

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

        # Como deve ficar:
        evidence_images = []
        cur.execute("SELECT stored_name FROM user_evidences WHERE vuln_id = ?", (v["id"],))
        for er in cur.fetchall():
            img_path = os.path.join(evidence_dir, er["stored_name"])
            if os.path.exists(img_path):
                # Mandamos um dicionário para facilitar o loop no Word!
                evidence_images.append({"img_path": img_path})
        v["evidence_images"] = evidence_images
        vulns.append(v)

    cur.execute(
        "SELECT file_path, source_url, title FROM screenshots WHERE host_id = ?",
        (host_id,),
    )

    screenshots = []
    full_path = os.path.join(ss_dir, s["file_path"])
    if os.path.exists(full_path):
        s["image"] = full_path
    else:
        s["image"] = ""
    screenshots.append(s)

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
        "all_ports": all_ports,
        "endpoints": endpoints,
        "vulnerabilities": vulns,
        "screenshots": screenshots,
        "narrative": host.get("narrative", "") or "",
    }


def _build_report_context(proj_path: str, client_name: str = "",
                          all_hosts: bool = False, tpl_doc=None) -> dict:
    """Build the complete Jinja2 context for the report template."""
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

        cur.execute("SELECT COUNT(*) FROM endpoints WHERE host_id IN "
                    "(SELECT id FROM hosts WHERE is_alive = 1 AND in_scope = 1)")
        total_endpoints = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM ports WHERE host_id IN "
                    "(SELECT id FROM hosts WHERE is_alive = 1 AND in_scope = 1) "
                    "AND state = 'open'")
        total_ports = cur.fetchone()[0]

        stats["total_endpoints"] = total_endpoints
        stats["total_ports"] = total_ports

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
        "methodology": {
            "scope_summary": f"{len(scope_domains)} domínio(s), {len(host_rows)} host(s)",
            "phases": (
                "1. Reconhecimento (DNS, WHOIS, subdomínios)\n"
                "2. Varredura de portas e serviços (Nmap)\n"
                "3. Descoberta de endpoints web (HTTPx, Katana, Feroxbuster)\n"
                "4. Análise de JavaScript (JSFinder)\n"
                "5. Detecção de vulnerabilidades (Nuclei)\n"
                "6. Descoberta de parâmetros (Arjun)\n"
                "7. Análise de padrões (GF)\n"
                "8. Documentação e relatório"
            ),
        },
    }


# ── Main entry point ─────────────────────────────────────────────
def generate_report(proj_path: str, template: str = None,
                    output: str = None, client_name: str = "",
                    all_hosts: bool = False):
    """Generate the DOCX pentest report using the Node.js Docxtemplater engine."""
    import subprocess
    
    template = template or DEFAULT_TEMPLATE
    if not os.path.exists(template):
        console.print(f"\n[bold red]✖ Template não encontrado: {template}[/bold red]")
        return

    output = output or os.path.join(
        proj_path, f"Relatorio_{os.path.basename(proj_path)}_{datetime.now().strftime('%Y%m%d')}.docx"
    )

    console.print(f"\n[bold cyan]▶ Preparando dados (Python) e Gerando DOCX (Node.js)...[/bold cyan]")
    
    # 1. Python extrai os dados da base PRIMEIRO
    ctx = _build_report_context(proj_path, client_name, all_hosts)
    
    # 2. Gera o gráfico e insere o caminho em string no contexto
    chart_path = os.path.join(tempfile.gettempdir(), "openpipes_severity_chart.png")
    chart_file = _generate_severity_chart(ctx["stats"], chart_path)

    if chart_file:
        ctx["severity_chart"] = chart_file
    else:
        ctx["severity_chart"] = ""

    # 3. Salva o contexto num JSON temporário
    temp_json = os.path.join(tempfile.gettempdir(), "openpipes_context.json")
    with open(temp_json, "w", encoding="utf-8") as f:
        json.dump(ctx, f, ensure_ascii=False)

    # 4. Passa a bola pro Node.js
    generator_script = os.path.join(os.path.dirname(__file__), "generator.js")
    
    try:
        result = subprocess.run(
            ["node", generator_script, template, temp_json, output],
            capture_output=True, text=True, check=True
        )
        if "SUCCESS" in result.stdout:
            file_size = os.path.getsize(output) / 1024
            console.print(f"\n[bold green]✔ Relatório gerado com sucesso![/bold green]")
            console.print(f" [dim]{output} ({file_size:.0f} KB)[/dim]")
        else:
            console.print(f"[bold red]✖ Erro no Node.js:[/bold red] {result.stderr}")

    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]✖ Falha ao executar o gerador JS:[/bold red] {e.stderr}")