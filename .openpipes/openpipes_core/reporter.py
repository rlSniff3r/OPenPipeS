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
        ORDER BY cvss_score DESC NULLS LAST
    """, (host_id,))
    vulns = []
    evidence_dir = os.path.join(proj_path, "Varreduras", f"nmap-{host_name}", "Evidencias")

    for r in cur.fetchall():
        v = dict(r)
        v["reference_urls"] = json.loads(v["reference_urls"]) if v.get("reference_urls") else []
        v["cvss_score"] = float(v["cvss_score"]) if v.get("cvss_score") else None
        v["severity_emoji"] = {"Crítica": "🔴", "Alta": "🟠", "Média": "🟡",
                               "Baixa": "🟢", "Info": "🔵"}.get(v["severity"], "⚪")

        # 👇 GERA A STRING MÁGICA DA COR SEM O '#' 👇
        hex_color = SEVERITY_COLORS.get(v["severity"], "FFFFFF").replace("#", "")
        v["severity_colored"] = f"BGCOLOR_{hex_color}_{v['severity']}"

        cwe_match = re.match(r"CWE-(\d+)", v.get("cwe_id") or "")
        v["cwe_url"] = (
            f"https://cwe.mitre.org/data/definitions/{cwe_match.group(1)}.html"
            if cwe_match else ""
        )

        evidence_images = []
        cur.execute("SELECT stored_name FROM user_evidences WHERE vuln_id = ?", (v["id"],))
        for er in cur.fetchall():
            img_path = os.path.join(evidence_dir, er["stored_name"])
            if os.path.exists(img_path):
                evidence_images.append({"img_path": img_path})
        v["evidence_images"] = evidence_images
        vulns.append(v)

    # ── Screenshots (Adaptado para o Node.js) ──
    cur.execute(
        "SELECT file_path, source_url, title FROM screenshots WHERE host_id = ?",
        (host_id,),
    )
    screenshots = []
    
    # Olha a nossa variável ss_dir de volta aqui!
    ss_dir = os.path.join(proj_path, "Varreduras", f"nmap-{host_name}", "Screenshots")
    
    for r in cur.fetchall():
        s = dict(r)
        full_path = os.path.join(ss_dir, s["file_path"])
        
        # Se a imagem existir no disco, mandamos a string absoluta pro Node.js
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
    import os
    import re
    from datetime import datetime
    
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
    vuln_matrix = []
    cwe_metrics = {}

    with db.get_connection(proj_path) as conn:
        cur = conn.cursor()

        # Puxa os detalhes administrativos do Projeto
        cur.execute("SELECT * FROM projects LIMIT 1")
        proj_row = cur.fetchone()
        proj_data = dict(proj_row) if proj_row else {}

        # Lida com a conversão da Logo de Base64 para Arquivo Físico Temporário
        logo_path = ""
        logo_b64 = proj_data.get("client_logo_b64", "")
        if logo_b64 and "," in logo_b64:
            import base64
            import tempfile
            try:
                # Separa o header (data:image/png;base64,) do conteúdo real
                header, encoded = logo_b64.split(",", 1)
                img_data = base64.b64decode(encoded)
                logo_path = os.path.join(tempfile.gettempdir(), "openpipes_client_logo.png")
                with open(logo_path, "wb") as f:
                    f.write(img_data)
            except Exception as e:
                console.print(f" [yellow]⚠ Erro ao decodificar a logo: {e}[/yellow]")

        # Formatando a data do relatório (fallback para o dia de hoje)
        report_date = proj_data.get("date_report")
        if not report_date:
            report_date = datetime.now().strftime("%d/%m/%Y")
        else:
            if "-" in report_date:
                try:
                    dt_obj = datetime.strptime(report_date, "%Y-%m-%d")
                    report_date = dt_obj.strftime("%d/%m/%Y")
                except:
                    pass

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
    
        # 1. Matriz de Vulnerabilidades (Agrupada por falha e não por host)
        cur.execute("""
            SELECT v.title, v.severity, v.cvss_score, v.cve_id, 
                   GROUP_CONCAT(h.host, ', ') as affected_hosts,
                   COUNT(h.id) as host_count
            FROM vulnerabilities v
            JOIN hosts h ON v.host_id = h.id
            GROUP BY v.title, v.severity
            ORDER BY v.cvss_score DESC NULLS LAST
        """)
        
        vuln_matrix = []
        for row in cur.fetchall():
            d = dict(row)
            # 👇 GERA A STRING MÁGICA NA MATRIZ 👇
            hex_color = SEVERITY_COLORS.get(d["severity"], "FFFFFF").replace("#", "")
            d["severity_colored"] = f"BGCOLOR_{hex_color}_{d['severity']}"
            vuln_matrix.append(d)

        # 2. Agrupamento para o Gráfico de CWE
        cur.execute("""
            SELECT cwe_id, COUNT(*) as qtd 
            FROM vulnerabilities 
            WHERE cwe_id IS NOT NULL AND cwe_id != '' 
            GROUP BY cwe_id
        """)
        cwe_metrics = {row["cwe_id"]: row["qtd"] for row in cur.fetchall()}

    # O retorno master consolidando tudo
    return {
        "project_name": os.path.basename(proj_path),
        "client_name": client_name or proj_data.get("client_first_name", os.path.basename(proj_path)),
        "client_first_name": proj_data.get("client_first_name", ""),
        "client_last_name": proj_data.get("client_last_name", ""),
        "client_email": proj_data.get("client_email", ""),
        "client_phone": proj_data.get("client_phone", ""),
        "date_start": proj_data.get("date_start", ""),
        "date_end": proj_data.get("date_end", ""),
        "report_date": report_date,
        "client_logo": logo_path,
        "stats": stats,
        "scope": {
            "domains": scope_domains,
            "total_endpoints": total_endpoints,
            "total_ports": total_ports,
        },
        "hosts": hosts_ctx,
        
        # 👇 NOVO: Injetando as listas separadas no Word 👇
        "vulnerability_matrix": vuln_matrix, # Lista com todas
        "vuln_matrix_critica": vuln_matrix_critica,
        "vuln_matrix_alta": vuln_matrix_alta,
        "vuln_matrix_media": vuln_matrix_media,
        "vuln_matrix_baixa": vuln_matrix_baixa,
        "vuln_matrix_info": vuln_matrix_info,
        
        "cwe_metrics": cwe_metrics,
    }

def _generate_severity_chart(stats, output_path):
    import matplotlib.pyplot as plt
    labels = ['Crítica', 'Alta', 'Média', 'Baixa', 'Info']
    sizes = [
        stats.get('critical', 0), stats.get('high', 0), 
        stats.get('medium', 0), stats.get('low', 0), stats.get('info', 0)
    ]
    
    # Nova paleta de cores exata solicitada (com azul para Info)
    colors = ['#FF0000', '#FF6600', '#FFEB3B', '#4CAF50', '#2196F3'] 
    
    # Filtra categorias zeradas
    dados = [(l, s, c) for l, s, c in zip(labels, sizes, colors) if s > 0]
    if not dados:
        return ""
    
    l, s, c = zip(*dados)
    
    # Aumentamos um pouco a largura da figura para caber a legenda lateral
    fig, ax = plt.subplots(figsize=(8, 4))
    
    # Note que removemos o parâmetro 'labels=l' para limpar a pizza!
    wedges, texts, autotexts = ax.pie(
        s, colors=c, autopct='%1.1f%%', startangle=140, 
        textprops={'color': "white", 'weight': 'bold', 'fontsize': 8},
        wedgeprops={'edgecolor': 'black', 'linewidth': 1}
    )
    
    plt.title("Severidade das Vulnerabilidades", weight='bold', pad=20, fontsize=14)
    
    # Adicionamos a legenda elegantemente alinhada à direita
    ax.legend(wedges, l, title="Severidades", loc="center left", bbox_to_anchor=(1, 0, 0.5, 1))
    
    plt.savefig(output_path, bbox_inches='tight', dpi=300, transparent=True)
    plt.close()
    return output_path


def _generate_cwe_chart(cwe_counts, output_path):
    import matplotlib.pyplot as plt
    if not cwe_counts: 
        return ""
    
    labels, sizes = zip(*cwe_counts.items())
    
    # Aumentamos a largura para a legenda não cortar
    fig, ax = plt.subplots(figsize=(8, 4))
    
    # Sem 'labels=labels', deixando só as porcentagens na rosca
    wedges, texts, autotexts = ax.pie(
        sizes, autopct='%1.1f%%', startangle=140, pctdistance=0.80,
        wedgeprops=dict(width=0.4, edgecolor='black', linewidth=1),
        textprops={'color': "white", 'weight': 'bold', 'fontsize': 8}
    )
           
    plt.title("Distribuição por Categoria (CWE)", weight='bold', pad=20, fontsize=12)
    
    # Legenda lateral para as CWEs
    ax.legend(wedges, labels, title="Categorias CWE", loc="center left", bbox_to_anchor=(1, 0, 0.5, 1))
    
    plt.savefig(output_path, bbox_inches='tight', dpi=300, transparent=True)
    plt.close()
    return output_path


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

    # 2. Gera os gráficos e injeta os caminhos no contexto
    chart_path = os.path.join(tempfile.gettempdir(), "openpipes_severity_chart.png")
    ctx["severity_chart"] = _generate_severity_chart(ctx["stats"], chart_path)

    cwe_path = os.path.join(tempfile.gettempdir(), "openpipes_cwe_chart.png")
    ctx["cwe_chart"] = _generate_cwe_chart(ctx.get("cwe_metrics", {}), cwe_path)    

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
            console.print(f"\n[bold green]✔ Relatório Enterprise gerado com sucesso![/bold green]")
            console.print(f" [dim]{output} ({file_size:.0f} KB)[/dim]")
        else:
            console.print(f"[bold red]✖ Erro no Node.js:[/bold red] {result.stderr}")

    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]✖ Falha ao executar o gerador JS:[/bold red] {e.stderr}")