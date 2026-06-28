import os
import json
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional

from jinja2 import Environment, FileSystemLoader, BaseLoader
from rich.console import Console

import db

console = Console()

HOME = str(Path.home())
CONFIG_FILE = os.path.join(HOME, ".openpipes", "config.sh")
TEMPLATE_DIR = os.path.join(HOME, ".openpipes", ".templates")

# ── Safe mode: write to Sync/ subfolder instead of overwriting bash output
SYNC_MODE = "parallel"  # "parallel" → Sync/ subfolder | "replace" → direct (future)


def _get_env_from_config():
    """Read project paths from config.sh (same pattern as cli.py)."""
    if not os.path.exists(CONFIG_FILE):
        return None, None, None
    try:
        cmd = (
            f"source {CONFIG_FILE} && echo -n \"$proj_name|$proj_path|$obsdir\""
        )
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, executable="/bin/bash"
        )
        parts = result.stdout.strip().split("|")
        if len(parts) == 3 and parts[0]:
            return parts[0], parts[1], parts[2]
    except Exception:
        pass
    return None, None, None


# ═════════════════════════════════════════════════════════════════════
# DB QUERY HELPERS
# ═════════════════════════════════════════════════════════════════════

def _dict_from_row(row):
    """Convert sqlite3.Row to plain dict."""
    return dict(row) if row else {}


def get_project_summary(proj_path: str) -> dict:
    """Aggregate stats across all targets in the project."""
    summary = {
        "total_hosts": 0,
        "total_ports": 0,
        "total_endpoints": 0,
        "total_vulns": 0,
        "total_js_routes": 0,
        "total_screenshots": 0,
        "severity_breakdown": {"Crítica": 0, "Alta": 0, "Média": 0, "Baixa": 0, "Info": 0},
        "last_updated": None,
    }
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM hosts")
        summary["total_hosts"] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM ports")
        summary["total_ports"] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM endpoints")
        summary["total_endpoints"] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        summary["total_vulns"] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM js_discoveries")
        summary["total_js_routes"] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM screenshots")
        summary["total_screenshots"] = cursor.fetchone()[0]

        try:
            cursor.execute(
                "SELECT severity, COUNT(*) as cnt FROM vulnerabilities GROUP BY severity"
            )
            for row in cursor.fetchall():
                sev = row["severity"]
                if sev in summary["severity_breakdown"]:
                    summary["severity_breakdown"][sev] = row["cnt"]
        except Exception:
            pass

        cursor.execute(
            "SELECT MAX(last_updated) FROM hosts"
        )
        val = cursor.fetchone()[0]
        summary["last_updated"] = val or "Nunca"

    return summary


def get_targets_list(proj_path: str) -> list[dict]:
    """Return a list of all targets with basic info."""
    targets = []
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT id, host, ips, is_alive, last_updated
               FROM hosts ORDER BY host"""
        )
        for row in cursor.fetchall():
            targets.append({
                "id": row["id"],
                "name": row["host"],
                "ips": json.loads(row["ips"]) if row["ips"] else [],
                "is_alive": bool(row["is_alive"]),
                "last_updated": row["last_updated"],
            })
    return targets


def get_target_report(proj_path: str, host_name: str) -> Optional[dict]:
    """
    Fetch ALL data for a single target from the DB.
    Returns a nested dict ready for Jinja2.
    """
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()

        # ── Host ────────────────────────────────────────────────────────
        cursor.execute(
            "SELECT * FROM hosts WHERE host = ?", (host_name,)
        )
        host_row = cursor.fetchone()
        if not host_row:
            return None

        host = dict(host_row)
        host["ips"] = json.loads(host["ips"]) if host.get("ips") else []
        host["cnames"] = json.loads(host["cnames"]) if host.get("cnames") else []

        # ── Ports ───────────────────────────────────────────────────────
        cursor.execute(
            """SELECT port, protocol, state, service, version
               FROM ports WHERE host_id = ?
               ORDER BY port""",
            (host["id"],),
        )
        ports = [dict(r) for r in cursor.fetchall()]
        open_ports = [p for p in ports if p["state"] == "open"]

        # ── Endpoints ───────────────────────────────────────────────────
        cursor.execute(
            """SELECT url, status_code, content_length, content_type,
                      title, web_server, tech_stack, source_tool,
                      vulnerability_patterns
               FROM endpoints WHERE host_id = ?
               ORDER BY url""",
            (host["id"],),
        )
        endpoints = []
        for r in cursor.fetchall():
            ep = dict(r)
            ep["tech_stack"] = json.loads(ep["tech_stack"]) if ep.get("tech_stack") else []
            ep["vulnerability_patterns"] = (
                json.loads(ep["vulnerability_patterns"])
                if ep.get("vulnerability_patterns") else []
            )
            endpoints.append(ep)

        # ── Vulnerabilities ─────────────────────────────────────────────
        cursor.execute(
            """SELECT title, severity, cvss_score, cvss_vector, cve_id,
                      vuln_name, description, matched_at, curl_command,
                      remediation, impact, reference_urls, source_tool,
                      enriched_by, created_at
               FROM vulnerabilities WHERE host_id = ?
               ORDER BY
                 CASE severity
                   WHEN 'Crítica' THEN 0 WHEN 'Alta' THEN 1
                   WHEN 'Média'  THEN 2 WHEN 'Baixa' THEN 3
                   ELSE 4
                 END""",
            (host["id"],),
        )
        vulnerabilities = []
        for r in cursor.fetchall():
            vuln = dict(r)
            vuln["reference_urls"] = (
                json.loads(vuln["reference_urls"])
                if vuln.get("reference_urls") else []
            )
            vuln["severity_emoji"] = {
                "Crítica": "🔴", "Alta": "🟠",
                "Média": "🟡", "Baixa": "🟢", "Info": "🔵",
            }.get(vuln["severity"], "⚪")
            vuln["cvss_score"] = float(vuln["cvss_score"]) if vuln.get("cvss_score") else None
            vuln["filename"] = (
                f"{vuln['created_at'][:8] if vuln.get('created_at') else '00000000'}"
                f"_{vuln['title'][:40].replace(' ', '_')}.md"
            )
            vulnerabilities.append(vuln)

        # ── Screenshots ─────────────────────────────────────────────────
        cursor.execute(
            "SELECT file_path, created_at FROM screenshots WHERE host_id = ?",
            (host["id"],),
        )
        screenshots = [dict(r) for r in cursor.fetchall()]

        # ── JS Discoveries ──────────────────────────────────────────────
        cursor.execute(
            "SELECT source_js_url, discovered_route FROM js_discoveries WHERE host_id = ?",
            (host["id"],),
        )
        js_discoveries = [dict(r) for r in cursor.fetchall()]

        # ── Compute derived fields ──────────────────────────────────────
        tech_stack = list(set(
            tech for ep in endpoints
            for tech in ep.get("tech_stack", [])
        ))
        tech_stack.sort()

        all_tasks = [
            *[{"type": "port", "label": f"Enumerar porta {p['port']}/{p['protocol']} ({p['service']})",
               "done": False} for p in open_ports
              if p["service"] not in ("ssl", "tcpwrapped", "unknown")],
        ]
        if endpoints:
            all_tasks.append({"type": "web", "label": "Analisar endpoints web", "done": False})
        if vulnerabilities:
            all_tasks.append({"type": "review", "label": "Revisar vulnerabilidades encontradas",
                              "done": False})
        if js_discoveries:
            all_tasks.append({"type": "js", "label": "Analisar rotas descobertas em JS",
                              "done": False})

        report = {
            "name": host["host"],
            "ip": host["ips"][0] if host["ips"] else "",
            "all_ips": host["ips"],
            "cnames": host["cnames"],
            "whois": host.get("whois_data", ""),
            "is_alive": bool(host["is_alive"]),
            "last_updated": host["last_updated"],
            "open_ports_count": len(open_ports),
            "ports": open_ports,
            "all_ports": ports,
            "endpoints": endpoints,
            "endpoint_count": len(endpoints),
            "httpx_count": len([e for e in endpoints if e["source_tool"] in ("httpx", "recon_httpx")]),
            "nuclei_count": len(vulnerabilities),
            "js_endpoint_count": len(js_discoveries),
            "screenshot_count": len(screenshots),
            "tech_stack": tech_stack,
            "tech_summary": f"O host possui {', '.join(tech_stack) if tech_stack else 'tecnologias a serem identificadas'}.",
            "vulnerabilities": vulnerabilities,
            "vuln_count": len(vulnerabilities),
            "vulns_critical": len([v for v in vulnerabilities if v["severity"] == "Crítica"]),
            "vulns_high": len([v for v in vulnerabilities if v["severity"] == "Alta"]),
            "vulns_medium": len([v for v in vulnerabilities if v["severity"] == "Média"]),
            "vulns_low": len([v for v in vulnerabilities if v["severity"] == "Baixa"]),
            "screenshots": screenshots,
            "js_discoveries": js_discoveries,
            "pending_tasks": [t["label"] for t in all_tasks if not t["done"]],
            "completed_tasks": [t["label"] for t in all_tasks if t["done"]],
            "pipeline_status": "completed" if vulnerabilities else "in_progress",
        }
        return report


def get_vulnerability_detail(proj_path: str, vuln_id: int) -> Optional[dict]:
    """Fetch a single vulnerability with host info for rendering."""
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT v.*, h.host as target_host, h.ips
               FROM vulnerabilities v
               JOIN hosts h ON h.id = v.host_id
               WHERE v.id = ?""",
            (vuln_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None

        vuln = dict(row)
        vuln["reference_urls"] = (
            json.loads(vuln["reference_urls"])
            if vuln.get("reference_urls") else []
        )
        vuln["target_ips"] = json.loads(vuln["ips"]) if vuln.get("ips") else []
        vuln["cvss_score"] = float(vuln["cvss_score"]) if vuln.get("cvss_score") else None
        vuln["severity_emoji"] = {
            "Crítica": "🔴", "Alta": "🟠",
            "Média": "🟡", "Baixa": "🟢", "Info": "🔵",
        }.get(vuln["severity"], "⚪")
        return vuln


# ═════════════════════════════════════════════════════════════════════
# JINJA2 RENDERER
# ═════════════════════════════════════════════════════════════════════

def _get_jinja_env():
    """Create a Jinja2 environment pointing at the templates directory."""
    if not os.path.exists(TEMPLATE_DIR):
        os.makedirs(TEMPLATE_DIR, exist_ok=True)
    return Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=False,
        keep_trailing_newline=True,
    )


def _get_vault_path(obsdir: str, proj_name: str, target_name: str = None) -> str:
    """Build the target directory path inside the Obsidian vault."""
    base = os.path.join(obsdir, proj_name, "Pentest", "Alvos")
    if target_name:
        vault_dir = os.path.join(base, target_name)
        if SYNC_MODE == "parallel":
            vault_dir = os.path.join(vault_dir, "Sync")
        return vault_dir
    return base


def render_target(proj_path: str, obsdir: str, proj_name: str, host_name: str) -> bool:
    """
    Fetch data for a single target and render its markdown note + individual vuln notes.
    Returns True if rendered successfully.
    """
    report = get_target_report(proj_path, host_name)
    if not report:
        console.print(f" [yellow]⚠ Alvo '{host_name}' não encontrado no banco.[/yellow]")
        return False

    env = _get_jinja_env()
    vault_dir = _get_vault_path(obsdir, proj_name, host_name)
    os.makedirs(vault_dir, exist_ok=True)

    # ── Render target note ──────────────────────────────────────────────
    target_template = env.get_template("target.j2")
    target_md = target_template.render(target=report)
    target_path = os.path.join(vault_dir, f"{host_name}.md")
    with open(target_path, "w", encoding="utf-8") as f:
        f.write(target_md)

    # ── Render individual vulnerability notes ──────────────────────────
    vuln_template = env.get_template("vuln.j2")
    vulns_dir = os.path.join(vault_dir, "Vulnerabilidades")
    os.makedirs(vulns_dir, exist_ok=True)

    vuln_count = 0
    for vuln in report.get("vulnerabilities", []):
        vuln_md = vuln_template.render(target=report, vuln=vuln)
        vuln_path = os.path.join(vulns_dir, vuln["filename"])
        with open(vuln_path, "w", encoding="utf-8") as f:
            f.write(vuln_md)
        vuln_count += 1

    console.print(
        f" [dim]↳ Render: {host_name} → {target_path}"
        f" ({vuln_count} vulns)[/dim]"
    )
    return True


def render_dashboard(proj_path: str, obsdir: str, proj_name: str):
    """Render the global project dashboard."""
    summary = get_project_summary(proj_path)
    targets = get_targets_list(proj_path)

    # Attach vuln counts to each target
    for t in targets:
        report = get_target_report(proj_path, t["name"])
        t["vuln_count"] = report["vuln_count"] if report else 0
        t["open_ports_count"] = report["open_ports_count"] if report else 0
        t["endpoint_count"] = report["endpoint_count"] if report else 0

    env = _get_jinja_env()
    dashboard_template = env.get_template("dashboard.j2")
    dashboard_md = dashboard_template.render(
        project_name=proj_name,
        summary=summary,
        targets=targets,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )

    dashboard_dir = _get_vault_path(obsdir, proj_name)
    if SYNC_MODE == "parallel":
        dashboard_dir = os.path.join(dashboard_dir, "Sync")
    os.makedirs(dashboard_dir, exist_ok=True)

    dashboard_path = os.path.join(dashboard_dir, "Dashboard_Global.md")
    with open(dashboard_path, "w", encoding="utf-8") as f:
        f.write(dashboard_md)

    console.print(f" [dim]↳ Render: Dashboard Global → {dashboard_path}[/dim]")


def render_index(proj_path: str, obsdir: str, proj_name: str):
    """Render a project index page with links to all targets."""
    targets = get_targets_list(proj_path)
    for t in targets:
        report = get_target_report(proj_path, t["name"])
        t["vuln_count"] = report["vuln_count"] if report else 0
        t["open_ports_count"] = report["open_ports_count"] if report else 0
        t["endpoint_count"] = report["endpoint_count"] if report else 0

    env = _get_jinja_env()
    index_template = env.get_template("index.j2")
    index_md = index_template.render(
        project_name=proj_name,
        targets=targets,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )

    index_dir = _get_vault_path(obsdir, proj_name)
    if SYNC_MODE == "parallel":
        index_dir = os.path.join(index_dir, "Sync")
    os.makedirs(index_dir, exist_ok=True)

    index_path = os.path.join(index_dir, "Index.md")
    with open(index_path, "w", encoding="utf-8") as f:
        f.write(index_md)

    console.print(f" [dim]↳ Render: Project Index → {index_path}[/dim]")


def render_all(proj_path: str, obsdir: str, proj_name: str, target_name: str = None):
    """
    Render all targets (or a single target) for the active project.
    Called by `openpipes sync`.
    """
    console.print(f"\n[bold cyan]▶ Sync: Renderizando vault do Obsidian[/bold cyan]")
    console.print(f" [dim]Projeto: {proj_name}[/dim]")
    console.print(f" [dim]Modo: {'Parallel (Sync/)' if SYNC_MODE == 'parallel' else 'Direct'}[/dim]")

    if target_name:
        # Single target
        render_target(proj_path, obsdir, proj_name, target_name)
    else:
        # All targets
        targets = get_targets_list(proj_path)
        if not targets:
            console.print(" [yellow]⚠ Nenhum alvo encontrado no banco de dados.[/yellow]")
            return

        for t in targets:
            render_target(proj_path, obsdir, proj_name, t["name"])

        render_dashboard(proj_path, obsdir, proj_name)
        render_index(proj_path, obsdir, proj_name)

    console.print(f"\n[bold green]✔ Sync concluído![/bold green]")


# ═════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT (called from cli.py)
# ═════════════════════════════════════════════════════════════════════

def sync_project(target_name: str = None):
    """
    Entry point called by `openpipes sync` or the interactive menu.
    Reads the active project from config.sh and renders everything.
    """
    proj_name, proj_path, obsdir = _get_env_from_config()
    if not proj_name or not proj_path or not obsdir:
        console.print("[bold red]✖ Erro: Projeto não configurado. Rode init-openpipes primeiro.[/bold red]")
        return

    # Ensure DB is up-to-date
    db.init_db(proj_path)

    render_all(proj_path, obsdir, proj_name, target_name)
