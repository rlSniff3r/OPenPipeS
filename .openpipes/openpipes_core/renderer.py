import os
import json
import re
import subprocess
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

from jinja2 import Environment, FileSystemLoader
from rich.console import Console

import db

console = Console()

HOME = str(Path.home())
CONFIG_FILE = os.path.join(HOME, ".openpipes", "config.sh")
TEMPLATE_DIR = os.path.join(HOME, ".openpipes", ".templates")

SYNC_MODE = "replace"


def _get_env_from_config():
    if not os.path.exists(CONFIG_FILE):
        return None, None, None
    try:
        cmd = f"source {CONFIG_FILE} && echo -n \"$proj_name|$proj_path|$obsdir\""
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, executable="/bin/bash")
        parts = result.stdout.strip().split("|")
        if len(parts) == 3 and parts[0]:
            return parts[0], parts[1], parts[2]
    except Exception:
        pass
    return None, None, None


def _get_nmap_dir(proj_path: str) -> str:
    if not os.path.exists(CONFIG_FILE):
        return os.path.join(proj_path, "Varreduras")
    try:
        cmd = f"source {CONFIG_FILE} && echo -n \"$NMAP_DIR\""
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, executable="/bin/bash")
        nmap_dir = result.stdout.strip()
        return nmap_dir if nmap_dir else os.path.join(proj_path, "Varreduras")
    except Exception:
        return os.path.join(proj_path, "Varreduras")


def _get_scope_domains(proj_path: str) -> list[str]:
    domains_file = os.path.join(proj_path, "domains.txt")
    if not os.path.exists(domains_file):
        return []
    scope = []
    with open(domains_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            domain = line.strip().lower()
            if not domain or domain.startswith("#") or re.match(r"^\d+\.", domain):
                continue
            scope.append(domain)
    return scope


def _is_in_scope(host: str, scope_domains: list[str]) -> bool:
    if not scope_domains:
        return True
    host = host.lower()
    for domain in scope_domains:
        if host == domain or host.endswith("." + domain):
            return True
    return False


def get_project_summary(proj_path: str) -> dict:
    scope_domains = _get_scope_domains(proj_path)
    fp_filter = "(vulnerability_patterns NOT LIKE '%potential_false_positive%' OR vulnerability_patterns IS NULL)"

    summary = {
        "total_hosts": 0, "total_ports": 0, "total_endpoints": 0,
        "total_vulns": 0, "total_js_routes": 0, "total_screenshots": 0,
        "severity_breakdown": {"Crítica": 0, "Alta": 0, "Média": 0, "Baixa": 0, "Info": 0},
        "last_updated": None,
    }
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, host FROM hosts WHERE is_alive = 1 AND in_scope = 1")
        alive_hosts = []
        for row in cursor.fetchall():
            if _is_in_scope(row["host"], scope_domains):
                alive_hosts.append(row["id"])
        summary["total_hosts"] = len(alive_hosts)
        if alive_hosts:
            ph = ",".join("?" for _ in alive_hosts)

            cursor.execute(f"SELECT COUNT(*) FROM ports WHERE host_id IN ({ph})", alive_hosts)
            summary["total_ports"] = cursor.fetchone()[0]

            # Endpoints count — excluding false positives
            cursor.execute(
                f"SELECT COUNT(*) FROM endpoints WHERE host_id IN ({ph}) AND {fp_filter}",
                alive_hosts,
            )
            summary["total_endpoints"] = cursor.fetchone()[0]

            cursor.execute(
                f"SELECT COUNT(*) FROM vulnerabilities "
                f"WHERE host_id IN ({ph}) AND status != 'false_positive'",
                alive_hosts,
            )
            summary["total_vulns"] = cursor.fetchone()[0]

            cursor.execute(f"SELECT COUNT(*) FROM js_discoveries WHERE host_id IN ({ph})", alive_hosts)
            summary["total_js_routes"] = cursor.fetchone()[0]

            cursor.execute(f"SELECT COUNT(*) FROM screenshots WHERE host_id IN ({ph})", alive_hosts)
            summary["total_screenshots"] = cursor.fetchone()[0]

            try:
                cursor.execute(
                    f"""SELECT severity, COUNT(*) as cnt FROM vulnerabilities
                        WHERE host_id IN ({ph}) AND status != 'false_positive'
                        GROUP BY severity""",
                    alive_hosts,
                )
                for r in cursor.fetchall():
                    if r["severity"] in summary["severity_breakdown"]:
                        summary["severity_breakdown"][r["severity"]] = r["cnt"]
            except Exception:
                pass

            cursor.execute(f"SELECT MAX(last_updated) FROM hosts WHERE id IN ({ph})", alive_hosts)
            summary["last_updated"] = cursor.fetchone()[0] or "Nunca"
    return summary


def get_targets_list(proj_path: str) -> list[dict]:
    scope_domains = _get_scope_domains(proj_path)
    targets = []
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, host, ips, is_alive, last_updated FROM hosts WHERE is_alive = 1 AND in_scope = 1 ORDER BY host")
        for row in cursor.fetchall():
            if not _is_in_scope(row["host"], scope_domains):
                continue
            targets.append({
                "id": row["id"], "name": row["host"],
                "ips": json.loads(row["ips"]) if row["ips"] else [],
                "is_alive": bool(row["is_alive"]), "last_updated": row["last_updated"],
            })
    if not scope_domains:
        console.print(" [yellow]⚠ Nenhum domains.txt encontrado — todos os hosts vivos serão incluídos.[/yellow]")
    else:
        console.print(f" [dim]↳ Scope: {len(scope_domains)} domínio(s) — {len(targets)} alvo(s) dentro do escopo.[/dim]")
    return targets


def get_target_report(proj_path: str, host_name: str) -> Optional[dict]:
    scope_domains = _get_scope_domains(proj_path)
    if not _is_in_scope(host_name, scope_domains):
        return None
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM hosts WHERE host = ?", (host_name,))
        host_row = cursor.fetchone()
        if not host_row:
            return None
        host = dict(host_row)
        host["ips"] = json.loads(host["ips"]) if host.get("ips") else []
        host["cnames"] = json.loads(host["cnames"]) if host.get("cnames") else []

        cursor.execute(
            "SELECT port, protocol, state, service, version "
            "FROM ports WHERE host_id = ? ORDER BY port",
            (host["id"],),
        )
        ports = [dict(r) for r in cursor.fetchall()]
        open_ports = [p for p in ports if p["state"] == "open"]

        # ADICIONADO O 'id' LOGO NO INÍCIO DO SELECT
        cursor.execute("""SELECT id, url, status_code, content_length, content_type,
                          title, web_server, tech_stack, source_tool,
                          vulnerability_patterns
                          FROM endpoints WHERE host_id = ? ORDER BY url""",
                       (host["id"],))
        endpoints = []
        for r in cursor.fetchall():
            ep = dict(r)
            ep["tech_stack"] = json.loads(ep["tech_stack"]) if ep.get("tech_stack") else []
            ep["vulnerability_patterns"] = json.loads(ep["vulnerability_patterns"]) if ep.get("vulnerability_patterns") else []
            endpoints.append(ep)

        cursor.execute("""SELECT id, status, title, severity, cvss_score, cvss_vector, cwe_id,
                          cve_id, vuln_name, description, matched_at,
                          curl_command, remediation, impact,
                          reference_urls, source_tool, enriched_by, created_at
                          FROM vulnerabilities WHERE host_id = ? AND status != 'false_positive'
                          ORDER BY CASE severity WHEN 'Crítica' THEN 0
                          WHEN 'Alta' THEN 1 WHEN 'Média' THEN 2
                          WHEN 'Baixa' THEN 3 ELSE 4 END""",
                       (host["id"],))
        vulnerabilities = []
        for r in cursor.fetchall():
            v = dict(r)
                        # Build full CWE reference URL
            cwe_match = re.match(r"CWE-(\d+)", v.get("cwe_id") or "")
            v["cwe_url"] = (
                f"https://cwe.mitre.org/data/definitions/{cwe_match.group(1)}.html"
                if cwe_match else ""
            )
            v["reference_urls"] = json.loads(v["reference_urls"]) if v.get("reference_urls") else []
            v["severity_emoji"] = {"Crítica": "🔴", "Alta": "🟠", "Média": "🟡", "Baixa": "🟢", "Info": "🔵"}.get(v["severity"], "⚪")
            v["cvss_score"] = float(v["cvss_score"]) if v.get("cvss_score") else None
            safe_title = re.sub(r'[^a-zA-Z0-9_\-]', '_', v['title'][:40].replace(' ', '_'))
            v["filename"] = f"{v['created_at'][:8] if v.get('created_at') else '00000000'}_{safe_title}.md"
            cursor.execute("SELECT stored_name FROM user_evidences WHERE vuln_id = ?",   # ← cursor, not cur
                           (v["id"],))
            v["evidences"] = [row["stored_name"] for row in cursor.fetchall()]
            vulnerabilities.append(v)

        cursor.execute(
            "SELECT file_path, source_url, final_url, status_code, "
            "title, content_length, created_at "
            "FROM screenshots WHERE host_id = ?",
            (host["id"],),
        )
        screenshots = [dict(r) for r in cursor.fetchall()]

        cursor.execute(
            "SELECT source_js_url, discovered_route "
            "FROM js_discoveries WHERE host_id = ?",
            (host["id"],),
        )
        js_discoveries = [dict(r) for r in cursor.fetchall()]

        # tech stack: auto (endpoints) + manual (user-edited in vault)
        tech_stack = []                          # ← add this line
        for ep in endpoints:
            ts = ep["tech_stack"]
            if isinstance(ts, str):              # defensive: some rows may be raw JSON
                try:
                    ts = json.loads(ts or "[]")
                except Exception:
                    ts = []
            tech_stack.extend(ts or [])

        try:
            manual_techs = json.loads(host["manual_techs"] or "[]")
        except Exception:
            manual_techs = []

        tech_stack = sorted(set(tech_stack) | set(manual_techs))

        # tasks: reconcile auto tasks (preserve done state), then read all from DB
        auto_specs = [
            {"key": f"port_{p['port']}_{p['protocol']}",
             "label": f"Enumerar porta {p['port']}/{p['protocol']} ({p['service'] or 'desconhecido'})"}
            for p in open_ports
            if (p["service"] or "unknown").lower() not in ("ssl", "tcpwrapped", "unknown")
        ]

        if endpoints:
            auto_specs.append({"key": "web_endpoints", "label": "Analisar endpoints web"})
        if vulnerabilities:
            auto_specs.append({"key": "review_vulns", "label": "Revisar vulnerabilidades encontradas"})
        if js_discoveries:
            auto_specs.append({"key": "js_routes", "label": "Analisar rotas descobertas em JS"})

        db.sync_auto_tasks(conn, host["id"], auto_specs)
        all_tasks = [{"key": r["task_key"], "label": r["label"], "done": bool(r["is_done"])}
                     for r in db.get_host_tasks(conn, host["id"])]
        all_tasks.sort(key=lambda t: (t["done"], t["key"]))   # pending on top

        return {
            "narrative": host.get("narrative", "") or "",
            "name": host["host"], "ip": host["ips"][0] if host["ips"] else "",
            "all_ips": host["ips"], "cnames": host["cnames"],
            "whois": host.get("whois_data", ""), "is_alive": bool(host["is_alive"]),
            "last_updated": host["last_updated"], "open_ports_count": len(open_ports),
            "ports": open_ports, "all_ports": ports, "endpoints": endpoints,
            "endpoint_count": len([
                ep for ep in endpoints
                if "potential_false_positive" not in ep.get("vulnerability_patterns", [])
            ]),
            "httpx_count": len([e for e in endpoints if e["source_tool"] in ("httpx", "recon_httpx")]),
            "nuclei_count": len(vulnerabilities), "js_endpoint_count": len(js_discoveries),
            "screenshot_count": len(screenshots), "tech_stack": tech_stack,
            "tech_summary": f"O host possui {', '.join(tech_stack) if tech_stack else 'tecnologias a serem identificadas'}.",
            "vulnerabilities": vulnerabilities, "vuln_count": len(vulnerabilities),
            "vulns_critical": len([v for v in vulnerabilities if v["severity"] == "Crítica"]),
            "vulns_high": len([v for v in vulnerabilities if v["severity"] == "Alta"]),
            "vulns_medium": len([v for v in vulnerabilities if v["severity"] == "Média"]),
            "vulns_low": len([v for v in vulnerabilities if v["severity"] == "Baixa"]),
            "screenshots": screenshots, "js_discoveries": js_discoveries,
            "pending_tasks": [t["label"] for t in all_tasks if not t["done"]],
            "tasks": all_tasks,
            "completed_tasks": [t["label"] for t in all_tasks if t["done"]],
            "pipeline_status": "completed" if vulnerabilities else "in_progress",
        }


def get_vulnerability_detail(proj_path: str, vuln_id: int) -> Optional[dict]:
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT v.*, h.host as target_host, h.ips "
            "FROM vulnerabilities v JOIN hosts h ON h.id = v.host_id WHERE v.id = ? AND v.status != 'false_positive'",
            (vuln_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        v = dict(row)
        v["reference_urls"] = json.loads(v["reference_urls"]) if v.get("reference_urls") else []
        v["target_ips"] = json.loads(v["ips"]) if v.get("ips") else []
        v["cvss_score"] = float(v["cvss_score"]) if v.get("cvss_score") else None
        v["severity_emoji"] = {"Crítica": "🔴", "Alta": "🟠", "Média": "🟡", "Baixa": "🟢", "Info": "🔵"}.get(v["severity"], "⚪")
        return v


def _group_endpoints_by_route(endpoints: list[dict]) -> dict[str, list[dict]]:
    reserved = {"con", "prn", "aux", "nul"} | {f"com{i}" for i in range(1, 10)} | {f"lpt{i}" for i in range(1, 10)}
    groups = {}
    for ep in endpoints:
        path = urlparse(ep["url"]).path.strip("/")
        if not path:
            group = "root"
        else:
            raw = path.split("/")[0]
            group = re.sub(r'[^a-zA-Z0-9_\-]', '_', raw) or "root"
        if group.lower() in reserved:
            group = f"_{group}"
        groups.setdefault(group, []).append(ep)
    return dict(sorted(groups.items()))


def _get_important_endpoints(proj_path: str, limit: int = 30) -> list[dict]:
    keywords = [
        "login", "signin", "sign-in", "logon", "log-in",
        "admin", "administrativo", "administracao", "painel",
        "dashboard", "console", "manager", "management",
        "portal", "intranet", "sso", "saml", "oauth",
        "gestao", "controle", "backup", "monitor",
    ]
    scope_domains = _get_scope_domains(proj_path)
    important = []
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""SELECT e.url, e.title, e.status_code, e.web_server, h.host, h.ips
                          FROM endpoints e JOIN hosts h ON h.id = e.host_id
                          WHERE h.is_alive = 1 AND h.in_scope = 1 AND e.title IS NOT NULL AND e.title != ''
                          AND (e.vulnerability_patterns NOT LIKE '%potential_false_positive%'
                               OR e.vulnerability_patterns IS NULL)
                          ORDER BY e.title""")
        for row in cursor.fetchall():
            if not _is_in_scope(row["host"], scope_domains):
                continue
            title = (row["title"] or "").lower()
            if any(kw in title for kw in keywords):
                important.append({
                    "url": row["url"], "title": row["title"],
                    "status": row["status_code"], "server": row["web_server"] or "",
                    "target": row["host"], "ip": json.loads(row["ips"])[0] if row["ips"] else "",
                })
            if len(important) >= limit:
                break
    return important


def _get_dashboard_endpoints(proj_path: str, limit: int = 100) -> list[dict]:
    scope_domains = _get_scope_domains(proj_path)
    endpoints = []
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""SELECT e.id, e.url, e.title, e.status_code, e.web_server, h.host, h.ips
                          FROM endpoints e JOIN hosts h ON h.id = e.host_id
                          WHERE h.is_alive = 1 AND h.in_scope = 1 AND e.status_code IN (200, 401, 403)
                          AND e.title IS NOT NULL AND e.title != '' AND e.title != '-'
                          AND (e.vulnerability_patterns NOT LIKE '%potential_false_positive%'
                               OR e.vulnerability_patterns IS NULL)
                          ORDER BY h.host, e.url""")
        seen_urls = set()
        for row in cursor.fetchall():
            if not _is_in_scope(row["host"], scope_domains):
                continue
            url = row["url"]
            url = re.sub(r'^http:\/\/([^\/:]+):80\b', r'http://\1', url)
            url = re.sub(r'^https:\/\/([^\/:]+):443\b', r'https://\1', url)
            url = url.rstrip("/")
            if url in seen_urls:
                continue
            seen_urls.add(url)
            endpoints.append({
                "url": url, "title": row["title"] or "-",
                "status": row["status_code"], "server": row["web_server"] or "",
                "target": row["host"],
            })
            if len(endpoints) >= limit:
                break
    return endpoints


def _render_nmap_file(target_name: str, nmap_dir: str, vault_dir: str):
    nmap_target_dir = os.path.join(nmap_dir, f"nmap-{target_name}")
    nmap_nmap_file = os.path.join(nmap_target_dir, "nmap.nmap")
    if not os.path.exists(nmap_nmap_file):
        return
    try:
        with open(nmap_nmap_file, "r", encoding="utf-8", errors="ignore") as f:
            raw_content = f.read()
    except Exception:
        return
    lines = raw_content.split("\n")
    if len(lines) > 500:
        lines = lines[:500]
        lines.append("\n*... (resultado truncado para 500 linhas)*")
    content = "\n".join(lines)
    cb = "```"
    nmd_md = (
        f"---\n"
        f"tipo: nmap-results\n"
        f"target: {target_name}\n"
        f"---\n"
        f"# 🧹 Nmap — {target_name}\n"
        f"\n"
        f"{cb}bash\n"
        f"{content}\n"
        f"{cb}\n"
    )
    nmap_out_path = os.path.join(vault_dir, "nmap.md")
    with open(nmap_out_path, "w", encoding="utf-8") as f:
        f.write(nmd_md)


def _get_jinja_env():
    if not os.path.exists(TEMPLATE_DIR):
        os.makedirs(TEMPLATE_DIR, exist_ok=True)
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=False,
        keep_trailing_newline=True,
    )
    env.filters["from_json"] = lambda v: json.loads(v) if v and v != "null" and v != "" else {}
    return env


def _get_vault_path(obsdir: str, proj_name: str, target_name: str = None) -> str:
    base = os.path.join(obsdir, proj_name, "Pentest", "Alvos")
    if target_name:
        return os.path.join(base, target_name)
    return base


def _get_all_vulnerabilities(proj_path: str, limit: int = 100) -> list[dict]:
    scope_domains = _get_scope_domains(proj_path)
    vulns = []
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT v.title, v.severity, v.cvss_score, v.cwe_id, v.cve_id, v.cvss_vector,
                   v.created_at, v.id, h.host
            FROM vulnerabilities v
            JOIN hosts h ON h.id = v.host_id
            WHERE h.is_alive = 1 AND h.in_scope = 1 AND v.status != 'false_positive'
            ORDER BY
                CASE v.severity
                    WHEN 'Crítica' THEN 0 WHEN 'Alta' THEN 1
                    WHEN 'Média' THEN 2 WHEN 'Baixa' THEN 3
                    ELSE 4
                END, v.created_at DESC
        """)
        for row in cursor.fetchall():
            if not _is_in_scope(row["host"], scope_domains):
                continue
            title = row["title"] or ""
            safe_title = re.sub(r'[^a-zA-Z0-9_\-]', '_', title[:40].replace(' ', '_'))
            filename = f"{row['created_at'][:8] if row['created_at'] else '00000000'}_{safe_title}.md"
            vulns.append({
                "title": title,
                "severity": row["severity"],
                "severity_emoji": {"Crítica": "🔴", "Alta": "🟠", "Média": "🟡", "Baixa": "🟢", "Info": "🔵"}.get(row["severity"], "⚪"),
                "cvss_score": row["cvss_score"],
                "cwe_id": row["cwe_id"] or "—",
                "cve_id": row["cve_id"] or "—",
                "target": row["host"],
                "filename": filename,
                "created_at": row["created_at"],
            })
            if len(vulns) >= limit:
                break
    return vulns


def _cleanup_fp_vuln_files(proj_path, obsdir, proj_name):
    """Remove .md files for false positive vulnerabilities from Obsidian."""
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT v.title, h.host, v.created_at
            FROM vulnerabilities v
            JOIN hosts h ON h.id = v.host_id
            WHERE v.status = 'false_positive'
        """)
        removed = 0
        for row in cursor.fetchall():
            safe_title = re.sub(r'[^a-zA-Z0-9_\-]', '_',
                                (row["title"] or "")[:40].replace(' ', '_'))
            date_part = (row["created_at"] or "")[:8] or "00000000"
            filename = f"{date_part}_{safe_title}.md"
            # Use obsdir + proj_name directly (not per-host vault_dir)
            vuln_dir = os.path.join(obsdir, proj_name, "Pentest", "Alvos",
                                    row["host"], "Vulnerabilidades")
            fp_path = os.path.join(vuln_dir, filename)
            if os.path.exists(fp_path):
                os.remove(fp_path)
                removed += 1
    if removed:
        console.print(f" [dim]↳ Removidos {removed} arquivos FP do vault Obsidian.[/dim]")


def _archive_inactive_vulns(proj_path: str, vault_dir: str):
    """Move FP/fixed/orphaned vuln files to _Arquivados/ (frozen, never re-rendered)."""
    vulns_dir = os.path.join(vault_dir, "Vulnerabilidades")
    archive_dir = os.path.join(vault_dir, "_Arquivados")
    if not os.path.isdir(vulns_dir):
        return
    archived_count = 0
    with db.get_connection(proj_path) as conn:
        cur = conn.cursor()
        for fname in os.listdir(vulns_dir):
            if not fname.endswith(".md"):
                continue
            fpath = os.path.join(vulns_dir, fname)
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
            m = re.search(r"^vuln_id:\s*(\d+)", text, re.MULTILINE)
            if not m:
                continue
            cur.execute("SELECT status FROM vulnerabilities WHERE id = ?", (int(m.group(1)),))
            row = cur.fetchone()
            if not row or row["status"] != "open":
                os.makedirs(archive_dir, exist_ok=True)
                dst = os.path.join(archive_dir, fname)
                if os.path.exists(dst):
                    base, ext = os.path.splitext(fname)
                    dst = os.path.join(archive_dir, f"{base}_{int(time.time())}{ext}")
                shutil.move(fpath, dst)
                archived_count += 1
    if archived_count:
        console.print(f"  [dim]↳ Arquivados {archived_count} apontamentos (FP/Resolvidos).[/dim]")


def render_target(proj_path: str, obsdir: str, proj_name: str, host_name: str) -> bool:
    report = get_target_report(proj_path, host_name)
    if not report:
        console.print(f" [yellow]⚠ Alvo '{host_name}' não encontrado no banco.[/yellow]")
        return False

    env = _get_jinja_env()
    vault_dir = _get_vault_path(obsdir, proj_name, host_name)
    endpoints_dir = os.path.join(vault_dir, "Endpoints")
    vulns_dir = os.path.join(vault_dir, "Vulnerabilidades")
    os.makedirs(endpoints_dir, exist_ok=True)
    os.makedirs(vulns_dir, exist_ok=True)

    # Cleanup FP vulnerability files from vault
    _archive_inactive_vulns(proj_path, vault_dir)

    # Group endpoints by route, apply FP filter and threshold
    MIN_ROUTE_SIZE = 3
    groups = _group_endpoints_by_route(report["endpoints"])
    for gname in list(groups.keys()):
        groups[gname] = [
            ep for ep in groups[gname]
            if "potential_false_positive" not in ep.get("vulnerability_patterns", [])
        ]
        if not groups[gname]:
            del groups[gname]
    large_groups = {}
    small_eps = []
    for gname, eps in groups.items():
        if len(eps) >= MIN_ROUTE_SIZE:
            large_groups[gname] = eps
        else:
            small_eps.extend(eps)
    if small_eps:
        large_groups["_agrupadas"] = small_eps
    groups = large_groups
    group_names = sorted(groups.keys(), key=lambda g: len(groups[g]), reverse=True)

    # ── Save full screenshots list, limit inline to 3 ────────────────
    all_screenshots = report["screenshots"]
    report["screenshots"] = all_screenshots[:3]

    # ── Add endpoint count to frontmatter (exclude false positives) ──
    report["endpoint_count"] = len([
        ep for ep in report["endpoints"]
        if "potential_false_positive" not in ep.get("vulnerability_patterns", [])
    ])

    # 1. Target note (inline: max 3 screenshots)
    target_md = env.get_template("target.j2").render(
        target=report, groups=groups, group_names=group_names,
    )
    with open(os.path.join(vault_dir, f"{host_name}.md"), "w", encoding="utf-8") as f:
        f.write(target_md)

    # 2. Route group files
    ep_group_template = env.get_template("endpoint-group.j2")
    for group_name, group_eps in groups.items():
        group_md = ep_group_template.render(
            target=report, group_name=group_name,
            endpoints=group_eps, count=len(group_eps),
        )
        with open(os.path.join(endpoints_dir, f"{group_name}.md"), "w", encoding="utf-8") as f:
            f.write(group_md)

    # 3. nmap.md
    nmap_dir = _get_nmap_dir(proj_path)
    _render_nmap_file(host_name, nmap_dir, vault_dir)

    # 4. JS Discoveries
    if report["js_discoveries"]:
        js_md = env.get_template("js-discoveries.j2").render(target=report)
        with open(os.path.join(vault_dir, "js-discoveries.md"), "w", encoding="utf-8") as f:
            f.write(js_md)

    # 5. HTTPX Results
    if report["httpx_count"] > 0:
        httpx_md = env.get_template("httpx-results.j2").render(target=report)
        with open(os.path.join(vault_dir, "httpx-results.md"), "w", encoding="utf-8") as f:
            f.write(httpx_md)

    # 6. Vulnerabilities
    vuln_template = env.get_template("vuln.j2")
    vuln_count = 0
    for vuln in report.get("vulnerabilities", []):
        vuln_md = vuln_template.render(target=report, vuln=vuln)
        with open(os.path.join(vulns_dir, vuln["filename"]), "w", encoding="utf-8") as f:
            f.write(vuln_md)
        vuln_count += 1

    # 7. Copy screenshots to vault
    nmap_target_dir = os.path.join(nmap_dir, f"nmap-{host_name}", "Screenshots")
    ss_vault_dir = os.path.join(vault_dir, "Screenshots")
    ss_copied = 0
    if os.path.isdir(nmap_target_dir):
        os.makedirs(ss_vault_dir, exist_ok=True)
        for shot in all_screenshots:  # copy ALL
            src = os.path.join(nmap_target_dir, shot["file_path"])
            dst = os.path.join(ss_vault_dir, shot["file_path"])
            if os.path.exists(src) and not os.path.exists(dst):
                shutil.copy2(src, dst)
                ss_copied += 1

    # 7.5 Copy user evidences (pasted in vault) back to per-host vault folder
    proj_ev = os.path.join(nmap_dir, f"nmap-{host_name}", "Evidencias")
    vault_ev = os.path.join(vault_dir, "Evidencias")
    if os.path.isdir(proj_ev):
        os.makedirs(vault_ev, exist_ok=True)
        for fname in os.listdir(proj_ev):
            src = os.path.join(proj_ev, fname)
            dst = os.path.join(vault_ev, fname)
            if not os.path.exists(dst):
                shutil.copy2(src, dst)

    # 8. Dedicated screenshots.md with full gallery
    if all_screenshots:
        ss_lines = [
            f"# 📸 Screenshots — {host_name}",
            f"**Total: {len(all_screenshots)} capturas**\n",
        ]
        for shot in all_screenshots:
            ss_lines.append(f"![[Screenshots/{shot['file_path']}|500]]")
            if shot.get("source_url"):
                ss_lines.append(f"[{shot['source_url']}]({shot['source_url']})")
            if shot.get("title"):
                ss_lines.append(f"*{shot['title']}*\n")
        with open(os.path.join(vault_dir, "screenshots.md"), "w", encoding="utf-8") as f:
            f.write("\n".join(ss_lines))

    if ss_copied > 0:
        console.print(f"  [dim]Copiadas {ss_copied} screenshots para o vault.[/dim]")

    console.print(
        f" [dim]↳ Render: {host_name} — "
        f"{sum(len(v) for v in groups.values())} endpoints ({len(groups)} rotas), "
        f"{vuln_count} vulns[/dim]"
    )
    return True


def render_index(proj_path: str, obsdir: str, proj_name: str):
    targets = get_targets_list(proj_path)
    for t in targets:
        report = get_target_report(proj_path, t["name"])
        t["vuln_count"] = report["vuln_count"] if report else 0
        t["open_ports_count"] = report["open_ports_count"] if report else 0
        t["endpoint_count"] = report["endpoint_count"] if report else 0

    env = _get_jinja_env()
    index_md = env.get_template("index.j2").render(
        project_name=proj_name, targets=targets,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
    index_dir = os.path.join(obsdir, proj_name, "Pentest")
    os.makedirs(index_dir, exist_ok=True)
    with open(os.path.join(index_dir, "Index.md"), "w", encoding="utf-8") as f:
        f.write(index_md)
    console.print(f" [dim]↳ Render: Project Index[/dim]")


def render_all(proj_path: str, obsdir: str, proj_name: str, target_name: str = None):
    console.print(f"\n[bold cyan]▶ Sync: Renderizando vault do Obsidian[/bold cyan]")
    console.print(f" [dim]Projeto: {proj_name}[/dim]")
    console.print(f" [dim]Modo: {'Parallel (Sync/)' if SYNC_MODE == 'parallel' else 'Direct'}[/dim]")
    if target_name:
        render_target(proj_path, obsdir, proj_name, target_name)
    else:
        targets = get_targets_list(proj_path)
        if not targets:
            console.print(" [yellow]⚠ Nenhum alvo encontrado no banco de dados.[/yellow]")
            return
        for t in targets:
            render_target(proj_path, obsdir, proj_name, t["name"])
        render_dashboard(proj_path, obsdir, proj_name)
        render_index(proj_path, obsdir, proj_name)
    console.print(f"\n[bold green]✔ Sync concluído![/bold green]")


def render_dashboard(proj_path: str, obsdir: str, proj_name: str):
    summary = get_project_summary(proj_path)
    targets = get_targets_list(proj_path)
    for t in targets:
        report = get_target_report(proj_path, t["name"])
        if report:
            t["all_ips_str"] = ", ".join(report["all_ips"])
            t["ports_str"] = ", ".join(str(p["port"]) for p in report["all_ports"])
            t["services_str"] = ", ".join(sorted(set(
                p["service"] for p in report["all_ports"] if p["service"]
            )))
            t["vuln_count"] = report["vuln_count"]
        else:
            t["all_ips_str"] = "—"
            t["ports_str"] = "—"
            t["services_str"] = "—"
            t["vuln_count"] = 0

    important = _get_important_endpoints(proj_path)
    all_endpoints = _get_dashboard_endpoints(proj_path)
    all_vulns = _get_all_vulnerabilities(proj_path)

    env = _get_jinja_env()
    dashboard_md = env.get_template("dashboard.j2").render(
        project_name=proj_name, summary=summary, targets=targets,
        important_endpoints=important, all_endpoints=all_endpoints,
        all_vulnerabilities=all_vulns,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
    pentest_dir = os.path.join(obsdir, proj_name, "Pentest")
    os.makedirs(pentest_dir, exist_ok=True)

    with open(os.path.join(pentest_dir, "Dashboard_Global.md"), "w", encoding="utf-8") as f:
        f.write(dashboard_md)

    # Hosts Panel (.base file)
    hosts_md = env.get_template("hosts-panel.j2").render(
        project_name=proj_name,
        vault_path=os.path.join(obsdir, proj_name, "Pentest"),
    )
    with open(os.path.join(pentest_dir, "Hosts_Panel.base"), "w", encoding="utf-8") as f:
        f.write(hosts_md)

    console.print(f" [dim]↳ Render: Dashboard Global ({len(important)} importantes, {len(all_endpoints)} endpoints, {len(all_vulns)} vulns)[/dim]")


def sync_project(target_name: str = None):
    proj_name, proj_path, obsdir = _get_env_from_config()
    if not proj_name or not proj_path or not obsdir:
        console.print("[bold red]✖ Erro: Projeto não configurado. Rode init-openpipes primeiro.[/bold red]")
        return
    db.init_db(proj_path)
    import sync
    sync.parse_vault_to_db(proj_path, obsdir, proj_name, target_name)   # MD → DB (ingest)
    render_all(proj_path, obsdir, proj_name, target_name)                # DB → MD (render)
