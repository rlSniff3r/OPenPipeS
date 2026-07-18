import re
import os
import json
from collections import defaultdict
from pathlib import Path

import db
from rich.console import Console

console = Console()
HOME = str(Path.home())
CONFIG_FILE = os.path.join(HOME, ".openpipes", "config.sh")


def _get_proj_path():
    if not os.path.exists(CONFIG_FILE):
        return None, None
    try:
        import subprocess
        cmd = f"source {CONFIG_FILE} && echo -n \"$proj_path|$NMAP_DIR\""
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, executable="/bin/bash")
        parts = result.stdout.strip().split("|")
        if len(parts) == 2:
            return parts[0], parts[1]
    except Exception:
        pass
    return None, None


def _get_scope_domains(proj_path: str) -> list[str]:
    """Read domains.txt and return list of in-scope domain suffixes."""
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


def _get_unscanned(proj_path: str, tool_name: str, status_min: int = 100, status_max: int = 599):
    """Get endpoints not yet processed by this tool, filtered by scope."""
    scope_domains = _get_scope_domains(proj_path)

    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT e.id, e.url, e.host_id, h.host
            FROM endpoints e
            JOIN hosts h ON h.id = e.host_id
            WHERE h.is_alive = 1
              AND (e.vulnerability_patterns NOT LIKE '%potential_false_positive%'
                   OR e.vulnerability_patterns IS NULL)
              AND (e.scanned_by NOT LIKE ? OR e.scanned_by IS NULL)
            ORDER BY h.host, e.url
        """, (f"%{tool_name}%",))

        # Filter by scope in Python
        return [r for r in cursor.fetchall() if _is_in_scope(r["host"], scope_domains)]


def _mark_scanned(proj_path: str, endpoint_ids: list, tool_name: str):
    """Append tool name to scanned_by for each endpoint."""
    if not endpoint_ids:
        return
    with db.get_connection(proj_path) as conn:
        with db.transaction(conn):
            cursor = conn.cursor()
            for eid in endpoint_ids:
                cursor.execute("""
                    UPDATE endpoints SET
                        scanned_by = CASE
                            WHEN scanned_by IS NULL OR scanned_by = '' THEN ?
                            ELSE scanned_by || ',' || ?
                        END
                    WHERE id = ?
                """, (tool_name, tool_name, eid))


def feed_httpx(proj_path: str, nmap_dir: str):
    """Feed targets with open HTTP ports to httpx. Skips hosts already scanned."""
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT DISTINCT h.id, h.host, h.ips
            FROM hosts h
            JOIN ports p ON p.host_id = h.id
            WHERE h.is_alive = 1 AND p.state = 'open'
              AND p.service IN ('http','https','http-proxy','ssl','unknown')
            ORDER BY h.host
        """)
        hosts = cursor.fetchall()

    if not hosts:
        console.print("[yellow]⚠ Nenhum host com portas HTTP.[/yellow]")
        return

    count = 0
    for row in hosts:
        host_id, host_name = row["id"], row["host"]
        target_dir = os.path.join(nmap_dir, f"nmap-{host_name}")

        # Skip if already scanned — remove input files so script skips too
        import glob
        existing = glob.glob(os.path.join(target_dir, "httpx-*.json"))
        if existing:
            for f in ["httpx_targets.txt", "httpx_ports.txt"]:
                p = os.path.join(target_dir, f)
                if os.path.exists(p):
                    os.remove(p)
            continue

        ips = json.loads(row["ips"]) if row["ips"] else []
        os.makedirs(target_dir, exist_ok=True)

        with db.get_connection(proj_path) as conn:
            c = conn.cursor()
            c.execute(
                "SELECT port FROM ports WHERE host_id = ? AND state = 'open' "
                "AND service IN ('http','https','http-proxy','ssl','unknown')",
                (host_id,),
            )
            ports = [str(r[0]) for r in c.fetchall()]

        with open(os.path.join(target_dir, "httpx_targets.txt"), "w") as f:
            f.write(f"http://{host_name}\nhttps://{host_name}\n")
            if ips:
                f.write(f"http://{ips[0]}\nhttps://{ips[0]}\n")
        with open(os.path.join(target_dir, "httpx_ports.txt"), "w") as f:
            f.write(",".join(ports))
        count += 1

    console.print(f" [dim]↳ Feed httpx: {count} novos hosts[/dim]")


def feed_katana(proj_path: str, nmap_dir: str):
    """Feed unscanned, verified endpoints to katana."""
    rows = _get_unscanned(proj_path, "katana", status_min=200, status_max=399)
    if not rows:
        console.print("[dim]↳ Feed katana: nada novo.[/dim]")
        return
    by_host = defaultdict(list)
    for r in rows:
        by_host[r["host"]].append(r["url"])
    total = 0
    for host, urls in by_host.items():
        target_dir = os.path.join(nmap_dir, f"nmap-{host}")
        os.makedirs(target_dir, exist_ok=True)
        with open(os.path.join(target_dir, "alive_urls.txt"), "w") as f:
            for url in urls:
                f.write(url + "\n")
        total += len(urls)
    _mark_scanned(proj_path, [r["id"] for r in rows], "katana")
    console.print(f" [dim]↳ Feed katana: {total} novos URLs para {len(by_host)} hosts[/dim]")


def feed_ferox(proj_path: str, nmap_dir: str):
    """Feed unscanned, verified endpoints to feroxbuster."""
    rows = _get_unscanned(proj_path, "ferox", status_min=200, status_max=399)
    if not rows:
        console.print("[dim]↳ Feed ferox: nada novo.[/dim]")
        return
    by_host = defaultdict(list)
    for r in rows:
        by_host[r["host"]].append(r["url"])
    total = 0
    for host, urls in by_host.items():
        target_dir = os.path.join(nmap_dir, f"nmap-{host}")
        os.makedirs(target_dir, exist_ok=True)
        with open(os.path.join(target_dir, "alive_urls.txt"), "w") as f:
            for url in urls:
                f.write(url + "\n")
        total += len(urls)
    _mark_scanned(proj_path, [r["id"] for r in rows], "ferox")
    console.print(f" [dim]↳ Feed ferox: {total} novos URLs para {len(by_host)} hosts[/dim]")


def feed_jsfinder(proj_path: str, nmap_dir: str):
    """Feed JS URLs (endpoints ending in .js) to jsfinder."""
    rows = _get_unscanned(proj_path, "jsfinder")
    js_rows = [r for r in rows if r["url"].lower().endswith(".js") or ".js?" in r["url"].lower()]
    if not js_rows:
        console.print("[dim]↳ Feed jsfinder: nada novo.[/dim]")
        return
    by_host = defaultdict(list)
    for r in js_rows:
        by_host[r["host"]].append(r["url"])
    total = 0
    for host, urls in by_host.items():
        target_dir = os.path.join(nmap_dir, f"nmap-{host}")
        os.makedirs(target_dir, exist_ok=True)
        out = os.path.join(target_dir, "js_urls.txt")
        with open(out, "w") as f:
            for url in urls:
                f.write(url + "\n")
        total += len(urls)
    _mark_scanned(proj_path, [r["id"] for r in js_rows], "jsfinder")
    console.print(f" [dim]↳ Feed jsfinder: {total} novos JS URLs[/dim]")


def feed_gf(proj_path: str, nmap_dir: str):
    """Feed unscanned endpoints to gf-summary."""
    rows = _get_unscanned(proj_path, "gf")
    if not rows:
        console.print("[dim]↳ Feed gf: nada novo.[/dim]")
        return
    by_host = defaultdict(list)
    for r in rows:
        by_host[r["host"]].append(r["url"])
    total = 0
    for host, urls in by_host.items():
        target_dir = os.path.join(nmap_dir, f"nmap-{host}")
        os.makedirs(target_dir, exist_ok=True)
        out = os.path.join(target_dir, "gf_urls.txt")
        with open(out, "w") as f:
            for url in urls:
                f.write(url + "\n")
        total += len(urls)
    _mark_scanned(proj_path, [r["id"] for r in rows], "gf")
    console.print(f" [dim]↳ Feed gf: {total} URLs[/dim]")


def feed_screenshot(proj_path: str, nmap_dir: str):
    """Feed verified, non-FP endpoints to screenshot-runner."""
    rows = _get_unscanned(proj_path, "screenshot", status_min=200, status_max=399)
    if not rows:
        console.print("[dim]↳ Feed screenshot: nada novo.[/dim]")
        return
    by_host = defaultdict(list)
    for r in rows:
        by_host[r["host"]].append(r["url"])
    total = 0
    for host, urls in by_host.items():
        target_dir = os.path.join(nmap_dir, f"nmap-{host}")
        os.makedirs(target_dir, exist_ok=True)
        alive_file = os.path.join(target_dir, "alive_urls.txt")
        with open(alive_file, "w") as f:
            for url in urls:
                f.write(url + "\n")
        total += len(urls)
    _mark_scanned(proj_path, [r["id"] for r in rows], "screenshot")
    console.print(f" [dim]↳ Feed screenshot: {total} URLs[/dim]")


def feed_nwrapper(proj_path: str, nmap_dir: str, cycle: bool = False):
    """
    Feed nwrapper with hosts to scan.
    In cycle mode, only includes hosts not yet scanned (no ports in DB).
    """
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()

        if cycle:
            # Only hosts without any port records
            cursor.execute("""
                SELECT h.host FROM hosts h
                WHERE h.is_alive = 1
                AND NOT EXISTS (SELECT 1 FROM ports p WHERE p.host_id = h.id)
                ORDER BY h.host
            """)
            out_file = os.path.join(nmap_dir, "targets_cycle.txt")
        else:
            cursor.execute("SELECT host FROM hosts WHERE is_alive = 1 ORDER BY host")
            out_file = os.path.join(nmap_dir, "targets.txt")

        hosts = [r["host"] for r in cursor.fetchall()]

    if hosts:
        os.makedirs(nmap_dir, exist_ok=True)
        with open(out_file, "w") as f:
            for h in hosts:
                f.write(h + "\n")
        console.print(f" [dim]↳ Feed nwrapper: {len(hosts)} hosts → {os.path.basename(out_file)}[/dim]")
    else:
        console.print("[dim]↳ Feed nwrapper: nada novo.[/dim]")


def feed_nwrapper_retry(proj_path: str, nmap_dir: str):
    """
    Feed nwrapper with hosts that have closed/filtered ports for re-scan.
    Writes targets_retry.txt with specific ports to re-scan.
    """
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT h.host, p.port, p.protocol
            FROM hosts h
            JOIN ports p ON p.host_id = h.id
            WHERE h.is_alive = 1
              AND p.state IN ('closed', 'filtered')
            ORDER BY h.host, p.port
        """)
        results = cursor.fetchall()

    if not results:
        console.print("[dim]↳ Feed nwrapper retry: nenhuma porta fechada/filtrada.[/dim]")
        return

    # Group by host
    from collections import defaultdict
    by_host = defaultdict(list)
    for r in results:
        by_host[r["host"]].append(f"{r['port']}/{r['protocol']}")

    out_file = os.path.join(nmap_dir, "targets_retry.txt")
    with open(out_file, "w") as f:
        for host, ports in by_host.items():
            ports_str = ",".join(p.split("/")[0] for p in ports)
            f.write(f"{host}:{ports_str}\n")

    total_ports = len(results)
    console.print(f" [dim]↳ Feed nwrapper retry: {len(by_host)} hosts, {total_ports} portas → targets_retry.txt[/dim]")


def feed_nuclei(proj_path: str, nmap_dir: str):
    """Feed unscanned, verified endpoints to nuclei."""
    rows = _get_unscanned(proj_path, "nuclei")
    if not rows:
        console.print("[dim]↳ Feed nuclei: nada novo.[/dim]")
        return
    by_host = defaultdict(list)
    for r in rows:
        by_host[r["host"]].append(r["url"])
    total = 0
    for host, urls in by_host.items():
        target_dir = os.path.join(nmap_dir, f"nmap-{host}")
        os.makedirs(target_dir, exist_ok=True)
        with open(os.path.join(target_dir, "alive_urls.txt"), "w") as f:
            for url in urls:
                f.write(url + "\n")
        total += len(urls)
    _mark_scanned(proj_path, [r["id"] for r in rows], "nuclei")
    console.print(f" [dim]↳ Feed nuclei: {total} URLs para {len(by_host)} hosts[/dim]")


def feed_all(proj_path: str, nmap_dir: str):
    feed_nwrapper(proj_path, nmap_dir, cycle=True)
    feed_httpx(proj_path, nmap_dir)
    feed_katana(proj_path, nmap_dir)
    feed_ferox(proj_path, nmap_dir)
    feed_jsfinder(proj_path, nmap_dir)
    feed_gf(proj_path, nmap_dir)
    feed_screenshot(proj_path, nmap_dir)
    feed_nuclei(proj_path, nmap_dir)


def run():
    """CLI entry point."""
    proj_path, nmap_dir = _get_proj_path()
    if not proj_path:
        console.print("[red]Erro: Projeto não configurado.[/red]")
        return
    db.init_db(proj_path)
    feed_all(proj_path, nmap_dir)
