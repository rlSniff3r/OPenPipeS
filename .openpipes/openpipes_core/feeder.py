import os
import json
import re
import glob
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

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


def _normalize_url(url: str) -> str:
    """Remove default ports and trailing slashes to match DB format."""
    if not url:
        return url
    parsed = urlparse(url)
    if (parsed.scheme == "http" and parsed.port == 80) or \
       (parsed.scheme == "https" and parsed.port == 443):
        url = f"{parsed.scheme}://{parsed.hostname}{parsed.path}"
    return url.rstrip("/")


def _filter_urls_by_host(urls: list, host: str) -> list:
    """Only include URLs whose hostname matches the target host. Deduplicates."""
    seen = set()
    result = []
    for url in urls:
        parsed = urlparse(url)
        if parsed.hostname != host:
            continue
        norm = _normalize_url(url)
        if norm not in seen:
            seen.add(norm)
            result.append(norm)
    return result


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
              AND h.in_scope = 1
              AND (e.vulnerability_patterns NOT LIKE '%potential_false_positive%'
                   OR e.vulnerability_patterns IS NULL)
              AND (e.scanned_by NOT LIKE ? OR e.scanned_by IS NULL)
            ORDER BY h.host, e.url
        """, (f"%{tool_name}%",))
        return [r for r in cursor.fetchall() if _is_in_scope(r["host"], scope_domains)]


def _mark_scanned(proj_path: str, endpoint_ids: list, tool_name: str):
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
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT DISTINCT h.id, h.host, h.ips
            FROM hosts h
            JOIN ports p ON p.host_id = h.id
            WHERE h.is_alive = 1 AND h.in_scope = 1
              AND p.state = 'open'
              AND p.service IN ('http','https','http-proxy','ssl','unknown',
                                'ssl/http','ssl/https','ssl/http-proxy','ssl/unknown','upnp')
            ORDER BY h.host
        """)
        hosts = cursor.fetchall()
    scope_domains = _get_scope_domains(proj_path)
    hosts = [h for h in hosts if _is_in_scope(h["host"], scope_domains)]
    if not hosts:
        console.print("[yellow]⚠ Nenhum host com portas HTTP.[/yellow]")
        return
    count = 0
    for row in hosts:
        host_id, host_name = row["id"], row["host"]
        target_dir = os.path.join(nmap_dir, f"nmap-{host_name}")
        os.makedirs(target_dir, exist_ok=True)

        ips = json.loads(row["ips"]) if row["ips"] else []
        with db.get_connection(proj_path) as conn:
            c = conn.cursor()
            c.execute(
                "SELECT port FROM ports WHERE host_id = ? AND state = 'open' "
                "AND service IN ('http','https','http-proxy','ssl','unknown',"
                "'ssl/http','ssl/https','ssl/http-proxy','ssl/unknown','upnp')",
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



def _feed_from_unscanned(proj_path: str, nmap_dir: str, tool_name: str, out_file: str = "alive_urls.txt"):
    """Generic feeder: writes filtered, normalized URLs to per-target files."""
    rows = _get_unscanned(proj_path, tool_name)
    if not rows:
        console.print(f"[dim]↳ Feed {tool_name}: nada novo.[/dim]")
        return
    by_host = defaultdict(list)
    for r in rows:
        by_host[r["host"]].append(r["url"])
    total = 0
    for host, urls in by_host.items():
        target_dir = os.path.join(nmap_dir, f"nmap-{host}")
        os.makedirs(target_dir, exist_ok=True)
        filtered = _filter_urls_by_host(urls, host)
        # Fallback: if no endpoints, feed base URL
        if not filtered:
            filtered = [f"https://{host}", f"http://{host}"]
        with open(os.path.join(target_dir, out_file), "w") as f:
            for url in filtered:
                f.write(url + "\n")
        total += len(filtered)
    console.print(f" [dim]↳ Feed {tool_name}: {total} URLs para {len(by_host)} hosts[/dim]")


def feed_katana(proj_path: str, nmap_dir: str):
    _feed_from_unscanned(proj_path, nmap_dir, "katana", "katana_urls.txt")


def feed_ferox(proj_path: str, nmap_dir: str):
    _feed_from_unscanned(proj_path, nmap_dir, "ferox", "ferox_urls.txt")


def feed_jsfinder(proj_path: str, nmap_dir: str):
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
        filtered = _filter_urls_by_host(urls, host)
        with open(os.path.join(target_dir, "js_urls.txt"), "w") as f:
            for url in filtered:
                f.write(url + "\n")
        total += len(filtered)
    console.print(f" [dim]↳ Feed jsfinder: {total} novos JS URLs[/dim]")


def feed_gf(proj_path: str, nmap_dir: str):
    _feed_from_unscanned(proj_path, nmap_dir, "gf", "gf_urls.txt")


def feed_screenshot(proj_path: str, nmap_dir: str):
    _feed_from_unscanned(proj_path, nmap_dir, "screenshot", "screenshot_urls.txt")


def feed_nuclei(proj_path: str, nmap_dir: str):
    _feed_from_unscanned(proj_path, nmap_dir, "nuclei", "nuclei_urls.txt")


def feed_nwrapper(proj_path: str, nmap_dir: str, cycle: bool = False):
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        if cycle:
            cursor.execute("""
                SELECT h.host FROM hosts h
                WHERE h.is_alive = 1 AND h.in_scope = 1
                AND NOT EXISTS (SELECT 1 FROM ports p WHERE p.host_id = h.id)
                ORDER BY h.host
            """)
            out_file = os.path.join(nmap_dir, "targets_cycle.txt")
        else:
            cursor.execute("SELECT host FROM hosts WHERE is_alive = 1 AND in_scope = 1 ORDER BY host")
            out_file = os.path.join(nmap_dir, "targets.txt")
        hosts = [r["host"] for r in cursor.fetchall()]
    scope_domains = _get_scope_domains(proj_path)
    hosts = [h for h in hosts if _is_in_scope(h, scope_domains)]
    if hosts:
        os.makedirs(nmap_dir, exist_ok=True)
        with open(out_file, "w") as f:
            for h in hosts:
                f.write(h + "\n")
        console.print(f" [dim]↳ Feed nwrapper: {len(hosts)} hosts → {os.path.basename(out_file)}[/dim]")
    else:
        console.print("[dim]↳ Feed nwrapper: nada novo.[/dim]")


def feed_nwrapper_retry(proj_path: str, nmap_dir: str):
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT h.host, p.port, p.protocol
            FROM hosts h
            JOIN ports p ON p.host_id = h.id
            WHERE h.is_alive = 1 AND h.in_scope = 1
              AND p.state IN ('closed', 'filtered')
            ORDER BY h.host, p.port
        """)
        results = cursor.fetchall()
    scope_domains = _get_scope_domains(proj_path)
    results = [r for r in results if _is_in_scope(r["host"], scope_domains)]
    if not results:
        console.print("[dim]↳ Feed nwrapper retry: nenhuma porta fechada/filtrada.[/dim]")
        return
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


def feed_all(proj_path: str, nmap_dir: str):
    feed_nwrapper(proj_path, nmap_dir, cycle=True)
    feed_httpx(proj_path, nmap_dir)
    feed_katana(proj_path, nmap_dir)
    feed_ferox(proj_path, nmap_dir)
    feed_jsfinder(proj_path, nmap_dir)
    feed_gf(proj_path, nmap_dir)
    feed_screenshot(proj_path, nmap_dir)
    feed_nuclei(proj_path, nmap_dir)

    # NEW: build contextual wordlists for feroxbuster
    import context_wordlist_builder
    context_wordlist_builder.build_context_wordlist(proj_path, nmap_dir)


def run():
    proj_path, nmap_dir = _get_proj_path()
    if not proj_path:
        console.print("[red]Erro: Projeto não configurado.[/red]")
        return
    db.init_db(proj_path)
    feed_all(proj_path, nmap_dir)
