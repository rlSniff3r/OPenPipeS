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


def _get_injected_targets(proj_path: str, tool_name: str) -> dict:
    """
    Reconstruct injection targets from injectable_params.
    Returns {host: {"get": [urls], "post": [(url, data)], "headers": [(url, header)]}}
    Skips params already consumed by tool_name.
    """
    result: dict[str, dict] = {}
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT h.host, e.url, ip.param_name, ip.http_method, ip.param_type
            FROM injectable_params ip
            JOIN endpoints e ON e.id = ip.endpoint_id
            JOIN hosts h ON h.id = e.host_id
            WHERE h.is_alive = 1 AND h.in_scope = 1
              AND (ip.scanned_by IS NULL OR ip.scanned_by NOT LIKE ?)
            ORDER BY h.host, e.url, ip.param_name
        """, (f"%{tool_name}%",))
        rows = cursor.fetchall()

    # Group params per endpoint
    endpoints: dict[tuple, dict] = {}
    for r in rows:
        key = (r["host"], r["url"], r["http_method"])
        ep = endpoints.setdefault(key, {"get": [], "post": [], "headers": []})
        if r["param_type"] == "header":
            ep["headers"].append(r["param_name"])
        elif "POST" in r["http_method"]:
            ep["post"].append(r["param_name"])
        else:
            ep["get"].append(r["param_name"])

    for (host, url, method), params in endpoints.items():
        entry = result.setdefault(host, {"get": [], "post": [], "headers": []})
        if params["get"]:
            entry["get"].append(f"{url}?{'&'.join(f'{p}=FUZZ' for p in params['get'])}")
        if params["post"]:
            entry["post"].append((url, "&".join(f"{p}=FUZZ" for p in params["post"])))
        if params["headers"]:
            for h in params["headers"]:
                entry["headers"].append((url, h))
    return result


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


def feed_arjun(proj_path: str, nmap_dir: str):
    """Feed unscanned endpoints to Arjun (skip already-scanned, skip URLs with visible params)."""
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT DISTINCT e.id, h.host, e.url
            FROM endpoints e
            JOIN hosts h ON e.host_id = h.id
            WHERE h.is_alive = 1 AND h.in_scope = 1
              AND e.status_code IN (200, 301, 302, 403, 500)
              AND (e.scanned_by IS NULL OR e.scanned_by NOT LIKE '%arjun%')
              AND e.url NOT LIKE '%?%'
              AND e.url NOT LIKE '%.png%'
              AND e.url NOT LIKE '%.jpg%'   AND e.url NOT LIKE '%.jpeg%'
              AND e.url NOT LIKE '%.gif%'   AND e.url NOT LIKE '%.svg%'
              AND e.url NOT LIKE '%.ico%'   AND e.url NOT LIKE '%.webp%'
              AND e.url NOT LIKE '%.bmp%'
              AND e.url NOT LIKE '%.css%'
              AND e.url NOT LIKE '%.woff%'  AND e.url NOT LIKE '%.woff2%'
              AND e.url NOT LIKE '%.ttf%'   AND e.url NOT LIKE '%.eot%'
            ORDER BY h.host, e.url
        """)
        rows = cursor.fetchall()

    host_urls: dict[str, list[str]] = {}
    seen: set[str] = set()
    for r in rows:
        host = r["host"]
        # Normalize: strip trailing slash (and duplicate scheme variants)
        url = r["url"].rstrip("/")
        key = url.lower()  # host/path case-insensitive dedup
        if key in seen:
            continue
        seen.add(key)
        host_urls.setdefault(host, []).append(url)

    count = 0
    for host, urls in host_urls.items():
        target_dir = os.path.join(nmap_dir, f"nmap-{host}")
        os.makedirs(target_dir, exist_ok=True)
        with open(os.path.join(target_dir, "arjun_targets.txt"), "w") as f:
            for u in urls:
                f.write(f"{u}\n")
        count += len(urls)

    # ── Remove stale target files: out-of-scope, dead OR fully-scanned hosts ──
    if os.path.isdir(nmap_dir):
        for folder in os.listdir(nmap_dir):
            if not folder.startswith("nmap-"):
                continue
            host = folder[len("nmap-"):]
            if host in host_urls:
                continue
            stale = os.path.join(nmap_dir, folder, "arjun_targets.txt")
            if os.path.exists(stale):
                os.remove(stale)
                console.print(f" [dim]↳ Removido alvo obsoleto: {host}[/dim]")

    console.print(f" [dim]↳ Feed Arjun: {count} endpoints para {len(host_urls)} hosts.[/dim]")


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


# ── Nuclei tag mapping ────────────────────────────────────────────
NUCLEI_BASE_TAGS = ["misconfig", "exposure", "default-login", "takeover", "panel", "auth-bypass"]

# Protocol-level tags that aren't tech-specific (never used for CVE pass 2)
NON_TECH_TAGS = {"http", "network", "ssl", "dns", "tcp", "webserver"}

# Normalized tech_stack name -> nuclei tag(s)
TECH_MAP = {
    "nginx": ["nginx"], "apache http server": ["apache"], "apache": ["apache"],
    "iis": ["iis"], "microsoft httpapi": ["iis"],
    "microsoft asp.net": ["aspnet", "iis", "windows"],
    "php": ["php"], "ruby": ["ruby"], "ruby on rails": ["rails", "ruby"],
    "wordpress": ["wordpress"], "w3 total cache": ["wordpress", "php"],
    "wpml": ["wordpress", "php"], "yoast seo": ["wordpress", "php"],
    "monsterinsights": ["wordpress", "php"],
    "drupal": ["drupal"], "joomla": ["joomla"],
    "mysql": ["mysql"], "postgresql": ["postgres"], "mariadb": ["mysql"],
    "openssl": ["openssl"], "ubuntu": ["ubuntu"], "windows server": ["windows"],
    "docker": ["docker"], "kubernetes": ["kubernetes"],
    "grafana": ["grafana"], "jenkins": ["jenkins"], "gitlab": ["gitlab"],
    "sharepoint": ["sharepoint"], "exchange": ["exchange"], "citrix": ["citrix"],
    "vmware": ["vmware"], "tomcat": ["tomcat"], "java": ["java"],
    "elasticsearch": ["elasticsearch"], "redis": ["redis"], "mongodb": ["mongodb"],
    "laravel": ["laravel"], "symfony": ["symfony"], "django": ["django"],
    "flask": ["flask"], "node.js": ["nodejs"], "express": ["express"],
    "openui5": ["sap"], "sap": ["sap"], "amazon s3": ["aws"], "azure": ["azure"],
}

# Entries with no nuclei signal (CDN/WAF/protocol/frontend libs)
TECH_NOISE = {
    "cloudflare", "cloudflare browser insights", "hsts", "http/2", "http/3",
    "azure front door", "akamai", "akamaighost", "basic",
    "google analytics", "google tag manager", "adobe fonts", "typekit",
    "jquery", "jquery cdn", "jquery ui", "jsdelivr", "slick", "lodash",
    "moment.js", "font awesome", "recaptcha", "linkedin ads",
}

SERVICE_MAP = {
    "ssh": ["ssh"], "ftp": ["ftp"], "smtp": ["smtp"], "mysql": ["mysql"],
    "postgresql": ["postgres"], "mssql": ["mssql"], "mongodb": ["mongodb"],
    "redis": ["redis"], "elasticsearch": ["elasticsearch"], "docker": ["docker"],
    "kubernetes": ["kubernetes"], "smb": ["smb"], "rdp": ["rdp"],
    "telnet": ["telnet"], "snmp": ["snmp"], "ldap": ["ldap"],
    "http": ["http"], "https": ["http"],
}

def _tech_to_tags(tech_stack) -> list:
    tags = []
    for raw in tech_stack or []:
        name = str(raw).split(":")[0].strip().lower()   # strip :version
        if name in TECH_NOISE:
            continue
        for t in TECH_MAP.get(name, []):
            if t not in tags:
                tags.append(t)
    return tags

def _services_to_tags(ports_rows) -> list:
    tags = []
    for p in ports_rows:
        svc = (p["service"] or "").lower()
        ver = (p["version"] or "").lower()
        mapped = SERVICE_MAP.get(svc, [])
        if not mapped:   # web server hidden in version string
            for key, t in (("nginx", "nginx"), ("apache", "apache"),
                           ("iis", "iis"), ("httpapi", "iis")):
                if key in ver:
                    mapped = [t]
                    break
        for t in mapped:
            if t not in tags:
                tags.append(t)
    return tags

def _build_nuclei_tags(proj_path: str, host_id: int) -> str:
    """Comma-separated nuclei tags: BASE + tech_stack + open ports."""
    tags = list(NUCLEI_BASE_TAGS)
    with db.get_connection(proj_path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT tech_stack FROM endpoints WHERE host_id = ?", (host_id,))
        for r in cur.fetchall():
            for t in _tech_to_tags(json.loads(r["tech_stack"] or "[]")):
                if t not in tags:
                    tags.append(t)
        cur.execute("SELECT service, version FROM ports WHERE host_id = ? AND state = 'open'",
                    (host_id,))
        for t in _services_to_tags(cur.fetchall()):
            if t not in tags:
                tags.append(t)
    return ",".join(tags)


def feed_nuclei(proj_path: str, nmap_dir: str):
    """Port-aware targets: one root URL per open web port + tag files."""
    with db.get_connection(proj_path) as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT h.id, h.host, p.port, p.service
            FROM hosts h JOIN ports p ON p.host_id = h.id
            WHERE h.is_alive = 1 AND h.in_scope = 1 AND p.state = 'open'
            AND (COALESCE(p.service, '') IN ('http','https','cloudflare','upnp','unknown','')
                OR p.port IN (80, 443, 8080, 8443, 8000, 8888))
            ORDER BY h.host, p.port
        """)
        rows = cur.fetchall()

    per_host: dict[int, dict] = {}
    for r in rows:
        scheme = "https" if r["port"] in (443, 8443) else "http"
        entry = per_host.setdefault(r["id"], {"host": r["host"], "urls": []})
        entry["urls"].append(f"{scheme}://{r['host']}:{r['port']}/")

    for host_id, entry in per_host.items():
        target_dir = os.path.join(nmap_dir, f"nmap-{entry['host']}")
        os.makedirs(target_dir, exist_ok=True)

        # 1. Targets: one root URL per open port
        with open(os.path.join(target_dir, "nuclei_urls.txt"), "w") as f:
            f.write("\n".join(entry["urls"]) + "\n")

        # 2. Pass-1 tags: BASE + techs (incl. 'http' — fine here)
        all_tags = _build_nuclei_tags(proj_path, host_id)
        with open(os.path.join(target_dir, "nuclei_tags.txt"), "w") as f:
            f.write(all_tags + "\n")

        # 3. Pass-2 techs: ONLY tech/service tags (no base, no 'http')
        tech_only = [t for t in all_tags.split(",")
                     if t not in NUCLEI_BASE_TAGS and t not in NON_TECH_TAGS]
        with open(os.path.join(target_dir, "nuclei_techs.txt"), "w") as f:
            f.write(",".join(tech_only) + "\n")

    console.print(f" [dim]↳ Feed Nuclei: {len(per_host)} hosts, "
                  f"{sum(len(e['urls']) for e in per_host.values())} alvos porta-específicos.[/dim]")


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


def feed_dalfox(proj_path: str, nmap_dir: str):
    """Feed unscanned endpoints to dalfox (skip already-scanned, exclude only static assets)."""
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT DISTINCT h.id, h.host, e.url
            FROM endpoints e
            JOIN hosts h ON e.host_id = h.id
            WHERE h.is_alive = 1 AND h.in_scope = 1
              AND (e.scanned_by IS NULL OR e.scanned_by NOT LIKE '%dalfox%')
              AND e.url NOT LIKE '%.png%'
              AND e.url NOT LIKE '%.jpg%'   AND e.url NOT LIKE '%.jpeg%'
              AND e.url NOT LIKE '%.gif%'   AND e.url NOT LIKE '%.svg%'
              AND e.url NOT LIKE '%.ico%'   AND e.url NOT LIKE '%.webp%'
              AND e.url NOT LIKE '%.bmp%'
              AND e.url NOT LIKE '%.css%'
              AND e.url NOT LIKE '%.woff%'  AND e.url NOT LIKE '%.woff2%'
              AND e.url NOT LIKE '%.ttf%'   AND e.url NOT LIKE '%.eot%'
            ORDER BY h.host, e.url
        """)
        rows = cursor.fetchall()

    host_urls: dict[str, list[str]] = {}
    for r in rows:
        host_urls.setdefault(r["host"], []).append(r["url"])

    count = 0
    for host, urls in host_urls.items():
        target_dir = os.path.join(nmap_dir, f"nmap-{host}")
        os.makedirs(target_dir, exist_ok=True)
        with open(os.path.join(target_dir, "dalfox_targets.txt"), "w") as f:
            for u in urls:
                f.write(f"{u}\n")
        count += len(urls)
    
    # ── Injected params from Arjun (GET → URL file, POST → separate file) ──
    injected = _get_injected_targets(proj_path, "dalfox")
    for host, targets in injected.items():
        target_dir = os.path.join(nmap_dir, f"nmap-{host}")
        os.makedirs(target_dir, exist_ok=True)
        if targets["get"]:
            with open(os.path.join(target_dir, "dalfox_targets.txt"), "a") as f:
                for u in targets["get"]:
                    f.write(f"{u}\n")
        if targets["post"]:
            # "w" = rebuild fresh, not append (prevents re-feeding stale targets)
            with open(os.path.join(target_dir, "dalfox_post_targets.txt"), "w") as f:
                for url, data in targets["post"]:
                    f.write(f"{url}|{data}\n")

    injected_count = sum(
        len(t["get"]) + len(t["post"]) for t in injected.values()
    )
    console.print(
        f" [dim]↳ Feed Dalfox: {count} URLs base + {injected_count} injetáveis "
        f"para {len(host_urls)} hosts.[/dim]"
    )


def feed_sqlmap(proj_path: str, nmap_dir: str):
    """Feed injectable params to sqlmap (GET URLs + POST pairs)."""
    injected = _get_injected_targets(proj_path, "sqlmap")
    for host, targets in injected.items():
        target_dir = os.path.join(nmap_dir, f"nmap-{host}")
        os.makedirs(target_dir, exist_ok=True)
        if targets["get"]:
            with open(os.path.join(target_dir, "sqlmap_get.txt"), "w") as f:
                for u in targets["get"]:
                    f.write(f"{u}\n")
        if targets["post"]:
            with open(os.path.join(target_dir, "sqlmap_post.txt"), "w") as f:
                for url, data in targets["post"]:
                    f.write(f"{url}|{data}\n")
    console.print(f" [dim]↳ Feed SQLMap: injetáveis para {len(injected)} hosts.[/dim]")


def feed_all(proj_path: str, nmap_dir: str):
    feed_nwrapper(proj_path, nmap_dir, cycle=True)
    feed_httpx(proj_path, nmap_dir)
    feed_katana(proj_path, nmap_dir)
    feed_ferox(proj_path, nmap_dir)
    feed_jsfinder(proj_path, nmap_dir)
    feed_gf(proj_path, nmap_dir)
    feed_screenshot(proj_path, nmap_dir)
    feed_nuclei(proj_path, nmap_dir)
    feed_dalfox(proj_path, nmap_dir)
    feed_arjun(proj_path, nmap_dir)
    feed_sqlmap(proj_path, nmap_dir)

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
