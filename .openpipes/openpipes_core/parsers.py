import os
import json
import re
import socket
import subprocess
import sqlite3
import xml.etree.ElementTree as ET
import glob
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import db
from rich.console import Console

console = Console()

CONFIG_FILE = os.path.expanduser("~/.openpipes/config.sh")


# ═════════════════════════════════════════════════════════════════════
# FUNÇÕES AUXILIARES
# ═════════════════════════════════════════════════════════════════════

def _normalize_url(url: str) -> str:
    if not url:
        return url
    parsed = urlparse(url)
    if (parsed.scheme == "http" and parsed.port == 80) or \
       (parsed.scheme == "https" and parsed.port == 443):
        url = f"{parsed.scheme}://{parsed.hostname}{parsed.path}"
    return url.rstrip("/")


def get_obsdir():
    """Descobre o caminho do cofre do Obsidian lendo o config.sh"""
    if os.path.exists(CONFIG_FILE):
        try:
            cmd = f"source {CONFIG_FILE} && echo -n \"$obsdir|$proj_name\""
            res = subprocess.check_output(
                cmd, shell=True, executable="/bin/bash", text=True
            ).split("|")
            if len(res) == 2:
                return os.path.join(res[0], res[1])
        except Exception:
            pass
    return None


def is_ipv4(string):
    return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', string))


def _ensure_port(cursor, host_id, port, protocol="tcp", service=None):
    """Create a port record for a host if one doesn't exist yet."""
    if not host_id or not port:
        return
    try:
        cursor.execute("""
            INSERT INTO ports (host_id, port, protocol, state, service, version)
            VALUES (?, ?, ?, 'open', ?, '')
            ON CONFLICT(host_id, port, protocol) DO NOTHING
        """, (host_id, port, protocol, service or "unknown"))
    except Exception:
        pass


def get_or_create_host(cursor, host_target, ips_to_add=None, cnames_to_add=None, skip_ip_correlation=False):
    if not host_target:
        return None

    clean_host = host_target.split(':')[0].strip().lower()
    ips_to_add = ips_to_add if ips_to_add else []
    cnames_to_add = cnames_to_add if cnames_to_add else []
    if not isinstance(ips_to_add, list):
        ips_to_add = [ips_to_add]
    if not isinstance(cnames_to_add, list):
        cnames_to_add = [cnames_to_add]

    # CORRELAÇÃO REVERSA PARA IPs ÓRFÃOS
    if is_ipv4(clean_host):
        if clean_host in ['1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4']:
            return None
        cursor.execute("SELECT id FROM hosts WHERE ips LIKE ?", (f'%"{clean_host}"%',))
        row = cursor.fetchone()
        if row:
            return row['id']

    cursor.execute('SELECT id, ips, cnames FROM hosts WHERE host = ?', (clean_host,))
    row = cursor.fetchone()

    if row:
        host_id = row['id']
        try:
            current_ips = json.loads(row['ips']) if row['ips'] else []
        except Exception:
            current_ips = []
        try:
            current_cnames = json.loads(row['cnames']) if row['cnames'] else []
        except Exception:
            current_cnames = []

        needs_update = False
        for ip in ips_to_add:
            if ip and ip not in current_ips and ip != clean_host and not is_ipv4(clean_host):
                current_ips.append(ip)
                needs_update = True
        for cname in cnames_to_add:
            if cname and cname not in current_cnames and cname != clean_host:
                current_cnames.append(cname)
                needs_update = True

        if needs_update:
            cursor.execute(
                'UPDATE hosts SET ips = ?, cnames = ? WHERE id = ?',
                (json.dumps(current_ips), json.dumps(current_cnames), host_id),
            )
        return host_id

    # ── IP correlation for orphan IPs (skipped when skip_ip_correlation=True) ──
    if not skip_ip_correlation:
        for ip in ips_to_add:
            if is_ipv4(ip):
                cursor.execute("SELECT id, ips FROM hosts WHERE ips LIKE ?", (f'%"{ip}"%',))
                existing = cursor.fetchone()
                if existing:
                    host_id = existing['id']
                    try:
                        current_ips = json.loads(existing['ips']) if existing['ips'] else []
                    except Exception:
                        current_ips = []
                    merged_ips = list(set(current_ips + [ip for ip in ips_to_add if is_ipv4(ip)]))
                    cursor.execute(
                        'UPDATE hosts SET ips = ? WHERE id = ?',
                        (json.dumps(merged_ips), host_id),
                    )
                    return host_id

    # ── Create new host entry ──
    initial_ips = json.dumps([ip for ip in ips_to_add if ip and ip != clean_host and not is_ipv4(clean_host)])
    initial_cnames = json.dumps([c for c in cnames_to_add if c and c != clean_host])
    cursor.execute(
        'INSERT INTO hosts (host, ips, cnames) VALUES (?, ?, ?)',
        (clean_host, initial_ips, initial_cnames),
    )
    return cursor.lastrowid


def resolve_domain(domain):
    try:
        _, _, ip_list = socket.gethostbyname_ex(domain)
        return domain, ip_list
    except Exception:
        return domain, []


def extract_urls_from_file(file_path):
    urls = set()
    url_pattern = re.compile(r'https?://[a-zA-Z0-9.\-]+(?:/[^\s]*)?')
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                urls.update(url_pattern.findall(line))
    except Exception:
        pass
    return urls


def process_httpx_json(cursor, json_file, source_name="httpx"):
    count_endpoints = 0
    resolved_in_httpx = {}

    with open(json_file, 'r') as f:
        for line in f:
            try:
                data = json.loads(line.strip())
            except json.JSONDecodeError:
                continue

            host_str = data.get('host', data.get('input', '')).split(':')[0]
            ips = data.get('a', []) + data.get('aaaa', [])
            if not ips and data.get('host_ip'):
                ips = [data.get('host_ip')]
            cnames = data.get('cname', [])

            if host_str and ips and not is_ipv4(host_str):
                resolved_in_httpx[host_str] = ips

            host_id = get_or_create_host(cursor, host_str, ips, cnames, skip_ip_correlation=True)
            if host_id and not data.get('failed', False):
                cursor.execute('UPDATE hosts SET is_alive = 1 WHERE id = ?', (host_id,))


            url = data.get('url', '')
            if url:
                cursor.execute("""
                    INSERT INTO endpoints
                        (host_id, url, status_code, content_length, content_type,
                        title, web_server, tech_stack, source_tool)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(url) DO UPDATE SET
                        status_code = CASE WHEN excluded.status_code BETWEEN 200 AND 599
                                        THEN excluded.status_code ELSE status_code END,
                        content_length = CASE WHEN excluded.content_length > 0
                                            THEN excluded.content_length ELSE content_length END,
                        title = CASE WHEN excluded.title IS NOT NULL AND excluded.title != ''
                                    THEN excluded.title ELSE title END,
                        tech_stack = CASE WHEN excluded.tech_stack IS NOT NULL AND excluded.tech_stack != '[]'
                                        THEN excluded.tech_stack ELSE tech_stack END,
                        web_server = CASE WHEN excluded.web_server IS NOT NULL AND excluded.web_server != ''
                                        THEN excluded.web_server ELSE web_server END
                """, (
                    host_id, url,
                    data.get('status_code', 0),
                    data.get('content_length', 0),
                    data.get('content_type', ''),
                    data.get('title', ''),
                    data.get('webserver', ''),
                    json.dumps(data.get('tech', [])),
                    source_name,
                ))

                count_endpoints += 1

                # Ensure a port record exists for this endpoint
                ep_port = data.get("port")
                if ep_port:
                    _ensure_port(cursor, host_id, ep_port, "tcp",
                                 data.get("webserver") or None)

    return count_endpoints, resolved_in_httpx


# ═════════════════════════════════════════════════════════════════════
# PARSERS NÚCLEO
# ═════════════════════════════════════════════════════════════════════

def parse_recon(proj_path, recon_dir):
    with db.get_connection(proj_path) as conn:
        with db.transaction(conn):
            cursor = conn.cursor()
            httpx_already_resolved = {}

            for root, dirs, files in os.walk(recon_dir):
                for file in files:
                    if file.endswith('.httpx.json'):
                        _, resolved = process_httpx_json(cursor, os.path.join(root, file), source_name="recon_httpx")
                        httpx_already_resolved.update(resolved)

            domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
            unique_hosts = set()

            for root, dirs, files in os.walk(recon_dir):
                for file in files:
                    if (file.endswith('.txt') or 'subs' in file) and not file.endswith('.json'):
                        try:
                            with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                                for line in f:
                                    clean_line = re.sub(r'https?://', '', line).strip()
                                    for h in domain_pattern.findall(clean_line):
                                        h = h.strip().lower()
                                        if h and not h.startswith('.') and len(h) > 3 and not is_ipv4(h):
                                            unique_hosts.add(h)
                        except Exception:
                            pass

            domains_to_resolve = [dom for dom in unique_hosts if dom not in httpx_already_resolved]
            resolved_data = {}

            if domains_to_resolve:
                with ThreadPoolExecutor(max_workers=50) as executor:
                    futures = {executor.submit(resolve_domain, dom): dom for dom in domains_to_resolve}
                    for future in as_completed(futures):
                        dom, ips = future.result()
                        resolved_data[dom] = ips

            for dom, ips in resolved_data.items():
                cursor.execute(
                    "INSERT INTO hosts (host, ips) VALUES (?, ?) ON CONFLICT(host) DO UPDATE SET ips=excluded.ips",
                    (dom, json.dumps(ips)),
                )

    console.print(f" [dim]↳ Parser Recon: Mapeou {len(unique_hosts)} Domínios limpos.[/dim]")


def parse_nmap(proj_path, nmap_dir):
    with db.get_connection(proj_path) as conn:
        with db.transaction(conn):
            cursor = conn.cursor()
            count_ports = 0
            count_whois = 0

            for root, dirs, files in os.walk(nmap_dir):
                for file in files:
                    if not file.endswith('.xml'):
                        continue
                    try:
                        tree = ET.parse(os.path.join(root, file))
                    except Exception:
                        continue

                    # Extract original target from folder name
                    folder_name = os.path.basename(root)  # "nmap-www.randon.com.br"
                    original_target = folder_name[5:] if folder_name.startswith("nmap-") else None

                    for host_node in tree.getroot().findall('host'):
                        ip = ""
                        hostname = ""
                        for address in host_node.findall('address'):
                            if address.get('addrtype') == 'ipv4':
                                ip = address.get('addr')
                        for hostnames in host_node.findall('hostnames'):
                            for hname in hostnames.findall('hostname'):
                                hostname = hname.get('name')
                        xml_target = hostname if hostname else ip
                        if not xml_target:
                            continue

                        # Use original scanned target as PRIMARY when available
                        # (nmap XML often reports rDNS instead of the scanned hostname)
                        if original_target and not is_ipv4(original_target) and original_target != xml_target:
                            primary_target = original_target
                        else:
                            primary_target = xml_target

                        # PRIMARY: Always create/update by exact hostname (bypass IP correlation)
                        cursor.execute("INSERT OR IGNORE INTO hosts (host) VALUES (?)", (primary_target,))
                        cursor.execute("UPDATE hosts SET is_alive = 1 WHERE host = ?", (primary_target,))
                        cursor.execute("SELECT id, ips FROM hosts WHERE host = ?", (primary_target,))
                        row = cursor.fetchone()
                        if row:
                            host_id = row["id"]
                            current_ips = json.loads(row["ips"]) if row["ips"] else []
                            if ip and ip not in current_ips:
                                current_ips.append(ip)
                                cursor.execute("UPDATE hosts SET ips = ? WHERE id = ?",
                                            (json.dumps(current_ips), host_id))
                        else:
                            host_id = None

                        # Also ensure the XML-reported hostname exists and is alive (rDNS)
                        if xml_target != primary_target:
                            sec_id = get_or_create_host(cursor, xml_target, [ip] if ip else [])
                            if sec_id:
                                cursor.execute('UPDATE hosts SET is_alive = 1 WHERE id = ?', (sec_id,))

                        whois_data = ""
                        for script in host_node.findall(".//script"):
                            if script.get('id') in ('whois-ip', 'whois-domain'):
                                whois_data = script.get('output', '')
                        if whois_data:
                            cursor.execute('UPDATE hosts SET whois_data = ? WHERE id = ?', (whois_data.strip(), host_id))
                            count_whois += 1

                        # ── Insert ports from nmap ──
                        ports_node = host_node.find('ports')
                        if ports_node is not None:
                            for port in ports_node.findall('port'):
                                portid = port.get('portid')
                                protocol = port.get('protocol')
                                state = port.find('state').get('state') if port.find('state') is not None else 'unknown'
                                srv_node = port.find('service')
                                service_name = srv_node.get('name') if srv_node is not None else ''
                                product = srv_node.get('product') if srv_node is not None else ''
                                version = srv_node.get('version') if srv_node is not None else ''
                                cursor.execute("""
                                    INSERT INTO ports (host_id, port, protocol, state, service, version)
                                    VALUES (?, ?, ?, ?, ?, ?)
                                    ON CONFLICT(host_id, port, protocol) DO UPDATE SET
                                        state=excluded.state, service=excluded.service, version=excluded.version
                                """, (host_id, portid, protocol, state, service_name, f"{product} {version}".strip()))
                                count_ports += 1

                        # ── Propagate to sibling hostnames sharing this IP ──
                        if ip and host_id:
                            cursor.execute("SELECT id FROM hosts WHERE ips LIKE ? AND id != ?",
                                           (f'%"{ip}"%', host_id))
                            siblings = cursor.fetchall()
                            if siblings:
                                sibling_ids = [s['id'] for s in siblings]
                                # Mark all siblings as alive
                                placeholders = ','.join('?' for _ in sibling_ids)
                                cursor.execute(f"""
                                    UPDATE hosts SET is_alive = 1
                                    WHERE id IN ({placeholders})
                                """, sibling_ids)
                                # Copy ports from scanned host to siblings
                                cursor.execute(
                                    "SELECT port, protocol, state, service, version FROM ports WHERE host_id = ?",
                                    (host_id,)
                                )
                                ports_data = cursor.fetchall()
                                for sid in sibling_ids:
                                    for p in ports_data:
                                        cursor.execute("""
                                            INSERT INTO ports (host_id, port, protocol, state, service, version)
                                            VALUES (?, ?, ?, ?, ?, ?)
                                            ON CONFLICT(host_id, port, protocol) DO UPDATE SET
                                                state = excluded.state,
                                                service = excluded.service,
                                                version = excluded.version
                                        """, (sid, p['port'], p['protocol'], p['state'],
                                              p['service'] or '', p['version'] or ''))

    console.print(f" [dim]↳ Parser Nmap: Inseriu {count_ports} portas abertas e extraiu {count_whois} dados de WHOIS.[/dim]")


def parse_httpx(proj_path, nmap_dir):
    json_file = os.path.join(nmap_dir, "httpx_output.json")
    if not os.path.exists(json_file):
        return
    with db.get_connection(proj_path) as conn:
        with db.transaction(conn):
            cursor = conn.cursor()
            count_endpoints, _ = process_httpx_json(cursor, json_file, source_name="httpx")
    console.print(f" [dim]↳ Parser HTTPx: Ingeriu {count_endpoints} URLs e Tecnologias.[/dim]")


def parse_url_discovery(proj_path, nmap_dir, tool_name):
    """Legacy text-based URL parser (fallback when JSONL not available)."""
    with db.get_connection(proj_path) as conn:
        with db.transaction(conn):
            cursor = conn.cursor()
            count = 0
            urls = set()

            for root, dirs, files in os.walk(nmap_dir):
                for file in files:
                    if tool_name in file.lower() and file.endswith('.txt'):
                        urls.update(extract_urls_from_file(os.path.join(root, file)))

            for url in urls:
                try:
                    host_str = urlparse(url).hostname
                    if host_str:
                        host_id = get_or_create_host(cursor, host_str)
                        if host_id:
                            cursor.execute(
                                "INSERT INTO endpoints (host_id, url, source_tool) VALUES (?, ?, ?) ON CONFLICT(url) DO NOTHING",
                                (host_id, url, tool_name),
                            )
                            if cursor.rowcount > 0:
                                count += 1

                            parsed = urlparse(url)
                            ep_port = parsed.port or (443 if parsed.scheme == "https" else 80)
                            service_map = {80: "http", 443: "https", 8080: "http-proxy",
                                           8443: "https", 8000: "http", 10443: "https"}
                            _ensure_port(cursor, host_id, ep_port, "tcp",
                                         service_map.get(ep_port, "unknown"))
                except Exception:
                    pass

    if count > 0:
        console.print(f" [dim]↳ Parser {tool_name}: Mapeou {count} Endpoints (TXT).[/dim]")


def parse_url_discovery_jsonl(proj_path, nmap_dir, tool_name):
    """
    Parse JSONL output from katana or feroxbuster.
    Handles both nested (katana) and flat (feroxbuster) formats.
    """
    with db.get_connection(proj_path) as conn:
        with db.transaction(conn):
            cursor = conn.cursor()
            count = 0
            jsonl_files = []

            for root, dirs, files in os.walk(nmap_dir):
                for file in files:
                    if tool_name in file.lower() and (file.endswith('.jsonl') or file.endswith('.json')):
                        jsonl_files.append(os.path.join(root, file))

            if not jsonl_files:
                parse_url_discovery(proj_path, nmap_dir, tool_name)
                return

            for jsonl_file in jsonl_files:
                try:
                    with open(jsonl_file, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                data = json.loads(line)
                            except json.JSONDecodeError:
                                continue

                            # Skip feroxbuster configuration line
                            if data.get("type") == "configuration":
                                continue

                            # Skip error entries
                            if data.get("error"):
                                continue

                            # Skip feroxbuster wildcard responses (known false positives)
                            if data.get("wildcard") is True:
                                continue

                            # Extract URL — handle both formats
                            # Feroxbuster: data["url"]
                            # Katana: data["request"]["endpoint"]
                            url = data.get("url", "")
                            if not url:
                                request_data = data.get("request", {})
                                url = request_data.get("endpoint", "") or data.get("url", "")
                            if not url:
                                continue

                            host_str = urlparse(url).hostname
                            if not host_str:
                                continue

                            host_id = get_or_create_host(cursor, host_str)
                            if not host_id:
                                continue

                            # Extract status — handle both formats
                            # Feroxbuster: data["status"]
                            # Katana: data["response"]["status_code"]
                            status_code = data.get("status")
                            if status_code is None:
                                response_data = data.get("response", {})
                                status_code = response_data.get("status_code") if response_data else None
                            
                            # Skip entries without a valid status code
                            if status_code is None or status_code == 0:
                                continue

                            # Extract content_length — handle both formats
                            content_length = data.get("content_length")
                            if content_length is None:
                                response_data = data.get("response", {})
                                content_length = response_data.get("content_length") if response_data else None

                            cursor.execute("""
                                INSERT INTO endpoints
                                    (host_id, url, status_code, content_length, source_tool)
                                VALUES (?, ?, ?, ?, ?)
                                ON CONFLICT(url) DO UPDATE SET
                                    status_code = CASE WHEN excluded.status_code BETWEEN 200 AND 599
                                                    THEN excluded.status_code ELSE status_code END,
                                    content_length = CASE WHEN excluded.content_length > 0
                                                        THEN excluded.content_length ELSE content_length END
                            """, (host_id, url, status_code, content_length, tool_name))

                            if cursor.rowcount > 0:
                                count += 1

                            # Ensure port record exists
                            parsed = urlparse(url)
                            ep_port = parsed.port or (443 if parsed.scheme == "https" else 80)
                            _ensure_port(cursor, host_id, ep_port, "tcp")
                except Exception:
                    continue

    console.print(f" [dim]↳ Parser {tool_name}: Ingeriu {count} endpoints com metadados.[/dim]")


def parse_screenshot(proj_path, nmap_dir):
    """
    Parse gowitness JSONL output + screenshot files from each target's
    $NMAP_DIR/nmap-$target/Screenshots/ directory.
    """
    with db.get_connection(proj_path) as conn:
        with db.transaction(conn):
            cursor = conn.cursor()
            count = 0

            for nmap_folder in sorted(os.listdir(nmap_dir)):
                if not nmap_folder.startswith("nmap-"):
                    continue
                target_name = nmap_folder[5:]
                ss_dir = os.path.join(nmap_dir, nmap_folder, "Screenshots")
                jsonl_file = os.path.join(ss_dir, "go.jsonl")
                if not os.path.exists(jsonl_file):
                    continue

                # Find host_id by target name
                host_id = get_or_create_host(cursor, target_name)
                if not host_id:
                    continue

                try:
                    with open(jsonl_file, "r") as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                data = json.loads(line)
                            except json.JSONDecodeError:
                                continue

                            file_name = data.get("file_name", "")
                            if not file_name:
                                continue

                            source_url = data.get("url", "")
                            final_url = data.get("final_url", "")
                            status_code = data.get("status_code")
                            title = data.get("title", "")
                            content_length = data.get("content_length")

                            cursor.execute("""
                                INSERT INTO screenshots
                                    (host_id, file_path, source_url, final_url, status_code, title, content_length)
                                VALUES (?, ?, ?, ?, ?, ?, ?)
                                ON CONFLICT(file_path) DO NOTHING""",
                                (host_id, file_name, source_url, final_url, status_code, title, content_length),
                            )

                            if cursor.rowcount > 0:
                                count += 1
                except Exception:
                    continue

    console.print(f" [dim]↳ Parser Screenshots (JSONL): Associou {count} imagens a hosts.[/dim]")



def parse_gf(proj_path, nmap_dir):
    with db.get_connection(proj_path) as conn:
        with db.transaction(conn):
            cursor = conn.cursor()
            count = 0
            for nmap_folder in sorted(os.listdir(nmap_dir)):
                if not nmap_folder.startswith("nmap-"):
                    continue
                gf_file = os.path.join(nmap_dir, nmap_folder, "gf-summary.json")
                if not os.path.exists(gf_file):
                    continue
                try:
                    with open(gf_file, "r") as f:
                        data = json.load(f)
                except (json.JSONDecodeError, IOError):
                    continue
                gf_patterns = data.get("gf_patterns", {})
                for pattern_name, urls in gf_patterns.items():
                    for url in urls:
                        if not url.strip():
                            continue
                        cursor.execute(
                            "SELECT id, vulnerability_patterns FROM endpoints WHERE url = ?",
                            (url.strip(),),
                        )
                        row = cursor.fetchone()
                        if row:
                            patterns = json.loads(row["vulnerability_patterns"]) if row["vulnerability_patterns"] else []
                            if pattern_name not in patterns:
                                patterns.append(pattern_name)
                                cursor.execute(
                                    "UPDATE endpoints SET vulnerability_patterns = ? WHERE id = ?",
                                    (json.dumps(patterns), row["id"]),
                                )
                                count += 1
    console.print(f" [dim]↳ Parser GF: Injetou {count} Tags de Padrões em Endpoints.[/dim]")


def parse_jsfinder(proj_path, nmap_dir):
    with db.get_connection(proj_path) as conn:
        with db.transaction(conn):
            cursor = conn.cursor()
            count = 0
            for nmap_folder in sorted(os.listdir(nmap_dir)):
                if not nmap_folder.startswith("nmap-"):
                    continue
                js_file = os.path.join(nmap_dir, nmap_folder, "jsfinder-results.json")
                if not os.path.exists(js_file):
                    continue
                try:
                    with open(js_file, "r") as f:
                        data = json.load(f)
                except (json.JSONDecodeError, IOError):
                    continue
                results = data.get("results", [])
                for entry in results:
                    source_js_url = entry.get("source_js_url", "")
                    if not source_js_url:
                        continue
                    host_str = urlparse(source_js_url).hostname
                    if not host_str:
                        continue
                    host_id = get_or_create_host(cursor, host_str)
                    if not host_id:
                        continue
                    for route in entry.get("discovered_routes", []):
                        if not route.strip():
                            continue
                        try:
                            cursor.execute(
                                """INSERT INTO js_discoveries
                                   (host_id, source_js_url, discovered_route)
                                   VALUES (?, ?, ?)
                                   ON CONFLICT DO NOTHING""",
                                (host_id, source_js_url, route.strip()),
                            )
                            if cursor.rowcount > 0:
                                count += 1
                        except Exception:
                            continue
    console.print(f" [dim]↳ Parser JSFinder: Salvou {count} rotas/arquivos descobertos no JS.[/dim]")


# ═════════════════════════════════════════════════════════════════════
# PARSE_NUCLEI
# ═════════════════════════════════════════════════════════════════════

def parse_nuclei(proj_path, nmap_dir):
    """Parse nuclei output from per-target JSON files (array or JSONL format)."""
    with db.get_connection(proj_path) as conn:
        with db.transaction(conn):
            cursor = conn.cursor()
            count = 0

            for nmap_folder in sorted(os.listdir(nmap_dir)):
                if not nmap_folder.startswith("nmap-"):
                    continue
                json_file = os.path.join(nmap_dir, nmap_folder, "nuclei_output.json")
                if not os.path.exists(json_file):
                    continue

                # Read all content and detect format
                with open(json_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read().strip()
                if not content:
                    continue

                # Parse — handles both JSON array and JSONL formats
                try:
                    if content.startswith("["):
                        items = json.loads(content)
                    else:
                        items = []
                        for line in content.split("\n"):
                            line = line.strip()
                            if line:
                                items.append(json.loads(line))
                except (json.JSONDecodeError, ValueError):
                    continue

                for data in items:
                    host_str = data.get("host") or data.get("ip", "")
                    if not host_str:
                        continue

                    ips = [data["ip"]] if data.get("ip") else []
                    host_id = get_or_create_host(cursor, host_str, ips)
                    if not host_id:
                        continue

                    info = data.get("info", {}) or {}
                    vuln_name = data.get("template-id") or info.get("name", "unknown")
                    raw_severity = (data.get("severity") or info.get("severity", "info")).lower()
                    severity_label = {
                        "critical": "Crítica", "high": "Alta",
                        "medium": "Média", "low": "Baixa", "info": "Info",
                    }.get(raw_severity, raw_severity.capitalize())

                    cvss_score = data.get("cvss-score") or info.get("cvss-score")
                    cvss_vector = data.get("cvss-metrics") or info.get("cvss-metrics")
                    cve_raw = data.get("cve-id") or info.get("cve-id", [])
                    cve_id = ",".join(cve_raw) if isinstance(cve_raw, list) else str(cve_raw) if cve_raw else ""
                    description = data.get("description") or info.get("description", "")
                    remediation = data.get("remediation") or info.get("remediation", "")
                    matched_at = data.get("matched-at", "")
                    curl_command = data.get("curl-command", "")
                    title = data.get("name") or info.get("name", vuln_name)
                    raw_refs = data.get("reference") or info.get("references") or []
                    raw_refs = [raw_refs] if isinstance(raw_refs, str) and raw_refs.strip() else raw_refs

                    try:
                        cursor.execute("""
                            INSERT INTO vulnerabilities
                                (host_id, title, severity, cvss_score, cvss_vector,
                                 cve_id, vuln_name, description, matched_at,
                                 curl_command, remediation, reference_urls, source_tool)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ON CONFLICT(vuln_name, matched_at, host_id) DO UPDATE SET
                                severity=excluded.severity, cvss_score=excluded.cvss_score,
                                cvss_vector=excluded.cvss_vector, cve_id=excluded.cve_id,
                                description=excluded.description, remediation=excluded.remediation,
                                reference_urls=excluded.reference_urls, source_tool=excluded.source_tool
                        """, (
                            host_id, title, severity_label,
                            float(cvss_score) if cvss_score else None,
                            cvss_vector or None, cve_id or None,
                            vuln_name, description, matched_at,
                            curl_command, remediation,
                            json.dumps(raw_refs), "nuclei",
                        ))
                        if cursor.rowcount > 0:
                            count += 1
                    except Exception:
                        continue

    console.print(f" [dim]↳ Parser Nuclei: Inseriu {count} vulnerabilidades.[/dim]")


def parse_dalfox(proj_path, nmap_dir):
    """Parse dalfox JSONL output into vulnerabilities table."""
    count = 0
    with db.get_connection(proj_path) as conn:
        with db.transaction(conn):
            cursor = conn.cursor()

            for root, dirs, files in os.walk(nmap_dir):
                for file in files:
                    if file != "dalfox_output.json":
                        continue

                    target_name = os.path.basename(root)[5:]  # strip "nmap-"
                    host_id = get_or_create_host(cursor, target_name, skip_ip_correlation=True)
                    if not host_id:
                        continue

                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            for line in f:
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    data = json.loads(line)
                                except json.JSONDecodeError:
                                    continue

                                # Skip non-vulnerability lines (info, safe, etc.)
                                if data.get("type") not in ("vulnerability",):
                                    continue

                                param = data.get("data", {}).get("param", "unknown")
                                poc = data.get("data", {}).get("poc", "")
                                payload = data.get("data", {}).get("payload", "")
                                vuln_type = data.get("data", {}).get("type", "XSS")
                                severity = data.get("data", {}).get("severity", "Alta")
                                cwe = data.get("data", {}).get("cwe", "")
                                ref = data.get("data", {}).get("ref", "")

                                title = f"{vuln_type} in parameter: {param}"
                                desc_parts = []
                                if payload:
                                    desc_parts.append(f"**Payload:** `{payload}`")
                                if cwe:
                                    desc_parts.append(f"**CWE:** {cwe}")
                                if ref:
                                    desc_parts.append(f"**References:** {ref}")
                                description = "\n\n".join(desc_parts) if desc_parts else f"XSS detected via parameter `{param}`."

                                # Map dalfox severity to our severity scale
                                sev_map = {
                                    "Critical": "Crítica",
                                    "High": "Alta",
                                    "Medium": "Média",
                                    "Low": "Baixa",
                                    "Info": "Info",
                                }
                                mapped_severity = sev_map.get(severity, "Média")

                                cursor.execute("""
                                    INSERT INTO vulnerabilities
                                        (host_id, title, severity, description, evidence,
                                         source_tool, status, enriched_by)
                                    VALUES (?, ?, ?, ?, ?, 'dalfox', 'open', NULL)
                                    ON CONFLICT(host_id, title) DO NOTHING
                                """, (host_id, title, mapped_severity, description, poc))

                                if cursor.rowcount > 0:
                                    count += 1
                    except FileNotFoundError:
                        pass

    console.print(f" [dim]↳ Parser Dalfox: Inseriu {count} novas vulnerabilidades (XSS).[/dim]")



# ═════════════════════════════════════════════════════════════════════
# PARSE_WHOIS_ENRICHMENT
# ═════════════════════════════════════════════════════════════════════

def parse_whois_enrichment(proj_path, nmap_dir):
    with db.get_connection(proj_path) as conn:
        with db.transaction(conn):
            cursor = conn.cursor()
            count = 0
            for root, dirs, files in os.walk(nmap_dir):
                for file in files:
                    if not file.endswith(".xml"):
                        continue
                    try:
                        tree = ET.parse(os.path.join(root, file))
                    except Exception:
                        continue
                    for host_node in tree.getroot().findall("host"):
                        ip = ""
                        hostname = ""
                        for address in host_node.findall("address"):
                            if address.get("addrtype") == "ipv4":
                                ip = address.get("addr")
                        for hostnames in host_node.findall("hostnames"):
                            for hname in hostnames.findall("hostname"):
                                hostname = hname.get("name")
                        target = hostname if hostname else ip
                        if not target:
                            continue
                        whois_data = ""
                        for script in host_node.findall(".//script"):
                            if script.get("id") in ("whois-ip", "whois-domain"):
                                whois_data = script.get("output", "")
                        if whois_data:
                            host_id = get_or_create_host(cursor, target, [ip] if ip else [])
                            if host_id:
                                cursor.execute(
                                    "UPDATE hosts SET whois_data = ? WHERE id = ?",
                                    (whois_data.strip(), host_id),
                                )
                                count += 1
    console.print(f" [dim]↳ Parser WHOIS: Atualizou WHOIS de {count} hosts.[/dim]")


def parse_whois_from_initial(proj_path, nmap_dir):
    """
    Parse WHOIS data from the $NMAP_DIR/nmap-$target/initial file.
    This file is generated by: nmap -oN initial --script=whois-ip ...

    The relevant section looks like:
      Host script results:
      | whois-ip: Record found at whois.arin.net
      | netrange: 23.192.0.0 - 23.223.255.255
      | netname: AKAMAI
      | orgname: Akamai Technologies, Inc.
      | ...
    """
    with db.get_connection(proj_path) as conn:
        with db.transaction(conn):
            cursor = conn.cursor()
            count = 0

            for nmap_folder in sorted(os.listdir(nmap_dir)):
                if not nmap_folder.startswith("nmap-"):
                    continue
                initial_file = os.path.join(nmap_dir, nmap_folder, "initial")
                if not os.path.exists(initial_file):
                    continue

                # Extract hostname/IP from the initial file header
                target_name = None
                target_ip = None
                whois_fields = {}
                in_whois_section = False

                try:
                    with open(initial_file, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line_stripped = line.strip()

                            # Grab hostname from: Nmap scan report for <host> (<ip>)
                            if line_stripped.startswith("Nmap scan report for "):
                                remainder = line_stripped[21:]  # after "Nmap scan report for "
                                if "(" in remainder and ")" in remainder:
                                    target_name = remainder.split("(")[0].strip()
                                    target_ip = remainder.split("(")[1].split(")")[0].strip()
                                else:
                                    target_name = remainder.strip()

                            # Detect WHOIS section start
                            if line_stripped == "Host script results:":
                                in_whois_section = True
                                continue

                            if in_whois_section:
                                # Lines like: | key: value
                                # Last line: |_key: value
                                if line_stripped.startswith("| ") or line_stripped.startswith("|_"):
                                    # Strip prefix
                                    content = line_stripped[2:] if line_stripped.startswith("| ") else line_stripped[2:]
                                    if ": " in content:
                                        key, value = content.split(": ", 1)
                                        whois_fields[key.strip()] = value.strip()
                                elif line_stripped == "":
                                    # Empty line ends the section
                                    in_whois_section = False
                except Exception:
                    continue

                if not whois_fields:
                    continue

                # Store as structured JSON
                whois_json = json.dumps(whois_fields, ensure_ascii=False)

                # Find the host in DB — try hostname first, then IP
                host_id = None
                if target_name:
                    cursor.execute(
                        "SELECT id FROM hosts WHERE host = ?",
                        (target_name.lower(),),
                    )
                    row = cursor.fetchone()
                    if row:
                        host_id = row["id"]

                if not host_id and target_ip:
                    cursor.execute(
                        "SELECT id FROM hosts WHERE ips LIKE ?",
                        (f'%"{target_ip}"%',),
                    )
                    row = cursor.fetchone()
                    if row:
                        host_id = row["id"]

                if host_id:
                    cursor.execute(
                        "UPDATE hosts SET whois_data = ? WHERE id = ?",
                        (whois_json, host_id),
                    )
                    count += 1

    console.print(f" [dim]↳ Parser WHOIS (initial): Processou {count} hosts.[/dim]")


# ═════════════════════════════════════════════════════════════════════
# FALSE POSITIVE DETECTION
# ═════════════════════════════════════════════════════════════════════

def flag_false_positives(proj_path: str):
    """
    Tag endpoints as potential_false_positive based on:
    1. Content-length clustering (5+ URLs, same host+status+size → same error page)
    2. Error keywords in title
    """
    error_titles = [
        "not found", "404", "error", "forbidden", "access denied",
        "page not found", "pagina nao encontrada", "página não encontrada",
        "erro", "acesso negado", "nao encontrado", "não encontrado",
        "bad request", "internal server error", "method not allowed",
        "access denied", "blocked", "waf", "security",
    ]

    with db.get_connection(proj_path) as conn:
        with db.transaction(conn):
            cursor = conn.cursor()
            tagged = 0

            # ── Cluster detection: 5+ endpoints with same host+status+size ──
            cursor.execute("""
                SELECT host_id, status_code, content_length, COUNT(*) as cnt
                FROM endpoints
                WHERE content_length > 0
                GROUP BY host_id, status_code, content_length
                HAVING cnt >= 5
                ORDER BY cnt DESC
            """)
            clusters = cursor.fetchall()
            for row in clusters:
                cursor.execute("""
                    SELECT id, url, vulnerability_patterns FROM endpoints
                    WHERE host_id = ? AND status_code = ? AND content_length = ?
                """, (row["host_id"], row["status_code"], row["content_length"]))
                for ep in cursor.fetchall():
                    patterns = json.loads(ep["vulnerability_patterns"]) if ep["vulnerability_patterns"] else []
                    if "potential_false_positive" not in patterns:
                        patterns.append("potential_false_positive")
                        cursor.execute(
                            "UPDATE endpoints SET vulnerability_patterns = ? WHERE id = ?",
                            (json.dumps(patterns), ep["id"]),
                        )
                        tagged += 1

            # ── Title heuristic ──
            for kw in error_titles:
                cursor.execute("""
                    SELECT id, vulnerability_patterns FROM endpoints
                    WHERE LOWER(title) LIKE ? AND title IS NOT NULL AND title != ''
                """, (f"%{kw}%",))
                for ep in cursor.fetchall():
                    patterns = json.loads(ep["vulnerability_patterns"]) if ep["vulnerability_patterns"] else []
                    if "potential_false_positive" not in patterns:
                        patterns.append("potential_false_positive")
                        cursor.execute(
                            "UPDATE endpoints SET vulnerability_patterns = ? WHERE id = ?",
                            (json.dumps(patterns), ep["id"]),
                        )
                        tagged += 1

    if tagged > 0:
        console.print(f" [dim]↳ False Positive Detection: Marcou {tagged} endpoints como potenciais falsos positivos.[/dim]")


def _mark_scanned_by_url(proj_path, nmap_dir, tool_name):
    """Mark endpoints as scanned based on URLs found in the tool's output files.
    Normalizes URLs to match DB format. Skips if tool already marked."""
    with db.get_connection(proj_path) as conn:
        with db.transaction(conn):
            cursor = conn.cursor()
            for nmap_folder in sorted(os.listdir(nmap_dir)):
                if not nmap_folder.startswith("nmap-"):
                    continue
                target_dir = os.path.join(nmap_dir, nmap_folder)

                files = []
                if tool_name in ("ferox",):
                    files = glob.glob(os.path.join(target_dir, "ferox_*.jsonl"))
                elif tool_name in ("katana", "crawled"):
                    f = os.path.join(target_dir, "crawled_all.jsonl")
                    if os.path.exists(f):
                        files = [f]
                elif tool_name == "jsfinder":
                    f = os.path.join(target_dir, "jsfinder-results.json")
                    if os.path.exists(f):
                        files = [f]
                elif tool_name == "nuclei":
                    f = os.path.join(target_dir, "nuclei_output.json")
                    if os.path.exists(f):
                        files = [f]
                elif tool_name == "screenshot":
                    f = os.path.join(target_dir, "Screenshots", "go.jsonl")
                    if os.path.exists(f):
                        files = [f]
                elif tool_name == "httpx":
                    f = os.path.join(nmap_dir, "httpx_output.json")
                    if os.path.exists(f):
                        files = [f]

                for fpath in files:
                    try:
                        with open(fpath) as fh:
                            for line in fh:
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    data = json.loads(line)
                                    url = (data.get("url") or
                                           data.get("request", {}).get("endpoint", "") or
                                           data.get("source_js_url", ""))
                                    if not url:
                                        continue
                                    url = _normalize_url(url)
                                    cursor.execute("""
                                        UPDATE endpoints SET scanned_by = CASE
                                            WHEN scanned_by IS NULL OR scanned_by = '' THEN ?
                                            WHEN scanned_by NOT LIKE ? THEN scanned_by || ',' || ?
                                            ELSE scanned_by
                                        END
                                        WHERE url LIKE ?
                                    """, (tool_name, f"%{tool_name}%", tool_name, f"{url}%"))
                                except Exception:
                                    continue
                    except Exception:
                        continue


# ═════════════════════════════════════════════════════════════════════
# DISPATCH
# ═════════════════════════════════════════════════════════════════════

def dispatch(module_name, proj_path, nmap_dir):
    db.init_db(proj_path)
    recon_dir = os.path.join(proj_path, "Recon")

    if module_name == "recon":
        parse_recon(proj_path, recon_dir)
    elif module_name == "nwrapper":
        parse_nmap(proj_path, nmap_dir)
    elif module_name == "httpx-runner":
        parse_httpx(proj_path, nmap_dir)
        _mark_scanned_by_url(proj_path, nmap_dir, "httpx")
    elif module_name == "feroxbuster-runner":
        parse_url_discovery_jsonl(proj_path, nmap_dir, "ferox")
        _mark_scanned_by_url(proj_path, nmap_dir, "ferox")
    elif module_name in ("katana-runner", "katana-buster"):
        parse_url_discovery_jsonl(proj_path, nmap_dir, "crawled")
        _mark_scanned_by_url(proj_path, nmap_dir, "crawled")
    elif module_name == "screenshot-runner":
        parse_screenshot(proj_path, nmap_dir)
        _mark_scanned_by_url(proj_path, nmap_dir, "screenshot")
    elif module_name == "gf-summary":
        parse_gf(proj_path, nmap_dir)
    elif module_name == "jsfinder-runner":
        parse_jsfinder(proj_path, nmap_dir)
        _mark_scanned_by_url(proj_path, nmap_dir, "jsfinder")
    elif module_name == "whois-enricher":
        parse_whois_from_initial(proj_path, nmap_dir)
    elif module_name == "nuclei-runner":
        parse_nuclei(proj_path, nmap_dir)
        _mark_scanned_by_url(proj_path, nmap_dir, "nuclei")
    elif module_name == "dalfox-runner":
        parse_dalfox(proj_path, nmap_dir)
        _mark_scanned_by_url(proj_path, nmap_dir, "dalfox")
    else:
        console.print(f" [yellow]⚠ Nenhum parser registrado para: {module_name}[/yellow]")

    # Run false positive detection after every parse
    flag_false_positives(proj_path)
