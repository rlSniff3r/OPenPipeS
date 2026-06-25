import os
import json
import re
import socket
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import sqlite3
import db
from rich.console import Console

console = Console()
CONFIG_FILE = os.path.expanduser("~/.openpipes/config.sh")

# --- FUNÇÕES AUXILIARES MÁGICAS ---

def get_obsdir():
    """Descobre o caminho do cofre do Obsidian lendo o config.sh"""
    if os.path.exists(CONFIG_FILE):
        try:
            cmd = f"source {CONFIG_FILE} && echo -n \"$obsdir|$proj_name\""
            res = subprocess.check_output(cmd, shell=True, executable="/bin/bash", text=True).split('|')
            import subprocess
        except:
            import subprocess
            try:
                cmd = f"source {CONFIG_FILE} && echo -n \"$obsdir|$proj_name\""
                res = subprocess.check_output(cmd, shell=True, executable="/bin/bash", text=True).split('|')
                if len(res) == 2:
                    return os.path.join(res[0], res[1]) # ex: ~/Obsidian/Pentest/cliente-xyz
            except: pass
    return None

def is_ipv4(string):
    return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', string))

def get_or_create_host(cursor, host_target, ips_to_add=None, cnames_to_add=None):
    if not host_target: return None
    clean_host = host_target.split(':')[0].strip().lower()
    
    ips_to_add = ips_to_add if ips_to_add else []
    cnames_to_add = cnames_to_add if cnames_to_add else []
    
    if not isinstance(ips_to_add, list): ips_to_add = [ips_to_add]
    if not isinstance(cnames_to_add, list): cnames_to_add = [cnames_to_add]

    # CORRELAÇÃO REVERSA PARA IPs ÓRFÃOS
    if is_ipv4(clean_host):
        if clean_host in ['1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4']: return None
        cursor.execute("SELECT id FROM hosts WHERE ips LIKE ?", (f'%"{clean_host}"%',))
        row = cursor.fetchone()
        if row: return row['id']

    cursor.execute('SELECT id, ips, cnames FROM hosts WHERE host = ?', (clean_host,))
    row = cursor.fetchone()
    
    if row:
        host_id = row['id']
        try: current_ips = json.loads(row['ips']) if row['ips'] else []
        except: current_ips = []
        try: current_cnames = json.loads(row['cnames']) if row['cnames'] else []
        except: current_cnames = []
        
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
            cursor.execute('UPDATE hosts SET ips = ?, cnames = ? WHERE id = ?', (json.dumps(current_ips), json.dumps(current_cnames), host_id))
        return host_id
    else:
        initial_ips = json.dumps([ip for ip in ips_to_add if ip and ip != clean_host and not is_ipv4(clean_host)])
        initial_cnames = json.dumps([c for c in cnames_to_add if c and c != clean_host])
        cursor.execute('INSERT INTO hosts (host, ips, cnames) VALUES (?, ?, ?)', (clean_host, initial_ips, initial_cnames))
        return cursor.lastrowid

def resolve_domain(domain):
    try:
        _, _, ip_list = socket.gethostbyname_ex(domain)
        return domain, ip_list
    except Exception: return domain, []

def extract_urls_from_file(file_path):
    urls = set()
    url_pattern = re.compile(r'https?://[a-zA-Z0-9.\-]+(?:/[^\s]*)?')
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f: urls.update(url_pattern.findall(line))
    except Exception: pass
    return urls

def process_httpx_json(cursor, json_file, source_name="httpx"):
    count_endpoints = 0
    resolved_in_httpx = {} 
    with open(json_file, 'r') as f:
        for line in f:
            try:
                data = json.loads(line.strip())
                host_str = data.get('host', data.get('input', '')).split(':')[0]
                ips = data.get('a', []) + data.get('aaaa', [])
                if not ips and data.get('host_ip'): ips = [data.get('host_ip')]
                cnames = data.get('cname', [])
                
                if host_str and ips and not is_ipv4(host_str):
                    resolved_in_httpx[host_str] = ips
                
                host_id = get_or_create_host(cursor, host_str, ips, cnames)
                if host_id and not data.get('failed', False):
                    cursor.execute('UPDATE hosts SET is_alive = 1 WHERE id = ?', (host_id,))
                    url = data.get('url', '')
                    if url:
                        cursor.execute('''
                            INSERT INTO endpoints (host_id, url, status_code, content_length, content_type, title, web_server, tech_stack, source_tool)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ON CONFLICT(url) DO UPDATE SET 
                                status_code=excluded.status_code, content_length=excluded.content_length,
                                title=excluded.title, tech_stack=excluded.tech_stack, web_server=excluded.web_server
                        ''', (host_id, url, data.get('status_code', 0), data.get('content_length', 0), data.get('content_type', ''), 
                              data.get('title', ''), data.get('webserver', ''), json.dumps(data.get('tech', [])), source_name))
                        count_endpoints += 1
            except Exception: pass
    return count_endpoints, resolved_in_httpx

# --- PARSERS NÚCLEO (FASES 1 E 2) ---

def parse_recon(proj_path, recon_dir):
    conn = db.get_connection(proj_path)
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
                except Exception: pass

    domains_to_resolve = [dom for dom in unique_hosts if dom not in httpx_already_resolved]
    resolved_data = {}
    
    if domains_to_resolve:
        with ThreadPoolExecutor(max_workers=50) as executor:
            for future in as_completed({executor.submit(resolve_domain, dom): dom for dom in domains_to_resolve}):
                dom, ips = future.result()
                resolved_data[dom] = ips

    for dom, ips in resolved_data.items():
        cursor.execute('INSERT INTO hosts (host, ips) VALUES (?, ?) ON CONFLICT(host) DO UPDATE SET ips=excluded.ips', (dom, json.dumps(ips)))

    conn.commit()
    conn.close()
    console.print(f"   [dim]↳ Parser Recon: Mapeou {len(unique_hosts)} Domínios limpos.[/dim]")

def parse_nmap(proj_path, nmap_dir):
    conn = db.get_connection(proj_path)
    cursor = conn.cursor()
    count_ports = 0
    count_whois = 0
    
    for root, dirs, files in os.walk(nmap_dir):
        for file in files:
            if file.endswith('.xml'):
                try:
                    tree = ET.parse(os.path.join(root, file))
                    for host_node in tree.getroot().findall('host'):
                        ip = ""
                        hostname = ""
                        for address in host_node.findall('address'):
                            if address.get('addrtype') == 'ipv4': ip = address.get('addr')
                        for hostnames in host_node.findall('hostnames'):
                            for hname in hostnames.findall('hostname'): hostname = hname.get('name')
                        
                        target = hostname if hostname else ip
                        if not target: continue
                        
                        host_id = get_or_create_host(cursor, target, [ip])
                        if host_id:
                            cursor.execute('UPDATE hosts SET is_alive = 1 WHERE id = ?', (host_id,))
                            
                            # EXTRAÇÃO WHOIS DO NMAP
                            whois_data = ""
                            for script in host_node.findall(".//script"):
                                if script.get('id') in ['whois-ip', 'whois-domain']:
                                    whois_data = script.get('output', '')
                                    
                            if whois_data:
                                cursor.execute('UPDATE hosts SET whois_data = ? WHERE id = ?', (whois_data.strip(), host_id))
                                count_whois += 1

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
                                    
                                    cursor.execute('''
                                        INSERT INTO ports (host_id, port, protocol, state, service, version) 
                                        VALUES (?, ?, ?, ?, ?, ?)
                                        ON CONFLICT(host_id, port, protocol) DO UPDATE SET 
                                            state=excluded.state, service=excluded.service, version=excluded.version
                                    ''', (host_id, portid, protocol, state, service_name, f"{product} {version}".strip()))
                                    count_ports += 1
                except Exception: pass
    conn.commit()
    conn.close()
    console.print(f"   [dim]↳ Parser Nmap: Inseriu {count_ports} portas abertas e extraiu {count_whois} dados de WHOIS.[/dim]")

def parse_httpx(proj_path, nmap_dir):
    json_file = os.path.join(nmap_dir, "httpx_output.json")
    if not os.path.exists(json_file): return
    conn = db.get_connection(proj_path)
    cursor = conn.cursor()
    count_endpoints, _ = process_httpx_json(cursor, json_file, source_name="httpx")
    conn.commit()
    conn.close()
    console.print(f"   [dim]↳ Parser HTTPx: Ingeriu {count_endpoints} URLs e Tecnologias.[/dim]")

def parse_url_discovery(proj_path, nmap_dir, tool_name):
    conn = db.get_connection(proj_path)
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
                    cursor.execute('INSERT INTO endpoints (host_id, url, source_tool) VALUES (?, ?, ?) ON CONFLICT(url) DO NOTHING', (host_id, url, tool_name))
                    if cursor.rowcount > 0: count += 1
        except Exception: pass
    conn.commit()
    conn.close()
    if count > 0: console.print(f"   [dim]↳ Parser {tool_name.capitalize()}: Mapeou {count} Endpoints.[/dim]")


# --- PARSERS COMPLEMENTARES (FASE 3 - INTEGRAÇÕES) ---

def parse_screenshot(proj_path):
    """Lê o Banco do Gowitness e atrela imagens aos nossos hosts"""
    screenshot_dir = os.path.join(proj_path, "Varreduras", "screenshots")
    db_path = os.path.join(screenshot_dir, "gowitness.sqlite3")
    if not os.path.exists(db_path): return
    
    conn = db.get_connection(proj_path)
    cursor = conn.cursor()
    count = 0
    
    try:
        gw_conn = sqlite3.connect(db_path)
        gw_cursor = gw_conn.cursor()
        gw_cursor.execute("SELECT url, filename FROM urls")
        
        for row in gw_cursor.fetchall():
            url, filename = row[0], row[1]
            host_str = urlparse(url).hostname
            if host_str:
                host_id = get_or_create_host(cursor, host_str)
                if host_id:
                    cursor.execute('INSERT INTO screenshots (host_id, file_path) VALUES (?, ?) ON CONFLICT(file_path) DO NOTHING', (host_id, filename))
                    if cursor.rowcount > 0: count += 1
        gw_conn.close()
    except Exception as e:
        console.print(f"   [yellow]Erro lendo db gowitness: {e}[/yellow]")
        
    conn.commit()
    conn.close()
    if count > 0: console.print(f"   [dim]↳ Parser Gowitness: Atrelou {count} Screenshots aos hosts.[/dim]")

def parse_gf(proj_path, obs_dir):
    """Varre os arquivos gf-summary.md e taggeia as URLs no DB"""
    conn = db.get_connection(proj_path)
    cursor = conn.cursor()
    count = 0
    
    for root, dirs, files in os.walk(obs_dir):
        for file in files:
            if file == "gf-summary.md":
                try:
                    with open(os.path.join(root, file), 'r', encoding='utf-8') as f:
                        current_vuln = None
                        for line in f:
                            line = line.strip()
                            if line.startswith("## 🧪 gf:"):
                                current_vuln = line.split(":", 1)[1].strip()
                            elif line.startswith("http") and current_vuln:
                                cursor.execute("SELECT id, vulnerability_patterns FROM endpoints WHERE url = ?", (line,))
                                row = cursor.fetchone()
                                if row:
                                    patterns = json.loads(row['vulnerability_patterns']) if row['vulnerability_patterns'] else []
                                    if current_vuln not in patterns:
                                        patterns.append(current_vuln)
                                        cursor.execute("UPDATE endpoints SET vulnerability_patterns = ? WHERE id = ?", (json.dumps(patterns), row['id']))
                                        count += 1
                except Exception: pass
                
    conn.commit()
    conn.close()
    if count > 0: console.print(f"   [dim]↳ Parser GF-Summary: Injetou {count} Tags de Padrões em Endpoints.[/dim]")

def parse_jsfinder(proj_path, obs_dir):
    """Extrai as rotas secretas dos JS"""
    conn = db.get_connection(proj_path)
    cursor = conn.cursor()
    count = 0
    
    for root, dirs, files in os.walk(obs_dir):
        for file in files:
            if file == "js-endpoints.md":
                try:
                    with open(os.path.join(root, file), 'r', encoding='utf-8') as f:
                        current_js_url = None
                        in_code_block = False
                        for line in f:
                            line = line.strip()
                            if line.startswith("## Fonte:"):
                                match = re.search(r'\[(.*?)\]', line)
                                if match: current_js_url = match.group(1)
                            elif line.startswith("```"):
                                in_code_block = not in_code_block
                            elif in_code_block and current_js_url and line:
                                host_str = urlparse(current_js_url).hostname
                                if host_str:
                                    host_id = get_or_create_host(cursor, host_str)
                                    if host_id:
                                        cursor.execute('''INSERT INTO js_discoveries (host_id, source_js_url, discovered_route) 
                                                          VALUES (?, ?, ?) ON CONFLICT DO NOTHING''', (host_id, current_js_url, line))
                                        if cursor.rowcount > 0: count += 1
                except Exception: pass

    conn.commit()
    conn.close()
    if count > 0: console.print(f"   [dim]↳ Parser JSFinder: Salvou {count} rotas/arquivos descobertos no JS.[/dim]")


def dispatch(module_name, proj_path, nmap_dir):
    recon_dir = os.path.join(proj_path, "Recon")
    obs_proj_dir = get_obsdir()
    
    if module_name == 'recon':
        parse_recon(proj_path, recon_dir)
    elif module_name == 'nwrapper':
        parse_nmap(proj_path, nmap_dir)
    elif module_name == 'httpx-runner':
        parse_httpx(proj_path, nmap_dir)
    elif module_name == 'feroxbuster-runner':
        parse_url_discovery(proj_path, nmap_dir, 'ferox')
    elif module_name in ['katana-runner', 'katana-buster']:
        parse_url_discovery(proj_path, nmap_dir, 'crawled')
    elif module_name == 'screenshot-runner':
        parse_screenshot(proj_path)
    elif module_name == 'gf-summary':
        if obs_proj_dir: parse_gf(proj_path, obs_proj_dir)
    elif module_name == 'jsfinder-runner':
        parse_url_discovery(proj_path, nmap_dir, 'js_files')
        if obs_proj_dir: parse_jsfinder(proj_path, obs_proj_dir)
    elif module_name == 'whois-enricher':
        parse_nmap(proj_path, nmap_dir) # Atualiza re-lendo os XMLs do Nmap