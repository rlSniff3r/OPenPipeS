import os
import json
import re
import socket
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import db
from rich.console import Console

console = Console()

# --- FUNÇÕES AUXILIARES MÁGICAS ---

def get_or_create_host(cursor, host_target, ip_to_add=None):
    if not host_target: return None
    clean_host = host_target.split(':')[0]
    
    cursor.execute('SELECT id, ips FROM hosts WHERE host = ?', (clean_host,))
    row = cursor.fetchone()
    
    if row:
        host_id = row['id']
        current_ips = []
        try:
            current_ips = json.loads(row['ips']) if row['ips'] else []
        except: pass
        
        if ip_to_add and ip_to_add not in current_ips and ip_to_add != clean_host:
            current_ips.append(ip_to_add)
            cursor.execute('UPDATE hosts SET ips = ? WHERE id = ?', (json.dumps(current_ips), host_id))
        return host_id
    else:
        initial_ips = json.dumps([ip_to_add]) if ip_to_add and ip_to_add != clean_host else '[]'
        cursor.execute('INSERT INTO hosts (host, ips) VALUES (?, ?)', (clean_host, initial_ips))
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
    except Exception: pass
    return urls

def process_httpx_json(cursor, json_file, source_name="httpx"):
    """Motor Universal de extração do HTTPx (Serve pro Recon e pro Httpx-Runner)"""
    count_endpoints = 0
    resolved_in_httpx = {} # Dicionário: {dominio: ip}
    
    with open(json_file, 'r') as f:
        for line in f:
            try:
                data = json.loads(line.strip())
                host_str = data.get('host', data.get('input', '')).split(':')[0]
                ip = data.get('host_ip', '')
                
                # Guarda na memória que o HTTPx já resolveu esse cara
                if host_str and ip:
                    resolved_in_httpx[host_str] = ip
                
                host_id = get_or_create_host(cursor, host_str, ip)
                
                # Se não falhou (tem porta aberta), atualiza info rica
                if not data.get('failed', False):
                    cursor.execute('UPDATE hosts SET is_alive = 1 WHERE id = ?', (host_id,))
                    
                    url = data.get('url', '')
                    status = data.get('status_code', 0)
                    length = data.get('content_length', 0)
                    content_type = data.get('content_type', '')
                    title = data.get('title', '')
                    webserver = data.get('webserver', '')
                    tech = json.dumps(data.get('tech', []))
                    
                    if url:
                        cursor.execute('''
                            INSERT INTO endpoints (host_id, url, status_code, content_length, content_type, title, web_server, tech_stack, source_tool)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ON CONFLICT(url) DO UPDATE SET 
                                status_code=excluded.status_code, content_length=excluded.content_length,
                                title=excluded.title, tech_stack=excluded.tech_stack, web_server=excluded.web_server
                        ''', (host_id, url, status, length, content_type, title, webserver, tech, source_name))
                        count_endpoints += 1
            except Exception: pass
            
    return count_endpoints, resolved_in_httpx

# --- PARSERS DOS MÓDULOS ---

def parse_recon(proj_path, recon_dir):
    conn = db.get_connection(proj_path)
    cursor = conn.cursor()
    
    # 1. SHIFT-LEFT: Extrai os dados do HTTPx gerados no Recon PRIMEIRO!
    httpx_endpoints_total = 0
    httpx_already_resolved = {}
    for root, dirs, files in os.walk(recon_dir):
        for file in files:
            if file.endswith('.httpx.json'):
                file_path = os.path.join(root, file)
                e_count, resolved = process_httpx_json(cursor, file_path, source_name="recon_httpx")
                httpx_endpoints_total += e_count
                httpx_already_resolved.update(resolved)

    # 2. Extrai os hosts dos outros arquivos TXT (Como fizemos antes)
    domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
    ip_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    unique_hosts = set() 
    
    for root, dirs, files in os.walk(recon_dir):
        for file in files:
            if file.endswith('.txt') or 'subs' in file:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            clean_line = re.sub(r'https?://', '', line)
                            for h in domain_pattern.findall(clean_line) + ip_pattern.findall(clean_line):
                                h = h.strip().lower()
                                if h and not h.startswith('.') and len(h) > 3:
                                    unique_hosts.add(h)
                except Exception: pass

    pure_ips = [h for h in unique_hosts if re.match(r'^\d+\.\d+\.\d+\.\d+$', h)]
    domains = [h for h in unique_hosts if not re.match(r'^\d+\.\d+\.\d+\.\d+$', h)]
    
    # 3. FILTRO DE PERFORMANCE: Só faz DNS lookup pra quem o HTTPx NÃO resolveu!
    domains_to_resolve = [dom for dom in domains if dom not in httpx_already_resolved]
    resolved_data = {}
    
    console.print(f"   [dim]↳ Resolvendo DNS pendente para {len(domains_to_resolve)} domínios (HTTPx já havia resolvido {len(httpx_already_resolved)})...[/dim]")
    if domains_to_resolve:
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_domain = {executor.submit(resolve_domain, dom): dom for dom in domains_to_resolve}
            for future in as_completed(future_to_domain):
                dom, ips = future.result()
                resolved_data[dom] = ips

    # 4. Salva no banco as resoluções feitas pelo nosso ThreadPool
    count_domains = 0
    for dom, ips in resolved_data.items():
        ips_json = json.dumps(ips)
        cursor.execute('INSERT INTO hosts (host, ips) VALUES (?, ?) ON CONFLICT(host) DO UPDATE SET ips=excluded.ips', (dom, ips_json))
        count_domains += 1
        for ip in ips: pure_ips.append(ip)
            
    # Salva IPs puros
    for ip in set(pure_ips):
        cursor.execute("INSERT INTO hosts (host, ips) VALUES (?, '[]') ON CONFLICT(host) DO NOTHING", (ip,))

    conn.commit()
    conn.close()
    
    if httpx_endpoints_total > 0:
        console.print(f"   [dim]↳ Parser Recon: Extraiu {httpx_endpoints_total} endpoints iniciais via HTTPx.[/dim]")
    console.print(f"   [dim]↳ Parser Recon: Mapeou {len(domains)} Domínios e {len(set(pure_ips))} IPs puros.[/dim]")

def parse_nmap(proj_path, nmap_dir):
    conn = db.get_connection(proj_path)
    cursor = conn.cursor()
    count_ports = 0
    
    for root, dirs, files in os.walk(nmap_dir):
        for file in files:
            if file.endswith('.xml'):
                xml_file = os.path.join(root, file)
                try:
                    tree = ET.parse(xml_file)
                    for host_node in tree.getroot().findall('host'):
                        ip = ""
                        hostname = ""
                        for address in host_node.findall('address'):
                            if address.get('addrtype') == 'ipv4': ip = address.get('addr')
                        for hostnames in host_node.findall('hostnames'):
                            for hname in hostnames.findall('hostname'): hostname = hname.get('name')
                        
                        target = hostname if hostname else ip
                        if not target: continue
                        
                        host_id = get_or_create_host(cursor, target, ip)
                        cursor.execute('UPDATE hosts SET is_alive = 1 WHERE id = ?', (host_id,))
                        
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
                                service_version = f"{product} {version}".strip()
                                
                                cursor.execute('''
                                    INSERT INTO ports (host_id, port, protocol, state, service, version) 
                                    VALUES (?, ?, ?, ?, ?, ?)
                                    ON CONFLICT(host_id, port, protocol) DO UPDATE SET 
                                        state=excluded.state, service=excluded.service, version=excluded.version
                                ''', (host_id, portid, protocol, state, service_name, service_version))
                                count_ports += 1
                except Exception: pass
    conn.commit()
    conn.close()
    console.print(f"   [dim]↳ Parser Nmap: Inseriu/Atualizou {count_ports} portas abertas e serviços.[/dim]")

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
                cursor.execute('INSERT INTO endpoints (host_id, url, source_tool) VALUES (?, ?, ?) ON CONFLICT(url) DO NOTHING', (host_id, url, tool_name))
                if cursor.rowcount > 0: count += 1
        except Exception: pass

    conn.commit()
    conn.close()
    if count > 0: console.print(f"   [dim]↳ Parser {tool_name.capitalize()}: Mapeou {count} novos Endpoints únicos.[/dim]")

def dispatch(module_name, proj_path, nmap_dir):
    recon_dir = os.path.join(proj_path, "Recon")
    
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
    elif module_name == 'jsfinder-runner':
        parse_url_discovery(proj_path, nmap_dir, 'js_files')