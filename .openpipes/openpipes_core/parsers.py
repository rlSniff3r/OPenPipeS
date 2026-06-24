import os
import json
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
import db
from rich.console import Console
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

console = Console()

# --- FUNÇÕES AUXILIARES MÁGICAS ---

def get_or_create_host(cursor, host_target, ip_to_add=None):
    """Garante a existência do Host e retorna o ID. Também acumula IPs conhecidos."""
    if not host_target: return None
    
    # Limpa portas se vierem grudadas no host (ex: api.empresa.com:8080)
    clean_host = host_target.split(':')[0]
    
    cursor.execute('SELECT id, ips FROM hosts WHERE host = ?', (clean_host,))
    row = cursor.fetchone()
    
    if row:
        host_id = row['id']
        current_ips = []
        try:
            current_ips = json.loads(row['ips']) if row['ips'] else []
        except: pass
        
        # Se descobriu um IP novo pra esse host, faz o append
        if ip_to_add and ip_to_add not in current_ips and ip_to_add != clean_host:
            current_ips.append(ip_to_add)
            cursor.execute('UPDATE hosts SET ips = ? WHERE id = ?', (json.dumps(current_ips), host_id))
        return host_id
    else:
        initial_ips = json.dumps([ip_to_add]) if ip_to_add and ip_to_add != clean_host else '[]'
        cursor.execute('INSERT INTO hosts (host, ips) VALUES (?, ?)', (clean_host, initial_ips))
        return cursor.lastrowid

def extract_urls_from_file(file_path):
    """Extrai estritamente URLs válidas ignorando lixo ao redor (, etc)"""
    urls = set()
    url_pattern = re.compile(r'https?://[a-zA-Z0-9.\-]+(?:/[^\s]*)?')
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                matches = url_pattern.findall(line)
                for match in matches:
                    urls.add(match)
    except Exception: pass
    return urls

# --- PARSERS DOS MÓDULOS ---

def resolve_domain(domain):
    """Função auxiliar para a ThreadPool: Tenta resolver o domínio para IPs"""
    try:
        # gethostbyname_ex retorna (hostname, aliaslist, ipaddrlist)
        _, _, ip_list = socket.gethostbyname_ex(domain)
        return domain, ip_list
    except Exception:
        return domain, []

def parse_recon(proj_path, recon_dir):
    """Lê subdomínios, resolve IPs via Multi-threading e popula o banco"""
    conn = db.get_connection(proj_path)
    cursor = conn.cursor()
    count_domains = 0
    count_ips = 0
    
    domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
    ip_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    
    unique_hosts = set() 
    
    # 1. Extração Cirúrgica (Lê os arquivos e extrai os alvos)
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

    # 2. Separa o que é IP direto do que é Domínio
    pure_ips = [h for h in unique_hosts if re.match(r'^\d+\.\d+\.\d+\.\d+$', h)]
    domains = [h for h in unique_hosts if not re.match(r'^\d+\.\d+\.\d+\.\d+$', h)]
    
    resolved_data = {}
    
    # 3. Resolução Multi-Thread DNS (A Mágica da Velocidade!)
    console.print(f"   [dim]↳ Resolvendo DNS para {len(domains)} domínios com 50 threads...[/dim]")
    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_domain = {executor.submit(resolve_domain, dom): dom for dom in domains}
        for future in as_completed(future_to_domain):
            dom, ips = future.result()
            resolved_data[dom] = ips

    # 4. Inserção no Banco de Dados
    # Inserindo Domínios com seus IPs resolvidos
    for dom, ips in resolved_data.items():
        ips_json = json.dumps(ips)
        cursor.execute('''
            INSERT INTO hosts (host, ips) VALUES (?, ?)
            ON CONFLICT(host) DO UPDATE SET ips=excluded.ips
        ''', (dom, ips_json))
        count_domains += 1
        
        # Opcional: Inserir também os IPs descobertos como hosts isolados
        # para garantir que o Nmap não deixe passar nada.
        for ip in ips:
            pure_ips.append(ip)
            
    # Inserindo os IPs puros
    for ip in set(pure_ips):
        cursor.execute('''
            INSERT INTO hosts (host, ips) VALUES (?, ?)
            ON CONFLICT(host) DO NOTHING
        ''', (ip, '[]'))
        count_ips += 1

    conn.commit()
    conn.close()
    console.print(f"   [dim]↳ Parser Recon: Mapeou {count_domains} Domínios (com IPs) e {count_ips} IPs puros.[/dim]")

def parse_nmap(proj_path, nmap_dir):
    """Varre XMLs do Nmap. Alimenta a tabela de Hosts e Portas"""
    conn = db.get_connection(proj_path)
    cursor = conn.cursor()
    count_ports = 0
    
    for root, dirs, files in os.walk(nmap_dir):
        for file in files:
            if file.endswith('.xml'):
                xml_file = os.path.join(root, file)
                try:
                    tree = ET.parse(xml_file)
                    nmaprun = tree.getroot()
                    
                    for host_node in nmaprun.findall('host'):
                        ip = ""
                        hostname = ""
                        # IP
                        for address in host_node.findall('address'):
                            if address.get('addrtype') == 'ipv4': ip = address.get('addr')
                        # Hostname
                        for hostnames in host_node.findall('hostnames'):
                            for hname in hostnames.findall('hostname'):
                                hostname = hname.get('name')
                        
                        target = hostname if hostname else ip
                        if not target: continue
                        
                        host_id = get_or_create_host(cursor, target, ip)
                        cursor.execute('UPDATE hosts SET is_alive = 1 WHERE id = ?', (host_id,))
                        
                        # Portas
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
                except Exception as e:
                    console.print(f"   [yellow]Erro ao ler Nmap XML {file}: {e}[/yellow]")
                    
    conn.commit()
    conn.close()
    console.print(f"   [dim]↳ Parser Nmap: Inseriu/Atualizou {count_ports} portas abertas e serviços.[/dim]")

def parse_httpx(proj_path, nmap_dir):
    """Analisa JSON do HTTPx e insere Endpoints Ricos"""
    json_file = os.path.join(nmap_dir, "httpx_output.json")
    if not os.path.exists(json_file): return
    
    conn = db.get_connection(proj_path)
    cursor = conn.cursor()
    count = 0
    
    with open(json_file, 'r') as f:
        for line in f:
            try:
                data = json.loads(line.strip())
                # Trata Host e IP
                host_str = data.get('host', data.get('input', ''))
                ip = data.get('host_ip', '')
                host_id = get_or_create_host(cursor, host_str, ip)
                cursor.execute('UPDATE hosts SET is_alive = 1 WHERE id = ?', (host_id,))
                
                # Dados do Endpoint
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
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'httpx')
                        ON CONFLICT(url) DO UPDATE SET 
                            status_code=excluded.status_code, content_length=excluded.content_length,
                            title=excluded.title, tech_stack=excluded.tech_stack, web_server=excluded.web_server
                    ''', (host_id, url, status, length, content_type, title, webserver, tech))
                    count += 1
            except Exception: pass
            
    conn.commit()
    conn.close()
    console.print(f"   [dim]↳ Parser HTTPx: Ingeriu {count} URLs e Tecnologias.[/dim]")

def parse_url_discovery(proj_path, nmap_dir, tool_name):
    """Parser Genérico para Feroxbuster, Katana, JSFinder (Arquivos cheios de URLs soltas)"""
    conn = db.get_connection(proj_path)
    cursor = conn.cursor()
    count = 0
    urls = set()
    
    # Procura txts na pasta Varreduras que tenham o nome da ferramenta
    for root, dirs, files in os.walk(nmap_dir):
        for file in files:
            if tool_name in file.lower() and file.endswith('.txt'):
                file_path = os.path.join(root, file)
                urls.update(extract_urls_from_file(file_path))
                
    for url in urls:
        try:
            parsed_url = urlparse(url)
            host_str = parsed_url.hostname
            if host_str:
                host_id = get_or_create_host(cursor, host_str)
                cursor.execute('''
                    INSERT INTO endpoints (host_id, url, source_tool)
                    VALUES (?, ?, ?)
                    ON CONFLICT(url) DO NOTHING
                ''', (host_id, url, tool_name))
                if cursor.rowcount > 0: count += 1
        except Exception: pass

    conn.commit()
    conn.close()
    if count > 0:
        console.print(f"   [dim]↳ Parser {tool_name.capitalize()}: Mapeou {count} novos Endpoints únicos.[/dim]")

# --- DISPATCHER CENTRAL ---

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
        parse_url_discovery(proj_path, nmap_dir, 'crawled') # Usa o nome do arquivo crawled_all.txt
    elif module_name == 'jsfinder-runner':
        parse_url_discovery(proj_path, nmap_dir, 'js_files')