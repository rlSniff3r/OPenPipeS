import os
import json
import re
import xml.etree.ElementTree as ET
import db
from rich.console import Console

console = Console()

def get_or_create_host(cursor, host_target, ip=""):
    """
    MÁGICA DINÂMICA: Verifica se o host existe. 
    Se existir, retorna o ID. Se não, cria na hora e retorna o novo ID.
    Isso resolve o problema de crawlers (Katana) achando subdomínios novos no meio do scan!
    """
    if not host_target:
        return None
        
    cursor.execute('SELECT id FROM hosts WHERE host = ?', (host_target,))
    row = cursor.fetchone()
    
    if row:
        return row['id']
    else:
        cursor.execute('INSERT INTO hosts (host, ip) VALUES (?, ?)', (host_target, ip))
        return cursor.lastrowid

def parse_recon(proj_path, recon_dir):
    """Lê os resultados de Reconhecimento (Subdomínios) e cria a fundação no banco"""
    conn = db.get_connection(proj_path)
    cursor = conn.cursor()
    count = 0
    
    # O Recon geralmente gera arquivos com a palavra 'subs' ou no próprio domains.txt
    # Vamos buscar qualquer arquivo de texto na pasta Recon que pareça ter subdomínios
    for root, dirs, files in os.walk(recon_dir):
        for file in files:
            if file.endswith('.txt') or 'subs' in file:
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    for line in f:
                        host = line.strip()
                        if host and not host.startswith('#') and '.' in host:
                            # Tenta inserir, se já existe ignora
                            cursor.execute('''
                                INSERT INTO hosts (host) VALUES (?)
                                ON CONFLICT(host) DO NOTHING
                            ''', (host,))
                            if cursor.rowcount > 0:
                                count += 1
                                
    conn.commit()
    conn.close()
    console.print(f"   [dim]↳ Parser Recon: Mapeou {count} subdomínios base na tabela Hosts.[/dim]")

def parse_nmap(proj_path, nmap_dir):
    """Lê arquivos XML do Nmap e mapeia IPs e Portas (Abertas, Fechadas, Filtradas)"""
    conn = db.get_connection(proj_path)
    cursor = conn.cursor()
    count = 0
    
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
                        open_ports = []
                        
                        # Coleta IP
                        for address in host_node.findall('address'):
                            if address.get('addrtype') == 'ipv4':
                                ip = address.get('addr')
                                
                        # Coleta Hostname
                        for hostnames in host_node.findall('hostnames'):
                            for hname in hostnames.findall('hostname'):
                                hostname = hname.get('name')
                        
                        target = hostname if hostname else ip
                        if not target:
                            continue
                            
                        # Coleta Portas
                        ports_node = host_node.find('ports')
                        if ports_node is not None:
                            for port in ports_node.findall('port'):
                                state = port.find('state').get('state')
                                if state == 'open':
                                    portid = port.get('portid')
                                    open_ports.append(int(portid))
                        
                        ports_str = json.dumps(open_ports)
                        
                        # Atualiza no banco
                        cursor.execute('''
                            INSERT INTO hosts (host, ip, ports) VALUES (?, ?, ?)
                            ON CONFLICT(host) DO UPDATE SET 
                                ip=excluded.ip,
                                ports=excluded.ports
                        ''', (target, ip, ports_str))
                        count += 1
                except Exception as e:
                    console.print(f"   [red]Erro parseando Nmap XML {file}: {e}[/red]")
                    continue
                    
    conn.commit()
    conn.close()
    console.print(f"   [dim]↳ Parser Nmap: Atualizou portas/IPs para {count} hosts.[/dim]")

def parse_httpx(proj_path, nmap_dir):
    json_file = os.path.join(nmap_dir, "httpx_output.json")
    if not os.path.exists(json_file): return
    
    conn = db.get_connection(proj_path)
    cursor = conn.cursor()
    count = 0
    
    with open(json_file, 'r') as f:
        for line in f:
            try:
                data = json.loads(line.strip())
                host = data.get('input', '')
                ip = data.get('host', '') 
                web_server = data.get('webserver', '')
                title = data.get('title', '')
                tech = json.dumps(data.get('tech', []))
                
                cursor.execute('''
                    INSERT INTO hosts (host, ip, is_alive, web_server, tech_stack, page_title)
                    VALUES (?, ?, 1, ?, ?, ?)
                    ON CONFLICT(host) DO UPDATE SET 
                        ip=excluded.ip, web_server=excluded.web_server,
                        tech_stack=excluded.tech_stack, page_title=excluded.page_title, is_alive=1
                ''', (host, ip, web_server, tech, title))
                count += 1
            except Exception: pass
    conn.commit()
    conn.close()
    console.print(f"   [dim]↳ Parser HTTPx: Ingeriu/Atualizou {count} hosts vivos no SQLite.[/dim]")

def parse_nuclei(proj_path, nmap_dir):
    json_file = os.path.join(nmap_dir, "nuclei_output.json")
    if not os.path.exists(json_file): return
        
    conn = db.get_connection(proj_path)
    cursor = conn.cursor()
    count = 0
    
    with open(json_file, 'r') as f:
        for line in f:
            try:
                data = json.loads(line.strip())
                vuln_name = data.get('info', {}).get('name', data.get('template-id', ''))
                severity = data.get('info', {}).get('severity', 'info')
                matched_at = data.get('matched-at', '')
                curl_cmd = data.get('curl-command', '')
                desc = data.get('info', {}).get('description', '')
                
                # Pega o host limpo (ex: tira o https://) para relacionar
                host_target = data.get('host', '')
                clean_host = re.sub(r'^https?://', '', host_target).split('/')[0].split(':')[0]
                
                # Uso da Mágica Dinâmica!
                host_id = get_or_create_host(cursor, clean_host)

                cursor.execute('''
                    INSERT INTO vulnerabilities (host_id, severity, vuln_name, description, matched_at, curl_command, source_tool)
                    VALUES (?, ?, ?, ?, ?, ?, 'nuclei')
                    ON CONFLICT(vuln_name, matched_at) DO NOTHING
                ''', (host_id, severity, vuln_name, desc, matched_at, curl_cmd))
                count += 1
            except Exception: pass
    conn.commit()
    conn.close()
    console.print(f"   [dim]↳ Parser Nuclei: Ingeriu {count} findings no SQLite.[/dim]")

def dispatch(module_name, proj_path, nmap_dir):
    """Distribui o trabalho para o parser correto"""
    recon_dir = os.path.join(proj_path, "Recon")
    
    if module_name == 'recon':
        parse_recon(proj_path, recon_dir)
    elif module_name == 'nwrapper':
        parse_nmap(proj_path, nmap_dir)
    elif module_name == 'httpx-runner':
        parse_httpx(proj_path, nmap_dir)
    elif module_name == 'nuclei-runner':
        parse_nuclei(proj_path, nmap_dir)