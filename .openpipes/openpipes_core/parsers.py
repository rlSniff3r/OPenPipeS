import os
import json
import db
from rich.console import Console

console = Console()

def parse_httpx(proj_path, nmap_dir):
    """Lê o output do HTTPx e consolida na tabela Hosts"""
    json_file = os.path.join(nmap_dir, "httpx_output.json")
    if not os.path.exists(json_file):
        return
    
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
                        ip=excluded.ip,
                        web_server=excluded.web_server,
                        tech_stack=excluded.tech_stack,
                        page_title=excluded.page_title,
                        is_alive=1
                ''', (host, ip, web_server, tech, title))
                count += 1
            except Exception:
                continue
                
    conn.commit()
    conn.close()
    console.print(f"   [dim]↳ Parser HTTPx: Ingeriu/Atualizou {count} hosts vivos no SQLite.[/dim]")

def parse_nuclei(proj_path, nmap_dir):
    """Lê o output do Nuclei e consolida na tabela Vulnerabilities"""
    json_file = os.path.join(nmap_dir, "nuclei_output.json")
    if not os.path.exists(json_file):
        return
        
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
                host_target = data.get('host', '')

                # Tenta amarrar a vuln ao ID do Host na tabela de Hosts
                cursor.execute('SELECT id FROM hosts WHERE host = ? OR host LIKE ? LIMIT 1', (host_target, f"%{host_target}%"))
                row = cursor.fetchone()
                host_id = row['id'] if row else None

                cursor.execute('''
                    INSERT INTO vulnerabilities (host_id, severity, vuln_name, description, matched_at, curl_command, source_tool)
                    VALUES (?, ?, ?, ?, ?, ?, 'nuclei')
                    ON CONFLICT(vuln_name, matched_at) DO NOTHING
                ''', (host_id, severity, vuln_name, desc, matched_at, curl_cmd))
                count += 1
            except Exception:
                continue
                
    conn.commit()
    conn.close()
    console.print(f"   [dim]↳ Parser Nuclei: Ingeriu {count} findings no SQLite.[/dim]")

def dispatch(module_name, proj_path, nmap_dir):
    """Descobre qual parser acionar baseado no módulo que acabou de rodar"""
    if module_name == 'httpx-runner':
        parse_httpx(proj_path, nmap_dir)
    elif module_name == 'nuclei-runner':
        parse_nuclei(proj_path, nmap_dir)