import os
import sys
import re
import json
import subprocess
from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware

# Adiciona o diretório raiz 'openpipes_core' ao sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import db

from .auth import verificar_autenticacao

app = FastAPI(title="OPenPipeS Web Dashboard")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =====================================================================
# FUNÇÕES CORE E DE ESCOPO
# =====================================================================

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

def _get_nmap_dir(proj_path: str) -> str:
    """Tenta ler NMAP_DIR do config.sh, caso contrário usa o padrão 'Varreduras'."""
    config_file = os.path.expanduser("~/.openpipes/config.sh")
    if not os.path.exists(config_file):
        return os.path.join(proj_path, "Varreduras")
    try:
        cmd = f"source {config_file} && echo -n \"$NMAP_DIR\""
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, executable="/bin/bash")
        nmap_dir = result.stdout.strip()
        return nmap_dir if nmap_dir else os.path.join(proj_path, "Varreduras")
    except Exception:
        return os.path.join(proj_path, "Varreduras")

# =====================================================================
# ROTAS DA API
# =====================================================================

def get_stats_from_db():
    proj_path = os.environ.get("OPENPIPES_PROJ_PATH")
    if not proj_path:
        return {"hosts": 0, "vulns": 0, "endpoints": 0, "error": "Projeto não carregado."}

    scope_domains = _get_scope_domains(proj_path)
    fp_filter = "(vulnerability_patterns NOT LIKE '%potential_false_positive%' OR vulnerability_patterns IS NULL)"

    try:
        with db.get_connection(proj_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, host FROM hosts WHERE is_alive = 1 AND in_scope = 1")
            alive_hosts = [row["id"] for row in cursor.fetchall() if _is_in_scope(row["host"], scope_domains)]

            hosts_count = len(alive_hosts)
            vulns_count = 0
            endpoints_count = 0

            if alive_hosts:
                ph = ",".join("?" for _ in alive_hosts)
                cursor.execute(f"SELECT COUNT(*) FROM vulnerabilities WHERE host_id IN ({ph}) AND status != 'false_positive'", alive_hosts)
                vulns_count = cursor.fetchone()[0]
                cursor.execute(f"SELECT COUNT(*) FROM endpoints WHERE host_id IN ({ph}) AND {fp_filter}", alive_hosts)
                endpoints_count = cursor.fetchone()[0]

            return {"hosts": hosts_count, "vulns": vulns_count, "endpoints": endpoints_count, "projeto": os.path.basename(proj_path)}
    except Exception as e:
        return {"hosts": 0, "vulns": 0, "endpoints": 0, "error": str(e)}

@app.get("/", response_class=HTMLResponse)
def serve_dashboard(username: str = Depends(verificar_autenticacao)):
    html_path = os.path.join(os.path.dirname(__file__), "index.html")
    try:
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "<h1>Erro: index.html não encontrado na pasta web/</h1>"

@app.get("/api/stats")
def api_stats(username: str = Depends(verificar_autenticacao)):
    return get_stats_from_db()

@app.get("/api/image/{host_id}/{filename:path}")
def get_image(host_id: int, filename: str, username: str = Depends(verificar_autenticacao)):
    """Serve as imagens de screenshots direto do diretório Nmap."""
    proj_path = os.environ.get("OPENPIPES_PROJ_PATH")
    if not proj_path:
        raise HTTPException(status_code=404, detail="Projeto não encontrado")

    try:
        with db.get_connection(proj_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT host FROM hosts WHERE id = ?", (host_id,))
            row = cursor.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Host não encontrado")
            host_name = row["host"]

        nmap_dir = _get_nmap_dir(proj_path)
        img_path = os.path.join(nmap_dir, f"nmap-{host_name}", "Screenshots", filename)

        if os.path.exists(img_path):
            return FileResponse(img_path)
        else:
            raise HTTPException(status_code=404, detail="Imagem não encontrada no sistema de arquivos.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/hosts")
def get_hosts(username: str = Depends(verificar_autenticacao)):
    proj_path = os.environ.get("OPENPIPES_PROJ_PATH")
    if not proj_path:
        return []

    scope_domains = _get_scope_domains(proj_path)
    fp_filter = "(vulnerability_patterns NOT LIKE '%potential_false_positive%' OR vulnerability_patterns IS NULL)"
    
    hosts_cards = []
    
    try:
        with db.get_connection(proj_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, host, ips FROM hosts WHERE is_alive = 1 AND in_scope = 1 ORDER BY host")
            
            for row in cursor.fetchall():
                if not _is_in_scope(row["host"], scope_domains):
                    continue
                
                host_id = row["id"]
                hostname = row["host"]
                ips = json.loads(row["ips"]) if row["ips"] else []
                
                cursor.execute("SELECT port FROM ports WHERE host_id = ? AND state = 'open' ORDER BY port", (host_id,))
                open_ports = [p["port"] for p in cursor.fetchall()]
                
                cursor.execute(f"SELECT COUNT(*) FROM endpoints WHERE host_id = ? AND {fp_filter}", (host_id,))
                ep_count = cursor.fetchone()[0]

                # Busca JS Discoveries
                cursor.execute(f"SELECT COUNT(*) FROM js_discoveries WHERE host_id = ?", (host_id,))
                js_count = cursor.fetchone()[0]

                # Busca Screenshots
                cursor.execute("SELECT file_path FROM screenshots WHERE host_id = ?", (host_id,))
                screenshots = [r["file_path"] for r in cursor.fetchall()]
                
                cursor.execute("""
                    SELECT severity, COUNT(*) as cnt 
                    FROM vulnerabilities 
                    WHERE host_id = ? AND status != 'false_positive' 
                    GROUP BY severity
                """, (host_id,))
                
                vuln_counts = {"Crítica": 0, "Alta": 0, "Média": 0, "Baixa": 0, "Info": 0}
                total_vulns = 0
                for v_row in cursor.fetchall():
                    sev = v_row["severity"]
                    if sev in vuln_counts:
                        vuln_counts[sev] = v_row["cnt"]
                        total_vulns += v_row["cnt"]
                
                hosts_cards.append({
                    "id": host_id,
                    "host": hostname,
                    "ip": ips[0] if ips else "Sem IP",
                    "open_ports": open_ports,
                    "endpoints_count": ep_count,
                    "js_count": js_count,
                    "screenshots": screenshots,
                    "screenshots_count": len(screenshots),
                    "vulns_total": total_vulns,
                    "vulns_severity": vuln_counts
                })
                
        return hosts_cards
    except Exception as e:
        return {"error": str(e)}