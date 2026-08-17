import os
import sys
import re
import json
import subprocess
import base64
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
import asyncio
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from cvss import CVSS3

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

@app.get("/api/image/{host_id}/{file_path:path}")
def get_image(host_id: int, file_path: str, username: str = Depends(verificar_autenticacao)):
    """Serve imagens das pastas Screenshots e Evidencias."""
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

        # Verifica na pasta Screenshots (Reconhecimento Automático)
        ss_path = os.path.join(proj_path, "Varreduras", f"nmap-{host_name}", "Screenshots", file_path)
        # Verifica na pasta Evidencias (Imagens coladas pelo usuário no Obsidian)
        ev_path = os.path.join(proj_path, "Varreduras", f"nmap-{host_name}", "Evidencias", file_path)

        if os.path.exists(ss_path):
            return FileResponse(ss_path)
        elif os.path.exists(ev_path):
            return FileResponse(ev_path)
        else:
            raise HTTPException(status_code=404, detail="Imagem não encontrada no disco")
            
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

@app.get("/api/hosts/{host_id}/details")
def get_host_details(host_id: int, username: str = Depends(verificar_autenticacao)):
    """Busca os detalhes profundos de um host específico (Dossiê)."""
    proj_path = os.environ.get("OPENPIPES_PROJ_PATH")
    if not proj_path:
        raise HTTPException(status_code=404, detail="Projeto não encontrado")

    fp_filter = "(vulnerability_patterns NOT LIKE '%potential_false_positive%' OR vulnerability_patterns IS NULL)"

    try:
        with db.get_connection(proj_path) as conn:
            cursor = conn.cursor()
            
            # 1. Portas Abertas
            cursor.execute("SELECT port, protocol, service, version FROM ports WHERE host_id = ? AND state = 'open' ORDER BY port", (host_id,))
            ports = [dict(row) for row in cursor.fetchall()]
            
            # 2. Endpoints e Tecnologias
            cursor.execute(f"""
                SELECT url, status_code, content_length, title, web_server, tech_stack 
                FROM endpoints 
                WHERE host_id = ? AND {fp_filter} 
                ORDER BY url
            """, (host_id,))
            
            endpoints = []
            tech_set = set()
            for row in cursor.fetchall():
                ep = dict(row)
                ts = []
                if ep.get("tech_stack"):
                    try:
                        ts = json.loads(ep["tech_stack"])
                    except:
                        pass
                ep["tech_stack"] = ts
                for t in ts:
                    tech_set.add(t)
                endpoints.append(ep)
            
            # 3. Vulnerabilidades
            cursor.execute("""
                SELECT id, title, severity, cvss_score, cwe_id, cve_id, description, 
                       curl_command, remediation, impact, reference_urls, source_tool, enriched_by 
                FROM vulnerabilities 
                WHERE host_id = ? AND status != 'false_positive'
                ORDER BY CASE severity WHEN 'Crítica' THEN 0 WHEN 'Alta' THEN 1 WHEN 'Média' THEN 2 WHEN 'Baixa' THEN 3 ELSE 4 END
            """, (host_id,))
            
            vulns = []
            for row in cursor.fetchall():
                v = dict(row)
                if v.get("reference_urls"):
                    try:
                        v["reference_urls"] = json.loads(v["reference_urls"])
                    except:
                        v["reference_urls"] = []
                else:
                    v["reference_urls"] = []
                vulns.append(v)

            # 4. Rotas JS (JS Discoveries)
            cursor.execute("SELECT source_js_url, discovered_route FROM js_discoveries WHERE host_id = ?", (host_id,))
            js_discoveries = [dict(row) for row in cursor.fetchall()]

            # 5. Screenshots
            cursor.execute("SELECT file_path, source_url, final_url, status_code, title, content_length FROM screenshots WHERE host_id = ?", (host_id,))
            screenshots = [dict(row) for row in cursor.fetchall()]

            return {
                "ports": ports,
                "endpoints": endpoints,
                "technologies": sorted(list(tech_set)),
                "vulnerabilities": vulns,
                "js_discoveries": js_discoveries,
                "screenshots": screenshots
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# =====================================================================
# ROTAS DA FASE 6 (AÇÕES E MANIPULAÇÃO)
# =====================================================================

@app.post("/api/endpoints/{host_id}/{b64_url}/fp")
def mark_endpoint_fp(host_id: int, b64_url: str, username: str = Depends(verificar_autenticacao)):
    """Marca um endpoint como Falso Positivo (adiciona flag de ignorar na coluna de vulnerabilidades)."""
    proj_path = os.environ.get("OPENPIPES_PROJ_PATH")
    if not proj_path:
        raise HTTPException(status_code=404, detail="Projeto não encontrado")

    try:
        # Decodifica a URL (Ela vem em base64 do frontend para não quebrar a rota com barras '/' e 'http://')
        url = base64.b64decode(b64_url).decode('utf-8')
    except Exception:
        raise HTTPException(status_code=400, detail="URL inválida")

    try:
        with db.get_connection(proj_path) as conn:
            cursor = conn.cursor()
            
            # Puxa os dados atuais
            cursor.execute("SELECT vulnerability_patterns FROM endpoints WHERE host_id = ? AND url = ?", (host_id, url))
            row = cursor.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Endpoint não encontrado")
            
            current_patterns = row["vulnerability_patterns"]
            patterns = []
            
            if current_patterns:
                try:
                    patterns = json.loads(current_patterns)
                except:
                    pass
            
            # Adiciona a flag se não existir
            if "potential_false_positive" not in patterns:
                patterns.append("potential_false_positive")
                
            cursor.execute("UPDATE endpoints SET vulnerability_patterns = ? WHERE host_id = ? AND url = ?", 
                           (json.dumps(patterns), host_id, url))
            conn.commit() # <--- ADICIONE ESTA LINHA AQUI
            
            return {"status": "success", "message": "Endpoint ocultado (Falso Positivo)."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/vulns/{vuln_id}/fp")
def mark_vuln_fp(vuln_id: int, username: str = Depends(verificar_autenticacao)):
    """Marca uma vulnerabilidade como Falso Positivo alterando seu status no banco."""
    proj_path = os.environ.get("OPENPIPES_PROJ_PATH")
    if not proj_path:
        raise HTTPException(status_code=404, detail="Projeto não encontrado")

    try:
        with db.get_connection(proj_path) as conn:
            cursor = conn.cursor()
            # Atualiza o status diretamente (conforme a lógica do seu renderer.py)
            cursor.execute("UPDATE vulnerabilities SET status = 'false_positive' WHERE id = ?", (vuln_id,))
            conn.commit()
            return {"status": "success", "message": "Vulnerabilidade marcada como Falso Positivo."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/sync")
def trigger_obsidian_sync(username: str = Depends(verificar_autenticacao)):
    """Chama o orquestrador para sincronizar as mudanças do banco de dados com a Vault do Obsidian."""
    try:
        # Chama o comando CLI exato que você pediu
        # Rodamos em background com nohup/& ou esperamos terminar? (Vamos esperar para o Toast)
        result = subprocess.run(
            ["openpipes-core", "sync"], 
            capture_output=True, text=True, check=False
        )
        if result.returncode == 0:
            return {"status": "success", "message": "Vault Obsidian sincronizada com sucesso!"}
        else:
            raise HTTPException(status_code=500, detail=f"Erro no sync: {result.stderr}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao invocar o orquestrador: {str(e)}")

# =====================================================================
# ROTAS DA FASE 7 (CAÇADA GLOBAL / DRILL-DOWN)
# =====================================================================

@app.get("/api/global/vulnerabilities")
def get_global_vulnerabilities(username: str = Depends(verificar_autenticacao)):
    """Busca todas as vulnerabilidades do projeto (Caçada Horizontal)."""
    proj_path = os.environ.get("OPENPIPES_PROJ_PATH")
    if not proj_path:
        raise HTTPException(status_code=404, detail="Projeto não encontrado")

    # CORREÇÃO: Removido o prefixo 'renderer.'
    scope_domains = _get_scope_domains(proj_path)
    
    vulns = []
    try:
        with db.get_connection(proj_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT v.id, v.title, v.severity, v.cvss_score, v.cwe_id, v.cve_id, v.cvss_vector,
                       v.description, v.curl_command, v.remediation, v.impact, v.reference_urls, 
                       h.host, h.id as host_id
                FROM vulnerabilities v
                JOIN hosts h ON h.id = v.host_id
                WHERE h.is_alive = 1 AND h.in_scope = 1 AND v.status != 'false_positive'
                ORDER BY CASE v.severity WHEN 'Crítica' THEN 0 WHEN 'Alta' THEN 1 WHEN 'Média' THEN 2 WHEN 'Baixa' THEN 3 ELSE 4 END
            """)
            rows = cursor.fetchall()
            
            for row in rows:
                # CORREÇÃO: Removido o prefixo 'renderer.'
                if not _is_in_scope(row["host"], scope_domains): 
                    continue
                v = dict(row)
                
                # Tratamento de URLs de Referência
                if v.get("reference_urls"):
                    try:
                        v["reference_urls"] = json.loads(v["reference_urls"])
                    except:
                        v["reference_urls"] = []
                else:
                    v["reference_urls"] = []
                    
                # BUSCA AS EVIDÊNCIAS DESTA VULNERABILIDADE
                cursor.execute("SELECT stored_name FROM user_evidences WHERE vuln_id = ?", (v["id"],))
                v["evidences"] = [ev["stored_name"] for ev in cursor.fetchall()]
                
                vulns.append(v)
        return vulns
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/global/endpoints")
def get_global_endpoints(username: str = Depends(verificar_autenticacao)):
    """Busca todos os endpoints higienizados do projeto (Caçada Horizontal)."""
    proj_path = os.environ.get("OPENPIPES_PROJ_PATH")
    if not proj_path:
        raise HTTPException(status_code=404, detail="Projeto não encontrado")

    scope_domains = _get_scope_domains(proj_path)
    fp_filter = "(e.vulnerability_patterns NOT LIKE '%potential_false_positive%' OR e.vulnerability_patterns IS NULL)"
    
    endpoints = []
    try:
        with db.get_connection(proj_path) as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                SELECT e.url, e.status_code, e.content_length, e.title, h.host, h.id as host_id
                FROM endpoints e
                JOIN hosts h ON h.id = e.host_id
                WHERE h.is_alive = 1 AND h.in_scope = 1 AND {fp_filter}
            """)
            for row in cursor.fetchall():
                if not _is_in_scope(row["host"], scope_domains): 
                    continue
                endpoints.append(dict(row))
        return endpoints
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# =====================================================================
# MODELOS DE DADOS (PYDANTIC)
# =====================================================================
class VulnUpdate(BaseModel):
    title: str
    description: str
    impact: str
    remediation: str
    cvss_vector: str
    reference_urls: List[str]
    cwe_id: str

# =====================================================================
# ROTAS DA FASE 8 (DEEP EDIT CVSS)
# =====================================================================
@app.put("/api/vulns/{vuln_id}")
def update_vulnerability(vuln_id: int, data: VulnUpdate, username: str = Depends(verificar_autenticacao)):
    """Atualiza a vulnerabilidade, recalculando o CVSS Score e Severidade via Backend."""
    proj_path = os.environ.get("OPENPIPES_PROJ_PATH")
    if not proj_path:
        raise HTTPException(status_code=404, detail="Projeto não encontrado")

    # Mapeamento de Severidades padrão da CVSS3 para o português da nossa UI
    sev_map = {"CRITICAL": "Crítica", "HIGH": "Alta", "MEDIUM": "Média", "LOW": "Baixa", "NONE": "Info"}
    score = 0.0
    severity = "Média" # Fallback

    # Recalcula o CVSS baseando-se no vetor enviado pelo Frontend
    if data.cvss_vector and data.cvss_vector.startswith("CVSS:3"):
        try:
            c = CVSS3(data.cvss_vector)
            score = float(c.scores()[0])
            raw_sev = c.severities()[0].upper()
            severity = sev_map.get(raw_sev, "Média")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Vetor CVSS inválido: {str(e)}")

    try:
        with db.get_connection(proj_path) as conn:
            cursor = conn.cursor()
            
            # Atualiza o banco, marcando o enriched_by como 'user_web' para o sync saber que foi edição humana
            cursor.execute("""
                UPDATE vulnerabilities SET
                    title = ?, description = ?, impact = ?, remediation = ?,
                    cvss_vector = ?, cvss_score = ?, severity = ?,
                    reference_urls = ?, cwe_id = ?, enriched_by = 'user_web'
                WHERE id = ?
            """, (
                data.title, data.description, data.impact, data.remediation,
                data.cvss_vector, score, severity,
                json.dumps(data.reference_urls), data.cwe_id, vuln_id
            ))
            conn.commit()
            
            return {
                "status": "success", 
                "message": "Vulnerabilidade atualizada!",
                "new_score": score,
                "new_severity": severity
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# =====================================================================
# ROTAS DA FASE 8.1 (CENTRO DE COMANDOS - MVP CYCLE)
# =====================================================================


# Variável global para armazenar a instância do processo ao invés de um booleano
CYCLE_PROCESS = None

@app.post("/api/cycle")
def start_cycle(username: str = Depends(verificar_autenticacao)):
    """Inicia o ciclo de varredura como um Daemon isolado do servidor web."""
    global CYCLE_PROCESS
    
    # Verifica se o processo existe e se ainda está rodando (poll() retorna None se estiver rodando)
    if CYCLE_PROCESS is not None and CYCLE_PROCESS.poll() is None:
        raise HTTPException(status_code=409, detail="Um ciclo já está em execução no servidor.")
    
    proj_path = os.environ.get("OPENPIPES_PROJ_PATH")
    log_file_path = os.path.join(proj_path, "cycle_web.log") if proj_path else "/tmp/cycle_web.log"
    
    try:
        # Abre o arquivo para onde o output será despejado
        f_log = open(log_file_path, "w")
        
        # Popen inicia o processo e solta (não trava o Python)
        CYCLE_PROCESS = subprocess.Popen(
            ["openpipes-core", "cycle"], 
            stdout=f_log,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, # Corta a entrada padrão (resolve o bug de 100% CPU)
            start_new_session=True    # Isola o processo do servidor web (Daemon)
        )
        
        return {"status": "success", "message": "Ciclo iniciado como processo fantasma!"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/status")
def get_system_status(username: str = Depends(verificar_autenticacao)):
    """Retorna o status atual dos processos (Polling)."""
    global CYCLE_PROCESS
    is_running = False
    
    if CYCLE_PROCESS is not None:
        # Se poll() for None, o processo ainda está vivo na máquina
        if CYCLE_PROCESS.poll() is None:
            is_running = True
            
    return {"cycle_running": is_running}

# =====================================================================
# FASE 8.3: A PONTE WEBSOCKET (TERMINAL LOGS)
# =====================================================================
@app.websocket("/api/ws/logs/{module_name}")
async def websocket_logs(websocket: WebSocket, module_name: str):
    """
    Mantém uma conexão viva com o navegador (WebSocket) e transmite 
    o arquivo de log em tempo real usando o `tail -f` do Linux.
    """
    await websocket.accept()
    proj_path = os.environ.get("OPENPIPES_PROJ_PATH")
    
    if not proj_path:
        await websocket.close()
        return
    
    # Define de onde o log será lido
    if module_name == "main":
        # O orquestrador principal grava na raiz do projeto
        log_path = os.path.join(proj_path, "cycle_web.log")
    else:
        # Ferramentas individuais gravam na subpasta logs/
        log_path = os.path.join(proj_path, "logs", f"{module_name}.log")

    # Se o log não existir ainda (módulo não começou), criamos um arquivo vazio
    if not os.path.exists(log_path):
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        open(log_path, 'a').close()

    # Cria um processo não-bloqueante no Linux para fazer o tail
    process = await asyncio.create_subprocess_exec(
        'tail', '-n', '100', '-f', log_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    try:
        while True:
            # Lê linha por linha conforme são gravadas no disco
            line = await process.stdout.readline()
            if not line:
                await asyncio.sleep(0.5)
                continue
            # Envia a linha para o Frontend
            await websocket.send_text(line.decode('utf-8'))
    except WebSocketDisconnect:
        # Quando o usuário fecha o painel no navegador, a conexão cai
        pass
    finally:
        # Sempre matamos o comando tail para não deixar processos zumbis
        try:
            process.terminate()
        except:
            pass