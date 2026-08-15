import os
import sys
from fastapi import FastAPI, Depends
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

# Adiciona o diretório raiz 'openpipes_core' ao sys.path para conseguirmos importar o db.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import db

from .auth import verificar_autenticacao

app = FastAPI(title="OPenPipeS Web Dashboard")

# Permite acesso CORS caso a gente separe o frontend no futuro
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_stats_from_db():
    proj_path = os.environ.get("OPENPIPES_PROJ_PATH")
    if not proj_path:
        return {"hosts": 0, "vulns": 0, "endpoints": 0, "error": "Projeto não carregado."}
        
    try:
        # Usa a mesma função de conexão do seu framework
        with db.get_connection(proj_path) as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM hosts")
            hosts = c.fetchone()[0]
            
            c.execute("SELECT COUNT(*) FROM vulnerabilities")
            vulns = c.fetchone()[0]
            
            c.execute("SELECT COUNT(*) FROM endpoints")
            endpoints = c.fetchone()[0]
            
            return {"hosts": hosts, "vulns": vulns, "endpoints": endpoints, "projeto": os.path.basename(proj_path)}
    except Exception as e:
        return {"hosts": 0, "vulns": 0, "endpoints": 0, "error": str(e)}

# Rota da Interface Web (Protegida)
@app.get("/", response_class=HTMLResponse)
def serve_dashboard(username: str = Depends(verificar_autenticacao)):
    html_path = os.path.join(os.path.dirname(__file__), "index.html")
    try:
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "<h1>Erro: index.html não encontrado na pasta web/</h1>"

# Rota da API (Protegida)
@app.get("/api/stats")
def api_stats(username: str = Depends(verificar_autenticacao)):
    stats = get_stats_from_db()
    return stats