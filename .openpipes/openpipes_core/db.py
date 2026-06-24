import sqlite3
import os

def get_connection(proj_path):
    db_path = os.path.join(proj_path, ".openpipes.db")
    conn = sqlite3.connect(db_path, timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL;')
    conn.execute('PRAGMA synchronous=NORMAL;')
    return conn

def init_db(proj_path):
    conn = get_connection(proj_path)
    cursor = conn.cursor()
    
    # 1. ENTIDADE FORTE: Hosts
    cursor.execute('''CREATE TABLE IF NOT EXISTS hosts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host TEXT UNIQUE,
        ips TEXT DEFAULT '[]', -- Array JSON de IPs [\"10.0.0.1\", \"10.0.0.2\"]
        is_alive BOOLEAN DEFAULT 0,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # 2. ENTIDADE FRACA: Portas (Relação 1:N com Hosts)
    cursor.execute('''CREATE TABLE IF NOT EXISTS ports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id INTEGER,
        port INTEGER,
        protocol TEXT,
        state TEXT,
        service TEXT,
        version TEXT,
        FOREIGN KEY(host_id) REFERENCES hosts(id),
        UNIQUE(host_id, port, protocol) -- Evita duplicar a mesma porta para o mesmo host
    )''')
    
    # 3. ENTIDADE FRACA: Endpoints e Tecnologias
    cursor.execute('''CREATE TABLE IF NOT EXISTS endpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id INTEGER,
        url TEXT UNIQUE,
        status_code INTEGER,
        content_length INTEGER,
        content_type TEXT,
        title TEXT,
        web_server TEXT,
        tech_stack TEXT,
        source_tool TEXT,
        discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(host_id) REFERENCES hosts(id)
    )''')
    
    # (A tabela de vulnerabilidades fica intacta pro futuro)
    cursor.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id INTEGER,
        endpoint_id INTEGER,
        severity TEXT,
        vuln_name TEXT,
        description TEXT,
        matched_at TEXT,
        curl_command TEXT,
        source_tool TEXT,
        FOREIGN KEY(host_id) REFERENCES hosts(id),
        UNIQUE(vuln_name, matched_at)
    )''')
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS execution_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        module_name TEXT NOT NULL,
        status TEXT NOT NULL,
        exit_code INTEGER,
        start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        end_time TIMESTAMP
    )''')

    conn.commit()
    conn.close()

def log_module_start(proj_path, module_name):
    conn = get_connection(proj_path)
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO execution_logs (module_name, status) VALUES (?, 'RUNNING')''', (module_name,))
    exec_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return exec_id

def log_module_finish(proj_path, execution_id, exit_code):
    conn = get_connection(proj_path)
    cursor = conn.cursor()
    status = 'SUCCESS' if exit_code == 0 else 'FAILED'
    cursor.execute('''UPDATE execution_logs SET status = ?, exit_code = ?, end_time = CURRENT_TIMESTAMP WHERE id = ?''', (status, exit_code, execution_id))
    conn.commit()
    conn.close()

def get_recent_executions(proj_path, limit=15):
    conn = get_connection(proj_path)
    cursor = conn.cursor()
    cursor.execute('''SELECT id, module_name, status, exit_code, start_time, end_time FROM execution_logs ORDER BY start_time DESC LIMIT ?''', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows