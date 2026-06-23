# ~/.openpipes/openpipes_core/db.py
import sqlite3
import os
from datetime import datetime
from pathlib import Path

DB_PATH = os.path.join(str(Path.home()), ".openpipes_state.db")

def get_connection():
    """Retorna a conexão com o banco SQLite"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Cria as tabelas de estado se não existirem"""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Tabela de Projetos
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Tabela de Execução de Módulos (Rastreabilidade)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS module_executions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_name TEXT NOT NULL,
            module_name TEXT NOT NULL,
            status TEXT NOT NULL,
            exit_code INTEGER,
            start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            end_time TIMESTAMP,
            FOREIGN KEY (project_name) REFERENCES projects (name)
        )
    ''')
    conn.commit()
    conn.close()

def log_module_start(project_name, module_name):
    """Registra o início de um módulo e retorna o ID da execução"""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Garante que o projeto existe
    cursor.execute('INSERT OR IGNORE INTO projects (name) VALUES (?)', (project_name,))
    
    cursor.execute('''
        INSERT INTO module_executions (project_name, module_name, status)
        VALUES (?, ?, 'RUNNING')
    ''', (project_name, module_name))
    
    execution_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return execution_id

def log_module_finish(execution_id, exit_code):
    """Atualiza a execução com o resultado final do Bash"""
    conn = get_connection()
    cursor = conn.cursor()
    status = 'SUCCESS' if exit_code == 0 else 'FAILED'
    
    cursor.execute('''
        UPDATE module_executions
        SET status = ?, exit_code = ?, end_time = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (status, exit_code, execution_id))
    
    conn.commit()
    conn.close()