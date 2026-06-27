import sqlite3
import os
from contextlib import contextmanager


DB_FILENAME = ".openpipes.db"


@contextmanager
def get_connection(proj_path):
    """Context manager that provides a connection and commits/rolls back on exit."""
    db_path = os.path.join(proj_path, DB_FILENAME)
    conn = sqlite3.connect(db_path, timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextmanager
def transaction(conn):
    """Explicit transaction context for a single parser call."""
    conn.execute("BEGIN")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_db(proj_path):
    """Create all tables, indexes, and migrations."""
    with get_connection(proj_path) as conn:
        cursor = conn.cursor()

        # ── Projects ────────────────────────────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS projects (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT UNIQUE NOT NULL,
                root_domain TEXT,
                client      TEXT,
                status      TEXT DEFAULT 'active',
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # ── Hosts (domains + resolved IPs) ──────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hosts (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id   INTEGER REFERENCES projects(id) ON DELETE CASCADE,
                host         TEXT UNIQUE,
                ips          TEXT DEFAULT '[]',
                cnames       TEXT DEFAULT '[]',
                whois_data   TEXT,
                is_alive     BOOLEAN DEFAULT 0,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # ── Ports ────────────────────────────────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ports (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id  INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                port     INTEGER,
                protocol TEXT,
                state    TEXT,
                service  TEXT,
                version  TEXT,
                UNIQUE(host_id, port, protocol)
            )
        """)

        # ── Endpoints ────────────────────────────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS endpoints (
                id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id               INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                url                   TEXT UNIQUE,
                status_code           INTEGER,
                content_length        INTEGER,
                content_type          TEXT,
                title                 TEXT,
                web_server            TEXT,
                tech_stack            TEXT DEFAULT '[]',
                source_tool           TEXT,
                vulnerability_patterns TEXT DEFAULT '[]',
                discovered_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # ── Screenshots ──────────────────────────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS screenshots (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                file_path  TEXT UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # ── JS Discoveries ───────────────────────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS js_discoveries (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id          INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                source_js_url    TEXT,
                discovered_route TEXT,
                UNIQUE(source_js_url, discovered_route)
            )
        """)

        # ── Vulnerabilities (expanded schema) ────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id      INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                endpoint_id  INTEGER REFERENCES endpoints(id) ON DELETE SET NULL,
                title        TEXT,
                severity     TEXT,
                cvss_score   REAL,
                cvss_vector  TEXT,
                cve_id       TEXT,
                vuln_name    TEXT,
                description  TEXT,
                matched_at   TEXT,
                curl_command TEXT,
                remediation  TEXT,
                impact       TEXT,
                references   TEXT DEFAULT '[]',
                source_tool  TEXT,
                enriched_by  TEXT,
                created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(vuln_name, matched_at, host_id)
            )
        """)

        # ── Execution Logs ───────────────────────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS execution_logs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id  INTEGER REFERENCES projects(id) ON DELETE SET NULL,
                module_name TEXT NOT NULL,
                status      TEXT NOT NULL,
                exit_code   INTEGER,
                start_time  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                end_time    TIMESTAMP
            )
        """)

        # ═══════════════════════════════════════════════════════════════
        # INDEXES
        # ═══════════════════════════════════════════════════════════════
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_hosts_project ON hosts(project_id)",
            "CREATE INDEX IF NOT EXISTS idx_ports_host    ON ports(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_endpoints_host ON endpoints(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_endpoints_url  ON endpoints(url)",
            "CREATE INDEX IF NOT EXISTS idx_screenshots_host ON screenshots(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_js_discoveries_host ON js_discoveries(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_vulns_host     ON vulnerabilities(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)",
            "CREATE INDEX IF NOT EXISTS idx_exec_logs_project ON execution_logs(project_id)",
            "CREATE INDEX IF NOT EXISTS idx_exec_logs_module ON execution_logs(module_name)",
        ]
        for idx in indexes:
            cursor.execute(idx)


# ── Execution log helpers ──────────────────────────────────────────────

def log_module_start(proj_path, module_name, project_id=None):
    with get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO execution_logs (project_id, module_name, status) VALUES (?, ?, 'RUNNING')",
            (project_id, module_name),
        )
        return cursor.lastrowid


def log_module_finish(proj_path, execution_id, exit_code):
    with get_connection(proj_path) as conn:
        cursor = conn.cursor()
        status = "SUCCESS" if exit_code == 0 else "FAILED"
        cursor.execute(
            "UPDATE execution_logs SET status = ?, exit_code = ?, end_time = CURRENT_TIMESTAMP WHERE id = ?",
            (status, exit_code, execution_id),
        )


def get_recent_executions(proj_path, limit=15):
    with get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT id, module_name, status, exit_code, start_time, end_time
               FROM execution_logs
               ORDER BY start_time DESC LIMIT ?""",
            (limit,),
        )
        return cursor.fetchall()
