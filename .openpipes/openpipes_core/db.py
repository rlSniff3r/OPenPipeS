import sqlite3
import os
from contextlib import contextmanager


DB_FILENAME = ".openpipes.db"


def _list_columns(conn, table):
    """Return set of existing column names for a table, or empty set if table doesn't exist."""
    try:
        cursor = conn.execute(f"PRAGMA table_info({table})")
        return {row[1] for row in cursor.fetchall()}
    except sqlite3.OperationalError:
        return set()


def _add_missing_columns(conn, table, columns):
    """
    Add columns to *table* that don't already exist.
    *columns* is a dict of {col_name: "col_name TYPE CONSTRAINTS"}.
    Safe to call repeatedly — only missing columns are added.
    """
    existing = _list_columns(conn, table)
    for col_name, col_def in columns.items():
        if col_name not in existing:
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_def}")
            except sqlite3.OperationalError:
                pass  # ignore if another process added it simultaneously


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
    """Explicit transaction context for atomic parser writes."""
    conn.execute("BEGIN")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_db(proj_path):
    """
    Create tables if missing and migrate existing tables with new columns.
    Safe to call on every module execution — no-op once schema is up-to-date.
    """
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

        # ── Hosts ───────────────────────────────────────────────────────
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
        _add_missing_columns(conn, "hosts", {
            "project_id": "project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE",
            "in_scope": "in_scope BOOLEAN DEFAULT 1"
        })

        # ── Ports ───────────────────────────────────────────────────────
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

        # ── Endpoints ───────────────────────────────────────────────────
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
                discovered_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                response_hash         TEXT,
                verified_at           TIMESTAMP
            )
        """)

        _add_missing_columns(conn, "endpoints", {
            "response_hash": "response_hash TEXT",
            "verified_at": "verified_at TIMESTAMP",
            "scanned_by": "scanned_by TEXT DEFAULT ''",
        })

        # ── Screenshots ─────────────────────────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS screenshots (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                file_path  TEXT UNIQUE,
                source_url    TEXT,               -- NEW: original URL that was screenshotted
                final_url     TEXT,               -- NEW: final URL after redirects
                status_code   INTEGER,            -- NEW: HTTP status code
                title         TEXT,               -- NEW: page title
                content_length INTEGER,           -- NEW: response size
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # ── JS Discoveries ──────────────────────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS js_discoveries (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id          INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                source_js_url    TEXT,
                discovered_route TEXT,
                UNIQUE(source_js_url, discovered_route)
            )
        """)

        # ── Vulnerabilities (expanded) ──────────────────────────────────
        # If table doesn't exist, create it with full schema.
        # If it exists, add any missing columns.
        existing_vuln_cols = _list_columns(conn, "vulnerabilities")

        if not existing_vuln_cols:
            cursor.execute("""
                CREATE TABLE vulnerabilities (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                    endpoint_id     INTEGER REFERENCES endpoints(id) ON DELETE SET NULL,
                    title           TEXT,
                    severity        TEXT,
                    cvss_score      REAL,
                    cvss_vector     TEXT,
                    cve_id          TEXT,
                    vuln_name       TEXT,
                    description     TEXT,
                    matched_at      TEXT,
                    curl_command    TEXT,
                    remediation     TEXT,
                    impact          TEXT,
                    reference_urls  TEXT DEFAULT '[]',
                    source_tool     TEXT,
                    enriched_by     TEXT,
                    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(vuln_name, matched_at, host_id)
                )
            """)
            _add_missing_columns(conn, "vulnerabilities", {
                "cwe_id": "cwe_id TEXT DEFAULT ''",
            })

        else:
            # Add new columns to existing table
            new_cols = {
                "title":          "title TEXT",
                "cvss_score":     "cvss_score REAL",
                "cvss_vector":    "cvss_vector TEXT",
                "cwe_id":         "cwe_id TEXT DEFAULT ''",
                "cve_id":         "cve_id TEXT",
                "remediation":    "remediation TEXT",
                "impact":         "impact TEXT",
                "reference_urls": "reference_urls TEXT DEFAULT '[]'",
                "enriched_by":    "enriched_by TEXT",
                "created_at":     "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
            }
            _add_missing_columns(conn, "vulnerabilities", new_cols)

        # ── Execution Logs ──────────────────────────────────────────────
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
        _add_missing_columns(conn, "execution_logs", {
            "project_id": "project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL"
        })

        # ═══════════════════════════════════════════════════════════════
        # INDEXES (idempotent)
        # ═══════════════════════════════════════════════════════════════
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_hosts_project       ON hosts(project_id)",
            "CREATE INDEX IF NOT EXISTS idx_ports_host          ON ports(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_endpoints_host      ON endpoints(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_endpoints_url       ON endpoints(url)",
            "CREATE INDEX IF NOT EXISTS idx_screenshots_host    ON screenshots(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_js_discoveries_host ON js_discoveries(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_vulns_host          ON vulnerabilities(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_vulns_severity      ON vulnerabilities(severity)",
            "CREATE INDEX IF NOT EXISTS idx_exec_logs_project   ON execution_logs(project_id)",
            "CREATE INDEX IF NOT EXISTS idx_exec_logs_module    ON execution_logs(module_name)",
        ]
        for idx in indexes:
            cursor.execute(idx)

    return True


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
