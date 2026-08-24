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
            "in_scope": "in_scope BOOLEAN DEFAULT 1",
            "narrative": "narrative TEXT",
            "manual_techs": "manual_techs TEXT DEFAULT '[]'",
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

        # ── Injectable Params (Arjun) ────────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS injectable_params (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id   INTEGER NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
                host_id       INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                param_name    TEXT NOT NULL,
                param_type    TEXT NOT NULL,
                http_method   TEXT NOT NULL,
                source_tool   TEXT DEFAULT 'arjun',
                scanned_by    TEXT DEFAULT '',
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(endpoint_id, param_name, param_type, http_method)
            )
        """)

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

        # ── Tasks ──────────────────────────────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                task_key TEXT NOT NULL,
                label TEXT NOT NULL,
                is_done BOOLEAN DEFAULT 0,
                kind TEXT NOT NULL DEFAULT 'auto',
                UNIQUE(host_id, task_key)
            )
        """)

        # ── User Evidences ─────────────────────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_evidences (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                vuln_id INTEGER REFERENCES vulnerabilities(id) ON DELETE CASCADE,
                original_name TEXT NOT NULL,
                stored_name TEXT NOT NULL UNIQUE,
                sha256 TEXT NOT NULL UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
                    status          TEXT NOT NULL DEFAULT 'open',
                    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(vuln_name, matched_at, host_id)
                )
            """)
            _add_missing_columns(conn, "vulnerabilities", {
                "cwe_id": "cwe_id TEXT DEFAULT ''",
                "status": "status TEXT NOT NULL DEFAULT 'open'",
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
                "status":         "status TEXT NOT NULL DEFAULT 'open'",
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


def sync_auto_tasks(conn, host_id, auto_specs):
    """Upsert auto tasks preserving done state; delete stale auto tasks."""
    cur = conn.cursor()
    seen = set()
    for spec in auto_specs:
        seen.add(spec["key"])
        cur.execute(
            "INSERT INTO tasks (host_id, task_key, label, is_done, kind) "
            "VALUES (?, ?, ?, 0, 'auto') "
            "ON CONFLICT(host_id, task_key) DO UPDATE SET label = excluded.label",
            (host_id, spec["key"], spec["label"]),
        )
    if seen:
        ph = ",".join("?" for _ in seen)
        cur.execute(
            f"DELETE FROM tasks WHERE host_id = ? AND kind = 'auto' AND task_key NOT IN ({ph})",
            (host_id, *seen),
        )
    else:
        cur.execute("DELETE FROM tasks WHERE host_id = ? AND kind = 'auto'", (host_id,))


def get_host_tasks(conn, host_id):
    cur = conn.cursor()
    cur.execute("SELECT task_key, label, is_done FROM tasks WHERE host_id = ?", (host_id,))
    return cur.fetchall()
