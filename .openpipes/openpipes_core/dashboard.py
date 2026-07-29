#!/usr/bin/env python3
"""OpenPipeS Web Dashboard — MVP (Overview, Hosts, Vulns)"""

import os
import json
import subprocess
from pathlib import Path

from flask import Flask, render_template, jsonify

import db

HOME = str(Path.home())
HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(HERE, "dashboard_templates")


def _get_proj_path():
    config_file = os.path.join(HOME, ".openpipes", "config.sh")
    if os.path.exists(config_file):
        try:
            cmd = f"source {config_file} && echo -n \"$proj_path\""
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, executable="/bin/bash")
            if r.stdout.strip():
                return r.stdout.strip()
        except Exception:
            pass
    return os.getcwd()


def _top_vulns(cursor, limit=5):
    cursor.execute("""
        SELECT v.id, v.title, v.cvss_score, v.severity,
               COALESCE(h.host, 'N/A') as host
        FROM vulnerabilities v
        LEFT JOIN hosts h ON h.id = v.host_id
        WHERE v.severity IN ('Crítica','Alta','High','Critical')
        ORDER BY CAST(COALESCE(v.cvss_score, 0) AS REAL) DESC
        LIMIT ?
    """, (limit,))
    return [dict(r) for r in cursor.fetchall()]


def create_app(proj_path=None):
    app = Flask(__name__, template_folder=TEMPLATE_DIR)
    app.config["proj_path"] = proj_path or _get_proj_path()

    # ─── Overview ────────────────────────────────────────────
    @app.route("/")
    def overview():
        pp = app.config["proj_path"]
        stats = {}
        with db.get_connection(pp) as conn:
            c = conn.cursor()
            stats["total_hosts"]   = c.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
            stats["alive_hosts"]   = c.execute("SELECT COUNT(*) FROM hosts WHERE is_alive=1").fetchone()[0]
            stats["in_scope"]      = c.execute("SELECT COUNT(*) FROM hosts WHERE in_scope=1").fetchone()[0]
            stats["total_ports"]   = c.execute("SELECT COUNT(*) FROM ports").fetchone()[0]
            stats["total_endpoints"] = c.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0]
            stats["total_vulns"]   = c.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]

            c.execute("SELECT COALESCE(severity,'N/A') as s, COUNT(*) as c FROM vulnerabilities GROUP BY s ORDER BY c DESC")
            stats["vulns_by_severity"] = {r["s"]: r["c"] for r in c.fetchall()}

            c.execute("SELECT module_name, started_at, status FROM execution_logs ORDER BY started_at DESC LIMIT 8")
            stats["recent_scans"] = [dict(r) for r in c.fetchall()]

            stats["top_vulns"] = _top_vulns(c, 5)

        return render_template("overview.html", stats=stats)

    @app.route("/api/stats")
    def api_stats():
        pp = app.config["proj_path"]
        with db.get_connection(pp) as conn:
            c = conn.cursor()
            c.execute("SELECT COALESCE(severity,'N/A') as s, COUNT(*) as c FROM vulnerabilities GROUP BY s")
            sev = {r["s"]: r["c"] for r in c.fetchall()}
            c.execute("SELECT COUNT(*) FROM hosts WHERE is_alive=1 AND in_scope=1")
            active = c.fetchone()[0]
        return jsonify({"severity": sev, "active_hosts": active})

    # ─── Hosts ───────────────────────────────────────────────
    @app.route("/hosts")
    def hosts():
        pp = app.config["proj_path"]
        with db.get_connection(pp) as conn:
            c = conn.cursor()
            c.execute("""
                SELECT h.id, h.host, h.ips, h.is_alive, h.in_scope,
                       (SELECT COUNT(*) FROM ports WHERE host_id=h.id) as ports,
                       (SELECT COUNT(*) FROM endpoints WHERE host_id=h.id) as endpoints,
                       (SELECT COUNT(*) FROM vulnerabilities WHERE host_id=h.id) as vulns
                FROM hosts h ORDER BY h.host
            """)
            rows = [dict(r) for r in c.fetchall()]
        return render_template("hosts.html", hosts=rows)

    @app.route("/api/hosts")
    def api_hosts():
        pp = app.config["proj_path"]
        with db.get_connection(pp) as conn:
            c = conn.cursor()
            c.execute("""
                SELECT h.id, h.host, h.ips, h.is_alive, h.in_scope,
                       (SELECT COUNT(*) FROM ports WHERE host_id=h.id) as ports,
                       (SELECT COUNT(*) FROM endpoints WHERE host_id=h.id) as endpoints,
                       (SELECT COUNT(*) FROM vulnerabilities WHERE host_id=h.id) as vulns
                FROM hosts h ORDER BY h.host
            """)
            return jsonify([dict(r) for r in c.fetchall()])

    # ─── Vulnerabilities ─────────────────────────────────────
    @app.route("/vulns")
    def vulns():
        pp = app.config["proj_path"]
        with db.get_connection(pp) as conn:
            c = conn.cursor()
            c.execute("""
                SELECT v.id, v.title, v.severity, v.cvss_score, v.cvss_vector,
                       v.cwe_id, v.cve_id, v.enriched_by,
                       COALESCE(h.host, 'N/A') as host
                FROM vulnerabilities v
                LEFT JOIN hosts h ON h.id = v.host_id
                ORDER BY CAST(COALESCE(v.cvss_score,0) AS REAL) DESC,
                         v.severity DESC
            """)
            rows = [dict(r) for r in c.fetchall()]

        c.execute("SELECT DISTINCT COALESCE(severity,'N/A') as s FROM vulnerabilities ORDER BY s")
        severities = [r["s"] for r in c.fetchall()]
        c.execute("SELECT DISTINCT COALESCE(enriched_by,'') as e FROM vulnerabilities WHERE enriched_by IS NOT NULL AND enriched_by != '' ORDER BY e")
        enrichers = [r["e"] for r in c.fetchall()]

        return render_template("vulns.html", vulns=rows, severities=severities, enrichers=enrichers)

    @app.route("/api/vulns")
    def api_vulns():
        pp = app.config["proj_path"]
        with db.get_connection(pp) as conn:
            c = conn.cursor()
            c.execute("""
                SELECT v.id, v.title, v.severity, v.cvss_score, v.cvss_vector,
                       v.cwe_id, v.cve_id, v.enriched_by,
                       COALESCE(h.host,'N/A') as host
                FROM vulnerabilities v
                LEFT JOIN hosts h ON h.id = v.host_id
                ORDER BY CAST(COALESCE(v.cvss_score,0) AS REAL) DESC
            """)
            return jsonify([dict(r) for r in c.fetchall()])

    return app


def run_dashboard(proj_path=None, host="127.0.0.1", port=8080):
    app = create_app(proj_path)
    print(f" 🌐 OpenPipeS Dashboard → http://{host}:{port}")
    print(f"    Projeto: {app.config['proj_path']}")
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    run_dashboard(host=args.host, port=args.port)
