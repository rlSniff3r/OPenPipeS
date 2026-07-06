import os
import json
from pathlib import Path

from rich.console import Console

import db

console = Console()
HOME = str(Path.home())
CONFIG_FILE = os.path.join(HOME, ".openpipes", "config.sh")


def _get_proj_path():
    """Get project path from config."""
    if not os.path.exists(CONFIG_FILE):
        return None
    try:
        cmd = f"source {CONFIG_FILE} && echo -n \"$proj_path|$NMAP_DIR\""
        import subprocess
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, executable="/bin/bash")
        parts = result.stdout.strip().split("|")
        if len(parts) == 2:
            return parts[0], parts[1]
    except Exception:
        pass
    return None, None


def feed_httpx(proj_path: str, nmap_dir: str):
    """
    Query DB for alive, in-scope hosts with open HTTP ports.
    Writes targets.txt and per-target httpx_targets.txt for httpx-runner.
    """
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()

        # Get alive hosts with open HTTP ports
        cursor.execute("""
            SELECT DISTINCT h.id, h.host, h.ips
            FROM hosts h
            JOIN ports p ON p.host_id = h.id
            WHERE h.is_alive = 1
              AND p.state = 'open'
              AND p.service IN ('http', 'https', 'http-proxy', 'ssl', 'unknown')
            ORDER BY h.host
        """)
        hosts = cursor.fetchall()

        if not hosts:
            console.print("[yellow]⚠ Nenhum host vivo com portas HTTP encontrado no banco.[/yellow]")
            return

        console.print(f" [dim]↳ Feed httpx: {len(hosts)} hosts com portas HTTP[/dim]")

        for host_row in hosts:
            host_id = host_row["id"]
            host_name = host_row["host"]
            ips = json.loads(host_row["ips"]) if host_row["ips"] else []
            ip = ips[0] if ips else ""

            # Get open HTTP ports for this host
            cursor.execute("""
                SELECT port, service FROM ports
                WHERE host_id = ? AND state = 'open'
                  AND service IN ('http', 'https', 'http-proxy', 'ssl', 'unknown')
                ORDER BY port
            """, (host_id,))
            ports = [str(r["port"]) for r in cursor.fetchall()]

            if not ports:
                continue

            # Write per-target target list (used by httpx-runner.sh)
            target_dir = os.path.join(nmap_dir, f"nmap-{host_name}")
            os.makedirs(target_dir, exist_ok=True)
            target_file = os.path.join(target_dir, "httpx_targets.txt")

            with open(target_file, "w") as f:
                f.write(f"http://{host_name}\n")
                f.write(f"https://{host_name}\n")
                if ip:
                    f.write(f"http://{ip}\n")
                    f.write(f"https://{ip}\n")

            # Write ports file
            ports_file = os.path.join(target_dir, "httpx_ports.txt")
            with open(ports_file, "w") as f:
                f.write(",".join(ports))

        # Write global targets.txt
        targets_file = os.path.join(nmap_dir, "targets.txt")
        with open(targets_file, "w") as f:
            for host_row in hosts:
                f.write(host_row["host"] + "\n")

        console.print(f" [dim]↳ Feed httpx: targets.txt e listas por alvo atualizados.[/dim]")


def feed_all(proj_path: str, nmap_dir: str):
    """Run all feeders."""
    feed_httpx(proj_path, nmap_dir)


def run():
    """CLI entry point."""
    proj_path, nmap_dir = _get_proj_path()
    if not proj_path:
        console.print("[red]Erro: Projeto não configurado.[/red]")
        return
    db.init_db(proj_path)
    feed_all(proj_path, nmap_dir)
