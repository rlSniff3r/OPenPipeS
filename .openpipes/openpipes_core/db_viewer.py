import os
import subprocess
import json
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import box

import db

console = Console()
HOME = str(Path.home())
CONFIG_FILE = os.path.join(HOME, ".openpipes", "config.sh")

TABLES = {
    "projects": {"id", "name", "root_domain", "client", "status", "created_at"},
    "hosts": {"id", "project_id", "host", "ips", "cnames", "whois_data", "is_alive", "last_updated"},
    "ports": {"id", "host_id", "port", "protocol", "state", "service", "version"},
    "endpoints": {"id", "host_id", "url", "status_code", "content_length", "content_type", "title", "web_server", "tech_stack", "source_tool", "vulnerability_patterns", "response_hash", "verified_at", "scanned_by", "discovered_at"},
    "screenshots": {"id", "host_id", "file_path", "source_url", "final_url", "status_code", "title", "content_length", "created_at"},
    "js_discoveries": {"id", "host_id", "source_js_url", "discovered_route"},
    "vulnerabilities": {"id", "host_id", "endpoint_id", "title", "severity", "cvss_score", "cvss_vector", "cve_id", "vuln_name", "description", "matched_at", "curl_command", "remediation", "impact", "reference_urls", "source_tool", "enriched_by", "created_at"},
    "execution_logs": {"id", "project_id", "module_name", "status", "exit_code", "start_time", "end_time"},
}


def _get_proj_path():
    if not os.path.exists(CONFIG_FILE):
        return None
    try:
        cmd = f"source {CONFIG_FILE} && echo -n \"$proj_path\""
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, executable="/bin/bash")
        return result.stdout.strip() or None
    except Exception:
        return None


def _fzf_select(items: list, prompt: str = "Select:", multi: bool = False) -> list:
    """Use fzf to let user select from a list. Returns selected items."""
    if not items:
        return []
    input_str = "\n".join(str(i) for i in items)
    multi_flag = "-m" if multi else ""
    try:
        result = subprocess.run(
            f"echo '{input_str}' | fzf {multi_flag} --prompt='{prompt} ' --height=20",
            shell=True, capture_output=True, text=True,
        )
        if result.returncode == 0:
            return [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
    except Exception:
        pass
    return []


def show_schema():
    """Display all tables and their columns."""
    console.clear()
    console.print(Panel("[bold cyan]Database Schema[/bold cyan]"))
    for table, columns in TABLES.items():
        with db.get_connection(_get_proj_path()) as conn:
            try:
                cursor = conn.execute(f"SELECT COUNT(*) FROM {table}")
                count = cursor.fetchone()[0]
            except Exception:
                count = "?"
        table_display = Table(box=box.SIMPLE, title=f"{table} ({count} rows)")
        table_display.add_column("Column", style="cyan")
        table_display.add_column("Type")
        # Get column info from actual DB
        try:
            cursor = conn.execute(f"PRAGMA table_info({table})")
            for row in cursor.fetchall():
                table_display.add_row(row[1], row[2])
        except Exception:
            for col in sorted(columns):
                table_display.add_row(col, "")
        console.print(table_display)
        console.print()
    input("\nPressione ENTER para voltar...")


def list_records():
    """Browse records from a selected table with pagination."""
    table = _fzf_select(list(TABLES.keys()), "Table:") if len(TABLES) > 0 else ""
    if not table:
        table = list(TABLES.keys())[0]
    table = table[0] if isinstance(table, list) and table else table

    if isinstance(table, list):
        table = table[0]
    if not table:
        return

    page = 0
    page_size = 20
    proj_path = _get_proj_path()

    while True:
        console.clear()
        with db.get_connection(proj_path) as conn:
            cursor = conn.cursor()
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            total = cursor.fetchone()[0]
            cursor.execute(f"SELECT * FROM {table} LIMIT {page_size} OFFSET {page * page_size}")
            rows = cursor.fetchall()
            cols = [d[0] for d in cursor.description]

        if not rows:
            console.print("[yellow]Nenhum registro encontrado.[/yellow]")
            input("Pressione ENTER...")
            return

        t = Table(box=box.SIMPLE, title=f"{table} ({total} total — página {page+1})")
        for col in cols[:8]:  # show first 8 columns
            t.add_column(col[:20], style="cyan", max_width=30)
        for row in rows:
            t.add_row(*[str(c)[:40] if c is not None else "" for c in row[:8]])
        console.print(t)

        action = Prompt.ask(
            "[cyan][N]ext [P]rev [Q]uit[/cyan]",
            choices=["n", "p", "q", ""], default=""
        )
        if action == "n" and (page + 1) * page_size < total:
            page += 1
        elif action == "p" and page > 0:
            page -= 1
        elif action == "q":
            break


def delete_records():
    """Delete records from a table with fzf selection and cascade confirmation."""
    proj_path = _get_proj_path()

    # Choose table — restrict to main entities
    table = _fzf_select(["hosts", "endpoints", "ports", "vulnerabilities", "screenshots", "js_discoveries"],
                        "Delete from:")
    if not table:
        return
    table = table[0] if isinstance(table, list) else table

    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        total = cursor.fetchone()[0]

    if total == 0:
        console.print("[yellow]Tabela vazia.[/yellow]")
        input("Pressione ENTER...")
        return

    # Select records to delete via fzf
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        if table == "hosts":
            cursor.execute("SELECT id, host FROM hosts ORDER BY host")
            items = [f"{row[0]} | {row[1]}" for row in cursor.fetchall()]
        elif table == "endpoints":
            cursor.execute("SELECT id, url FROM endpoints ORDER BY url LIMIT 2000")
            items = [f"{row[0]} | {row[1][:80]}" for row in cursor.fetchall()]
        else:
            cursor.execute(f"SELECT id FROM {table} ORDER BY id LIMIT 2000")
            items = [str(row[0]) for row in cursor.fetchall()]

    selected = _fzf_select(items, f"Select {table} to delete (TAB to multi):", multi=True)
    if not selected:
        return

    ids = []
    for s in selected:
        id_str = s.split(" | ")[0] if " | " in s else s
        try:
            ids.append(int(id_str.strip()))
        except ValueError:
            continue

    if not ids:
        return

    console.print(f"\n[red]⚠ You are about to delete {len(ids)} record(s) from '{table}'.[/red]")
    if table == "hosts":
        console.print("[red]⚠ All related ports, endpoints, screenshots, vulnerabilities and JS discoveries will also be deleted (CASCADE).[/red]")

    if not Confirm.ask("Confirm deletion?"):
        console.print("[yellow]Cancelado.[/yellow]")
        input("Pressione ENTER...")
        return

    with db.get_connection(proj_path) as conn:
        with db.transaction(conn):
            cursor = conn.cursor()
            for rid in ids:
                cursor.execute(f"DELETE FROM {table} WHERE id = ?", (rid,))
                console.print(f"  [red]✖[/red] Deleted {table} id={rid}")

    console.print(f"\n[green]✔ {len(ids)} registro(s) deletado(s).[/green]")
    input("Pressione ENTER...")


def insert_record():
    """Insert a new record into a table with guided input."""
    proj_path = _get_proj_path()
    table = _fzf_select(["hosts", "endpoints", "ports", "vulnerabilities"], "Insert into:")
    if not table:
        return
    table = table[0] if isinstance(table, list) else table

    console.print(f"\n[cyan]Insert into {table}[/cyan]")
    console.print("[dim]Leave field empty to skip (NULL). Type 'q' to cancel.[/dim]\n")

    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute(f"PRAGMA table_info({table})")
        columns = [row for row in cursor.fetchall() if row[1] != "id"]  # skip auto-increment id

    values = {}
    for col in columns:
        name = col[1]
        col_type = col[2]
        default = col[4]

        if default is not None:
            prompt_text = f"{name} ({col_type}) [{default}]: "
        else:
            prompt_text = f"{name} ({col_type}): "

        val = input(prompt_text).strip()
        if val.lower() == "q":
            return
        if not val:
            values[name] = None
        elif col_type.upper().startswith("INT"):
            values[name] = int(val)
        elif col_type.upper() == "BOOLEAN":
            values[name] = 1 if val.lower() in ("1", "true", "yes", "y") else 0
        else:
            values[name] = val

    cols = ", ".join(values.keys())
    placeholders = ", ".join("?" for _ in values)
    sql = f"INSERT INTO {table} ({cols}) VALUES ({placeholders})"

    try:
        with db.get_connection(proj_path) as conn:
            cursor = conn.cursor()
            cursor.execute(sql, list(values.values()))
            new_id = cursor.lastrowid
        console.print(f"\n[green]✔ Registro inserido em '{table}' com id={new_id}.[/green]")
    except Exception as e:
        console.print(f"\n[red]✖ Erro: {e}[/red]")

    input("Pressione ENTER...")


def interactive_db():
    """Main interactive database menu."""
    proj_path = _get_proj_path()
    if not proj_path:
        console.print("[red]Erro: Projeto não configurado.[/red]")
        input("Pressione ENTER...")
        return
    db.init_db(proj_path)

    while True:
        console.clear()
        console.print(Panel("[bold cyan]🗄️  Database Manager[/bold cyan]"))
        console.print("[1] View Schema")
        console.print("[2] List Records (paginated)")
        console.print("[3] Delete Records (via fzf)")
        console.print("[4] Insert Record")
        console.print("[0] Exit")

        choice = Prompt.ask("Choose", choices=["0", "1", "2", "3", "4", ""], default="")

        if choice == "0":
            break
        elif choice == "1":
            show_schema()
        elif choice == "2":
            list_records()
        elif choice == "3":
            delete_records()
        elif choice == "4":
            insert_record()
