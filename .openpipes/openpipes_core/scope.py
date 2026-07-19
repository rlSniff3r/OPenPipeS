import os
import subprocess
from pathlib import Path

import db
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

console = Console()


def _get_proj_path():
    cfg = os.path.join(Path.home(), ".openpipes", "config.sh")
    if not os.path.exists(cfg):
        return None
    cmd = f"source {cfg} && echo -n \"$proj_path\""
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, executable="/bin/bash")
    return r.stdout.strip() or None


def _fzf_select(items: list, prompt: str = "Select (TAB):") -> list:
    if not items:
        return []
    try:
        items_str = "\n".join(str(i) for i in items)
        r = subprocess.run(
            f"echo '{items_str}' | fzf -m --prompt='{prompt} ' --height=20",
            shell=True, capture_output=True, text=True,
        )
        if r.returncode == 0:
            return [line.strip() for line in r.stdout.strip().split("\n") if line.strip()]
    except Exception:
        pass
    return []


def interactive_scope():
    """Interactive fzf selection of which hosts are in scope."""
    proj_path = _get_proj_path()
    if not proj_path:
        console.print("[red]Erro: Projeto não configurado.[/red]")
        return

    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT host, in_scope FROM hosts WHERE is_alive = 1 ORDER BY host")
        hosts = cursor.fetchall()

    if not hosts:
        console.print("[yellow]⚠ Nenhum host vivo no banco.[/yellow]")
        return

    # Show current state
    in_s = sum(1 for h in hosts if h["in_scope"])
    out_s = len(hosts) - in_s
    console.print(f"\n[cyan]📋 Escopo atual: {in_s} em escopo, {out_s} fora[/cyan]\n")

    # Build display list — mark current in-scope hosts
    display = []
    for h in hosts:
        marker = "[IN]" if h["in_scope"] else "[  ]"
        display.append(f"{marker} {h['host']}")

    console.print("[cyan]Selecione os hosts para INCLUIR no escopo (TAB alterna):[/cyan]")
    selected = _fzf_select(display, "Scope:")
    selected_set = set()
    for s in selected:
        # Extract hostname after "[IN] " or "[  ] "
        parts = s.split(" ", 1)
        if len(parts) == 2:
            selected_set.add(parts[1].strip())

    # Update DB
    with db.get_connection(proj_path) as conn:
        with db.transaction(conn):
            cursor = conn.cursor()
            for row in hosts:
                new_val = 1 if row["host"] in selected_set else 0
                if row["in_scope"] != new_val:
                    cursor.execute("UPDATE hosts SET in_scope = ? WHERE host = ?",
                                   (new_val, row["host"]))

    # Show summary
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM hosts WHERE is_alive = 1 AND in_scope = 1")
        final_in = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM hosts WHERE is_alive = 1 AND in_scope = 0")
        final_out = cursor.fetchone()[0]

    console.print(f"\n[green]✔ Escopo atualizado: {final_in} em escopo, {final_out} fora[/green]")


def show_scope():
    """Display current scope status."""
    proj_path = _get_proj_path()
    if not proj_path:
        console.print("[red]Erro: Projeto não configurado.[/red]")
        return

    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT host, is_alive, in_scope FROM hosts
            ORDER BY in_scope DESC, host
        """)
        hosts = cursor.fetchall()

    if not hosts:
        console.print("[yellow]⚠ Nenhum host no banco.[/yellow]")
        return

    table = Table(title="Escopo de Varredura")
    table.add_column("Host", style="cyan")
    table.add_column("Vivo", justify="center")
    table.add_column("Escopo", justify="center")

    in_count = 0
    for h in hosts:
        status = "🟢" if h["is_alive"] else "⚫"
        scope = "✅" if h["in_scope"] else "❌"
        if h["in_scope"]:
            in_count += 1
        table.add_row(h["host"], status, scope)

    console.print(table)
    console.print(f"\n[cyan]Total: {len(hosts)} hosts | {in_count} em escopo[/cyan]")
    input("\nPressione ENTER para voltar...")
