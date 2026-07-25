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
    """Interactive fzf selection — toggle hosts in/out of scope."""
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

    in_s = sum(1 for h in hosts if h["in_scope"])
    out_s = len(hosts) - in_s
    console.print(f"\n[cyan]📋 Escopo atual: {in_s} em escopo, {out_s} fora[/cyan]")
    console.print("[dim]Selecione hosts com TAB para TOGGLE (IN ↔ OUT). Confirme com ENTER.[/dim]\n")

    # Build display list
    display = []
    for h in hosts:
        marker = "[IN]" if h["in_scope"] else "[  ]"
        display.append(f"{marker} {h['host']}")

    selected = _fzf_select(display, "Toggle (TAB):")

    # Extract hostnames from selected items
    toggled = set()
    for s in selected:
        if s.startswith("[IN] ") or s.startswith("[  ] "):
            toggled.add(s[5:])
        else:
            toggled.add(s.strip())

    # Toggle only the explicitly selected hosts
    with db.get_connection(proj_path) as conn:
        with db.transaction(conn):
            cursor = conn.cursor()
            for row in hosts:
                if row["host"] in toggled:
                    new_val = 0 if row["in_scope"] else 1
                    cursor.execute("UPDATE hosts SET in_scope = ? WHERE host = ?",
                                   (new_val, row["host"]))

    # Show updated state
    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM hosts WHERE is_alive = 1 AND in_scope = 1")
        final_in = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM hosts WHERE is_alive = 1 AND in_scope = 0")
        final_out = cursor.fetchone()[0]
        changes = len(toggled)

    console.print(f"\n[green]✔ {changes} host(s) alterado(s). Escopo: {final_in} em, {final_out} fora[/green]")

    # Delete vault folders for out-of-scope hosts
    _cleanup_out_of_scope_vault(proj_path)


def _cleanup_out_of_scope_vault(proj_path: str):
    """Delete vault folders AND tool input files for out-of-scope hosts."""
    import shutil, subprocess
    cfg = os.path.join(Path.home(), ".openpipes", "config.sh")
    cmd = f"source {cfg} && echo -n \"$obsdir|$proj_name|$NMAP_DIR\""
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, executable="/bin/bash")
    parts = r.stdout.strip().split("|")
    if len(parts) < 3:
        return
    obsdir, proj_name, nmap_dir = parts[0], parts[1], parts[2]

    # Files to delete per out-of-scope host
    target_files = [
        "httpx_targets.txt", "httpx_ports.txt",
        "katana_urls.txt", "ferox_urls.txt",
        "js_urls.txt", "gf_urls.txt",
        "screenshot_urls.txt", "nuclei_urls.txt",
        "alive_urls.txt", "context_wordlist.txt",
    ]

    with db.get_connection(proj_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT host FROM hosts WHERE is_alive = 1 AND in_scope = 0")
        removed_files = 0
        removed_vaults = 0
        for row in cursor.fetchall():
            host = row["host"]
            # Vault folder
            vault_path = os.path.join(obsdir, proj_name, "Pentest", "Alvos", host)
            if os.path.exists(vault_path):
                shutil.rmtree(vault_path)
                removed_vaults += 1
            # Tool input files
            target_dir = os.path.join(nmap_dir, f"nmap-{host}")
            for fname in target_files:
                fpath = os.path.join(target_dir, fname)
                if os.path.exists(fpath):
                    os.remove(fpath)
                    removed_files += 1

        if removed_vaults:
            console.print(f" [dim]🗑️ {removed_vaults} pasta(s) de vault removidas.[/dim]")
        if removed_files:
            console.print(f" [dim]🗑️ {removed_files} arquivo(s) de input removidos.[/dim]")


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
