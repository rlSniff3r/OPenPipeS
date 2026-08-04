import os
import tarfile
import glob
import time
import shutil
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

import db

console = Console()

BACKUP_DIR = os.path.join(Path.home(), "backups-openpipes")
RESCAN_PATTERNS = [
    "*/httpx-*.json", "*/ferox_*.jsonl", "*/crawled_all.jsonl",
    "*/jsfinder-results.json", "*/nuclei_output.json",
    "*/Screenshots/go.jsonl", "httpx_output.json",
    "*/*_urls.txt", "*/context_wordlist.txt",
]


def _timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d_%Hh%M")


def _size_str(path: str) -> str:
    size = os.path.getsize(path)
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}TB"


def _get_proj_name(proj_path: str) -> str:
    return os.path.basename(proj_path)


def backup_fresh(proj_path: str, nmap_dir: str):
    """Backup DB + all raw outputs before --fresh."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = _timestamp()
    proj = _get_proj_name(proj_path)
    backup_path = os.path.join(BACKUP_DIR, f"fresh_{proj}_{ts}.tar.gz")

    db_path = os.path.join(proj_path, ".openpipes.db")
    if not os.path.exists(db_path):
        console.print("[yellow]⚠ Nada a backupar (banco não encontrado).[/yellow]")
        return None

    with tarfile.open(backup_path, "w:gz") as tar:
        # DB
        tar.add(db_path, arcname=".openpipes.db")
        # All nmap dirs
        if os.path.exists(nmap_dir):
            for folder in sorted(os.listdir(nmap_dir)):
                fpath = os.path.join(nmap_dir, folder)
                if folder.startswith("nmap-") and os.path.isdir(fpath):
                    tar.add(fpath, arcname=f"Varreduras/{folder}")

    size = _size_str(backup_path)
    console.print(f" [dim]💾 Backup fresh: {backup_path} ({size})[/dim]")
    return backup_path


def backup_rescan(proj_path: str, nmap_dir: str):
    """Backup only tool output files before --rescan."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = _timestamp()
    proj = _get_proj_name(proj_path)
    backup_path = os.path.join(BACKUP_DIR, f"rescan_{proj}_{ts}.tar.gz")

    files_to_backup = []
    for pattern in RESCAN_PATTERNS:
        for f in glob.glob(os.path.join(nmap_dir, pattern)):
            if os.path.isfile(f):
                files_to_backup.append(f)

    if not files_to_backup:
        console.print("[yellow]⚠ Nada a backupar (nenhum arquivo de output encontrado).[/yellow]")
        return None

    with tarfile.open(backup_path, "w:gz") as tar:
        for fpath in sorted(files_to_backup):
            arcname = os.path.relpath(fpath, os.path.dirname(nmap_dir))
            tar.add(fpath, arcname=arcname)

    size = _size_str(backup_path)
    console.print(f" [dim]💾 Backup rescan: {backup_path} ({size}, {len(files_to_backup)} arquivos)[/dim]")
    return backup_path


def backup_manual(proj_path: str, nmap_dir: str, mode: str = "full"):
    """Manual backup with granularity levels."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = _timestamp()
    proj = _get_proj_name(proj_path)
    backup_path = os.path.join(BACKUP_DIR, f"{mode}_{proj}_{ts}.tar.gz")

    with tarfile.open(backup_path, "w:gz") as tar:
        if mode in ("full", "project"):
            # DB
            db_path = os.path.join(proj_path, ".openpipes.db")
            if os.path.exists(db_path):
                tar.add(db_path, arcname=".openpipes.db")
            # Raw outputs
            if os.path.exists(nmap_dir):
                for folder in sorted(os.listdir(nmap_dir)):
                    fpath = os.path.join(nmap_dir, folder)
                    if folder.startswith("nmap-") and os.path.isdir(fpath):
                        tar.add(fpath, arcname=f"Varreduras/{folder}")
            # Config
            for cfg in ["domains.txt", ".openpipes_scope", ".openpipes_modules"]:
                cpath = os.path.join(proj_path, cfg)
                if os.path.exists(cpath):
                    tar.add(cpath, arcname=cfg)

        if mode in ("full", "cache"):
            # Vulnerability cache
            cache_dir = os.path.join(Path.home(), ".openpipes_cache")
            if os.path.exists(cache_dir):
                tar.add(cache_dir, arcname=".openpipes_cache")
            # Tech wordlists
            wl_dir = os.path.join(Path.home(), ".openpipes", "wordlists", "tech")
            if os.path.exists(wl_dir):
                tar.add(wl_dir, arcname="wordlists")

    size = _size_str(backup_path)
    console.print(f" [green]✔ Backup {mode}: {backup_path} ({size})[/green]")
    return backup_path


def list_backups():
    """List all available backups."""
    if not os.path.exists(BACKUP_DIR):
        console.print("[yellow]⚠ Nenhum backup encontrado em ~/backups-openpipes/[/yellow]")
        return []

    backups = sorted([f for f in os.listdir(BACKUP_DIR) if f.endswith(".tar.gz")], reverse=True)
    if not backups:
        console.print("[yellow]⚠ Nenhum backup encontrado.[/yellow]")
        return []

    table = Table(title="Backups Disponíveis")
    table.add_column("Arquivo", style="cyan")
    table.add_column("Tamanho", justify="right")
    table.add_column("Tipo", style="magenta")
    table.add_column("Data")

    for b in backups:
        fpath = os.path.join(BACKUP_DIR, b)
        fsize = _size_str(fpath)
        ftype = "fresh" if "fresh_" in b else "rescan" if "rescan_" in b else "reinstall" if "reinstall_" in b else "manual"
        fdate = " ".join(b.split("_")[1:3]) if "_" in b else "-"
        table.add_row(b, fsize, ftype, fdate)

    console.print(table)
    return backups


def backup_framework() -> str | None:
    """Backup framework config before reinstall.
    Follows BACKUP_DIR convention: ~/backups-openpipes/reinstall_*.tar.gz.
    NEVER touches ~/Projetos."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = _timestamp()
    backup_path = os.path.join(BACKUP_DIR, f"reinstall_{ts}.tar.gz")

    home = str(Path.home())
    added = False

    with tarfile.open(backup_path, "w:gz") as tar:
        for f in ["config.sh", "secrets.conf"]:
            fpath = os.path.join(home, ".openpipes", f)
            if os.path.exists(fpath):
                tar.add(fpath, arcname=f)
                added = True
        wl = os.path.join(home, ".openpipes", "wordlists")
        if os.path.exists(wl):
            tar.add(wl, arcname="wordlists")
            added = True
        cache = os.path.join(home, ".openpipes_cache")
        if os.path.exists(cache):
            tar.add(cache, arcname=".openpipes_cache")
            added = True

    if not added:
        console.print("[yellow]⚠ Nada a backupar (framework já limpo?).[/yellow]")
        os.remove(backup_path)
        return None

    console.print(f" [dim]💾 Backup framework: {backup_path} ({_size_str(backup_path)})[/dim]")
    return backup_path


def restore_framework(backup_file: str):
    """Restore framework config after reinstall. Never touches ~/Projetos."""
    if not os.path.isabs(backup_file):
        backup_file = os.path.join(BACKUP_DIR, backup_file)
    if not os.path.exists(backup_file):
        console.print(f"[red]✖ Backup não encontrado: {backup_file}[/red]")
        return

    home = str(Path.home())
    staging = os.path.join(BACKUP_DIR, "_restore_staging")
    shutil.rmtree(staging, ignore_errors=True)
    os.makedirs(staging, exist_ok=True)

    console.print(f"[yellow]⚠ Restaurando: {os.path.basename(backup_file)}[/yellow]")
    with tarfile.open(backup_file, "r:gz") as tar:
        tar.extractall(staging)

    for f in ["config.sh", "secrets.conf"]:
        src = os.path.join(staging, f)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(home, ".openpipes", f))
            console.print(f"  [green]✔ restaurado: {f}[/green]")

    wl_src = os.path.join(staging, "wordlists")
    if os.path.isdir(wl_src):
        shutil.copytree(wl_src, os.path.join(home, ".openpipes", "wordlists"),
                        dirs_exist_ok=True)
        console.print("  [green]✔ restaurado: wordlists/[/green]")

    cache_src = os.path.join(staging, ".openpipes_cache")
    if os.path.isdir(cache_src):
        shutil.copytree(cache_src, os.path.join(home, ".openpipes_cache"),
                        dirs_exist_ok=True)
        console.print("  [green]✔ restaurado: .openpipes_cache/[/green]")

    shutil.rmtree(staging, ignore_errors=True)
    console.print(f" [green]✔ Framework restaurado: {os.path.basename(backup_file)}[/green]")


def latest_framework_backup() -> str | None:
    """Most recent reinstall_*.tar.gz (chronological by name)."""
    if not os.path.exists(BACKUP_DIR):
        return None
    backups = sorted(f for f in os.listdir(BACKUP_DIR)
                     if f.startswith("reinstall_") and f.endswith(".tar.gz"))
    return os.path.join(BACKUP_DIR, backups[-1]) if backups else None


def restore(backup_file: str, proj_path: str, nmap_dir: str):
    """Restore a backup file to the appropriate locations."""
    if not os.path.isabs(backup_file):
        backup_file = os.path.join(BACKUP_DIR, backup_file)
    if not os.path.exists(backup_file):
        console.print(f"[red]✖ Backup não encontrado: {backup_file}[/red]")
        return

    is_fresh = "fresh_" in os.path.basename(backup_file)
    console.print(f"[yellow]⚠ Restaurando: {os.path.basename(backup_file)}[/yellow]")

    with tarfile.open(backup_file, "r:gz") as tar:
        members = tar.getmembers()

        for member in members:
            path = member.name
            # Determine where to extract
            if path == ".openpipes.db":
                member.name = os.path.basename(path)
                tar.extract(member, path=proj_path)
            elif path.startswith("Varreduras/"):
                rel = path[len("Varreduras/"):]
                member.name = rel
                tar.extract(member, path=nmap_dir)
            elif path == ".openpipes_cache":
                tar.extract(member, path=Path.home())
            elif path == "wordlists":
                wl_dir = os.path.join(Path.home(), ".openpipes", "wordlists")
                tar.extract(member, path=wl_dir)
            elif path in ("domains.txt", ".openpipes_scope", ".openpipes_modules"):
                member.name = path
                tar.extract(member, path=proj_path)

    console.print(f" [green]✔ Restaurado: {os.path.basename(backup_file)}[/green]")
