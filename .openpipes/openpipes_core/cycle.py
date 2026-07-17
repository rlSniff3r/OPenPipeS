import os
import subprocess
import time
import threading
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

import db
import feeder
import verifier
import renderer

console = Console()
HOME = str(Path.home())
CONFIG_FILE = os.path.join(HOME, ".openpipes", "config.sh")
BIN_DIR = os.path.join(HOME, ".openpipes", "bin")


def _sudo_keepalive(stop_event):
    while not stop_event.is_set():
        subprocess.run(["sudo", "-v"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stop_event.wait(120)  # refresh every 2 minutes


def _get_env():
    if not os.path.exists(CONFIG_FILE):
        return None, None, None
    cmd = f"source {CONFIG_FILE} && echo -n \"$proj_name|$proj_path|$NMAP_DIR\""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, executable="/bin/bash")
    parts = result.stdout.strip().split("|")
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    return None, None, None


def _run_module(name):
    script = os.path.join(BIN_DIR, name)
    if not os.path.exists(script):
        return False, f"Script {name} não encontrado"
    proj_name, proj_path, nmap_dir = _get_env()
    db.init_db(proj_path)
    exec_id = db.log_module_start(proj_path, name)
    try:
        extra_args = ""
        if name == "nwrapper":
            extra_args = f"-f {os.path.join(nmap_dir, 'targets_cycle.txt')}"
        cmd = f"source {CONFIG_FILE} && {script} {extra_args}"
        # No capture_output — user sees sudo prompts, progress bars, etc.
        result = subprocess.run(cmd, shell=True, cwd=proj_path, executable="/bin/bash")
        exit_code = result.returncode
        db.log_module_finish(proj_path, exec_id, exit_code)
        if exit_code == 0:
            import parsers
            parsers.dispatch(name, proj_path, nmap_dir)
        return exit_code == 0, ""
    except KeyboardInterrupt:
        console.print("\n[yellow]Execução interrompida.[/yellow]")
        db.log_module_finish(proj_path, exec_id, 130)
        return False, "Interrompido"
    except Exception as e:
        db.log_module_finish(proj_path, exec_id, 1)
        return False, str(e)


def run_cycle(targets: list = None):
    """
    Full cycle: feed → run modules → verify → sync.
    Uses cycle-specific targets for nwrapper (only unscanned hosts).
    """
    proj_name, proj_path, nmap_dir = _get_env()
    if not proj_path:
        console.print("[red]Projeto não configurado.[/red]")
        return

    console.print(Panel(f"[bold cyan]🔄 Cycle — {proj_name}[/bold cyan]"))
    start = time.time()
    db.init_db(proj_path)

    # 1. Feed — cycle mode for nwrapper (only unscanned hosts)
    console.print("\n[bold]1. Feed[/bold]")
    feeder.feed_nwrapper(proj_path, nmap_dir, cycle=True)
    feeder.feed_httpx(proj_path, nmap_dir)
    feeder.feed_katana(proj_path, nmap_dir)
    feeder.feed_ferox(proj_path, nmap_dir)
    feeder.feed_jsfinder(proj_path, nmap_dir)
    feeder.feed_gf(proj_path, nmap_dir)
    feeder.feed_screenshot(proj_path, nmap_dir)

    # 2. Run modules
    modules = ["nwrapper", "httpx-runner", "katana-runner", "feroxbuster-runner",
           "jsfinder-runner", "gf-summary", "screenshot-runner", "nuclei-runner"]
    results = []
    console.print("\n[bold]2. Run[/bold]")
    for mod in modules:
        ok, msg = _run_module(mod)
        status = "[green]OK[/green]" if ok else "[red]FAIL[/red]"
        console.print(f"  {status} {mod}")
        if msg:
            console.print(f"    {msg}")
        results.append((mod, ok))

    # 3. Verify
    console.print("\n[bold]3. Verify[/bold]")
    verifier.verify_endpoints(proj_path)

    # 4. Sync
    console.print("\n[bold]4. Sync[/bold]")
    renderer.sync_project()

    elapsed = time.time() - start
    console.print(f"\n[bold green]✔ Ciclo completo em {elapsed:.1f}s[/bold green]")

    table = Table(box=None)
    table.add_column("Módulo", style="cyan")
    table.add_column("Status")
    for mod, ok in results:
        table.add_row(mod, "[green]OK[/green]" if ok else "[red]FAIL[/red]")
    console.print(table)
