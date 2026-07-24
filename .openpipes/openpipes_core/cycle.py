import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
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

MODULES_FILE = ".openpipes_modules"
ALL_MODULES = {
    "sequential": ["httpx-runner"],
    "parallel": ["katana-runner", "feroxbuster-runner", "jsfinder-runner",
                  "gf-summary", "screenshot-runner", "nuclei-runner"],
}


def _fzf_select(items: list, prompt: str = "Select (TAB):") -> list:
    import subprocess
    if not items:
        return []
    try:
        r = subprocess.run(
            f"echo '{chr(10).join(items)}' | fzf -m --prompt='{prompt} ' --height=20",
            shell=True, capture_output=True, text=True,
        )
        if r.returncode == 0:
            return [line.strip() for line in r.stdout.strip().split(chr(10)) if line.strip()]
    except Exception:
        pass
    return []


def select_modules(proj_path: str):
    """Interactive fzf to choose which modules run in the cycle."""
    all_mods = ALL_MODULES["sequential"] + ALL_MODULES["parallel"]
    selected = _fzf_select(all_mods, "Cycle modules (TAB):")
    mods_file = os.path.join(proj_path, MODULES_FILE)
    if selected:
        with open(mods_file, "w") as f:
            for m in selected:
                f.write(m + "\n")
        console.print(f"[green]✔ {len(selected)} módulo(s) selecionados.[/green]")
    elif os.path.exists(mods_file):
        os.remove(mods_file)
        console.print("[yellow]✔ Todos os módulos ativados (arquivo de seleção removido).[/yellow]")


def _load_selected_modules(proj_path: str) -> set:
    mods_file = os.path.join(proj_path, MODULES_FILE)
    if not os.path.exists(mods_file):
        return set()  # empty = all modules
    with open(mods_file) as f:
        return set(line.strip() for line in f if line.strip())


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
    """Run a bash module and parse its output."""
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
        result = subprocess.run(cmd, shell=True, cwd=proj_path, executable="/bin/bash")
        exit_code = result.returncode
        db.log_module_finish(proj_path, exec_id, exit_code)
        if exit_code == 0:
            import parsers
            parsers.dispatch(name, proj_path, nmap_dir)
        return exit_code == 0, ""
    except KeyboardInterrupt:
        db.log_module_finish(proj_path, exec_id, 130)
        return False, "Interrompido"
    except Exception as e:
        db.log_module_finish(proj_path, exec_id, 1)
        return False, str(e)


def run_cycle(targets: list = None, fresh: bool = False, rescan: bool = False):
    proj_name, proj_path, nmap_dir = _get_env()
    if not proj_path:
        console.print("[red]Erro: Projeto não configurado.[/red]")
        return

    if fresh:
        console.print("[red]⚠ Fresh mode: deletando banco de dados e resultados...[/red]")
        db_path = os.path.join(proj_path, ".openpipes.db")
        if os.path.exists(db_path):
            os.remove(db_path)
        import shutil
        for folder in os.listdir(nmap_dir):
            fpath = os.path.join(nmap_dir, folder)
            if folder.startswith("nmap-") and os.path.isdir(fpath):
                shutil.rmtree(fpath)
        console.print("[green]✔ Banco e resultados deletados. Execute recon + nwrapper manualmente.[/green]")
        return

    if rescan:
        console.print("[yellow]⚠ Rescan: limpando marcas e outputs antigos...[/yellow]")
        with db.get_connection(proj_path) as conn:
            conn.execute("UPDATE endpoints SET scanned_by = ''")
        # Delete old tool output files so parsers don't re-mark from stale data
        import glob
        patterns = ["httpx_output.json", "*/httpx-*.json", "*/ferox_*.jsonl",
                    "*/crawled_all.jsonl", "*/katana_urls.txt", "*/ferox_urls.txt",
                    "*/screenshot_urls.txt", "*/nuclei_urls.txt", "*/gf_urls.txt",
                    "*/js_urls.txt", "*/jsfinder-results.json",
                    "*/Screenshots/go.jsonl", "*/nuclei_output.json"]
        deleted = 0
        for pat in patterns:
            for f in glob.glob(os.path.join(nmap_dir, pat)):
                try:
                    os.remove(f)
                    deleted += 1
                except Exception:
                    pass
        console.print(f"[green]✔ {deleted} arquivos de output removidos, scanned_by limpo.[/green]")

    selected = _load_selected_modules(proj_path)

    console.print(Panel(f"[bold cyan]🔄 Cycle — {proj_name}[/bold cyan]"))
    if selected:
        console.print(f" [dim]Módulos selecionados: {len(selected)}[/dim]")
    start = time.time()
    db.init_db(proj_path)

    # Stage 1: Feed
    console.print("\n[bold]1. Feed[/bold]")
    feeder.feed_nwrapper(proj_path, nmap_dir, cycle=True)
    feeder.feed_httpx(proj_path, nmap_dir)
    feeder.feed_katana(proj_path, nmap_dir)
    feeder.feed_ferox(proj_path, nmap_dir)
    feeder.feed_jsfinder(proj_path, nmap_dir)
    feeder.feed_gf(proj_path, nmap_dir)
    feeder.feed_screenshot(proj_path, nmap_dir)
    feeder.feed_nuclei(proj_path, nmap_dir)

    results = []

    # Stage 2: Sequential (httpx — if selected)
    console.print("\n[bold]2. Sequential[/bold]")
    if not selected or "httpx-runner" in selected:
        ok, _ = _run_module("httpx-runner")
        results.append(("httpx-runner", ok))
        console.print(f"  {'[green]OK[/green]' if ok else '[red]FAIL[/red]'} httpx-runner")

        # Re-feed endpoint-dependent tools after httpx
        console.print("\n[bold]2.5 Re-feed[/bold]")
        feeder.feed_katana(proj_path, nmap_dir)
        feeder.feed_ferox(proj_path, nmap_dir)
        feeder.feed_jsfinder(proj_path, nmap_dir)
        feeder.feed_gf(proj_path, nmap_dir)
        feeder.feed_screenshot(proj_path, nmap_dir)
        feeder.feed_nuclei(proj_path, nmap_dir)
    else:
        console.print("  [dim]httpx-runner: skip[/dim]")

    # Stage 3: Parallel (filtered by selection)
    console.print("\n[bold]3. Parallel[/bold]")
    parallel_all = ["katana-runner", "feroxbuster-runner", "jsfinder-runner",
                    "gf-summary", "screenshot-runner", "nuclei-runner"]
    parallel = [m for m in parallel_all if not selected or m in selected]

    if parallel:
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(_run_module, m): m for m in parallel}
            for future in as_completed(futures):
                mod = futures[future]
                try:
                    ok, _ = future.result()
                except Exception:
                    ok = False
                results.append((mod, ok))
                console.print(f"  {'[green]OK[/green]' if ok else '[red]FAIL[/red]'} {mod}")
    else:
        console.print("  [dim]Nenhum módulo paralelo selecionado.[/dim]")

    # Stage 4: Verify
    console.print("\n[bold]4. Verify[/bold]")
    verifier.verify_endpoints(proj_path)

    # Stage 5: Sync
    console.print("\n[bold]5. Sync[/bold]")
    renderer.sync_project()

    elapsed = time.time() - start
    console.print(f"\n[bold green]✔ Ciclo completo em {elapsed:.1f}s[/bold green]")

    table = Table(box=None)
    table.add_column("Módulo", style="cyan")
    table.add_column("Status")
    for mod, ok in results:
        table.add_row(mod, "[green]OK[/green]" if ok else "[red]FAIL[/red]")
    console.print(table)


def run_cycle_watch(interval_hours: float = 6):
    console.print(f"[cyan]🔄 Watch mode — interval: {interval_hours}h[/cyan]")
    console.print("[dim]Ctrl+C interrompe o ciclo atual, mas o watch continua.[/dim]")
    console.print("[dim]Ctrl+C duas vezes para sair.[/dim]\n")
    while True:
        try:
            start = time.time()
            run_cycle()
            elapsed = time.time() - start
            sleep_sec = max(0, interval_hours * 3600 - elapsed)
            if sleep_sec > 0:
                next_time = time.strftime("%H:%M:%S", time.localtime(time.time() + sleep_sec))
                console.print(f"[dim]⏳ Cycle: {elapsed:.0f}s. Next: ~{next_time} ({sleep_sec/3600:.1f}h)[/dim]")
                time.sleep(sleep_sec)
            else:
                console.print(f"[yellow]⚠ Cycle took {elapsed:.0f}s > {interval_hours}h. Starting next immediately.[/yellow]")
        except KeyboardInterrupt:
            console.print("\n[yellow]⚠ Ciclo interrompido. Watch continua...[/yellow]")
            console.print("[dim]Pressione Ctrl+C novamente para sair.[/dim]\n")
            continue