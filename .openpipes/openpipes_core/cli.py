# ~/.openpipes/openpipes_core/cli.py
import renderer
import os
import sys
import subprocess
import argparse
import time
import verifier
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich.markdown import Markdown
from rich import box

# Garante que o diretório do módulo está no sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import db
import parsers

ENRICHER_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "osint_people_enricher_v1.0.py"
)

console = Console()
HOME = str(Path.home())
CONFIG_FILE = os.path.join(HOME, ".openpipes", "config.sh")
BIN_DIR = os.path.join(HOME, ".openpipes", "bin")


def get_project_env():
    """Extrai as variáveis de ambiente essenciais do bash config"""
    if not os.path.exists(CONFIG_FILE):
        return "DESCONHECIDO", "", ""
    cmd = f"source {CONFIG_FILE} && echo -n \"$proj_name|$proj_path|$NMAP_DIR\""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, executable="/bin/bash")
    parts = result.stdout.split('|')
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    return "DESCONHECIDO", "", ""


def show_execution_history():
    console.clear()
    console.print(Panel("[bold cyan]Histórico de Execuções (SQLite do Projeto)[/bold cyan]"))
    proj_name, proj_path, _ = get_project_env()
    if not proj_path:
        console.print("[red]Erro: Projeto não inicializado.[/red]")
        input("\nPressione ENTER...")
        return
    try:
        rows = db.get_recent_executions(proj_path, 15)
    except Exception:
        console.print("[yellow]Nenhuma execução registrada ainda ou banco não inicializado.[/yellow]")
        input("\nPressione ENTER para voltar...")
        return

    table = Table(box=box.SIMPLE_HEAVY, show_lines=True)
    table.add_column("ID", justify="right", style="cyan")
    table.add_column("Módulo", style="magenta")
    table.add_column("Status", justify="center")
    table.add_column("Exit", justify="center")
    table.add_column("Início", style="dim")
    for row in rows:
        status_color = "green" if row['status'] == "SUCCESS" else "red" if row['status'] == "FAILED" else "yellow"
        exit_code_str = str(row['exit_code']) if row['exit_code'] is not None else "-"
        table.add_row(
            str(row['id']), row['module_name'],
            f"[{status_color}]{row['status']}[/{status_color}]",
            exit_code_str, row['start_time']
        )
    console.print(table)
    input("\nPressione ENTER para voltar ao menu...")


def run_bash_module(module_name):
    proj_name, proj_path, nmap_dir = get_project_env()
    if proj_name == "DESCONHECIDO" or not proj_path:
        console.print("\n[bold red]✖ Erro: Projeto não configurado. Rode init-openpipes primeiro.[/bold red]")
        input("Pressione ENTER para continuar...")
        return

    script_path = os.path.join(BIN_DIR, module_name)
    if not os.path.exists(script_path):
        console.print(f"\n[bold red]✖ Erro: Módulo Bash '{module_name}' não encontrado.[/bold red]")
        input("Pressione ENTER para continuar...")
        return

    run_cwd = proj_path
    cmd_args = ""
    if module_name == "recon":
        if not os.path.exists(os.path.join(proj_path, "domains.txt")):
            console.print(f"\n[bold red]✖ Erro: domains.txt não encontrado em {proj_path}[/bold red]")
            input("Pressione ENTER para continuar...")
            return
    elif module_name == "nwrapper":
        run_cwd = nmap_dir
        os.makedirs(run_cwd, exist_ok=True)
        cmd_args = "-f targets.txt"

    # 1. Auto-migrate schema
    db.init_db(proj_path)

    # 2. Start execution log
    exec_id = db.log_module_start(proj_path, module_name)

    console.print(f"\n[bold cyan]▶ Iniciando módulo:[/bold cyan] {module_name}")
    console.print(f"[dim]CWD: {run_cwd}[/dim]")
    console.print("=" * 50)

    try:
        cmd_exec = f"source {CONFIG_FILE} && {script_path} {cmd_args}"
        result = subprocess.run(cmd_exec, shell=True, cwd=run_cwd, executable="/bin/bash")
        exit_code = result.returncode
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Execução abortada pelo usuário.[/bold red]")
        exit_code = 130

    console.print("=" * 50)
    db.log_module_finish(proj_path, exec_id, exit_code)

    if exit_code == 0:
        console.print(f"[bold green]✔ Módulo {module_name} concluído com sucesso![/bold green]")
        try:
            parsers.dispatch(module_name, proj_path, nmap_dir)
        except Exception as e:
            console.print(f"[bold red]✖ Erro no Parser: {e}[/bold red]")
    else:
        console.print(f"[bold red]✖ Módulo {module_name} falhou (Exit Code: {exit_code}).[/bold red]\n")

    input("\nPressione ENTER para voltar ao menu...")


def show_help():
    console.clear()
    help_text = """\
# 📚 Guia Rápido: OPenPipeS Core

Bem-vindo ao orquestrador Python do **OPenPipeS**.
Este framework automatiza o pipeline de Reconhecimento e Pentest, integrando os resultados diretamente ao **Obsidian MD**.

## 1. Configuração Inicial (`init-openpipes`)
Antes de rodar qualquer módulo, você deve **sempre** inicializar o projeto:
1. Saia deste menu e digite no terminal: `init-openpipes`
2. Escolha o nome do seu cliente/projeto (ex: `cliente-xyz`).
3. O framework criará as pastas estruturadas em `~/Projetos/cliente-xyz` e no seu Obsidian.

## 2. Inserindo os Alvos (DOMÍNIOS)
Os módulos (como o *Recon*) precisam saber o que atacar.
Vá até a pasta do projeto (ex: `~/Projetos/cliente-xyz`) e edite o arquivo `domains.txt`.
Coloque **um domínio por linha** (ex: `empresa.com`).

## 3. Chaves de API e Segredos
Para máxima eficiência (WHOIS, AI, Subdomínios), configure suas chaves em:
`~/.openpipes/secrets.conf`

## 4. Fluxo de Execução Recomendado (O Pipeline)
No menu principal, execute os módulos nesta ordem lógica:
1. **[1] Recon**: Encontra os subdomínios (Lê o `domains.txt`).
2. **[2] Nmap**: Escaneia as portas dos subdomínios encontrados.
3. **[3] Cria Alvos**: Gera os dashboards iniciais no Obsidian!
4. **[4 a 7] Web Discovery**: (HTTPx, Katana, Feroxbuster) Analisa os serviços web vivos.
5. **[8 a 11] Análise Profunda**: (JSFinder, GF, Screenshots) Extrai vulnerabilidades.
6. **[12] Gerir Vulns**: Selecione o alvo no menu e documente a falha achada.

*Pressione ENTER para voltar ao menu principal...*
"""
    console.print(Panel(Markdown(help_text), title="[bold cyan]Documentação Integrada[/bold cyan]", border_style="cyan"))
    input()


def run_osint_people_enricher():
    proj_name, proj_path, _ = get_project_env()
    if proj_name == "DESCONHECIDO" or not proj_path:
        console.print("\n[bold red]✖ Erro: Projeto não configurado.[/bold red]")
        input("Pressione ENTER para continuar...")
        return
    if not os.path.exists(ENRICHER_PATH):
        console.print(f"\n[bold red]✖ osint_people_enricher_v1.0.py não encontrado em:[/bold red]\n {ENRICHER_PATH}")
        input("Pressione ENTER para continuar...")
        return

    console.print(f"\n[bold cyan]OSINT People Enricher[/bold cyan]")
    console.print(f"[dim]Projeto ativo: {proj_name}[/dim]\n")
    target = Prompt.ask("[bold cyan]Alvo (domínio)[/bold cyan]", default=proj_name)

    obsdir = os.path.join(str(Path.home()), ".obsidianFixedMount")
    auth_path = os.path.join(str(Path.home()), ".openpipes", "auth.txt")
    if not os.path.exists(auth_path):
        with open(auth_path, "w") as fh:
            fh.write(f"authorized_by=openpipes-core\ntarget={target}\n")
        console.print(f"[dim]Auth stub criado em {auth_path}[/dim]")

    db.init_db(proj_path)
    exec_id = db.log_module_start(proj_path, "osint-people-enricher")

    console.print(f"\n[bold cyan]▶ Iniciando:[/bold cyan] osint-people-enricher → {target}")
    console.print("=" * 50)
    try:
        result = subprocess.run(
            [sys.executable, ENRICHER_PATH, "--target", target, "--obsdir", obsdir, "--auth", auth_path],
            cwd=os.path.dirname(ENRICHER_PATH),
        )
        exit_code = result.returncode
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Execução abortada pelo usuário.[/bold red]")
        exit_code = 130

    console.print("=" * 50)
    db.log_module_finish(proj_path, exec_id, exit_code)

    if exit_code == 0:
        console.print("[bold green]✔ OSINT People Enricher concluído com sucesso![/bold green]")
        output_json = os.path.join(obsdir, "Pentest", "Alvos", target, "OSINT", "osint_people.json")
        if os.path.exists(output_json):
            console.print(f"[dim]Output: {output_json}[/dim]")
    else:
        console.print(f"[bold red]✖ Falhou (Exit Code: {exit_code}).[/bold red]")
    input("\nPressione ENTER para voltar ao menu...")


def run_full_pipeline():
    proj_name, proj_path, nmap_dir = get_project_env()
    if proj_name == "DESCONHECIDO" or not proj_path:
        console.print("\n[bold red]✖ Projeto não configurado.[/bold red]")
        input("Pressione ENTER para continuar...")
        return
    if not os.path.exists(os.path.join(proj_path, "domains.txt")):
        console.print(f"\n[bold red]✖ domains.txt não encontrado em {proj_path}[/bold red]")
        input("Pressione ENTER para continuar...")
        return

    # Pipeline com nuclei-runner incluso
    PIPELINE = [
        ("recon",               proj_path, ""),
        ("nwrapper",            nmap_dir,  "-f targets.txt"),
        ("cria-alvos",          nmap_dir,  ""),
        ("httpx-runner",        proj_path, ""),
        ("katana-runner",       proj_path, ""),
        ("feroxbuster-runner",  proj_path, ""),
        ("katana-buster",       proj_path, ""),
        ("jsfinder-runner",     proj_path, ""),
        ("screenshot-runner",   proj_path, ""),
        ("gf-summary",          proj_path, ""),
        ("whois-enricher",      proj_path, ""),
        ("nuclei-runner",       proj_path, ""),   # NOVO
    ]

    console.clear()
    console.print(Panel(
        f"[bold yellow]Pipeline Completo[/bold yellow]\n"
        f"Projeto: [cyan]{proj_name}[/cyan] | "
        f"{len(PIPELINE) + 1} módulos (+ OSINT People)",
        border_style="yellow"
    ))
    console.print(
        "\n[dim]Módulos com falha serão registrados mas o pipeline continuará.\n"
        "Revise o histórico ao final com a opção [14].[/dim]\n"
    )
    escolha = Prompt.ask("[bold cyan]Confirma execução do pipeline completo?[/bold cyan]", choices=["s", "n"], default="n")
    if escolha != "s":
        console.print("[yellow]Cancelado.[/yellow]")
        input("Pressione ENTER...")
        return

    db.init_db(proj_path)
    results = []

    for module_name, run_cwd, cmd_args in PIPELINE:
        script_path = os.path.join(BIN_DIR, module_name)
        if not os.path.exists(script_path):
            console.print(f"\n[bold yellow]⚠ Módulo '{module_name}' não encontrado — pulando.[/bold yellow]")
            results.append((module_name, -1))
            continue

        if module_name == "nwrapper":
            os.makedirs(run_cwd, exist_ok=True)

        exec_id = db.log_module_start(proj_path, module_name)
        console.print(f"\n[bold cyan]▶ [{len(results)+1}/{len(PIPELINE)+1}][/bold cyan] {module_name}")

        try:
            cmd_exec = f"source {CONFIG_FILE} && {script_path} {cmd_args}"
            result = subprocess.run(cmd_exec, shell=True, cwd=run_cwd, executable="/bin/bash")
            exit_code = result.returncode
        except KeyboardInterrupt:
            console.print("\n[bold red][!] Pipeline interrompido pelo usuário.[/bold red]")
            db.log_module_finish(proj_path, exec_id, 130)
            results.append((module_name, 130))
            break

        db.log_module_finish(proj_path, exec_id, exit_code)
        results.append((module_name, exit_code))

        # Roda parser mesmo em falha parcial
        if exit_code == 0:
            try:
                parsers.dispatch(module_name, proj_path, nmap_dir)
            except Exception as e:
                console.print(f"  [yellow]Parser warning: {e}[/yellow]")

        status = "[bold green]✔[/bold green]" if exit_code == 0 else f"[bold red]✖ (exit {exit_code})[/bold red]"
        console.print(f"  {status} {module_name}")

    # OSINT People Enricher
    if os.path.exists(ENRICHER_PATH):
        console.print(f"\n[bold cyan]▶ [{len(PIPELINE)+1}/{len(PIPELINE)+1}][/bold cyan] osint-people-enricher")
        obsdir = os.path.join(str(Path.home()), ".obsidianFixedMount")
        auth_path = os.path.join(str(Path.home()), ".openpipes", "auth.txt")
        if not os.path.exists(auth_path):
            with open(auth_path, "w") as fh:
                fh.write(f"authorized_by=openpipes-core\ntarget={proj_name}\n")
        exec_id = db.log_module_start(proj_path, "osint-people-enricher")
        try:
            result = subprocess.run(
                [sys.executable, ENRICHER_PATH, "--target", proj_name, "--obsdir", obsdir, "--auth", auth_path],
                cwd=os.path.dirname(ENRICHER_PATH),
            )
            exit_code = result.returncode
        except KeyboardInterrupt:
            exit_code = 130
        db.log_module_finish(proj_path, exec_id, exit_code)
        results.append(("osint-people-enricher", exit_code))
        status = "[bold green]✔[/bold green]" if exit_code == 0 else f"[bold red]✖ (exit {exit_code})[/bold red]"
        console.print(f"  {status} osint-people-enricher")
    else:
        console.print(f"\n[yellow]⚠ osint_people_enricher_v1.0.py não encontrado — pulando.[/yellow]")

    # Sumário final
    console.print("\n" + "=" * 50)
    console.print("[bold]Sumário do Pipeline[/bold]")
    summary_table = Table(box=box.SIMPLE_HEAVY, show_lines=True)
    summary_table.add_column("Módulo", style="white")
    summary_table.add_column("Status", justify="center")
    summary_table.add_column("Exit Code", justify="center")
    for mod, code in results:
        if code == 0:
            s, color = "SUCCESS", "green"
        elif code == -1:
            s, color = "NÃO ENCONTRADO", "yellow"
        elif code == 130:
            s, color = "ABORTADO", "yellow"
        else:
            s, color = "FAILED", "red"
        summary_table.add_row(mod, f"[{color}]{s}[/{color}]", str(code) if code >= 0 else "-")
    console.print(summary_table)
    console.print(f"\n[bold green]{sum(1 for _, c in results if c == 0)} OK[/bold green] "
                  f"[bold red]{sum(1 for _, c in results if c != 0)} com problema[/bold red] "
                  f"de {len(results)} módulos")
    console.print("[dim]Use a opção [14] para ver o histórico detalhado no SQLite.[/dim]")
    input("\nPressione ENTER para voltar ao menu...")


def interactive_menu():
    while True:
        console.clear()
        proj_name, _, _ = get_project_env()
        banner = """[bold blue]
 ___   ____   ____   _    ____ 
/ _ \\ |  _ \\  ___  |_ | |  _ \\
| | | || |_) )/ _ \\ | '_ \\| |_) )
| |_| || __/( (_) )| | | | __/
 \\___/ |_|  \\___/ |_| |_|_|
                                
Framework de Reconhecimento v2.0
[/bold blue]"""
        console.print(banner)
        console.print(Panel(
            f"Projeto Ativo: [bold yellow]{proj_name}[/bold yellow] | "
            f"Motor: [bold green]Python Core[/bold green]",
            expand=False
        ))

        menu_table = Table(box=box.MINIMAL_DOUBLE_HEAD, show_header=False)
        menu_table.add_column("ID", style="bold green", justify="right")
        menu_table.add_column("Módulo/Ação", style="bold white")

        opcoes = {
            "1": "recon", "2": "nwrapper", "3": "cria-alvos",
            "4": "httpx-runner", "5": "katana-runner", "6": "feroxbuster-runner",
            "7": "katana-buster", "8": "jsfinder-runner", "9": "screenshot-runner",
            "10": "gf-summary", "11": "whois-enricher", "12": "cria-vulnerabilidades",
        }

        menu_table.add_row("[cyan]--[/cyan]", "[bold cyan]MÓDULOS DE PENTEST[/bold cyan]")
        for k, v in opcoes.items():
            menu_table.add_row(f"[{k}]", v.replace("-", " ").title())

        menu_table.add_row("", "")
        menu_table.add_row("[cyan]--[/cyan]", "[bold cyan]OSINT[/bold cyan]")
        menu_table.add_row("[15]", "[bold blue]OSINT People Enricher[/bold blue]")

        menu_table.add_row("", "")
        menu_table.add_row("[cyan]--[/cyan]", "[bold cyan]BANCO DE DADOS[/bold cyan]")
        menu_table.add_row("[16]", "[bold cyan]Reparse All (Recria DB dos outputs)[/bold cyan]")
        menu_table.add_row("[17]", "[bold cyan]Ver Dados do Banco[/bold cyan]")
        menu_table.add_row("[18]", "[bold green]Sync Obsidian Vault (Jinja2)[/bold green]")
        menu_table.add_row("[19]", "[bold cyan]Verifier (Valida Endpoints via HTTP)[/bold cyan]")
        menu_table.add_row("[20]", "[bold green]Feed Tools from DB[/bold green]")

        menu_table.add_row("", "")
        menu_table.add_row("[cyan]--[/cyan]", "[bold cyan]ORQUESTRAÇÃO E SISTEMA[/bold cyan]")
        menu_table.add_row("[13]", "[bold yellow]Pipeline Completo (Auto-Run)[/bold yellow]")
        menu_table.add_row("[14]", "[bold magenta]Ver Histórico de Execuções[/bold magenta]")
        menu_table.add_row("[99]", "[bold cyan]Ajuda / Documentação[/bold cyan]")
        menu_table.add_row("[0]", "[bold red]Sair[/bold red]")

        console.print(menu_table)
        escolha = Prompt.ask("\n[bold cyan]Escolha uma opção[/bold cyan]")

        if escolha == "0":
            console.print("[bold blue]Saindo...[/bold blue]")
            break

        elif escolha == "99":
            show_help()

        elif escolha == "14":
            show_execution_history()

        elif escolha == "13":
            run_full_pipeline()

        elif escolha == "15":
            run_osint_people_enricher()

        elif escolha == "16":
            run_reparse_all()

        elif escolha == "17":
            show_database_viewer()

        elif escolha == "18":
            renderer.sync_project()           # all targets

        elif escolha == "19":
            proj_name, proj_path, _ = get_project_env()
            if proj_path:
                db.init_db(proj_path)
                verifier.verify_endpoints(proj_path, limit=args.limit)
            else:
                console.print("[red]Projeto não configurado.[/red]")
                input("Pressione ENTER...")

        elif escolha == "20":
            import feeder
            feeder.run()


        elif escolha in opcoes:
            run_bash_module(opcoes[escolha])
        else:
            console.print("[bold red]Opção inválida![/bold red]")
            time.sleep(1)


def run_reparse_all():
    """
    Option 16: Walk all tool output directories and re-run every parser.
    Useful after schema migration or adding a new parser.
    """
    proj_name, proj_path, nmap_dir = get_project_env()
    if proj_name == "DESCONHECIDO" or not proj_path:
        console.print("\n[bold red]✖ Erro: Projeto não configurado.[/bold red]")
        input("Pressione ENTER para continuar...")
        return

    console.clear()
    console.print(Panel("[bold cyan]Reparse All — Repopulando banco de dados[/bold cyan]"))
    console.print(f"[dim]Projeto: {proj_name}[/dim]")
    console.print("[yellow]Isso irá re-processar todos os outputs das ferramentas nos diretórios Recon/ e Varreduras/[/yellow]\n")

    escolha = Prompt.ask("[bold cyan]Confirmar?[/bold cyan]", choices=["s", "n"], default="n")
    if escolha != "s":
        console.print("[yellow]Cancelado.[/yellow]")
        input("Pressione ENTER...")
        return

    # Auto-migrate schema first
    db.init_db(proj_path)

    recon_dir = os.path.join(proj_path, "Recon")
    nmap_dir_path = nmap_dir

    modules = [
        ("recon",      lambda: parsers.parse_recon(proj_path, recon_dir)),
        ("nmap",       lambda: parsers.parse_nmap(proj_path, nmap_dir_path)),
        ("httpx",      lambda: parsers.parse_httpx(proj_path, nmap_dir_path)),
        ("feroxbuster", lambda: parsers.parse_url_discovery_jsonl(proj_path, nmap_dir_path, "ferox")),
        ("katana",     lambda: parsers.parse_url_discovery_jsonl(proj_path, nmap_dir_path, "crawled")),
        ("screenshots", lambda: parsers.parse_screenshot(proj_path, nmap_dir)),
        ("nuclei",     lambda: parsers.parse_nuclei(proj_path, nmap_dir_path)),
        ("whois",      lambda: parsers.parse_whois_enrichment(proj_path, nmap_dir_path)),
    ]

    for name, fn in modules:
        try:
            fn()
            console.print(f"  [bold green]✔[/bold green] {name}")
        except Exception as e:
            console.print(f"  [bold red]✖[/bold red] {name}: {e}")

    console.print("\n[bold green]Reparse concluído![/bold green]")
    input("Pressione ENTER para voltar ao menu...")


def show_database_viewer():
    """
    Option 17: Quick-read stats from SQLite without leaving the menu.
    """
    proj_name, proj_path, _ = get_project_env()
    if not proj_path:
        console.print("[red]Erro: Projeto não configurado.[/red]")
        input("Pressione ENTER...")
        return

    try:
        with db.get_connection(proj_path) as conn:
            cursor = conn.cursor()

            stats = {}
            for table in ["hosts", "ports", "endpoints", "screenshots",
                          "js_discoveries", "vulnerabilities", "execution_logs"]:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                stats[table] = cursor.fetchone()[0]

            # Severity breakdown
            severity_counts = {"Crítica": 0, "Alta": 0, "Média": 0, "Baixa": 0, "Info": 0}
            try:
                cursor.execute(
                    "SELECT severity, COUNT(*) as cnt FROM vulnerabilities GROUP BY severity"
                )
                for row in cursor.fetchall():
                    sev = row["severity"]
                    if sev in severity_counts:
                        severity_counts[sev] = row["cnt"]
            except Exception:
                pass

            # Last execution
            cursor.execute(
                "SELECT module_name, status, start_time FROM execution_logs ORDER BY start_time DESC LIMIT 5"
            )
            recent = cursor.fetchall()

    except Exception as e:
        console.print(f"[red]Erro ao ler banco de dados: {e}[/red]")
        input("Pressione ENTER...")
        return

    console.clear()
    console.print(Panel("[bold cyan]📊 Dados do Banco de Dados[/bold cyan]"))

    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("Tabela", style="cyan")
    table.add_column("Registros", justify="right")
    table.add_row("Hosts",           str(stats.get("hosts", 0)))
    table.add_row("Portas",          str(stats.get("ports", 0)))
    table.add_row("Endpoints URL",   str(stats.get("endpoints", 0)))
    table.add_row("Screenshots",     str(stats.get("screenshots", 0)))
    table.add_row("JS Discoveries",  str(stats.get("js_discoveries", 0)))
    table.add_row("Vulnerabilidades", str(stats.get("vulnerabilities", 0)))
    table.add_row("Execuções",       str(stats.get("execution_logs", 0)))
    console.print(table)

    if stats.get("vulnerabilities", 0) > 0:
        sev_table = Table(box=box.SIMPLE_HEAVY)
        sev_table.add_column("Severidade", style="cyan")
        sev_table.add_column("Quantidade", justify="right")
        for sev, count in severity_counts.items():
            color = {"Crítica": "red", "Alta": "yellow", "Média": "blue",
                     "Baixa": "green", "Info": "dim"}.get(sev, "white")
            sev_table.add_row(f"[{color}]{sev}[/{color}]", str(count))
        console.print("\n[bold]Vulnerabilidades por Severidade:[/bold]")
        console.print(sev_table)

    if recent:
        console.print("\n[bold]Últimas execuções:[/bold]")
        for row in recent:
            color = "green" if row["status"] == "SUCCESS" else "red"
            console.print(f"  [{color}]{row['module_name']}[/{color}] "
                          f"({row['status']}) — {row['start_time']}")

    input("\nPressione ENTER para voltar ao menu...")

def main():
    parser = argparse.ArgumentParser(description="OPenPipeS Core Engine")
    subparsers = parser.add_subparsers(dest="command")
    run_parser = subparsers.add_parser("run", help="Executa um módulo bash e rastreia o estado")
    run_parser.add_argument("module", help="Nome do módulo (ex: recon, nwrapper, nuclei-runner)")
    sync_parser = subparsers.add_parser("sync", help="Renderiza Jinja2 templates para o vault do Obsidian")
    sync_parser.add_argument("--target", "-t", help="Renderizar apenas um alvo específico")
    verify_parser = subparsers.add_parser("verify", help="Verifica endpoints com HTTP real")
    verify_parser.add_argument("--limit", type=int, default=None, help="Limite de endpoints")
    feed_parser = subparsers.add_parser("feed", help="Alimenta ferramentas a partir do banco de dados")


    if len(sys.argv) == 1:
        interactive_menu()
    else:
        args = parser.parse_args()
        if args.command == "run":
            run_bash_module(args.module)
        elif args.command == "sync":
            renderer.sync_project(target_name=args.target)
        elif args.command == "verify":
            proj_name, proj_path, _ = get_project_env()
            if proj_path:
                db.init_db(proj_path)
                verifier.verify_endpoints(proj_path, limit=args.limit)
        elif args.command == "feed":    
            import feeder
            feeder.run()

if __name__ == "__main__":
    main()
