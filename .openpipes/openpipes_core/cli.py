# ~/.openpipes/openpipes_core/cli.py
import os
import sys
import subprocess
import argparse
import time
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import box
from rich.markdown import Markdown

# Garante que o diretório do módulo está no sys.path,
# independente de onde o script é chamado (wrapper bash, cwd, etc.)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Importa o gerenciador de banco de dados e os novos Parsers (Fase 3)
import db
import parsers

# Caminho para o módulo de enriquecimento OSINT de pessoas.
ENRICHER_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "osint_people_enricher_v1.0.py")

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

# --- MÓDULOS DE VISUALIZAÇÃO DE DADOS (FASE 3) ---

def show_host_details(proj_path, host_id):
    """Renderiza uma tabela detalhada de um host específico (Portas e Endpoints)"""
    conn = db.get_connection(proj_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM hosts WHERE id = ?", (host_id,))
    host = cursor.fetchone()
    if not host: return

    console.clear()
    ips_str = ", ".join(json.loads(host['ips'])) if host['ips'] and host['ips'] != '[]' else "Nenhum IP resolvido"
    cnames_str = ", ".join(json.loads(host['cnames'])) if host['cnames'] and host['cnames'] != '[]' else "Nenhum CNAME"
    
    console.print(Panel(f"[bold cyan]🎯 Detalhes do Host:[/bold cyan] [bold white]{host['host']}[/bold white]\n[dim]IPs: {ips_str} | CNAMEs: {cnames_str}[/dim]"))

    # Portas
    cursor.execute("SELECT port, protocol, state, service, version FROM ports WHERE host_id = ? ORDER BY port", (host_id,))
    ports = cursor.fetchall()
    if ports:
        console.print("\n[bold magenta]🔌 Portas e Serviços (Nmap)[/bold magenta]")
        ptable = Table(box=box.SIMPLE)
        ptable.add_column("Porta/Proto", style="cyan")
        ptable.add_column("Estado")
        ptable.add_column("Serviço")
        ptable.add_column("Versão/Produto")
        for p in ports:
            state_color = "green" if p['state'] == 'open' else "yellow"
            ptable.add_row(f"{p['port']}/{p['protocol']}", f"[{state_color}]{p['state']}[/{state_color}]", p['service'], p['version'])
        console.print(ptable)

    # Endpoints
    cursor.execute("SELECT url, status_code, title, web_server, tech_stack, source_tool FROM endpoints WHERE host_id = ? ORDER BY status_code", (host_id,))
    endpoints = cursor.fetchall()
    if endpoints:
        console.print("\n[bold blue]🌐 Endpoints e Tecnologias Mapeadas[/bold blue]")
        etable = Table(box=box.SIMPLE)
        etable.add_column("URL")
        etable.add_column("Status", justify="center")
        etable.add_column("Title")
        etable.add_column("Stack & Server", style="dim")
        etable.add_column("Fonte", justify="right")
        for ep in endpoints:
            status = str(ep['status_code']) if ep['status_code'] else "-"
            status_fmt = f"[green]{status}[/green]" if status.startswith('2') else f"[yellow]{status}[/yellow]" if status.startswith('3') else f"[red]{status}[/red]"
            techs = ", ".join(json.loads(ep['tech_stack'])) if ep['tech_stack'] and ep['tech_stack'] != '[]' else ""
            server = ep['web_server'] if ep['web_server'] else ""
            stack_fmt = f"{server} {techs}".strip() or "-"
            etable.add_row(ep['url'], status_fmt, ep['title'] or "-", stack_fmt, ep['source_tool'])
        console.print(etable)
    else:
        console.print("\n[dim]Nenhum endpoint web rico mapeado para este host ainda.[/dim]")

    input("\nPressione ENTER para voltar ao Explorador...")

def data_explorer():
    """Dashboard Global interativo do projeto no Terminal"""
    proj_name, proj_path, _ = get_project_env()
    if not proj_path:
        console.print("[red]Erro: Projeto não inicializado.[/red]")
        input("Pressione ENTER...")
        return

    while True:
        conn = db.get_connection(proj_path)
        cursor = conn.cursor()
        console.clear()
        console.print(Panel(f"[bold cyan]📊 Explorador de Dados (SQLite) - Projeto: {proj_name}[/bold cyan]"))

        # Resumo Estatístico
        cursor.execute("SELECT count(*) as total, sum(is_alive) as vivos FROM hosts")
        res = cursor.fetchone()
        total_hosts = res['total'] or 0
        vivos = res['vivos'] or 0
        cursor.execute("SELECT count(*) as total FROM endpoints")
        total_endpoints = cursor.fetchone()['total'] or 0
        cursor.execute("SELECT count(*) as total FROM ports WHERE state='open'")
        total_ports = cursor.fetchone()['total'] or 0

        console.print(f"[bold]Alvos Totais:[/bold] {total_hosts} | [bold green]Alvos Vivos:[/bold green] {vivos} | [bold magenta]Portas Abertas:[/bold magenta] {total_ports} | [bold blue]Endpoints:[/bold blue] {total_endpoints}\n")

        # Tabela dos Principais Hosts
        table = Table(box=box.MINIMAL_DOUBLE_HEAD)
        table.add_column("ID", justify="right", style="cyan")
        table.add_column("Host (Subdomínio/IP)", style="bold white")
        table.add_column("IPs Resolvidos", style="dim")
        table.add_column("Portas Abertas", style="magenta")
        table.add_column("Qtd Endpoints", justify="right")

        cursor.execute('''
            SELECT h.id, h.host, h.ips, h.is_alive,
                   (SELECT GROUP_CONCAT(port) FROM ports WHERE host_id = h.id AND state='open') as open_ports,
                   (SELECT count(*) FROM endpoints WHERE host_id = h.id) as ep_count
            FROM hosts h
            ORDER BY h.is_alive DESC, ep_count DESC, h.id ASC
            LIMIT 25
        ''')
        rows = cursor.fetchall()
        conn.close()

        for row in rows:
            status_color = "green" if row['is_alive'] else "dim"
            host_display = f"[{status_color}]{row['host']}[/{status_color}]"
            ips_list = json.loads(row['ips']) if row['ips'] else []
            ips_fmt = f"{ips_list[0]} (+{len(ips_list)-1})" if len(ips_list) > 1 else (ips_list[0] if ips_list else "-")
            ports_fmt = row['open_ports'] if row['open_ports'] else "-"
            table.add_row(str(row['id']), host_display, ips_fmt, ports_fmt, str(row['ep_count']))

        console.print(table)
        console.print("[dim]* Exibindo o Top 25 hosts (priorizando alvos vivos com mais endpoints descobertos).[/dim]\n")

        console.print("[cyan]Opções:[/cyan]")
        console.print("[1] Ver detalhes de um Host (Digite o [bold]ID[/bold])")
        console.print("[0] Voltar ao Menu Principal")

        choice = Prompt.ask("\nDigite o ID do Host para detalhar ou 0 para voltar").strip()
        if choice == "0":
            break
        elif choice.isdigit():
            show_host_details(proj_path, choice)


def parse_retroactive(module_name="all"):
    """Comando para reprocessar dados brutos que já estão no disco sem rodar os scans de novo"""
    proj_name, proj_path, nmap_dir = get_project_env()
    if not proj_path:
        console.print("[red]Erro: Projeto não inicializado.[/red]")
        return
        
    db.init_db(proj_path)  # CORRIGIDO AQUI
    modules_to_parse = ['recon', 'nwrapper', 'httpx-runner', 'feroxbuster-runner', 'katana-runner', 'jsfinder-runner'] if module_name == "all" else [module_name]
    
    console.print(f"[bold cyan]♻️ Iniciando Reprocessamento Retroativo de Dados...[/bold cyan]")
    for mod in modules_to_parse:
        try: 
            parsers.dispatch(mod, proj_path, nmap_dir)
        except Exception as e: 
            console.print(f"[yellow]Aviso no parse de {mod}: {e}[/yellow]")
    console.print("[bold green]✔ Reprocessamento concluído![/bold green]")

# --- NÚCLEO DE ORQUESTRAÇÃO ---

def show_execution_history():
    console.clear()
    console.print(Panel("[bold cyan]Histórico de Execuções (SQLite Database)[/bold cyan]"))
    proj_name, proj_path, _ = get_project_env()
    if not proj_path: return
    try: rows = db.get_recent_executions(proj_path, 15)  # CORRIGIDO AQUI
    except Exception:
        console.print("[yellow]Nenhuma execução registrada ainda ou banco não inicializado.[/yellow]")
        input("\nPressione ENTER para voltar...")
        return
    table = Table(box=box.SIMPLE_HEAVY, show_lines=True)
    table.add_column("ID", justify="right", style="cyan", no_wrap=True)
    table.add_column("Módulo", style="magenta")
    table.add_column("Status", justify="center")
    table.add_column("Exit Code", justify="center")
    table.add_column("Início", style="dim")
    for row in rows:
        status_color = "green" if row['status'] == "SUCCESS" else "red" if row['status'] == "FAILED" else "yellow"
        exit_code_str = str(row['exit_code']) if row['exit_code'] is not None else "-"
        table.add_row(str(row['id']), row['module_name'], f"[{status_color}]{row['status']}[/{status_color}]", exit_code_str, row['start_time'])
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

    db.init_db(proj_path)  # CORRIGIDO AQUI
    exec_id = db.log_module_start(proj_path, module_name)  # CORRIGIDO AQUI
    
    console.print(f"\n[bold cyan]▶ Iniciando módulo:[/bold cyan] {module_name}")
    console.print(f"[dim]CWD (Diretório Alvo): {run_cwd}[/dim]")
    console.print("=" * 50)
    
    try:
        cmd_exec = f"source {CONFIG_FILE} && {script_path} {cmd_args}"
        result = subprocess.run(cmd_exec, shell=True, cwd=run_cwd, executable="/bin/bash")
        exit_code = result.returncode
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Execução abortada pelo usuário.[/bold red]")
        exit_code = 130 

    console.print("=" * 50)
    db.log_module_finish(proj_path, exec_id, exit_code)  # CORRIGIDO AQUI
    
    if exit_code == 0:
        console.print(f"[bold green]✔ Módulo {module_name} concluído com sucesso![/bold green]\n")
        # --- PARSER MÁGICO AQUI ---
        try: parsers.dispatch(module_name, proj_path, nmap_dir)
        except Exception as e: console.print(f"[bold red]✖ Erro no Parser: {e}[/bold red]")
    else:
        console.print(f"[bold red]✖ Módulo {module_name} falhou (Exit Code: {exit_code}).[/bold red]\n")
        
    input("Pressione ENTER para voltar ao menu...")

def show_help():
    console.clear()
    help_text = """
# 📚 Guia Rápido: OPenPipeS Core

Bem-vindo ao orquestrador Python do **OPenPipeS**. 
Este framework automatiza o pipeline de Reconhecimento e Pentest, integrando os resultados diretamente ao **Obsidian MD** e a um Banco Relacional SQLite.

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

## 4. O Cérebro Analítico (Fase 3)
* Você pode usar a opção **16 (Reprocessar Dados)** para reler arquivos `.txt` e `.json` antigos sem precisar escanear tudo de novo.
* A opção **17 (Explorador)** mostra seus alvos vivos, IPs associados, CNAMEs e Endpoints direto no terminal!
"""
    console.print(Panel(Markdown(help_text), title="[bold cyan]Documentação Integrada[/bold cyan]", border_style="cyan"))
    input("\nPressione ENTER para voltar ao menu principal...")

def run_osint_people_enricher():
    proj_name, proj_path, _ = get_project_env()
    if proj_name == "DESCONHECIDO" or not proj_path:
        console.print("\n[bold red]✖ Erro: Projeto não configurado. Rode init-openpipes primeiro.[/bold red]")
        input("Pressione ENTER para continuar...")
        return
    if not os.path.exists(ENRICHER_PATH):
        console.print(f"\n[bold red]✖ osint_people_enricher_v1.0.py não encontrado em:[/bold red]\n  {ENRICHER_PATH}")
        input("Pressione ENTER para continuar...")
        return
    console.print(f"\n[bold cyan]OSINT People Enricher[/bold cyan]")
    console.print(f"[dim]Projeto ativo: {proj_name}[/dim]\n")
    target = Prompt.ask("[bold cyan]Alvo (domínio)[/bold cyan]", default=proj_name)
    obsdir = os.path.join(str(Path.home()), ".obsidianFixedMount")
    auth_path = os.path.join(str(Path.home()), ".openpipes", "auth.txt")
    if not os.path.exists(auth_path):
        with open(auth_path, "w") as fh: fh.write(f"authorized_by=openpipes-core\ntarget={target}\n")
        console.print(f"[dim]Auth stub criado em {auth_path}[/dim]")
        
    db.init_db(proj_path)  # CORRIGIDO AQUI
    exec_id = db.log_module_start(proj_path, "osint-people-enricher")  # CORRIGIDO AQUI
    
    console.print(f"\n[bold cyan]▶ Iniciando:[/bold cyan] osint-people-enricher → {target}")
    console.print("=" * 50)
    try:
        result = subprocess.run([sys.executable, ENRICHER_PATH, "--target", target, "--obsdir", obsdir, "--auth", auth_path], cwd=os.path.dirname(ENRICHER_PATH))
        exit_code = result.returncode
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Execução abortada pelo usuário.[/bold red]")
        exit_code = 130
    console.print("=" * 50)
    
    db.log_module_finish(proj_path, exec_id, exit_code)  # CORRIGIDO AQUI
    
    if exit_code == 0:
        console.print("[bold green]✔ OSINT People Enricher concluído com sucesso![/bold green]")
    else: console.print(f"[bold red]✖ Falhou (Exit Code: {exit_code}).[/bold red]")
    input("\nPressione ENTER para voltar ao menu...")

def run_full_pipeline():
    proj_name, proj_path, nmap_dir = get_project_env()
    if proj_name == "DESCONHECIDO" or not proj_path:
        console.print("\n[bold red]✖ Projeto não configurado. Rode init-openpipes primeiro.[/bold red]")
        input("Pressione ENTER para continuar...")
        return
    if not os.path.exists(os.path.join(proj_path, "domains.txt")):
        console.print(f"\n[bold red]✖ domains.txt não encontrado em {proj_path}[/bold red]")
        input("Pressione ENTER para continuar...")
        return

    PIPELINE = [
        ("recon",               proj_path,  ""),
        ("nwrapper",            nmap_dir,   "-f targets.txt"),
        ("cria-alvos",          nmap_dir,   ""),
        ("httpx-runner",        proj_path,  ""),
        ("katana-runner",       proj_path,  ""),
        ("feroxbuster-runner",  proj_path,  ""),
        ("katana-buster",       proj_path,  ""),
        ("jsfinder-runner",     proj_path,  ""),
        ("screenshot-runner",   proj_path,  ""),
        ("gf-summary",          proj_path,  ""),
        ("whois-enricher",      proj_path,  ""),
        ("nuclei-runner",       proj_path,  ""),
    ]

    console.clear()
    console.print(Panel(
        f"[bold yellow]Pipeline Completo[/bold yellow]\n"
        f"Projeto: [cyan]{proj_name}[/cyan] | "
        f"{len(PIPELINE) + 1} módulos (+ OSINT People)",
        border_style="yellow"
    ))
    
    escolha = Prompt.ask("[bold cyan]Confirma execução do pipeline completo?[/bold cyan]", choices=["s", "n"], default="n")
    if escolha != "s": return

    db.init_db(proj_path)  # CORRIGIDO AQUI
    results = []

    for module_name, run_cwd, cmd_args in PIPELINE:
        script_path = os.path.join(BIN_DIR, module_name)
        if not os.path.exists(script_path):
            results.append((module_name, -1))
            continue
        if module_name == "nwrapper": os.makedirs(run_cwd, exist_ok=True)

        exec_id = db.log_module_start(proj_path, module_name)  # CORRIGIDO AQUI
        console.print(f"\n[bold cyan]▶ [{len(results)+1}/{len(PIPELINE)+1}][/bold cyan] {module_name}")

        try:
            cmd_exec = f"source {CONFIG_FILE} && {script_path} {cmd_args}"
            result = subprocess.run(cmd_exec, shell=True, cwd=run_cwd, executable="/bin/bash")
            exit_code = result.returncode
        except KeyboardInterrupt:
            db.log_module_finish(proj_path, exec_id, 130)  # CORRIGIDO AQUI
            results.append((module_name, 130))
            break

        db.log_module_finish(proj_path, exec_id, exit_code)  # CORRIGIDO AQUI
        results.append((module_name, exit_code))
        status = "[bold green]✔[/bold green]" if exit_code == 0 else f"[bold red]✖ (exit {exit_code})[/bold red]"
        console.print(f"  {status} {module_name}")
        
        # --- PARSER INTEGRADO AO AUTO-RUN ---
        if exit_code == 0:
            try: parsers.dispatch(module_name, proj_path, nmap_dir)
            except Exception as e: console.print(f"    [dim red]↳ Erro no Parser: {e}[/dim red]")

    # OSINT People
    if os.path.exists(ENRICHER_PATH):
        console.print(f"\n[bold cyan]▶ [{len(PIPELINE)+1}/{len(PIPELINE)+1}][/bold cyan] osint-people-enricher")
        obsdir = os.path.join(str(Path.home()), ".obsidianFixedMount")
        auth_path = os.path.join(str(Path.home()), ".openpipes", "auth.txt")
        if not os.path.exists(auth_path):
            with open(auth_path, "w") as fh: fh.write(f"authorized_by=openpipes-core\ntarget={proj_name}\n")
            
        exec_id = db.log_module_start(proj_path, "osint-people-enricher")  # CORRIGIDO AQUI
        try:
            result = subprocess.run([sys.executable, ENRICHER_PATH, "--target", proj_name, "--obsdir", obsdir, "--auth", auth_path], cwd=os.path.dirname(ENRICHER_PATH))
            exit_code = result.returncode
        except KeyboardInterrupt: exit_code = 130
        
        db.log_module_finish(proj_path, exec_id, exit_code)  # CORRIGIDO AQUI
        
        results.append(("osint-people-enricher", exit_code))
        status = "[bold green]✔[/bold green]" if exit_code == 0 else f"[bold red]✖ (exit {exit_code})[/bold red]"
        console.print(f"  {status} osint-people-enricher")

    console.print("\n" + "=" * 50)
    console.print("[bold]Sumário do Pipeline[/bold]")
    total, success = len(results), sum(1 for _, c in results if c == 0)
    summary_table = Table(box=box.SIMPLE_HEAVY, show_lines=True)
    summary_table.add_column("Módulo"); summary_table.add_column("Status"); summary_table.add_column("Exit")
    for mod, code in results:
        if code == 0: s, color = "SUCCESS", "green"
        elif code == -1: s, color = "NOT FOUND", "yellow"
        elif code == 130: s, color = "ABORTED", "yellow"
        else: s, color = "FAILED", "red"
        summary_table.add_row(mod, f"[{color}]{s}[/{color}]", str(code) if code >= 0 else "-")
    console.print(summary_table)
    input("\nPressione ENTER para voltar ao menu...")

def interactive_menu():
    while True:
        console.clear()
        proj_name, _, _ = get_project_env()
        
        banner = """[bold blue]
   ___  ____            ____  _             ____  
  / _ \\|  _ \\ ___ _ __ |  _ \\(_)_ __   ___ / ___| 
 | | | | |_) / _ | '_ \\| |_) | | '_ \\ / _ \\___ \\ 
 | |_| |  __/  __| | | |  __/| | |_) |  __/ ___) |
  \\___/|_|   \\___|_| |_|_|   |_| .__/ \\___||____/ 
                               |_|                  
                    Framework de Reconhecimento v2.0 
[/bold blue]"""
        console.print(banner)
        console.print(Panel(f"Projeto Ativo: [bold yellow]{proj_name}[/bold yellow] | Motor: [bold green]Python Core[/bold green]", expand=False))
        
        menu_table = Table(box=box.MINIMAL_DOUBLE_HEAD, show_header=False)
        menu_table.add_column("ID", style="bold green", justify="right")
        menu_table.add_column("Módulo/Ação", style="bold white")
        
        opcoes = {
            "1": "recon", "2": "nwrapper", "3": "cria-alvos",
            "4": "httpx-runner", "5": "katana-runner", "6": "feroxbuster-runner",
            "7": "katana-buster", "8": "jsfinder-runner", "9": "screenshot-runner",
            "10": "gf-summary", "11": "whois-enricher", "12": "cria-vulnerabilidades"
        }
        
        menu_table.add_row("[cyan]--[/cyan]", "[bold cyan]MÓDULOS DE PENTEST[/bold cyan]")
        for k, v in opcoes.items():
            menu_table.add_row(f"[{k}]", v.replace("-", " ").title())
            
        menu_table.add_row("", "")
        menu_table.add_row("[cyan]--[/cyan]", "[bold cyan]OSINT[/bold cyan]")
        menu_table.add_row("[15]", "[bold blue]OSINT People Enricher[/bold blue]")
        
        menu_table.add_row("", "")
        menu_table.add_row("[cyan]--[/cyan]", "[bold cyan]CÉREBRO ANALÍTICO (SQLITE)[/bold cyan]")
        menu_table.add_row("[16]", "[bold yellow]♻️  Reprocessar Dados (Parse Retroativo)[/bold yellow]")
        menu_table.add_row("[17]", "[bold blue]📊 Explorador de Dados Interativo[/bold blue]")

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
            if Confirm.ask("Ler arquivos locais e re-popular o Banco de Dados?"):
                parse_retroactive("all")
                input("\nPressione ENTER para continuar...")
        elif escolha == "17":
            data_explorer()
        elif escolha in opcoes:
            run_bash_module(opcoes[escolha])
        else:
            console.print("[bold red]Opção inválida![/bold red]")
            time.sleep(1)

def main():
    parser = argparse.ArgumentParser(description="OPenPipeS Core Engine")
    subparsers = parser.add_subparsers(dest="command")

    run_parser = subparsers.add_parser("run", help="Executa um módulo bash e rastreia o estado")
    run_parser.add_argument("module", help="Nome do módulo")

    parse_parser = subparsers.add_parser("parse", help="Reprocessa os outputs raw em disco para o DB")
    parse_parser.add_argument("module", help="Nome do módulo ou 'all'")

    if len(sys.argv) == 1:
        interactive_menu()
    else:
        args = parser.parse_args()
        if args.command == "run":
            run_bash_module(args.module)
        elif args.command == "parse":
            parse_retroactive(args.module)

if __name__ == "__main__":
    main()