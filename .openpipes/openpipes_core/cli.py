# ~/.openpipes/openpipes_core/cli.py
import os
import sys
import subprocess
import argparse
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich import box

# Importa o gerenciador de banco de dados
import db

console = Console()
HOME = str(Path.home())
CONFIG_FILE = os.path.join(HOME, ".openpipes", "config.sh")
BIN_DIR = os.path.join(HOME, ".openpipes", "bin")

def get_active_project():
    """Lê o projeto ativo diretamente do config.sh"""
    if not os.path.exists(CONFIG_FILE):
        return "NENHUM PROJETO (Rode init-openpipes)"
        
    cmd = f"source {CONFIG_FILE} && echo $proj_name"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, executable="/bin/bash")
    proj_name = result.stdout.strip()
    return proj_name if proj_name else "DESCONHECIDO"

def show_execution_history():
    """Consulta o SQLite e renderiza uma tabela incrível usando Rich"""
    console.clear()
    console.print(Panel("[bold cyan]Histórico de Execuções (SQLite Database)[/bold cyan]"))
    
    try:
        rows = db.get_recent_executions(15)
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
        
        table.add_row(
            str(row['id']),
            row['module_name'],
            f"[{status_color}]{row['status']}[/{status_color}]",
            exit_code_str,
            row['start_time']
        )
        
    console.print(table)
    input("\nPressione ENTER para voltar ao menu...")

def run_bash_module(module_name):
    """Executa o script bash original envolvido pela telemetria do Python"""
    project_name = get_active_project()
    script_path = os.path.join(BIN_DIR, module_name)
    
    if not os.path.exists(script_path):
        console.print(f"\n[bold red]✖ Erro: Módulo Bash '{module_name}' não encontrado.[/bold red]")
        input("Pressione ENTER para continuar...")
        return

    db.init_db()
    exec_id = db.log_module_start(project_name, module_name)
    
    console.print(f"\n[bold cyan]▶ Iniciando módulo:[/bold cyan] {module_name}")
    console.print("=" * 50)
    
    try:
        result = subprocess.run([script_path])
        exit_code = result.returncode
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Execução abortada pelo usuário.[/bold red]")
        exit_code = 130 

    console.print("=" * 50)
    db.log_module_finish(exec_id, exit_code)
    
    if exit_code == 0:
        console.print(f"[bold green]✔ Módulo {module_name} concluído com sucesso![/bold green]\n")
    else:
        console.print(f"[bold red]✖ Módulo {module_name} falhou (Exit Code: {exit_code}).[/bold red]\n")
        
    input("Pressione ENTER para voltar ao menu...")

def interactive_menu():
    """O Novo Dashboard Python renderizado no Terminal"""
    while True:
        console.clear()
        project = get_active_project()
        
        # Banner e Cabeçalho
        banner = """[bold blue]
   ___  ____            ____  _             ____                 
  / _ \|  _ \ ___ _ __ |  _ \(_)_ __   ___ / ___|___  _ __ ___   
 | | | | |_) / _ | '_ \| |_) | | '_ \ / _ | |   / _ \| '__/ _ \  
 | |_| |  __/  __| | | |  __/| | |_) |  __| |__| (_) | | |  __/  
  \___/|_|   \___|_| |_|_|   |_| .__/ \___|\____\___/|_|  \___|  
                               |_|                               
[/bold blue]"""
        console.print(banner)
        console.print(Panel(f"Projeto Ativo: [bold yellow]{project}[/bold yellow] | Motor: [bold green]Python Core[/bold green]", expand=False))
        
        # Tabela de Opções
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
        menu_table.add_row("[cyan]--[/cyan]", "[bold cyan]ORQUESTRAÇÃO E BANCO DE DADOS[/bold cyan]")
        menu_table.add_row("[13]", "[bold yellow]Pipeline Completo (Auto-Run)[/bold yellow]")
        menu_table.add_row("[14]", "[bold magenta]Ver Histórico de Execuções (Testar SQLite)[/bold magenta]")
        menu_table.add_row("[0]", "[bold red]Sair[/bold red]")
        
        console.print(menu_table)
        
        # Coleta a opção do usuário
        escolha = Prompt.ask("\n[bold cyan]Escolha uma opção[/bold cyan]")
        
        if escolha == "0":
            console.print("[bold blue]Saindo...[/bold blue]")
            break
        elif escolha == "14":
            show_execution_history()
        elif escolha == "13":
            console.print("[yellow]Pipeline completo será implementado na Fase 3...[/yellow]")
            input("Pressione ENTER...")
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

    # Se nenhum argumento for passado, abre o menu interativo
    if len(sys.argv) == 1:
        interactive_menu()
    else:
        args = parser.parse_args()
        if args.command == "run":
            run_bash_module(args.module)

if __name__ == "__main__":
    import time
    main()