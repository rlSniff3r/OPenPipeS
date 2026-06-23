# ~/.openpipes/openpipes_core/cli.py
import os
import sys
import subprocess
import argparse
from pathlib import Path
from rich.console import Console

# Importa o gerenciador de banco de dados
import db

console = Console()
HOME = str(Path.home())
CONFIG_FILE = os.path.join(HOME, ".openpipes", "config.sh")
BIN_DIR = os.path.join(HOME, ".openpipes", "bin")

def get_active_project():
    """Lê o projeto ativo diretamente do config.sh do bash"""
    if not os.path.exists(CONFIG_FILE):
        console.print("[bold red]Erro: config.sh não encontrado. Rode init-openpipes primeiro.[/bold red]")
        sys.exit(1)
        
    # Extrai a variável proj_name via bash para ser 100% fiel ao ambiente atual
    cmd = f"source {CONFIG_FILE} && echo $proj_name"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, executable="/bin/bash")
    proj_name = result.stdout.strip()
    
    if not proj_name:
        console.print("[bold red]Erro: proj_name não definido no config.sh.[/bold red]")
        sys.exit(1)
        
    return proj_name

def run_bash_module(module_name):
    """Executa o script bash original envolvido pela telemetria do Python"""
    project_name = get_active_project()
    script_path = os.path.join(BIN_DIR, module_name)
    
    if not os.path.exists(script_path):
        console.print(f"[bold red]Erro: Módulo Bash '{module_name}' não encontrado em {BIN_DIR}[/bold red]")
        sys.exit(1)

    # 1. Registra no SQLite que a tarefa COMEÇOU
    db.init_db()
    exec_id = db.log_module_start(project_name, module_name)
    console.print(f"\n[bold cyan][OPenPipeS-Core][/bold cyan] [yellow]Iniciando módulo:[/yellow] {module_name} (Projeto: {project_name})")
    
    # 2. Executa o músculo (Bash) de forma transparente
    # Não interceptamos o stdout/stderr para que você veja a saída normal na tela
    try:
        result = subprocess.run([script_path])
        exit_code = result.returncode
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Execução abortada pelo usuário.[/bold red]")
        exit_code = 130 # Padrão POSIX para SIGINT

    # 3. Registra no SQLite que a tarefa TERMINOU
    db.log_module_finish(exec_id, exit_code)
    
    if exit_code == 0:
        console.print(f"[bold green]✔ Módulo {module_name} concluído com sucesso![/bold green]\n")
    else:
        console.print(f"[bold red]✖ Módulo {module_name} falhou (Exit Code: {exit_code}).[/bold red]\n")

def main():
    parser = argparse.ArgumentParser(description="OPenPipeS Core Engine")
    subparsers = parser.add_subparsers(dest="command")

    # Comando 'run'
    run_parser = subparsers.add_parser("run", help="Executa um módulo bash e rastreia o estado")
    run_parser.add_argument("module", help="Nome do módulo (ex: recon, nwrapper, httpx-runner)")

    args = parser.parse_args()

    if args.command == "run":
        run_bash_module(args.module)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()