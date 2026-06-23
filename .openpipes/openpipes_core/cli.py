# ~/.openpipes/openpipes_core/cli.py
import os
import sys
import subprocess
import argparse
import time
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

def get_project_env():
    """Extrai as variáveis de ambiente essenciais do bash config"""
    if not os.path.exists(CONFIG_FILE):
        return "DESCONHECIDO", "", ""
        
    # Pega as 3 variáveis vitais
    cmd = f"source {CONFIG_FILE} && echo -n \"$proj_name|$proj_path|$NMAP_DIR\""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, executable="/bin/bash")
    
    parts = result.stdout.split('|')
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    return "DESCONHECIDO", "", ""

def show_execution_history():
    """Consulta o SQLite e renderiza a tabela"""
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
    """Executa o script bash garantindo o diretório correto e TTY para o fzf"""
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
        
    # --- PREPARAÇÃO DO AMBIENTE E DIRETÓRIO (CWD) ---
    run_cwd = proj_path
    cmd_args = ""
    
    # Validações específicas herdadas do orchestrator bash
    if module_name == "recon":
        if not os.path.exists(os.path.join(proj_path, "domains.txt")):
            console.print(f"\n[bold red]✖ Erro: domains.txt não encontrado em {proj_path}[/bold red]")
            input("Pressione ENTER para continuar...")
            return
    elif module_name == "nwrapper":
        run_cwd = nmap_dir
        os.makedirs(run_cwd, exist_ok=True)
        cmd_args = "-f targets.txt"  # O nwrapper exige este argumento!

    db.init_db()
    exec_id = db.log_module_start(proj_name, module_name)
    
    console.print(f"\n[bold cyan]▶ Iniciando módulo:[/bold cyan] {module_name}")
    console.print(f"[dim]CWD (Diretório Alvo): {run_cwd}[/dim]")
    console.print("=" * 50)
    
    try:
        # MAGIA AQUI: Rodamos o "source config.sh" DENTRO do subprocesso para que 
        # as variáveis globais sejam repassadas para os scripts, ativando o fzf corretamente!
        cmd_exec = f"source {CONFIG_FILE} && {script_path} {cmd_args}"
        
        result = subprocess.run(
            cmd_exec, 
            shell=True, 
            cwd=run_cwd, 
            executable="/bin/bash"
        )
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

from rich.markdown import Markdown

def show_help():
    """Renderiza a documentação robusta de ajuda no terminal"""
    console.clear()
    help_text = """
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


def interactive_menu():
    """Dashboard Python renderizado no Terminal"""
    while True:
        console.clear()
        proj_name, _, _ = get_project_env()
        
        banner = """[bold blue]
   ___  ____            ____  _             ____  
  / _ \|  _ \ ___ _ __ |  _ \(_)_ __   ___ / ___| 
 | | | | |_) / _ | '_ \| |_) | | '_ \ / _ \\___ \ 
 | |_| |  __/  __| | | |  __/| | |_) |  __/ ___) |
  \___/|_|   \___|_| |_|_|   |_| .__/ \___||____/ 
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
            console.print("[yellow]Pipeline completo será implementado na Fase 3...[/yellow]")
            input("Pressione ENTER...")
        elif escolha in opcoes:
            run_bash_module(opcoes[escolha])
        else:
            console.print("[bold red]Opção inválida![/bold red]")
            import time
            time.sleep(1)

def main():
    parser = argparse.ArgumentParser(description="OPenPipeS Core Engine")
    subparsers = parser.add_subparsers(dest="command")

    run_parser = subparsers.add_parser("run", help="Executa um módulo bash e rastreia o estado")
    run_parser.add_argument("module", help="Nome do módulo")

    if len(sys.argv) == 1:
        interactive_menu()
    else:
        args = parser.parse_args()
        if args.command == "run":
            run_bash_module(args.module)

if __name__ == "__main__":
    main()