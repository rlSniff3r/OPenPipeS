#!/usr/bin/env python3
import os
import subprocess
import sys
import shutil
import threading
import time
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

console = Console()

# --- Configurações de Paths ---
HOME = str(Path.home())
OPENPIPES_DIR = f"{HOME}/.openpipes"
OPENPIPES_BIN = f"{OPENPIPES_DIR}/bin"
OPENPIPES_SCRIPTS = f"{OPENPIPES_DIR}/scripts"
VENV_JSFINDER = f"{HOME}/.venv-jsfinder"

# --- Versões Estritas (NÃO ALTERAR) ---
GO_VERSION = "1.21.5"
AMASS_VERSION = "3.20.0"
DNSRECON_VERSION = "1.1.3"

def check_sudo():
    """Valida as credenciais sudo antes de iniciar as tarefas invisíveis"""
    console.print("[yellow][!] Algumas dependências (como APT e Golang) exigem privilégios de administrador.[/yellow]")
    console.print("[yellow][!] Por favor, insira sua senha se solicitado:[/yellow]")
    result = subprocess.run(["sudo", "-v"])
    if result.returncode != 0:
        console.print("[bold red]✖ Falha na autenticação. Privilégios sudo são obrigatórios.[/bold red]")
        sys.exit(1)
    console.print("[green]✔ Autenticação sudo validada![/green]\n")

def keep_sudo_alive(stop_event):
    """
    Thread em background que renova o token do sudo a cada 60 segundos.
    Isso impede que compilações demoradas causem timeout de permissão.
    """
    while not stop_event.is_set():
        # Pinga o sudo silenciosamente
        subprocess.run(["sudo", "-v"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Aguarda 60 segundos ou até o evento de parada ser acionado
        stop_event.wait(60)

def run_cmd(cmd, shell=True, sudo=False, check=True):
    """Executa comandos shell de forma segura"""
    if sudo:
        cmd = f"sudo {cmd}"
    result = subprocess.run(cmd, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and result.returncode != 0:
        console.print(f"[red]Erro executando: {cmd}[/red]\n{result.stderr}")
        sys.exit(1)
    return result.stdout

def setup_directories():
    dirs = [OPENPIPES_DIR, OPENPIPES_BIN, OPENPIPES_SCRIPTS, 
            f"{OPENPIPES_DIR}/.templates", f"{OPENPIPES_DIR}/tools", 
            f"{HOME}/.openpipes_cache", f"{HOME}/.obsidianFixedMount"]
    for d in dirs:
        os.makedirs(d, exist_ok=True)

def install_apt_deps():
    deps = "nmap curl wget git jq python3 python3-pip python3-venv golang-go build-essential whois dnsutils libpcap-dev libssl-dev pkg-config unzip"
    run_cmd("apt-get update -qq", sudo=True)
    run_cmd(f"apt-get install -y -qq {deps}", sudo=True)

def install_golang():
    if shutil.which("go"):
        version_out = run_cmd("go version", check=False)
        if GO_VERSION in version_out:
            return
    
    run_cmd(f"wget -q https://go.dev/dl/go{GO_VERSION}.linux-amd64.tar.gz -O /tmp/go.tar.gz")
    run_cmd("rm -rf /usr/local/go", sudo=True)
    run_cmd(f"tar -C /usr/local -xzf /tmp/go.tar.gz", sudo=True)
    run_cmd("rm /tmp/go.tar.gz")

def install_go_and_rust_tools():
    # Go Tools
    go_path = "/usr/local/go/bin/go" if os.path.exists("/usr/local/go/bin/go") else "go"
    go_env = os.environ.copy()
    go_env["GOPATH"] = f"{HOME}/go"
    go_env["PATH"] = f"{go_path}:{go_env['GOPATH']}/bin:{go_env.get('PATH', '')}"

    tools = [
        "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "github.com/projectdiscovery/katana/cmd/katana@latest",
        "github.com/tomnomnom/gf@latest",
        "github.com/openrdap/rdap/cmd/rdap@latest",
        "github.com/sensepost/gowitness@latest"
    ]
    for tool in tools:
        subprocess.run([go_path, "install", tool], env=go_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Rust & Feroxbuster
    if not shutil.which("cargo"):
        run_cmd("curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y -q", check=False)
    
    cargo_path = f"{HOME}/.cargo/bin/cargo"
    if not shutil.which("feroxbuster"):
        run_cmd(f"{cargo_path} install feroxbuster", check=False)

def install_strict_versions():
    # Amass v3.20.0
    if not os.path.exists(f"{OPENPIPES_BIN}/amass-{AMASS_VERSION}"):
        run_cmd(f"wget -q https://github.com/owasp-amass/amass/releases/download/v{AMASS_VERSION}/amass_linux_amd64.zip -O /tmp/amass.zip")
        run_cmd(f"unzip -q /tmp/amass.zip -d {OPENPIPES_BIN}")
        run_cmd(f"mv {OPENPIPES_BIN}/amass_linux_amd64 {OPENPIPES_BIN}/amass-{AMASS_VERSION}")
        run_cmd("rm /tmp/amass.zip")
    run_cmd(f"ln -sf {OPENPIPES_BIN}/amass-{AMASS_VERSION}/amass {OPENPIPES_BIN}/amass")
    # Aqui o Sudo agora não travará mais, mesmo horas depois!
    run_cmd(f"ln -sf {OPENPIPES_BIN}/amass /usr/local/bin/amass", sudo=True)

    # Dnsrecon v1.1.3
    if not os.path.exists(f"{OPENPIPES_BIN}/dnsrecon-{DNSRECON_VERSION}"):
        run_cmd(f"wget -q https://github.com/darkoperator/dnsrecon/archive/refs/tags/{DNSRECON_VERSION}.tar.gz -O /tmp/dnsrecon.tar.gz")
        run_cmd(f"tar -xzf /tmp/dnsrecon.tar.gz -C {OPENPIPES_BIN}")
        run_cmd("rm /tmp/dnsrecon.tar.gz")
    run_cmd(f"ln -sf {OPENPIPES_BIN}/dnsrecon-{DNSRECON_VERSION}/dnsrecon.py {OPENPIPES_BIN}/dnsrecon")

def setup_isolated_venvs():
    # LinkFinder / JS-Finder VENV
    if not os.path.exists(VENV_JSFINDER):
        run_cmd(f"python3 -m venv {VENV_JSFINDER}")
    
    linkfinder_dir = f"{VENV_JSFINDER}/LinkFinder"
    if not os.path.exists(linkfinder_dir):
        run_cmd(f"git clone https://github.com/GerbenJavado/LinkFinder.git {linkfinder_dir}")
        run_cmd(f"{VENV_JSFINDER}/bin/pip install -r {linkfinder_dir}/requirements.txt -q")
        run_cmd(f"cd {linkfinder_dir} && {VENV_JSFINDER}/bin/python setup.py install", check=False)

    # Criação do Wrapper do LinkFinder
    wrapper_code = f"""#!/bin/bash
source "{VENV_JSFINDER}/bin/activate"
python -m linkfinder "$@"
deactivate
"""
    with open(f"{OPENPIPES_BIN}/linkfinder.py", "w") as f:
        f.write(wrapper_code)
    run_cmd(f"chmod +x {OPENPIPES_BIN}/linkfinder.py")

    # Main Project VENV
    main_venv = f"{OPENPIPES_DIR}/.venv"
    if not os.path.exists(main_venv):
        run_cmd(f"python3 -m venv {main_venv}")
        req_file = f"{os.getcwd()}/.openpipes/scripts/requirements.txt"
        if os.path.exists(req_file):
            run_cmd(f"{main_venv}/bin/pip install -r {req_file} -q")

def main():
    console.print("[bold blue]🚀 OPenPipeS Python Installer (Core Engine)[/bold blue]\n")
    
    # 1. Valida credenciais SUDO
    check_sudo()
    
    # 2. Inicia o Keep-Alive do Sudo em uma thread de fundo
    sudo_stop_event = threading.Event()
    sudo_thread = threading.Thread(target=keep_sudo_alive, args=(sudo_stop_event,))
    sudo_thread.daemon = True
    sudo_thread.start()
    
    tasks = [
        ("Criando estrutura de diretórios...", setup_directories),
        ("Instalando dependências APT (requer sudo)...", install_apt_deps),
        ("Instalando Golang 1.21.5...", install_golang),
        ("Compilando ferramentas Go e Rust...", install_go_and_rust_tools),
        ("Instalando versões estritas (Amass 3.20.0, Dnsrecon 1.1.3)...", install_strict_versions),
        ("Configurando VENVs isolados (JS-Finder/LinkFinder)...", setup_isolated_venvs)
    ]

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            
            main_task = progress.add_task("[cyan]Progresso Geral...", total=len(tasks))
            
            for desc, func in tasks:
                step_task = progress.add_task(f"[yellow]{desc}", total=None)
                try:
                    func()
                    progress.update(step_task, completed=100, description=f"[green]✔ {desc}")
                except Exception as e:
                    progress.update(step_task, description=f"[red]✖ Falha: {desc}")
                    console.print(f"\n[red]Erro crítico abortando instalação: {str(e)}[/red]")
                    sys.exit(1)
                progress.advance(main_task)

        console.print("\n[bold green]✅ OPenPipeS Core Modules instalados com sucesso![/bold green]")
        console.print("[cyan]A estrutura Bash original não foi alterada. Você já pode rodar o orquestrador atual.[/cyan]")
        
    finally:
        # Garante que a thread do sudo morra elegantemente se algo falhar ou terminar
        sudo_stop_event.set()
        sudo_thread.join(timeout=2)

if __name__ == "__main__":
    main()