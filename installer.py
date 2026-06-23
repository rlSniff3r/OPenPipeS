#!/usr/bin/env python3
import os
import subprocess
import sys
import shutil
import threading
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
    """Renova o token do sudo a cada 60 segundos em background."""
    while not stop_event.is_set():
        subprocess.run(["sudo", "-v"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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

def setup_framework_files():
    """Copia os scripts do repositório para o diretório de instalação do usuário"""
    cwd = os.getcwd()
    
    # 1. Copia e dá permissão aos scripts
    if os.path.exists(f"{cwd}/.openpipes/scripts"):
        run_cmd(f"cp -r {cwd}/.openpipes/scripts/* {OPENPIPES_SCRIPTS}/", check=False)
        run_cmd(f"chmod +x {OPENPIPES_SCRIPTS}/*.sh {OPENPIPES_SCRIPTS}/*.py", check=False)
    
    # 2. Copia templates e cache
    if os.path.exists(f"{cwd}/.openpipes/.templates"):
        run_cmd(f"cp -r {cwd}/.openpipes/.templates/* {OPENPIPES_DIR}/.templates/", check=False)
    if os.path.exists(f"{cwd}/.openpipes_cache"):
        run_cmd(f"cp -r {cwd}/.openpipes_cache/* {HOME}/.openpipes_cache/", check=False)
        
    # 3. [NOVO] Copia o Cérebro Python (Core)
    if os.path.exists(f"{cwd}/.openpipes/openpipes_core"):
        run_cmd(f"cp -r {cwd}/.openpipes/openpipes_core {OPENPIPES_DIR}/", check=False)
        
    # 4. Cria configurações padrão
    config_dest = f"{OPENPIPES_DIR}/config.sh"
    secrets_dest = f"{OPENPIPES_DIR}/secrets.conf"
    if not os.path.exists(config_dest) and os.path.exists(f"{cwd}/.openpipes/config.sh"):
        run_cmd(f"cp {cwd}/.openpipes/config.sh {config_dest}")
    if not os.path.exists(secrets_dest) and os.path.exists(f"{cwd}/.openpipes/secrets.conf.example"):
        run_cmd(f"cp {cwd}/.openpipes/secrets.conf.example {secrets_dest}")

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

    if not shutil.which("cargo"):
        run_cmd("curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y -q", check=False)
    cargo_path = f"{HOME}/.cargo/bin/cargo"
    if not shutil.which("feroxbuster"):
        run_cmd(f"{cargo_path} install feroxbuster", check=False)

def install_strict_versions():
    if not os.path.exists(f"{OPENPIPES_BIN}/amass-{AMASS_VERSION}"):
        run_cmd(f"wget -q https://github.com/owasp-amass/amass/releases/download/v{AMASS_VERSION}/amass_linux_amd64.zip -O /tmp/amass.zip")
        run_cmd(f"unzip -q /tmp/amass.zip -d {OPENPIPES_BIN}")
        run_cmd(f"mv {OPENPIPES_BIN}/amass_linux_amd64 {OPENPIPES_BIN}/amass-{AMASS_VERSION}")
        run_cmd("rm /tmp/amass.zip")
    run_cmd(f"ln -sf {OPENPIPES_BIN}/amass-{AMASS_VERSION}/amass {OPENPIPES_BIN}/amass")
    run_cmd(f"ln -sf {OPENPIPES_BIN}/amass /usr/local/bin/amass", sudo=True)

    if not os.path.exists(f"{OPENPIPES_BIN}/dnsrecon-{DNSRECON_VERSION}"):
        run_cmd(f"wget -q https://github.com/darkoperator/dnsrecon/archive/refs/tags/{DNSRECON_VERSION}.tar.gz -O /tmp/dnsrecon.tar.gz")
        run_cmd(f"tar -xzf /tmp/dnsrecon.tar.gz -C {OPENPIPES_BIN}")
        run_cmd("rm /tmp/dnsrecon.tar.gz")
    run_cmd(f"ln -sf {OPENPIPES_BIN}/dnsrecon-{DNSRECON_VERSION}/dnsrecon.py {OPENPIPES_BIN}/dnsrecon")

def setup_isolated_venvs():
    if not os.path.exists(VENV_JSFINDER):
        run_cmd(f"python3 -m venv {VENV_JSFINDER}")
    
    linkfinder_dir = f"{VENV_JSFINDER}/LinkFinder"
    if not os.path.exists(linkfinder_dir):
        run_cmd(f"git clone https://github.com/GerbenJavado/LinkFinder.git {linkfinder_dir}")
        run_cmd(f"{VENV_JSFINDER}/bin/pip install -r {linkfinder_dir}/requirements.txt -q")
        run_cmd(f"cd {linkfinder_dir} && {VENV_JSFINDER}/bin/python setup.py install", check=False)

    wrapper_code = f"""#!/bin/bash
source "{VENV_JSFINDER}/bin/activate"
python -m linkfinder "$@"
deactivate
"""
    with open(f"{OPENPIPES_BIN}/linkfinder.py", "w") as f:
        f.write(wrapper_code)
    run_cmd(f"chmod +x {OPENPIPES_BIN}/linkfinder.py")

    main_venv = f"{OPENPIPES_DIR}/.venv"
    if not os.path.exists(main_venv):
        run_cmd(f"python3 -m venv {main_venv}")
        req_file = f"{os.getcwd()}/.openpipes/scripts/requirements.txt"
        if os.path.exists(req_file):
            run_cmd(f"{main_venv}/bin/pip install -r {req_file} -q")

def configure_environment():
    """Cria os atalhos (symlinks) e insere as variáveis de ambiente no .bashrc / .zshrc"""
    # 1. Configurar o PATH no RC File correspondente
    shell = os.environ.get("SHELL", "")
    rc_file = f"{HOME}/.zshrc" if "zsh" in shell else f"{HOME}/.bashrc"
    
    config_block = f"""
# ========== OpenPipeS Configuration ==========
export OPENPIPES_DIR="$HOME/.openpipes"
export OPENPIPES_CONFIG="$OPENPIPES_DIR/config.sh"
export OPENPIPES_BIN="$OPENPIPES_DIR/bin"
export OPENPIPES_SCRIPTS="$OPENPIPES_DIR/scripts"
export OPENPIPES_TEMPLATES="$OPENPIPES_DIR/.templates"
export OPENPIPES_TOOLS="$OPENPIPES_DIR/tools"
export OPENPIPES_CACHE="$HOME/.openpipes_cache"
export PATH="$OPENPIPES_BIN:$PATH"
export CONFIG_FILE="$OPENPIPES_CONFIG"
export SECRETS_OPENPIPES="$OPENPIPES_DIR/secrets.conf"

# Go & Rust configuration
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin:$HOME/.cargo/bin"
# ============================================

# Loads Config.sh
if [ -f "$HOME/.openpipes/config.sh" ]; then
    source "$HOME/.openpipes/config.sh"
fi
"""
    try:
        with open(rc_file, "r") as f:
            content = f.read()
    except FileNotFoundError:
        content = ""

    if "OPENPIPES_DIR" not in content:
        with open(rc_file, "a") as f:
            f.write("\n" + config_block)

    # 2. Criar os Symlinks dos comandos principais
    symlinks = {
        "init-openpipes.sh": "init-openpipes",
        "openpipes_orchestrator.sh": "openpipes",
        "recon.sh": "recon",
        "nwrapper.sh": "nwrapper",
        "cria_Alvos_Obsidian.sh": "cria-alvos",
        "httpx-runner.sh": "httpx-runner",
        "katana-buster.sh": "katana-buster",
        "jsfinder-runner.sh": "jsfinder-runner",
        "nuclei-runner.sh": "nuclei-runner",
        "gf-summary.sh": "gf-summary",
        "whois-enricher.sh": "whois-enricher",
        "cria_Vulnerabilidades.sh": "cria-vulnerabilidades",
        "vuln-enricher.sh": "vuln-enricher",
        "osint-runner-people.sh": "osint-people",
        "screenshot-runner.sh": "screenshot-runner",
        "identities_manager.sh": "id-manager",
        "katana-runner.sh": "katana-runner",
        "context-wordlist-builder.sh": "context-builder",
        "feroxbuster-runner.sh": "feroxbuster-runner",
        "osint_people_collector.py": "osint-collector",
        "osint_doc_finder.py": "osint-doc-finder",
        "osint_people_parser.py": "osint-parser",
        "osint_people_enricher_v1.0.py": "osint-enricher"
    }
    
    # ... (código existente dos symlinks) ...
    for src, link in symlinks.items():
        src_path = f"{OPENPIPES_SCRIPTS}/{src}"
        link_path = f"{OPENPIPES_BIN}/{link}"
        if os.path.exists(src_path):
            run_cmd(f"ln -sf {src_path} {link_path}")

    # [NOVO] 3. Criar wrapper executável para o Cérebro Python (CLI)
    core_wrapper = f"""#!/bin/bash
source "{HOME}/.openpipes/.venv-core/bin/activate"
python "{OPENPIPES_DIR}/openpipes_core/cli.py" "$@"
deactivate
"""
    with open(f"{OPENPIPES_BIN}/openpipes-core", "w") as f:
        f.write(core_wrapper)
    run_cmd(f"chmod +x {OPENPIPES_BIN}/openpipes-core")

def main():
    console.print("[bold blue]🚀 OPenPipeS Python Installer (Core Engine)[/bold blue]\n")
    
    check_sudo()
    
    sudo_stop_event = threading.Event()
    sudo_thread = threading.Thread(target=keep_sudo_alive, args=(sudo_stop_event,))
    sudo_thread.daemon = True
    sudo_thread.start()
    
    tasks = [
        ("Criando estrutura de diretórios...", setup_directories),
        ("Copiando scripts, templates e cache...", setup_framework_files),
        ("Instalando dependências APT...", install_apt_deps),
        ("Instalando Golang 1.21.5...", install_golang),
        ("Compilando ferramentas Go e Rust...", install_go_and_rust_tools),
        ("Instalando versões estritas (Amass, Dnsrecon)...", install_strict_versions),
        ("Configurando VENVs isolados...", setup_isolated_venvs),
        ("Configurando variáveis de ambiente e symlinks (openpipes)...", configure_environment)
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

        console.print("\n[bold green]✅ Instalação concluída com sucesso![/bold green]")
        console.print("[yellow]Para usar o framework imediatamente no terminal atual, execute:[/yellow]")
        console.print(f"[cyan]source {HOME}/.bashrc[/cyan]  (ou ~/.zshrc)")
        
    finally:
        sudo_stop_event.set()
        sudo_thread.join(timeout=2)

if __name__ == "__main__":
    main()