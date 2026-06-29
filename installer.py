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

HOME = str(Path.home())
OPENPIPES_DIR = f"{HOME}/.openpipes"
OPENPIPES_BIN = f"{OPENPIPES_DIR}/bin"
OPENPIPES_SCRIPTS = f"{OPENPIPES_DIR}/scripts"
VENV_CORE = f"{OPENPIPES_DIR}/.venv"            # Core engine venv (cli.py, parsers, renderer)
VENV_JSFINDER = f"{HOME}/.venv-jsfinder"         # FIXED: matches bash script expectation
ERROR_LOG = f"{OPENPIPES_DIR}/install_error.log"

GO_VERSION = "1.21.5"
AMASS_VERSION = "3.20.0"
DNSRECON_VERSION = "1.1.3"                      # FIXED: newer version with pkg_resources fix


def check_sudo():
    console.print("[yellow][!] Algumas dependências (como APT e Golang) exigem privilégios de administrador.[/yellow]")
    console.print("[yellow][!] Por favor, insira sua senha se solicitado:[/yellow]")
    result = subprocess.run(["sudo", "-v"])
    if result.returncode != 0:
        console.print("[bold red]✖ Falha na autenticação sudo. Abortando.[/bold red]")
        sys.exit(1)


def check_root():
    if os.getuid() == 0:
        console.print("[bold red]✖ Não execute o installer como root![/bold red]")
        console.print("[dim]Use seu usuário normal. sudo será solicitado quando necessário.[/dim]")
        sys.exit(1)


def check_os():
    if not os.path.exists("/etc/debian_version"):
        console.print("[bold yellow]⚠ Este installer foi testado apenas em Kali/Debian/Ubuntu.[/bold yellow]")
        resp = input("Deseja continuar mesmo assim? [s/N]: ").strip().lower()
        if resp != "s":
            console.print("[dim]Instalação cancelada.[/dim]")
            sys.exit(0)


def keep_sudo_alive(stop_event):
    while not stop_event.is_set():
        subprocess.run(["sudo", "-v"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stop_event.wait(60)


def run_cmd(cmd, shell=True, sudo=False, check=True):
    if sudo:
        cmd = f"sudo {cmd}"
    result = subprocess.run(cmd, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        if not check:
            return result.stdout
        error_msg = f"Comando falhou: {cmd}\nSaída de Erro:\n{result.stderr}\n"
        raise RuntimeError(error_msg)
    return result.stdout


def setup_directories():
    dirs = [
        OPENPIPES_DIR, OPENPIPES_BIN, OPENPIPES_SCRIPTS,
        f"{OPENPIPES_DIR}/.templates", f"{OPENPIPES_DIR}/tools",
        f"{HOME}/.openpipes_cache", f"{HOME}/.obsidianFixedMount",
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)


def setup_framework_files():
    cwd = os.getcwd()
    if os.path.exists(f"{cwd}/.openpipes/scripts"):
        shutil.copytree(f"{cwd}/.openpipes/scripts", OPENPIPES_SCRIPTS, dirs_exist_ok=True)
        run_cmd(f"chmod +x {OPENPIPES_SCRIPTS}/*.sh {OPENPIPES_SCRIPTS}/*.py")
    if os.path.exists(f"{cwd}/.openpipes/.templates"):
        shutil.copytree(f"{cwd}/.openpipes/.templates", f"{OPENPIPES_DIR}/.templates", dirs_exist_ok=True)
    if os.path.exists(f"{cwd}/.openpipes_cache"):
        shutil.copytree(f"{cwd}/.openpipes_cache", f"{HOME}/.openpipes_cache", dirs_exist_ok=True)
    if os.path.exists(f"{cwd}/.openpipes/openpipes_core"):
        shutil.copytree(f"{cwd}/.openpipes/openpipes_core", f"{OPENPIPES_DIR}/openpipes_core", dirs_exist_ok=True)
    config_src = f"{cwd}/.openpipes/config.sh"
    if not os.path.exists(f"{OPENPIPES_DIR}/config.sh") and os.path.exists(config_src):
        shutil.copy2(config_src, f"{OPENPIPES_DIR}/config.sh")
    secrets_src = f"{cwd}/.openpipes/secrets.conf.example"
    if not os.path.exists(f"{OPENPIPES_DIR}/secrets.conf") and os.path.exists(secrets_src):
        shutil.copy2(secrets_src, f"{OPENPIPES_DIR}/secrets.conf")


def install_apt_deps():
    deps = "nmap curl wget git jq fzf yq exiftool python3 python3-pip python3-venv python3-setuptools golang-go build-essential whois dnsutils libpcap-dev libssl-dev pkg-config unzip"
    run_cmd("apt-get update -qq", sudo=True)
    run_cmd(f"apt-get install -y -qq {deps}", sudo=True)


def install_golang():
    if shutil.which("go") and GO_VERSION in run_cmd("go version", check=False):
        return
    run_cmd(f"wget -q https://go.dev/dl/go{GO_VERSION}.linux-amd64.tar.gz -O /tmp/go.tar.gz")
    run_cmd("rm -rf /usr/local/go", sudo=True)
    run_cmd(f"tar -C /usr/local -xzf /tmp/go.tar.gz", sudo=True)
    run_cmd("rm /tmp/go.tar.gz")


def get_go_env():
    go_path = "/usr/local/go/bin/go" if os.path.exists("/usr/local/go/bin/go") else "go"
    go_env = os.environ.copy()
    go_env["GOPATH"] = f"{HOME}/go"
    go_env["PATH"] = f"{go_path}:{go_env['GOPATH']}/bin:{go_env.get('PATH', '')}"
    return go_path, go_env


def install_go_tool(package):
    go_path, go_env = get_go_env()
    result = subprocess.run([go_path, "install", package], env=go_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Falha ao compilar {package}:\n{result.stderr}")


def install_rust_and_ferox():
    if not shutil.which("cargo"):
        run_cmd("curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y -q")
    if not shutil.which("feroxbuster"):
        run_cmd(f"{HOME}/.cargo/bin/cargo install feroxbuster")


def install_amass():
    if not os.path.exists(f"{OPENPIPES_BIN}/amass-{AMASS_VERSION}"):
        run_cmd(f"wget -q https://github.com/owasp-amass/amass/releases/download/v{AMASS_VERSION}/amass_linux_amd64.zip -O /tmp/amass.zip")
        run_cmd(f"unzip -q /tmp/amass.zip -d {OPENPIPES_BIN}")
        run_cmd(f"mv {OPENPIPES_BIN}/amass_linux_amd64 {OPENPIPES_BIN}/amass-{AMASS_VERSION}")
        run_cmd("rm /tmp/amass.zip")
        run_cmd(f"ln -sf {OPENPIPES_BIN}/amass-{AMASS_VERSION}/amass {OPENPIPES_BIN}/amass")
        run_cmd(f"ln -sf {OPENPIPES_BIN}/amass /usr/local/bin/amass", sudo=True)


def install_dnsrecon():
    if not os.path.exists(f"{OPENPIPES_BIN}/dnsrecon-{DNSRECON_VERSION}"):
        run_cmd(f"wget -q https://github.com/darkoperator/dnsrecon/archive/refs/tags/{DNSRECON_VERSION}.tar.gz -O /tmp/dnsrecon.tar.gz")
        run_cmd(f"tar -xzf /tmp/dnsrecon.tar.gz -C {OPENPIPES_BIN}")
        run_cmd("rm /tmp/dnsrecon.tar.gz")
        run_cmd(f"ln -sf {OPENPIPES_BIN}/dnsrecon-{DNSRECON_VERSION}/dnsrecon.py {OPENPIPES_BIN}/dnsrecon")


def setup_isolated_venvs():
    # ── JS Finder venv (LinkFinder) ─────────────────────────────────
    if not os.path.exists(VENV_JSFINDER):
        run_cmd(f"python3 -m venv {VENV_JSFINDER}")
    linkfinder_dir = f"{VENV_JSFINDER}/LinkFinder"
    if not os.path.exists(linkfinder_dir):
        run_cmd(f"git clone https://github.com/GerbenJavado/LinkFinder.git {linkfinder_dir}")
    run_cmd(f"{VENV_JSFINDER}/bin/pip install --upgrade pip setuptools wheel -q")
    run_cmd(f"{VENV_JSFINDER}/bin/pip install -r {linkfinder_dir}/requirements.txt -q")
    run_cmd(f"{VENV_JSFINDER}/bin/pip install {linkfinder_dir} -q")
    wrapper_code = f'#!/bin/bash\nsource "{VENV_JSFINDER}/bin/activate"\npython -m linkfinder "$@"\ndeactivate\n'
    with open(f"{OPENPIPES_BIN}/linkfinder.py", "w") as f:
        f.write(wrapper_code)
    run_cmd(f"chmod +x {OPENPIPES_BIN}/linkfinder.py")

    # ── Core Engine venv (cli.py, parsers, renderer, Jinja2) ────────
    if not os.path.exists(VENV_CORE):
        run_cmd(f"python3 -m venv {VENV_CORE}")
    # Always upgrade pip + setuptools (needed by dnsrecon and others)
    run_cmd(f"{VENV_CORE}/bin/pip install --upgrade pip setuptools wheel -q")
    # Install requirements.txt (includes jinja2, rich, etc.)
    req_file = f"{os.getcwd()}/.openpipes/scripts/requirements.txt"
    if os.path.exists(req_file):
        run_cmd(f"{VENV_CORE}/bin/pip install -r {req_file} -q")
    # Ensures Jinja2 specifically is present
    run_cmd(f"{VENV_CORE}/bin/pip install jinja2 -q")


def install_wordlists():
    seclists_path = "/usr/share/wordlists/seclists"
    if not os.path.exists(seclists_path):
        run_cmd(f"git clone --depth 1 https://github.com/danielmiessler/SecLists.git {seclists_path}", sudo=True)
    big_txt = "/usr/share/wordlists/dirb/big.txt"
    big_parsed = "/usr/share/wordlists/dirb/big-parsed.txt"
    if os.path.exists(big_txt) and not os.path.exists(big_parsed):
        run_cmd(f"grep -v '%' {big_txt} > /tmp/big-parsed.txt")
        run_cmd(f"mv /tmp/big-parsed.txt {big_parsed}", sudo=True)


def configure_environment():
    rc_files = [f"{HOME}/.bashrc", f"{HOME}/.zshrc"]
    config_block = f"""
# ========== OpenPipeS Configuration ==========
export OPENPIPES_DIR="{HOME}/.openpipes"
export OPENPIPES_CONFIG="$OPENPIPES_DIR/config.sh"
export OPENPIPES_BIN="$OPENPIPES_DIR/bin"
export OPENPIPES_SCRIPTS="$OPENPIPES_DIR/scripts"
export OPENPIPES_TEMPLATES="$OPENPIPES_DIR/.templates"
export OPENPIPES_TOOLS="$OPENPIPES_DIR/tools"
export OPENPIPES_CACHE="{HOME}/.openpipes_cache"
export PATH="$OPENPIPES_BIN:$PATH"
export CONFIG_FILE="$OPENPIPES_CONFIG"
export SECRETS_OPENPIPES="$OPENPIPES_DIR/secrets.conf"
export GOPATH="{HOME}/go"
export PATH="$PATH:$GOPATH/bin:{HOME}/.cargo/bin"
if [ -f "{HOME}/.openpipes/config.sh" ]; then source "{HOME}/.openpipes/config.sh"; fi
"""
    for rc_file in rc_files:
        try:
            with open(rc_file, "r") as f:
                content = f.read()
        except FileNotFoundError:
            content = ""
        if "OPENPIPES_DIR" not in content:
            with open(rc_file, "a") as f:
                f.write("\n" + config_block)

    symlinks = {
        "recon.sh": "recon", "nwrapper.sh": "nwrapper",
        "httpx-runner.sh": "httpx-runner", "katana-runner.sh": "katana-runner",
        "katana-buster.sh": "katana-buster", "feroxbuster-runner.sh": "feroxbuster-runner",
        "jsfinder-runner.sh": "jsfinder-runner", "nuclei-runner.sh": "nuclei-runner",
        "gf-summary.sh": "gf-summary", "whois-enricher.sh": "whois-enricher",
        "screenshot-runner.sh": "screenshot-runner", "vuln-enricher.sh": "vuln-enricher",
        "init-openpipes.sh": "init-openpipes",
    }
    for src, link in symlinks.items():
        src_path = f"{OPENPIPES_SCRIPTS}/{src}"
        if os.path.exists(src_path):
            run_cmd(f"ln -sf '{src_path}' '{OPENPIPES_BIN}/{link}'")

    # FIXED: wrapper now points to VENV_CORE (.venv, not .venv-core)
    core_wrapper = f'#!/bin/bash\nsource "{VENV_CORE}/bin/activate"\npython "{OPENPIPES_DIR}/openpipes_core/cli.py" "$@"\ndeactivate\n'
    with open(f"{OPENPIPES_BIN}/openpipes-core", "w") as f:
        f.write(core_wrapper)
    run_cmd(f"chmod +x {OPENPIPES_BIN}/openpipes-core")


def main():
    console.print("[bold blue]🚀 OPenPipeS Python Installer (Core Engine)[/bold blue]\n")
    check_root()
    check_os()
    check_sudo()

    sudo_stop_event = threading.Event()
    sudo_thread = threading.Thread(target=keep_sudo_alive, args=(sudo_stop_event,), daemon=True)
    sudo_thread.start()

    tasks = [
        ("Criando estrutura de diretórios...", setup_directories),
        ("Copiando scripts, templates e cache...", setup_framework_files),
        ("Instalando dependências APT...", install_apt_deps),
        ("Instalando Golang 1.21.5...", install_golang),
        ("Compilando HTTPX (Go)...", lambda: install_go_tool("github.com/projectdiscovery/httpx/cmd/httpx@latest")),
        ("Compilando Nuclei (Go)...", lambda: install_go_tool("github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")),
        ("Compilando Katana (Go)...", lambda: install_go_tool("github.com/projectdiscovery/katana/cmd/katana@latest")),
        ("Compilando GF (Go)...", lambda: install_go_tool("github.com/tomnomnom/gf@latest")),
        ("Compilando RDAP (Go)...", lambda: install_go_tool("github.com/openrdap/rdap/cmd/rdap@latest")),
        ("Compilando Gowitness (Go)...", lambda: install_go_tool("github.com/sensepost/gowitness@latest")),
        ("Instalando Rust e Feroxbuster...", install_rust_and_ferox),
        ("Instalando Amass 3.20.0...", install_amass),
        ("Instalando Dnsrecon 1.1.3...", install_dnsrecon),                # UPDATED version
        ("Configurando VENVs isolados...", setup_isolated_venvs),
        ("Instalando Wordlists (SecLists + big-parsed)...", install_wordlists),
        ("Configurando variáveis de ambiente...", configure_environment),
    ]

    try:
        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TaskProgressColumn(), console=console,
        ) as progress:
            main_task = progress.add_task("[cyan]Progresso Total", total=len(tasks))
            for desc, func in tasks:
                step_task = progress.add_task(f"[yellow]{desc}", total=None)
                try:
                    func()
                    progress.update(step_task, completed=100, description=f"[green]✔ {desc}")
                except Exception as e:
                    progress.update(step_task, description=f"[red]✖ Falha: {desc}[/red]")
                    console.print(f"\n[bold red]Erro Crítico![/bold red] Verifique o log em: [yellow]{ERROR_LOG}[/yellow]")
                    with open(ERROR_LOG, "w") as f:
                        f.write(str(e))
                    sys.exit(1)
                progress.advance(main_task)

        console.print("\n[bold green]✅ Instalação concluída com sucesso![/bold green]")
        console.print("[cyan]Execute 'source ~/.bashrc' e digite 'openpipes-core' para iniciar![/cyan]")
    finally:
        sudo_stop_event.set()
        sudo_thread.join(timeout=2)


if __name__ == "__main__":
    main()
