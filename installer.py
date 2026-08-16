#!/usr/bin/env python3
import os
import subprocess
import sys
import shutil
import threading
import argparse
import os
import sys
import argparse
import shutil

from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

# ── Ensure core modules (backup, db, ...) are importable ──
# When running from a fresh git clone (repo root):
_REPO_CORE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          ".openpipes", "openpipes_core")
if os.path.isdir(_REPO_CORE):
    sys.path.insert(0, _REPO_CORE)
# When running from the installed location:
else:
    _INSTALLED_CORE = os.path.join(str(Path.home()), ".openpipes", "openpipes_core")
    if os.path.isdir(_INSTALLED_CORE):
        sys.path.insert(0, _INSTALLED_CORE)

import backup


console = Console()

HOME = str(Path.home())
OPENPIPES_DIR = f"{HOME}/.openpipes"
OPENPIPES_BIN = f"{OPENPIPES_DIR}/bin"
OPENPIPES_SCRIPTS = f"{OPENPIPES_DIR}/scripts"
VENV_CORE = f"{OPENPIPES_DIR}/.venv"
VENV_JSFINDER = f"{HOME}/.venv-jsfinder"
ERROR_LOG = f"{OPENPIPES_DIR}/install_error.log"
GO_VERSION = "1.21.5"
AMASS_VERSION = "3.20.0"


def check_sudo():
    console.print("[yellow][!] Algumas dependências exigem privilégios de administrador.[/yellow]")
    result = subprocess.run(["sudo", "-v"])
    if result.returncode != 0:
        console.print("[bold red]✖ Falha na autenticação sudo. Abortando.[/bold red]")
        sys.exit(1)


def check_root():
    if os.getuid() == 0:
        console.print("[bold red]✖ Não execute o installer como root![/bold red]")
        sys.exit(1)


def check_os():
    if not os.path.exists("/etc/debian_version"):
        console.print("[bold yellow]⚠ Testado apenas em Kali/Debian/Ubuntu.[/bold yellow]")
        resp = input("Deseja continuar? [s/N]: ").strip().lower()
        if resp != "s":
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
        raise RuntimeError(f"Comando falhou: {cmd}\n{result.stderr}")
    return result.stdout


def setup_directories():
    dirs = [OPENPIPES_DIR, OPENPIPES_BIN, OPENPIPES_SCRIPTS,
            f"{OPENPIPES_DIR}/.templates", f"{OPENPIPES_DIR}/.gf", f"{OPENPIPES_DIR}/tools",
            f"{HOME}/.openpipes_cache", f"{HOME}/.obsidianFixedMount"]
    for d in dirs:
        os.makedirs(d, exist_ok=True)


def setup_framework_files():
    cwd = os.getcwd()
    if os.path.exists(f"{cwd}/.openpipes/scripts"):
        shutil.copytree(f"{cwd}/.openpipes/scripts", OPENPIPES_SCRIPTS, dirs_exist_ok=True)
        run_cmd(f"chmod +x {OPENPIPES_SCRIPTS}/*.sh {OPENPIPES_SCRIPTS}/*.py")
    if os.path.exists(f"{cwd}/.openpipes/.templates"):
        shutil.copytree(f"{cwd}/.openpipes/.templates", f"{OPENPIPES_DIR}/.templates", dirs_exist_ok=True)
    if os.path.exists(f"{cwd}/.openpipes/.gf"):
        shutil.copytree(f"{cwd}/.openpipes/.gf", f"{OPENPIPES_DIR}/.gf", dirs_exist_ok=True)
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

    tech_dir = f"{OPENPIPES_DIR}/wordlists/tech"
    os.makedirs(tech_dir, exist_ok=True)
    starters = {
        "wordpress.txt": ["wp-admin", "wp-content", "wp-includes", "wp-json", "wp-login", "xmlrpc.php"],
        "laravel.txt": ["artisan", ".env", "storage", "vendor", "public", "resources"],
        "django.txt": ["admin", "static", "media", "api", "graphql"],
        "nextjs.txt": ["_next/static", "_next/data", "api", "public"],
        "nginx.txt": ["nginx_status", "health", "status"],
        "apache.txt": ["server-status", "server-info", "icons"],
        "tomcat.txt": ["manager/html", "manager/status", "examples"],
        "iis.txt": ["App_Browsers", "App_Code", "App_Data", "bin"],
        "akamai.txt": ["akamai", "edgekey", "purl", "akamaized"],
        "cloudflare.txt": ["cdn-cgi", "__cfduid"],
    }
    for fname, words in starters.items():
        fpath = os.path.join(tech_dir, fname)
        if not os.path.exists(fpath):
            with open(fpath, "w") as f:
                f.write("\n".join(words) + "\n")
    generic_path = f"{OPENPIPES_DIR}/wordlists/generic.txt"
    if not os.path.exists(generic_path):
        with open(generic_path, "w") as f:
            f.write("admin\nlogin\nconfig\nbackup\napi\nv1\napi/v1\n")


def install_apt_deps():
    deps = ("nmap curl wget git jq fzf yq exiftool python3 python3-pip "
            "python3-venv python3-setuptools golang-go build-essential whois "
            "dnsutils libpcap-dev libssl-dev pkg-config unzip")
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
    result = subprocess.run([go_path, "install", package], env=go_env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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
    """Clone dnsrecon from git and install into the core venv (non-editable)."""
    repo_url = "https://github.com/darkoperator/dnsrecon.git"
    clone_dir = "/tmp/dnsrecon-install"
    if os.path.exists(clone_dir):
        shutil.rmtree(clone_dir)
    run_cmd(f"git clone --depth 1 {repo_url} {clone_dir}")
    # FIXED: removed -e flag — copies files into venv permanently
    run_cmd(f"{VENV_CORE}/bin/pip install {clone_dir} -q")
    shutil.rmtree(clone_dir, ignore_errors=True)


def install_dalfox():
    """Download latest dalfox binary release to OPENPIPES_BIN."""
    url = "https://github.com/hahwul/dalfox/releases/download/v3.1.2/dalfox-v3.1.2-linux-x86_64.tar.gz"
    tarball = "/tmp/dalfox.tar.gz"

    os.makedirs(OPENPIPES_BIN, exist_ok=True)
    run_cmd(f"wget -q {url} -O {tarball}")
    run_cmd(f"tar -xzf {tarball} -C /tmp/")
    run_cmd(f"mv /tmp/dalfox-*/dalfox {OPENPIPES_BIN}/dalfox")
    run_cmd(f"chmod +x {OPENPIPES_BIN}/dalfox")
    run_cmd(f"rm -rf /tmp/dalfox*")


def setup_isolated_venvs():
    import shutil  # ← MOVED TO TOP, before any usage

    # === JS Finder venv ===
    if not os.path.exists(VENV_JSFINDER):
        run_cmd(f"python3 -m venv {VENV_JSFINDER}")
    linkfinder_dir = f"{VENV_JSFINDER}/LinkFinder"
    if not os.path.exists(linkfinder_dir):
        run_cmd(f"git clone https://github.com/GerbenJavado/LinkFinder.git {linkfinder_dir}")
    run_cmd(f"{VENV_JSFINDER}/bin/pip install --upgrade pip setuptools wheel -q")
    run_cmd(f"{VENV_JSFINDER}/bin/pip install -r {linkfinder_dir}/requirements.txt -q")
    run_cmd(f"{VENV_JSFINDER}/bin/pip install {linkfinder_dir} -q")
    wrapper = f'#!/bin/bash\nsource "{VENV_JSFINDER}/bin/activate"\npython -m linkfinder "$@"\ndeactivate\n'
    with open(f"{OPENPIPES_BIN}/linkfinder.py", "w") as f:
        f.write(wrapper)
    run_cmd(f"chmod +x {OPENPIPES_BIN}/linkfinder.py")

    # === DNSRecon isolated venv ===
    VENV_DNSRECON = f"{OPENPIPES_DIR}/.venv-dnsrecon"
    if not os.path.exists(VENV_DNSRECON):
        run_cmd(f"python3 -m venv {VENV_DNSRECON}")
    run_cmd(f"{VENV_DNSRECON}/bin/pip install --upgrade pip setuptools wheel -q")
    clone_dir = "/tmp/dnsrecon-install"
    if os.path.exists(clone_dir):
        shutil.rmtree(clone_dir, ignore_errors=True)
    run_cmd(f"git clone https://github.com/darkoperator/dnsrecon.git {clone_dir}")
    run_cmd(f"{VENV_DNSRECON}/bin/pip install {clone_dir} -q")
    shutil.rmtree(clone_dir, ignore_errors=True)
    wrapper = f'#!/bin/bash\nsource "{VENV_DNSRECON}/bin/activate"\nexec dnsrecon "$@"\n'
    with open(f"{OPENPIPES_BIN}/dnsrecon", "w") as f:
        f.write(wrapper)
    run_cmd(f"chmod +x {OPENPIPES_BIN}/dnsrecon")
    run_cmd(f"{VENV_CORE}/bin/pip uninstall dnsrecon -y -q 2>/dev/null || true")

    # === Core venv ===
    if not os.path.exists(VENV_CORE):
        run_cmd(f"python3 -m venv {VENV_CORE}")
    run_cmd(f"{VENV_CORE}/bin/pip install --upgrade pip setuptools wheel -q")
    run_cmd(f"{VENV_CORE}/bin/pip install arjun -q")
    run_cmd(f"{VENV_CORE}/bin/pip install sqlmap -q")
    run_cmd(f"{VENV_CORE}/bin/pip install fastapi uvicorn -q")
    run_cmd(f"{VENV_CORE}/bin/pip install google-genai -q")
    run_cmd(f"{VENV_CORE}/bin/pip install requests jinja2 rich jq textual cvss flask -q")
    run_cmd(f"{VENV_CORE}/bin/pip uninstall dnsrecon httpx -y -q 2>/dev/null || true")

    # Physically remove any dnsrecon files from core venv
    dnsrecon_bin = os.path.join(VENV_CORE, "bin", "dnsrecon")
    if os.path.exists(dnsrecon_bin):
        os.remove(dnsrecon_bin)
    lib_dir = os.path.join(VENV_CORE, "lib")
    for root, dirs, files in os.walk(lib_dir):
        for d in dirs:
            if d == "dnsrecon" or d.startswith("dnsrecon-"):
                shutil.rmtree(os.path.join(root, d), ignore_errors=True)

    # Remove Python httpx library + binary from core venv
    httpx_bin = os.path.join(VENV_CORE, "bin", "httpx")
    if os.path.exists(httpx_bin):
        os.remove(httpx_bin)
    for root, dirs, files in os.walk(lib_dir):
        for d in dirs:
            if d == "httpx" or d.startswith("httpx-"):
                shutil.rmtree(os.path.join(root, d), ignore_errors=True)


def install_wordlists():
    seclists = "/usr/share/wordlists/seclists"
    if not os.path.exists(seclists):
        run_cmd(f"git clone --depth 1 https://github.com/danielmiessler/SecLists.git {seclists}", sudo=True)
    big_parsed = "/usr/share/wordlists/dirb/big-parsed.txt"
    if os.path.exists("/usr/share/wordlists/dirb/big.txt") and not os.path.exists(big_parsed):
        run_cmd("grep -v '%' /usr/share/wordlists/dirb/big.txt > /tmp/big-parsed.txt")
        run_cmd(f"mv /tmp/big-parsed.txt {big_parsed}", sudo=True)


def configure_environment():
    rc_files = [f"{HOME}/.bashrc", f"{HOME}/.zshrc"]
    config_block = f"""
# ========== OpenPipeS ==========
export OPENPIPES_DIR="{HOME}/.openpipes"
export OPENPIPES_BIN="$OPENPIPES_DIR/bin"
export OPENPIPES_SCRIPTS="$OPENPIPES_DIR/scripts"
export OPENPIPES_CONFIG="$OPENPIPES_DIR/config.sh"
export OPENPIPES_TEMPLATES="$OPENPIPES_DIR/.templates"
export OPENPIPES_TOOLS="$OPENPIPES_DIR/tools"
export OPENPIPES_CACHE="{HOME}/.openpipes_cache"
export CONFIG_FILE="$OPENPIPES_CONFIG"
export PATH="$OPENPIPES_BIN:$PATH"
export GOPATH="{HOME}/go"
export PATH="$PATH:$GOPATH/bin:{HOME}/.cargo/bin"
if [ -f "{HOME}/.openpipes/config.sh" ]; then source "{HOME}/.openpipes/config.sh"; fi
"""
    for rc in rc_files:
        try:
            with open(rc) as f:
                content = f.read()
        except FileNotFoundError:
            content = ""
        if "OPENPIPES_DIR" not in content:
            with open(rc, "a") as f:
                f.write("\n" + config_block)

    symlinks = {
        "recon.sh": "recon", "nwrapper.sh": "nwrapper",
        "httpx-runner.sh": "httpx-runner", "katana-runner.sh": "katana-runner",
        "feroxbuster-runner.sh": "feroxbuster-runner",
        "jsfinder-runner.sh": "jsfinder-runner", "nuclei-runner.sh": "nuclei-runner",
        "gf-summary.sh": "gf-summary", "whois-enricher.sh": "whois-enricher",
        "screenshot-runner.sh": "screenshot-runner",
        "init-openpipes.sh": "init-openpipes",
        "dalfox-runner.sh": "dalfox-runner",
        "arjun-runner.sh": "arjun-runner",
        "sqlmap-runner.sh": "sqlmap-runner",
    }
    for src, link in symlinks.items():
        src_path = f"{OPENPIPES_SCRIPTS}/{src}"
        if os.path.exists(src_path):
            run_cmd(f"ln -sf '{src_path}' '{OPENPIPES_BIN}/{link}'")

    # Core wrapper with PATH reordering
    wrapper = f"""#!/bin/bash
source "{VENV_CORE}/bin/activate"
# Ensure OPENPIPES_BIN and GOPATH/bin come BEFORE .venv/bin in PATH
export PATH="$OPENPIPES_BIN:$GOPATH/bin:$PATH"

python "{OPENPIPES_DIR}/openpipes_core/cli.py" "$@"
deactivate
"""
    with open(f"{OPENPIPES_BIN}/openpipes-core", "w") as f:
        f.write(wrapper)
    run_cmd(f"chmod +x {OPENPIPES_BIN}/openpipes-core")


def main():
    console.print("[bold blue]🚀 OPenPipeS Installer (Core Engine)[/bold blue]\n")
    check_root()
    check_os()
    check_sudo()
    stop = threading.Event()
    t = threading.Thread(target=keep_sudo_alive, args=(stop,), daemon=True)
    t.start()

    tasks = [
        ("Criando diretórios...", setup_directories),
        ("Copiando arquivos...", setup_framework_files),
        ("Dependências APT...", install_apt_deps),
        ("Golang...", install_golang),
        ("HTTPX...", lambda: install_go_tool("github.com/projectdiscovery/httpx/cmd/httpx@latest")),
        ("Nuclei...", lambda: install_go_tool("github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")),
        ("Katana...", lambda: install_go_tool("github.com/projectdiscovery/katana/cmd/katana@latest")),
        ("GF...", lambda: install_go_tool("github.com/tomnomnom/gf@latest")),
        ("RDAP...", lambda: install_go_tool("github.com/openrdap/rdap/cmd/rdap@latest")),
        ("Gowitness...", lambda: install_go_tool("github.com/sensepost/gowitness@latest")),
        ("Dalfox...", lambda: install_dalfox()),
        ("Rust + Feroxbuster...", install_rust_and_ferox),
        ("Amass...", install_amass),
        ("VENVs...", setup_isolated_venvs),
        ("Dnsrecon...", install_dnsrecon),
        ("Wordlists...", install_wordlists),
        ("Configurando ambiente...", configure_environment),
    ]

    try:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TaskProgressColumn(), console=console) as p:
            main_task = p.add_task("[cyan]Progresso", total=len(tasks))
            for desc, func in tasks:
                step = p.add_task(f"[yellow]{desc}", total=None)
                try:
                    func()
                    p.update(step, completed=100, description=f"[green]✔ {desc}")
                except Exception as e:
                    p.update(step, description=f"[red]✖ {desc}")
                    with open(ERROR_LOG, "w") as f:
                        f.write(str(e))
                    console.print(f"\n[red]Erro! Log: {ERROR_LOG}[/red]")
                    sys.exit(1)
                p.advance(main_task)
    finally:
        stop.set()
        t.join(timeout=2)

    console.print("\n[bold green]✅ Instalação concluída![/bold green]")
    console.print("[cyan]Execute 'source ~/.bashrc' e digite 'openpipes-core'[/cyan]")


def wipe_installation():
    """Only framework dirs. Never touches ~/Projetos."""
    console.print("[yellow]⚠ Apagando instalação antiga...[/yellow]")
    shutil.rmtree(OPENPIPES_DIR, ignore_errors=True)
    shutil.rmtree(VENV_JSFINDER, ignore_errors=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OPenPipeS Installer")
    parser.add_argument("--reinstall", action="store_true",
                        help="Backup framework, wipe, reinstall, restore")
    parser.add_argument("--clean-backup", action="store_true",
                        help="Delete the backup created by this reinstall")
    parser.add_argument("--restore", nargs="?", const="latest",
                        metavar="BACKUP", help="Restore latest (or specific) framework backup")
    parser.add_argument("--backup", action="store_true",
                        help="Just create a framework backup")
    args = parser.parse_args()

    if args.clean_backup and not args.reinstall:
        parser.error("--clean-backup requires --reinstall")
    if args.reinstall and args.restore:
        parser.error("--reinstall and --restore cannot be used together")

    # --backup: standalone framework backup
    if args.backup:
        backup.backup_framework()
        sys.exit(0)

    # --restore: failure recovery
    if args.restore:
        snap = (backup.latest_framework_backup()
                if args.restore == "latest"
                else os.path.join(backup.BACKUP_DIR, args.restore))
        backup.restore_framework(snap)
        sys.exit(0)

    # ── Reinstall: backup → wipe → normal install → restore ──
    if args.reinstall:
        snap_file = backup.backup_framework()
        wipe_installation()
        ret = subprocess.run(
            [sys.executable, os.path.abspath(__file__)],
            cwd=os.path.dirname(os.path.abspath(__file__)),
        )
        if ret.returncode != 0:
            console.print("[red]✖ Instalação falhou. Restaurando backup...[/red]")
            backup.restore_framework(snap_file)
            sys.exit(1)

        backup.restore_framework(snap_file)
        if args.clean_backup:
            os.remove(snap_file)
            console.print(f" [dim]🗑 Backup limpo: {os.path.basename(snap_file)}[/dim]")
        sys.exit(0)

    # ← ADD THIS (4-space indent, same level as the if blocks above)
    # Normal install — no flags, which is exactly what bootstrap.sh invokes
    main()
