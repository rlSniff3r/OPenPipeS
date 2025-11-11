#!/bin/bash

# ═══════════════════════════════════════════════════════════════════════════
# OPenPipeS - Instalador Automático
# Autor: Rafael Luís da Silva
# ═══════════════════════════════════════════════════════════════════════════

set -euo pipefail

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Diretórios
OPENPIPES_HOME="${HOME}/.openpipes"
OPENPIPES_BIN="${OPENPIPES_HOME}/bin"
OPENPIPES_SCRIPTS="${OPENPIPES_HOME}/scripts"
OPENPIPES_TEMPLATES="${OPENPIPES_HOME}/.templates"
OPENPIPES_CACHE="${OPENPIPES_HOME}_cache"
OPENPIPES_CONFIG="${OPENPIPES_HOME}/config.sh"

log() {
    local level=$1
    shift
    case $level in
        INFO)  echo -e "${GREEN}[+]${NC} $*" ;;
        WARN)  echo -e "${YELLOW}[!]${NC} $*" ;;
        ERROR) echo -e "${RED}[-]${NC} $*" ;;
        STEP)  echo -e "${CYAN}[*]${NC} $*" ;;
    esac
}

banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
   ___  ____            ____  _            ____  
  / _ \|  _ \ ___ _ __ |  _ \(_)_ __   ___/ ___| 
 | | | | |_) / _ \ '_ \| |_) | | '_ \ / _ \___ \ 
 | |_| |  __/  __/ | | |  __/| | |_) |  __/___) |
  \___/|_|   \___|_| |_|_|   |_| .__/ \___|____/ 
                                |_|               
EOF
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}           INSTALADOR AUTOMÁTICO v2.0${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

check_root() {
    if [[ $EUID -eq 0 ]]; then
        log ERROR "Não execute como root!"
        exit 1
    fi
}

check_os() {
    if [[ ! -f /etc/debian_version ]]; then
        log WARN "Este instalador foi testado apenas no Kali/Debian/Ubuntu"
        echo -ne "${YELLOW}Deseja continuar? [s/N]:${NC} "
        read -r resp
        [[ ! "$resp" =~ ^[sS]$ ]] && exit 1
    fi
}

create_directories() {
    log STEP "Criando estrutura de diretórios..."
    
    mkdir -p "$OPENPIPES_HOME"
    mkdir -p "$OPENPIPES_BIN"
    mkdir -p "$OPENPIPES_SCRIPTS"
    mkdir -p "$OPENPIPES_TEMPLATES"
    mkdir -p "$OPENPIPES_CACHE"
    
    log INFO "Diretórios criados em: $OPENPIPES_HOME"
}

install_apt_packages() {
    log STEP "Instalando pacotes via APT..."
    
    local packages=(
        nmap
        curl
        wget
        git
        jq
        python3
        python3-pip
        python3-venv
        golang-go
        build-essential
        whois
        dnsutils
    )
    
    log INFO "Atualizando repositórios..."
    sudo apt update
    
    log INFO "Instalando pacotes base..."
    sudo apt install -y "${packages[@]}"
    
    log INFO "Pacotes APT instalados!"
}

install_go_tools() {
    log STEP "Instalando ferramentas Go..."
    
    # Configurar GOPATH se necessário
    if [[ -z "${GOPATH:-}" ]]; then
        export GOPATH="$HOME/go"
        export PATH="$PATH:$GOPATH/bin"
        echo 'export GOPATH="$HOME/go"' >> ~/.bashrc
        echo 'export PATH="$PATH:$GOPATH/bin"' >> ~/.bashrc
    fi
    
    # httpx
    if ! command -v httpx &>/dev/null; then
        log INFO "Instalando httpx..."
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    fi
    
    # nuclei
    if ! command -v nuclei &>/dev/null; then
        log INFO "Instalando nuclei..."
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        nuclei -update-templates
    fi
    
    # katana
    if ! command -v katana &>/dev/null; then
        log INFO "Instalando katana..."
        go install github.com/projectdiscovery/katana/cmd/katana@latest
    fi
    
    # gf (GrepFuzzable)
    if ! command -v gf &>/dev/null; then
        log INFO "Instalando gf..."
        go install github.com/tomnomnom/gf@latest
        
        # Instalar padrões
        mkdir -p ~/.gf
        git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf-patterns 2>/dev/null || true
        cp -r ~/.gf-patterns/*.json ~/.gf/ 2>/dev/null || true
    fi
    
    log INFO "Ferramentas Go instaladas!"
}

install_rust_tools() {
    log STEP "Instalando ferramentas Rust..."
    
    # Instalar Rust se necessário
    if ! command -v cargo &>/dev/null; then
        log INFO "Instalando Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    fi
    
    # feroxbuster
    if ! command -v feroxbuster &>/dev/null; then
        log INFO "Instalando feroxbuster..."
        cargo install feroxbuster
    fi
    
    log INFO "Ferramentas Rust instaladas!"
}

install_python_tools() {
    log STEP "Instalando ferramentas Python..."
    
    # Criar venv para LinkFinder
    if [[ ! -d "$HOME/.venv-jsfinder" ]]; then
        log INFO "Criando ambiente virtual para LinkFinder..."
        python3 -m venv "$HOME/.venv-jsfinder"
    fi
    
    # Instalar LinkFinder
    source "$HOME/.venv-jsfinder/bin/activate"
    pip install --upgrade pip
    pip install linkfinder
    deactivate
    
    # Criar wrapper para linkfinder.py
    cat > "$OPENPIPES_BIN/linkfinder.py" << 'WRAPPER'
#!/bin/bash
source "$HOME/.venv-jsfinder/bin/activate"
python -m linkfinder "$@"
deactivate
WRAPPER
    chmod +x "$OPENPIPES_BIN/linkfinder.py"
    
    # Instalar outras ferramentas Python
    pip3 install --user papaparse cvss-calculator
    
    log INFO "Ferramentas Python instaladas!"
}

install_additional_tools() {
    log STEP "Instalando ferramentas adicionais..."
    
    # amass
    if ! command -v amass &>/dev/null; then
        log INFO "Instalando amass..."
        go install -v github.com/owasp-amass/amass/v4/...@master
    fi
    
    # dnsrecon (geralmente já vem no Kali)
    if ! command -v dnsrecon &>/dev/null; then
        log INFO "Instalando dnsrecon..."
        pip3 install --user dnsrecon
    fi
    
    # rdap
    if ! command -v rdap &>/dev/null; then
        log INFO "Instalando rdap..."
        go install github.com/openrdap/rdap/cmd/rdap@latest
    fi
    
    log INFO "Ferramentas adicionais instaladas!"
}

install_wordlists() {
    log STEP "Instalando wordlists..."
    
    # SecLists
    if [[ ! -d /usr/share/wordlists/seclists ]]; then
        log INFO "Clonando SecLists..."
        sudo git clone https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/seclists
    fi
    
    # Parse dirb/big.txt
    if [[ -f /usr/share/wordlists/dirb/big.txt ]]; then
        log INFO "Preparando wordlist customizada..."
        cat /usr/share/wordlists/dirb/big.txt | sort -u > /tmp/big-parsed.txt
        sudo mv /tmp/big-parsed.txt /usr/share/wordlists/dirb/big-parsed.txt
    fi
    
    log INFO "Wordlists instaladas!"
}

copy_scripts() {
    log STEP "Copiando scripts para $OPENPIPES_SCRIPTS..."
    
    # Verificar se estamos no diretório do projeto
    if [[ ! -f "./scripts/recon.sh" ]]; then
        log ERROR "Scripts não encontrados no diretório atual!"
        log INFO "Execute este instalador a partir do diretório raiz do OPenPipeS"
        exit 1
    fi
    
    # Copiar todos os scripts
    cp -r ./scripts/* "$OPENPIPES_SCRIPTS/"
    
    # Criar symlinks no bin
    for script in "$OPENPIPES_SCRIPTS"/*.sh; do
        script_name=$(basename "$script")
        ln -sf "$script" "$OPENPIPES_BIN/${script_name}"
        chmod +x "$OPENPIPES_BIN/${script_name}"
    done
    
    log INFO "Scripts copiados e linkados!"
}

copy_templates() {
    log STEP "Copiando templates..."
    
    if [[ -d "./.openpipes/.templates" ]]; then
        cp -r ./.openpipes/.templates/* "$OPENPIPES_TEMPLATES/"
        log INFO "Templates copiados!"
    else
        log WARN "Templates não encontrados em ./.openpipes/.templates"
    fi
}

copy_cache() {
    log STEP "Copiando cache de vulnerabilidades..."
    
    if [[ -d "./.openpipes_cache" ]]; then
        cp -r ./.openpipes_cache/* "$OPENPIPES_CACHE/"
        log INFO "Cache de vulnerabilidades copiado! (${OPENPIPES_CACHE})"
    else
        log WARN "Cache não encontrado em ./.openpipes_cache"
    fi
}

create_config() {
    log STEP "Criando arquivo de configuração..."
    
    cat > "$OPENPIPES_CONFIG" << 'EOF'
#!/bin/bash

# Diretório base dos projetos
proj_dir=""

# Nome do projeto atual
proj_name=""

# Caminho completo (será construído automaticamente)
proj_path="$proj_dir/$proj_name"

# Diretório do Obsidian (vault)
obsdir="$HOME/.obsidianFixedMount/"

# Diretório de templates
tpdir="$OPENPIPES_TEMPLATES"

# Diretório base de varreduras
base_dir="$proj_path/Varreduras/"

# API Keys
securitytrailskey=""
OPENAI_API_KEY=""
EOF
    
    log INFO "Arquivo de configuração criado: $OPENPIPES_CONFIG"
    log WARN "IMPORTANTE: Edite este arquivo antes de usar o OPenPipeS!"
}

setup_path() {
    log STEP "Configurando PATH..."
    
    # Adicionar ao .bashrc se ainda não estiver lá
    if ! grep -q "OPENPIPES_BIN" ~/.bashrc; then
        echo "" >> ~/.bashrc
        echo "# OPenPipeS" >> ~/.bashrc
        echo "export OPENPIPES_HOME=\"$OPENPIPES_HOME\"" >> ~/.bashrc
        echo "export PATH=\"\$PATH:\$OPENPIPES_HOME/bin\"" >> ~/.bashrc
        log INFO "PATH configurado no ~/.bashrc"
    fi
    
    # Criar comando principal
    cat > "$OPENPIPES_BIN/openpipes" << 'OPENPIPES_CMD'
#!/bin/bash
bash "$HOME/.openpipes/bin/openpipes-orchestrator.sh" "$@"
OPENPIPES_CMD
    chmod +x "$OPENPIPES_BIN/openpipes"
    
    # Copiar orquestrador
    cat > "$OPENPIPES_BIN/openpipes-orchestrator.sh" << 'ORCH_PLACEHOLDER'
# Este arquivo será substituído pelo orquestrador real
echo "Orquestrador não instalado corretamente!"
ORCH_PLACEHOLDER
    
    log INFO "Comando 'openpipes' criado!"
}

create_obsidian_mount() {
    log STEP "Configurando ponto de montagem do Obsidian..."
    
    mkdir -p "$HOME/.obsidianFixedMount"
    
    echo -ne "${CYAN}Deseja criar uma estrutura inicial no Obsidian? [S/n]:${NC} "
    read -r resp
    
    if [[ ! "$resp" =~ ^[nN]$ ]]; then
        mkdir -p "$HOME/.obsidianFixedMount/Pentest/Alvos"
        cp "$OPENPIPES_TEMPLATES/Dashboard_Global.md" "$HOME/.obsidianFixedMount/Pentest/" 2>/dev/null || true
        cp "$OPENPIPES_TEMPLATES/Tarefas.md" "$HOME/.obsidianFixedMount/Pentest/" 2>/dev/null || true
        log INFO "Estrutura inicial criada!"
    fi
}

final_setup() {
    log STEP "Finalizando instalação..."
    
    # Recarregar PATH temporariamente
    export PATH="$PATH:$OPENPIPES_BIN"
    
    log INFO "Instalação concluída!"
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Próximos passos:${NC}"
    echo ""
    echo -e "1. ${YELLOW}Recarregue seu shell:${NC}"
    echo -e "   ${BLUE}source ~/.bashrc${NC}"
    echo ""
    echo -e "2. ${YELLOW}Configure o arquivo:${NC}"
    echo -e "   ${BLUE}nano $OPENPIPES_CONFIG${NC}"
    echo ""
    echo -e "3. ${YELLOW}Execute o orquestrador:${NC}"
    echo -e "   ${BLUE}openpipes${NC}"
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
}

# Main
main() {
    banner
    check_root
    check_os
    
    log INFO "Bem-vindo ao instalador do OPenPipeS!"
    echo ""
    echo -ne "${YELLOW}Deseja prosseguir com a instalação? [S/n]:${NC} "
    read -r resp
    [[ "$resp" =~ ^[nN]$ ]] && exit 0
    
    echo ""
    
    create_directories
    install_apt_packages
    install_go_tools
    install_rust_tools
    install_python_tools
    install_additional_tools
    install_wordlists
    copy_scripts
    copy_templates
    copy_cache
    create_config
    setup_path
    create_obsidian_mount
    final_setup
    
    echo ""
    log INFO "Instalação completa! 🎉"
}

main "$@"