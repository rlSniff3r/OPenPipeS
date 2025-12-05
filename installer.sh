#!/bin/bash

# Grava diretório de instalação
INSTALL_DIR="$(pwd)"

# Cores para output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Variáveis globais
OPENPIPES_DIR="$HOME/.openpipes"
OPENPIPES_CONFIG="$OPENPIPES_DIR/config.sh"
OPENPIPES_BIN="$OPENPIPES_DIR/bin"
OPENPIPES_SCRIPTS="$OPENPIPES_DIR/scripts"
OPENPIPES_TEMPLATES="$OPENPIPES_DIR/.templates"
OPENPIPES_TOOLS="$OPENPIPES_DIR/tools"
OPENPIPES_CACHE="$HOME/.openpipes_cache"
OBSIDIAN_DIR="$HOME/.obsidianFixedMount"
VENV_PATH="$OPENPIPES_DIR/.venv"

# Função de log
log() {
    local level=$1
    shift
    local message="$@"
    
    case $level in
        INFO)
            echo -e "${BLUE}[*] $message${NC}"
            ;;
        SUCCESS)
            echo -e "${GREEN}[✓] $message${NC}"
            ;;
        WARNING)
            echo -e "${YELLOW}[!] $message${NC}"
            ;;
        ERROR)
            echo -e "${RED}[✗] $message${NC}"
            ;;
    esac
}

# Banner
print_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
   ___  ____                 ____  _                ____  
  / _ \|  _ \ ___ _ __  _ __|  _ \(_)_ __   ___  / ___| 
 | | | | |_) / _ | '_ \| '__| |_) | | '_ \ / _ \ \___ \ 
 | |_| |  __/  __| | | | |  |  __/| | |_) |  __/  ___) |
  \___/|_|   \___|_| |_|_|  |_|   |_| .__/ \___| |____/ 
                                     |_|                  
                    Framework de Reconhecimento v2.0
EOF
    echo -e "${NC}"
    echo -e "${CYAN}By: Rafael Luís da Silva${NC}"
    echo -e "${CYAN}GitHub: github.com/rlSniff3r/openPipes${NC}\n"
}

# Verificar se está rodando como root
check_root() {
    if [ "$EUID" -eq 0 ]; then
        log ERROR "Não execute este script como root!"
        log WARNING "O script pedirá sudo quando necessário."
        exit 1
    fi
}

# Detectar sistema operacional
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
        log INFO "Sistema detectado: $PRETTY_NAME"
        
        case $OS in
            kali|debian|ubuntu)
                return 0
                ;;
            *)
                log WARNING "Sistema não testado: $OS"
                log WARNING "Continuando instalação (pode haver problemas)"
                return 0
                ;;
        esac
    else
        log ERROR "Não foi possível detectar o sistema operacional"
        return 1
    fi
}

# Atualizar sistema
update_system() {
    log INFO "Atualizando sistema..."
    sudo apt update -qq
    log SUCCESS "Sistema atualizado"
}

# Instalar dependências APT
install_apt_deps() {
    log INFO "Instalando dependências APT..."
    
    local DEPS=(
        nmap curl wget git jq python3 python3-pip python3-venv
        golang-go build-essential whois dnsutils libpcap-dev
        libssl-dev pkg-config unzip
    )
    
    for dep in "${DEPS[@]}"; do
        if dpkg -l | grep -qw "^ii  $dep"; then
            log SUCCESS "$dep já instalado"
        else
            log INFO "Instalando $dep..."
            sudo apt install -y $dep -qq
            
            if [ $? -eq 0 ]; then
                log SUCCESS "$dep instalado"
            else
                log ERROR "Falha ao instalar $dep"
                return 1
            fi
        fi
    done
    
    log SUCCESS "Dependências APT instaladas"
}

# Verificar instalação do Go
check_go_installation() {
    if command -v go &>/dev/null; then
        local GO_VERSION=$(go version | awk '{print $3}')
        log SUCCESS "Go já instalado: $GO_VERSION"
        
        # Verificar GOPATH
        if [ -z "$GOPATH" ]; then
            export GOPATH="$HOME/go"
            export PATH="$PATH:$GOPATH/bin"
        fi
        
        return 0
    fi
    return 1
}

# Instalar Go (se necessário)
install_golang() {
    if check_go_installation; then
        return 0
    fi
    
    log INFO "Instalando Go..."
    
    local GO_VERSION="1.21.5"
    local GO_TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"
    local GO_URL="https://go.dev/dl/${GO_TARBALL}"
    
    cd /tmp
    wget -q "$GO_URL"
    
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "$GO_TARBALL"
    rm "$GO_TARBALL"
    
    export PATH="$PATH:/usr/local/go/bin"
    export GOPATH="$HOME/go"
    export PATH="$PATH:$GOPATH/bin"
    
    log SUCCESS "Go instalado: $(go version)"
}

# Instalar ferramenta Go com retry
install_go_tool() {
    local pkg=$1
    local name=$(basename "$pkg" | cut -d'@' -f1)
    local retries=3
    
    log INFO "Instalando $name..."
    
    # Verificar se já está instalado
    if command -v "$name" &>/dev/null; then
        log SUCCESS "$name já instalado"
        return 0
    fi
    
    for i in $(seq 1 $retries); do
        if go install -v "$pkg" 2>/dev/null; then
            log SUCCESS "$name instalado com sucesso"
            return 0
        else
            log WARNING "Tentativa $i/$retries falhou para $name"
            [ $i -lt $retries ] && sleep 2
        fi
    done
    
    log ERROR "Falha ao instalar $name após $retries tentativas"
    return 1
}

# Instalar Go tools
install_go_tools() {
    log INFO "Instalando ferramentas Go..."
    
    check_go_installation || install_golang
    
    local GO_TOOLS=(
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/projectdiscovery/katana/cmd/katana@latest"
        "github.com/tomnomnom/gf@latest"
        "github.com/openrdap/rdap/cmd/rdap@latest"
    )
    
    local FAILED=0
    
    for tool in "${GO_TOOLS[@]}"; do
        install_go_tool "$tool" || ((FAILED++))
    done
    
    if [ $FAILED -eq 0 ]; then
        log SUCCESS "Todas as ferramentas Go instaladas"
    else
        log WARNING "$FAILED ferramenta(s) falharam na instalação"
    fi
    
    # Atualizar templates do Nuclei
    if command -v nuclei &>/dev/null; then
        log INFO "Atualizando templates do Nuclei..."
        nuclei -update-templates -silent
        log SUCCESS "Templates do Nuclei atualizados"
    fi
}

# Verificar instalação do Rust
check_rust_installation() {
    if command -v cargo &>/dev/null; then
        local RUST_VERSION=$(cargo --version | awk '{print $2}')
        log SUCCESS "Rust já instalado: $RUST_VERSION"
        return 0
    fi
    return 1
}

# Instalar Rust
install_rust() {
    if check_rust_installation; then
        return 0
    fi
    
    log INFO "Instalando Rust..."
    
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y -q
    
    source "$HOME/.cargo/env"
    
    log SUCCESS "Rust instalado: $(cargo --version)"
}

# Instalar Rust tools
install_rust_tools() {
    log INFO "Instalando ferramentas Rust..."
    
    check_rust_installation || install_rust
    
    source "$HOME/.cargo/env"
    
    if command -v feroxbuster &>/dev/null; then
        log SUCCESS "feroxbuster já instalado"
    else
        log INFO "Instalando feroxbuster..."
        cargo install feroxbuster
        log SUCCESS "feroxbuster instalado"
    fi
}

# Instalar Python tools (BLOCOS HOMOLOGADOS)
install_python_tools() {
    log INFO "Instalando ferramentas Python..."
    
    # ========================================================================
    # VENV Isolado para LinkFinder (conflitos de versão)
    # ========================================================================
    if [[ ! -d "$HOME/.venv-jsfinder" ]]; then
        log INFO "Criando VENV isolado para LinkFinder..."
        python3 -m venv "$HOME/.venv-jsfinder"
    fi
    
    log INFO "Instalando LinkFinder em VENV isolado..."
    source "$HOME/.venv-jsfinder/bin/activate"
    
    if [[ ! -d "$HOME/.venv-jsfinder/LinkFinder" ]]; then
        git clone https://github.com/GerbenJavado/LinkFinder.git "$HOME/.venv-jsfinder/LinkFinder"
    fi
    
    cd "$HOME/.venv-jsfinder/LinkFinder"
    pip install -r requirements.txt
    pip install .
    
    deactivate
    
    # Criar wrapper que ativa o VENV correto
    cat > "$OPENPIPES_BIN/linkfinder.py" << 'LINKFINDER_WRAPPER'
#!/bin/bash
source "$HOME/.venv-jsfinder/bin/activate"
python -m linkfinder "$@"
deactivate
LINKFINDER_WRAPPER
    chmod +x "$OPENPIPES_BIN/linkfinder.py"
    
    # ========================================================================
    # Download e instalação do dnsrecon versão 1.1.3
    # ========================================================================
    log INFO "Instalando dnsrecon-1.1.3..."
    
    if [[ ! -d "$OPENPIPES_BIN/dnsrecon-1.1.3" ]]; then
        cd "$OPENPIPES_BIN"
        wget -q https://github.com/darkoperator/dnsrecon/archive/refs/tags/1.1.3.tar.gz
        tar -xzf 1.1.3.tar.gz
        rm -f 1.1.3.tar.gz
    fi
    
    # Criar wrapper que usa VENV global
#    cat > "$OPENPIPES_BIN/dnsrecon" << 'DNSRECON_WRAPPER'
##!/bin/bash
#source "$HOME/.openpipes/.venv/bin/activate"
#python "$HOME/.openpipes/bin/dnsrecon-1.1.3/dnsrecon.py" "$@"
#deactivate
#DNSRECON_WRAPPER
#    chmod +x "$OPENPIPES_BIN/dnsrecon"
    
    # Criar symlink para sistema
    sudo ln -sf "$OPENPIPES_BIN/dnsrecon-1.1.3/dnsrecon.py" /usr/local/bin/dnsrecon
    
    log SUCCESS "Ferramentas Python instaladas!"
}

# Instalar amass 3.20.0 (BLOCO HOMOLOGADO)
install_amass_custom() {
    # ========================================================================
    # Download e instalação do amass versão 3.20.0
    # ========================================================================
    log INFO "Instalando amass 3.20.0..."
    
    if ! command -v amass &>/dev/null; then
        amass_atual="$OPENPIPES_BIN/amass"
    else
        amass_atual=$(which amass)
        if [[ ! -L "$amass_atual" ]]; then
            sudo mv "$amass_atual" "${amass_atual}.bkp"
        fi
    fi
    
    if [[ ! -d "$OPENPIPES_BIN/amass-3.20.0" ]]; then
        cd "$OPENPIPES_BIN"
        wget -q https://github.com/owasp-amass/amass/releases/download/v3.20.0/amass_linux_amd64.zip
        unzip -q amass_linux_amd64.zip
        mv amass_linux_amd64 amass-3.20.0
        rm -f amass_linux_amd64.zip
    fi
    
    # Criar symlink
    if [[ ! -L "$OPENPIPES_BIN/amass" ]]; then
        ln -sf "$OPENPIPES_BIN/amass-3.20.0/amass" "$OPENPIPES_BIN/amass"
    fi
    
    # Symlink para sistema
    sudo ln -sf "$OPENPIPES_BIN/amass" /usr/local/bin/amass
    
    log SUCCESS "amass 3.20.0 instalado"
}

# Instalar SecLists
install_seclists() {
    log INFO "Instalando SecLists (wordlists)..."
    
    local SECLISTS_DIR="/usr/share/wordlists/seclists"
    
    if [ -d "$SECLISTS_DIR" ]; then
        log SUCCESS "SecLists já instalado em: $SECLISTS_DIR"
        return 0
    fi
    
    sudo mkdir -p /usr/share/wordlists
    
    log INFO "Clonando SecLists (pode demorar alguns minutos)..."
    sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$SECLISTS_DIR" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        log SUCCESS "SecLists instalado em: $SECLISTS_DIR"
        
        # Processar big.txt (remover comentários e linhas vazias)
        local BIG_TXT="$SECLISTS_DIR/Discovery/Web-Content/dirb/big.txt"
        if [ -f "$BIG_TXT" ]; then
            log INFO "Processando big.txt..."
            sudo sed -i '/^#/d; /^$/d' "$BIG_TXT"
            log SUCCESS "big.txt processado ($(wc -l < "$BIG_TXT") linhas)"
        fi
        
        return 0
    else
        log ERROR "Falha ao clonar SecLists"
        log WARNING "Instale manualmente: sudo git clone https://github.com/danielmiessler/SecLists.git $SECLISTS_DIR"
        return 1
    fi
}

# Criar estrutura de diretórios
create_directories() {
    log INFO "Criando estrutura de diretórios..."
    
    local DIRS=(
        "$OPENPIPES_DIR"
        "$OPENPIPES_BIN"
        "$OPENPIPES_SCRIPTS"
        "$OPENPIPES_TEMPLATES"
        "$OPENPIPES_TOOLS"
        "$OPENPIPES_CACHE"
        "$OBSIDIAN_DIR"
    )
    
    for dir in "${DIRS[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            log SUCCESS "Criado: $dir"
        else
            log WARNING "Já existe: $dir"
        fi
    done
}

# Detectar shell
detect_shell() {
    if [ -n "$BASH_VERSION" ]; then
        echo "bash"
    elif [ -n "$ZSH_VERSION" ]; then
        echo "zsh"
    else
        basename "$SHELL"
    fi
}

# Configurar PATH
configure_path() {
    log INFO "Configurando PATH..."
    
    local SHELL_TYPE=$(detect_shell)
    local RC_FILE=""
    
    case $SHELL_TYPE in
        bash)
            RC_FILE="$HOME/.bashrc"
            ;;
        zsh)
            RC_FILE="$HOME/.zshrc"
            ;;
        *)
            log WARNING "Shell não suportado: $SHELL_TYPE"
            log WARNING "Adicione manualmente ao seu RC file:"
            echo -e "${CYAN}export PATH=\"\$HOME/.openpipes/bin:\$PATH\"${NC}"
            return 1
            ;;
    esac
    
    # Verificar se já está configurado
    if grep -q "OPENPIPES_DIR" "$RC_FILE" 2>/dev/null; then
        log WARNING "PATH já configurado em $RC_FILE"
        return 0
    fi
    
    # Adicionar configuração
    cat >> "$RC_FILE" << 'PATH_EOF'

# ========== OpenPipeS Configuration ==========
export OPENPIPES_DIR="$HOME/.openpipes"
export OPENPIPES_CONFIG="$OPENPIPES_DIR/config.sh"
export OPENPIPES_BIN="$OPENPIPES_DIR/bin"
export OPENPIPES_SCRIPTS="$OPENPIPES_DIR/scripts"
export OPENPIPES_TEMPLATES="$OPENPIPES_DIR/.templates"
export OPENPIPES_TOOLS="$OPENPIPES_DIR/tools"
export OPENPIPES_CACHE="$HOME/.openpipes_cache"
export PATH="$OPENPIPES_BIN:$PATH"

# Go configuration
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin"

# Rust configuration
export PATH="$HOME/.cargo/bin:$PATH"
# ============================================

# Loads Config.sh
source ~/.openpipes/config.sh
PATH_EOF
    
    log SUCCESS "PATH configurado em: $RC_FILE"
    echo -e "${CYAN}[i] Execute: source $RC_FILE${NC}"
    
    # Carregar configuração na sessão atual
    source "$RC_FILE"
}

#source ~/.bashrc

log INFO "Copying scripts from repo $INSTALL_DIR/.openpipes/scripts to $OPENPIPES_SCRIPTS"

# Copia scripts
mkdir -p $OPENPIPES_SCRIPTS
cp -r $INSTALL_DIR/.openpipes/scripts/* $OPENPIPES_SCRIPTS/
chmod +x $OPENPIPES_SCRIPTS/*.sh
chmod +x $OPENPIPES_SCRIPTS/*.py

log SUCCESS "Scripts copied to $OPENPIPES_SCRIPTS"

# Criar symlinks
create_symlinks() {
    log INFO "Criando symlinks..."
    
    # Scripts shell
    local SHELL_SCRIPTS=(
        "openpipes_orchestrator.sh:openpipes"
        "recon.sh:recon"
        "nwrapper.sh:nwrapper"
        "cria_Alvos_Obsidian.sh:cria-alvos"
        "httpx-runner.sh:httpx-runner"
        "katana-buster.sh:katana-buster"
        "jsfinder-runner.sh:jsfinder-runner"
        "nuclei-runner.sh:nuclei-runner"
        "gf-summary.sh:gf-summary"
        "whois-enricher.sh:whois-enricher"
        "cria_Vulnerabilidades.sh:cria-vulns"
        "vuln-enricher.sh:vuln-enricher"
        "osint-runner-people.sh:osint-people"
    )
    
    for script_pair in "${SHELL_SCRIPTS[@]}"; do
        local source_name="${script_pair%%:*}"
        local link_name="${script_pair##*:}"
        local source_path="$OPENPIPES_SCRIPTS/$source_name"
        local link_path="$OPENPIPES_BIN/$link_name"
        
        if [ -f "$source_path" ]; then
            ln -sf "$source_path" "$link_path"
            chmod +x "$source_path"
            log SUCCESS "Symlink: $link_name -> $source_name"
        else
            log WARNING "Script não encontrado: $source_name"
        fi
    done
    
    # Scripts Python
    local PYTHON_SCRIPTS=(
        "osint_people_collector.py:osint-collector"
        "osint_doc_finder.py:osint-doc-finder"
        "osint_people_parser.py:osint-parser"
        "osint_people_enricher_v1.0.py:osint-enricher"
    )
    
    for script_pair in "${PYTHON_SCRIPTS[@]}"; do
        local source_name="${script_pair%%:*}"
        local link_name="${script_pair##*:}"
        local source_path="$OPENPIPES_SCRIPTS/$source_name"
        local link_path="$OPENPIPES_BIN/$link_name"
        
        if [ -f "$source_path" ]; then
            ln -sf "$source_path" "$link_path"
            chmod +x "$source_path"
            log SUCCESS "Symlink: $link_name -> $source_name"
        else
            log WARNING "Script Python não encontrado: $source_name"
        fi
    done
}

# Criar Python VENV
create_python_venv() {
    log INFO "Criando Python virtual environment..."
    
    if [ -d "$VENV_PATH" ]; then
        log WARNING "VENV já existe em: $VENV_PATH"
        return 0
    fi
    
    python3 -m venv "$VENV_PATH"
    
    if [ $? -eq 0 ]; then
        log SUCCESS "VENV criado em: $VENV_PATH"
    else
        log ERROR "Falha ao criar VENV"
        return 1
    fi
}

# Instalar requirements Python
install_python_requirements() {
    log INFO "Instalando dependências Python (VENV)..."
    
    local REQUIREMENTS_FILE="$OPENPIPES_DIR/requirements.txt"
    
    if [ ! -f "$REQUIREMENTS_FILE" ]; then
        log WARNING "requirements.txt não encontrado"
        log WARNING "Criando requirements.txt básico..."
        
        cat > "$REQUIREMENTS_FILE" << 'REQUIREMENTS_EOF'
# Web scraping
requests>=2.31.0
beautifulsoup4>=4.12.0
lxml>=4.9.0
tqdm>=4.66.0

# Document parsing
pandas>=2.0.0
python-docx>=0.8.11
python-pptx>=0.6.21
openpyxl>=3.1.0
PyPDF2>=3.0.0

# Metadata extraction
exifread>=3.0.0
hachoir>=3.2.0

# OSINT automation
duckduckgo-search>=3.9.0
google-search-results>=2.4.2
linkedin-api>=2.1.0
github3.py>=3.2.0

# Utilities
orjson>=3.9.0
validators>=0.22.0
rich>=13.7.0
REQUIREMENTS_EOF
    fi
    
    source "$VENV_PATH/bin/activate"
    
    pip install --upgrade pip -q
    pip install -r "$REQUIREMENTS_FILE" -q
    
    if [ $? -eq 0 ]; then
        log SUCCESS "Dependências Python instaladas"
        echo -e "${CYAN}[i] Pacotes instalados: $(pip list --format=freeze | wc -l)${NC}"
    else
        log ERROR "Falha ao instalar dependências Python"
        deactivate
        return 1
    fi
    
    deactivate
}

# Criar wrapper APT
create_apt_wrapper() {
    log INFO "Criando wrapper APT para proteção do dnsrecon..."
    
    local APT_WRAPPER="$OPENPIPES_BIN/apt-openpipes"
    
    cat > "$APT_WRAPPER" << 'APT_WRAPPER_EOF'
#!/bin/bash
# Wrapper APT - OpenPipeS
# Protege o symlink do dnsrecon durante operações APT

OPENPIPES_BIN="$HOME/.openpipes/bin"
DNSRECON_CUSTOM="$OPENPIPES_BIN/dnsrecon"
DNSRECON_BACKUP="$OPENPIPES_BIN/.dnsrecon.backup"
DNSRECON_SYSTEM="/usr/bin/dnsrecon"

# Backup do dnsrecon customizado
if [ -f "$DNSRECON_CUSTOM" ] && [ ! -L "$DNSRECON_CUSTOM" ]; then
    mv "$DNSRECON_CUSTOM" "$DNSRECON_BACKUP"
    
    # Criar symlink temporário para o sistema (se existir)
    if [ -f "$DNSRECON_SYSTEM" ]; then
        ln -sf "$DNSRECON_SYSTEM" "$DNSRECON_CUSTOM"
    fi
fi

# Executar comando APT original
sudo apt "$@"
APT_EXIT_CODE=$?

# Restaurar dnsrecon customizado
if [ -f "$DNSRECON_BACKUP" ]; then
    rm -f "$DNSRECON_CUSTOM"
    mv "$DNSRECON_BACKUP" "$DNSRECON_CUSTOM"
fi

exit $APT_EXIT_CODE
APT_WRAPPER_EOF
    
    chmod +x "$APT_WRAPPER"
    
    log SUCCESS "Wrapper APT criado: $APT_WRAPPER"
    echo -e "${CYAN}[i] Use 'apt-openpipes' em vez de 'apt' para proteger dnsrecon${NC}"
}

# Download cache de vulnerabilidades
download_vuln_cache() {
    log INFO "Baixando cache de vulnerabilidades..."
    
    local CACHE_URL="https://raw.githubusercontent.com/rlSniff3r/openPipes/master/.openpipes_cache/OWASP_WSTG_PwnDoc_pt-br.json"
    local CACHE_FILE="$OPENPIPES_CACHE/OWASP_WSTG_PwnDoc_pt-br.json"
    
    if [ -f "$CACHE_FILE" ]; then
        log WARNING "Cache já existe: $CACHE_FILE"
        read -p "Sobrescrever? (s/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Ss]$ ]]; then
            log WARNING "Download cancelado"
            return 0
        fi
    fi
    
    wget -q -O "$CACHE_FILE" "$CACHE_URL"
    
    if [ $? -eq 0 ]; then
        local VULN_COUNT=$(jq '. | length' "$CACHE_FILE" 2>/dev/null || echo "?")
        log SUCCESS "Cache baixado: $VULN_COUNT templates"
    else
        log WARNING "Falha no download. Cache será criado no primeiro uso."
    fi
}

# Copiar templates
copy_templates() {
    log INFO "Copiando templates..."
    
    local REPO_TEMPLATES="$INSTALL_DIR/.openpipes/.templates"
    
    if [ ! -d "$REPO_TEMPLATES" ]; then
        log WARNING "Diretório de templates não encontrado"
        return 1
    fi
    
    # Copiar todos os templates
    cp -r "$REPO_TEMPLATES"/* "$OPENPIPES_TEMPLATES/" 2>/dev/null
    
    log SUCCESS "Templates copiados para: $OPENPIPES_TEMPLATES"
}

# Criar config.sh padrão
create_default_config() {
    log INFO "Criando configuração padrão..."
    local CONFIG_FILE="$OPENPIPES_DIR/config.sh"
  
    datetime_suffix=$(date +%Y%m%d_%H%M%S)
    backup_dir=$(backup_openpipes_${datetime_suffix})
    mkdir -p ~/${backup_dir}

    cp $CONFIG_FILE ~/${backup_dir}

    cp $INSTALL_DIR/.openpipes/config.sh $CONFIG_FILE
    echo -e "${CYAN}[i] Edite suas API keys em: $CONFIG_FILE${NC}"
}

# Verificar instalação
verify_installation() {
    log INFO "Verificando instalação..."
    
    local ERRORS=0
    
    # Verificar diretórios
    echo -e "\n${CYAN}=== Diretórios ===${NC}"
    for dir in "$OPENPIPES_DIR" "$OPENPIPES_BIN" "$OPENPIPES_SCRIPTS" "$OPENPIPES_TOOLS" "$OPENPIPES_CACHE"; do
        if [ -d "$dir" ]; then
            log SUCCESS "$dir"
        else
            log ERROR "$dir"
            ((ERRORS++))
        fi
    done
    
    # Verificar comandos essenciais
    echo -e "\n${CYAN}=== Comandos Principais ===${NC}"
    for cmd in openpipes recon nwrapper cria-alvos httpx-runner nuclei-runner; do
        if command -v "$cmd" &>/dev/null; then
            log SUCCESS "$cmd"
        else
            log ERROR "$cmd não encontrado no PATH"
            ((ERRORS++))
        fi
    done
    
    # Verificar ferramentas Go
    echo -e "\n${CYAN}=== Ferramentas Go ===${NC}"
    for tool in httpx nuclei katana gf rdap; do
        if command -v "$tool" &>/dev/null; then
            log SUCCESS "$tool"
        else
            log WARNING "$tool não encontrado"
        fi
    done
    
    # Verificar amass customizado
    echo -e "\n${CYAN}=== Amass ===${NC}"
    if [ -d "$OPENPIPES_BIN/amass-3.20.0" ]; then
        log SUCCESS "amass 3.20.0 instalado"
    else
        log WARNING "amass 3.20.0 não encontrado"
    fi
    
    # Verificar ferramentas Rust
    echo -e "\n${CYAN}=== Ferramentas Rust ===${NC}"
    if command -v feroxbuster &>/dev/null; then
        log SUCCESS "feroxbuster"
    else
        log WARNING "feroxbuster não encontrado"
    fi
    
    # Verificar LinkFinder
    echo -e "\n${CYAN}=== LinkFinder ===${NC}"
    if [ -d "$HOME/.venv-jsfinder/LinkFinder" ]; then
        log SUCCESS "LinkFinder instalado (VENV isolado)"
    else
        log WARNING "LinkFinder não encontrado"
    fi
    
    # Verificar SecLists
    echo -e "\n${CYAN}=== Wordlists ===${NC}"
    if [ -d "/usr/share/wordlists/seclists" ]; then
        log SUCCESS "SecLists instalado"
    else
        log WARNING "SecLists não encontrado"
    fi
    
    # Verificar Python VENV
    echo -e "\n${CYAN}=== Python Environment ===${NC}"
    if [ -f "$VENV_PATH/bin/activate" ]; then
        log SUCCESS "Virtual environment criado"
        
        source "$VENV_PATH/bin/activate"
        local PKG_COUNT=$(pip list --format=freeze 2>/dev/null | wc -l)
        log SUCCESS "Pacotes Python instalados: $PKG_COUNT"
        deactivate
    else
        log ERROR "Virtual environment não criado"
        ((ERRORS++))
    fi
    
    # Verificar cache
    echo -e "\n${CYAN}=== Cache ===${NC}"
    if [ -f "$OPENPIPES_CACHE/OWASP_WSTG_PwnDoc_pt-br.json" ]; then
        local VULN_COUNT=$(jq '. | length' "$OPENPIPES_CACHE/OWASP_WSTG_PwnDoc_pt-br.json" 2>/dev/null || echo "?")
        log SUCCESS "Cache de vulnerabilidades: $VULN_COUNT templates"
    else
        log WARNING "Cache de vulnerabilidades não encontrado"
    fi
    
    # Resultado final
    echo -e "\n${CYAN}=== Resultado Final ===${NC}"
    if [ $ERRORS -eq 0 ]; then
        log SUCCESS "Instalação verificada com sucesso!"
        return 0
    else
        log ERROR "Instalação incompleta ($ERRORS erros críticos)"
        return 1
    fi
}

# Mensagem final
print_final_message() {
    echo -e "\n${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                 INSTALAÇÃO CONCLUÍDA!                      ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    
    echo -e "\n${CYAN}Próximos passos:${NC}"
    echo -e "  1. ${YELLOW}Recarregue seu shell:${NC}"
    echo -e "     ${BLUE}source ~/.bashrc${NC}  (ou ~/.zshrc)"
    echo -e ""
    echo -e "  2. ${YELLOW}Configure suas API keys:${NC}"
    echo -e "     ${BLUE}nano ~/.openpipes/config.sh${NC}"
    echo -e ""
    echo -e "  3. ${YELLOW}Execute o framework:${NC}"
    echo -e "     ${BLUE}openpipes${NC}"
    echo -e ""
    echo -e "  4. ${YELLOW}Use o wrapper APT (quando necessário):${NC}"
    echo -e "     ${BLUE}apt-openpipes install <pacote>${NC}"
    echo -e ""
    echo -e "${CYAN}Documentação:${NC}"
    echo -e "  ${BLUE}https://github.com/rlSniff3r/openPipes${NC}"
    echo -e ""
    echo -e "${CYAN}Comandos disponíveis:${NC}"
    echo -e "  ${BLUE}openpipes${NC}          - Menu principal"
    echo -e "  ${BLUE}recon${NC}              - Reconhecimento DNS"
    echo -e "  ${BLUE}nwrapper${NC}           - Wrapper Nmap"
    echo -e "  ${BLUE}cria-alvos${NC}         - Criar estrutura Obsidian"
    echo -e "  ${BLUE}httpx-runner${NC}       - HTTP probing"
    echo -e "  ${BLUE}katana-buster${NC}      - Web discovery"
    echo -e "  ${BLUE}nuclei-runner${NC}      - Vulnerability scanning"
    echo -e "  ${BLUE}osint-people${NC}       - OSINT People module"
    echo -e "  ${BLUE}apt-openpipes${NC}      - Wrapper APT seguro"
    echo -e ""
    echo -e "${CYAN}Ferramentas customizadas instaladas:${NC}"
    echo -e "  ${BLUE}dnsrecon 1.1.3${NC}     - $OPENPIPES_BIN/dnsrecon-1.1.3"
    echo -e "  ${BLUE}amass 3.20.0${NC}       - $OPENPIPES_BIN/amass-3.20.0"
    echo -e "  ${BLUE}LinkFinder${NC}         - ~/.venv-jsfinder/LinkFinder"
    echo -e ""
}

# ========== MAIN ==========

main() {
    print_banner
    
    check_root
    detect_os || exit 1
    
    update_system
    install_apt_deps || exit 1
    
    create_directories
    
    install_go_tools
    install_rust_tools
    install_seclists
    
    configure_path
    
    create_python_venv || exit 1
    install_python_requirements || exit 1
    
    install_python_tools || exit 1
    install_amass_custom || exit 1
    
    create_apt_wrapper
    
    create_symlinks
    download_vuln_cache
    copy_templates
    create_default_config
    
    verify_installation
    
    print_final_message
}

# Executar instalação
main "$@"
