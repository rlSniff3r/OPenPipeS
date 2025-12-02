#!/bin/bash

# Cores para output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Variáveis globais
OPENPIPES_DIR="$HOME/.openpipes"
OPENPIPES_BIN="$OPENPIPES_DIR/bin"
OPENPIPES_SCRIPTS="$OPENPIPES_DIR/scripts"
OPENPIPES_TEMPLATES="$OPENPIPES_DIR/.templates"
OPENPIPES_TOOLS="$OPENPIPES_DIR/tools"
OPENPIPES_CACHE="$HOME/.openpipes_cache"
OBSIDIAN_DIR="$HOME/.obsidianFixedMount"
VENV_PATH="$OPENPIPES_DIR/.venv"

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
        echo -e "${RED}[✗] Não execute este script como root!${NC}"
        echo -e "${YELLOW}[!] O script pedirá sudo quando necessário.${NC}"
        exit 1
    fi
}

# Detectar sistema operacional
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
        echo -e "${BLUE}[*] Sistema detectado: $PRETTY_NAME${NC}"
        
        case $OS in
            kali|debian|ubuntu)
                return 0
                ;;
            *)
                echo -e "${YELLOW}[!] Sistema não testado: $OS${NC}"
                echo -e "${YELLOW}[!] Continuando instalação (pode haver problemas)${NC}"
                return 0
                ;;
        esac
    else
        echo -e "${RED}[✗] Não foi possível detectar o sistema operacional${NC}"
        return 1
    fi
}

# Atualizar sistema
update_system() {
    echo -e "\n${BLUE}[*] Atualizando sistema...${NC}"
    sudo apt update -qq
    echo -e "${GREEN}[✓] Sistema atualizado${NC}"
}

# Instalar dependências APT
install_apt_deps() {
    echo -e "\n${BLUE}[*] Instalando dependências APT...${NC}"
    
    local DEPS=(
        nmap curl wget git jq python3 python3-pip python3-venv
        golang-go build-essential whois dnsutils libpcap-dev
        libssl-dev pkg-config unzip
    )
    
    for dep in "${DEPS[@]}"; do
        if dpkg -l | grep -qw "^ii  $dep"; then
            echo -e "${GREEN}[✓] $dep já instalado${NC}"
        else
            echo -e "${BLUE}[*] Instalando $dep...${NC}"
            sudo apt install -y $dep -qq
            
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}[✓] $dep instalado${NC}"
            else
                echo -e "${RED}[✗] Falha ao instalar $dep${NC}"
                return 1
            fi
        fi
    done
    
    echo -e "${GREEN}[✓] Dependências APT instaladas${NC}"
}

# Verificar instalação do Go
check_go_installation() {
    if command -v go &>/dev/null; then
        local GO_VERSION=$(go version | awk '{print $3}')
        echo -e "${GREEN}[✓] Go já instalado: $GO_VERSION${NC}"
        
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
    
    echo -e "\n${BLUE}[*] Instalando Go...${NC}"
    
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
    
    echo -e "${GREEN}[✓] Go instalado: $(go version)${NC}"
}

# Instalar ferramenta Go com retry
install_go_tool() {
    local pkg=$1
    local name=$(basename "$pkg" | cut -d'@' -f1)
    local retries=3
    
    echo -e "${BLUE}[*] Instalando $name...${NC}"
    
    # Verificar se já está instalado
    if command -v "$name" &>/dev/null; then
        echo -e "${GREEN}[✓] $name já instalado${NC}"
        return 0
    fi
    
    for i in $(seq 1 $retries); do
        if go install -v "$pkg" 2>/dev/null; then
            echo -e "${GREEN}[✓] $name instalado com sucesso${NC}"
            return 0
        else
            echo -e "${YELLOW}[!] Tentativa $i/$retries falhou para $name${NC}"
            [ $i -lt $retries ] && sleep 2
        fi
    done
    
    echo -e "${RED}[✗] Falha ao instalar $name após $retries tentativas${NC}"
    return 1
}

# Instalar Go tools
install_go_tools() {
    echo -e "\n${BLUE}[*] Instalando ferramentas Go...${NC}"
    
    check_go_installation || install_golang
    
    local GO_TOOLS=(
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/projectdiscovery/katana/cmd/katana@latest"
        "github.com/tomnomnom/gf@latest"
        "github.com/owasp-amass/amass/v4/...@master"
        "github.com/openrdap/rdap/cmd/rdap@latest"
    )
    
    local FAILED=0
    
    for tool in "${GO_TOOLS[@]}"; do
        install_go_tool "$tool" || ((FAILED++))
    done
    
    if [ $FAILED -eq 0 ]; then
        echo -e "${GREEN}[✓] Todas as ferramentas Go instaladas${NC}"
    else
        echo -e "${YELLOW}[!] $FAILED ferramenta(s) falharam na instalação${NC}"
    fi
    
    # Atualizar templates do Nuclei
    if command -v nuclei &>/dev/null; then
        echo -e "${BLUE}[*] Atualizando templates do Nuclei...${NC}"
        nuclei -update-templates -silent
        echo -e "${GREEN}[✓] Templates do Nuclei atualizados${NC}"
    fi
}

# Verificar instalação do Rust
check_rust_installation() {
    if command -v cargo &>/dev/null; then
        local RUST_VERSION=$(cargo --version | awk '{print $2}')
        echo -e "${GREEN}[✓] Rust já instalado: $RUST_VERSION${NC}"
        return 0
    fi
    return 1
}

# Instalar Rust
install_rust() {
    if check_rust_installation; then
        return 0
    fi
    
    echo -e "\n${BLUE}[*] Instalando Rust...${NC}"
    
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y -q
    
    source "$HOME/.cargo/env"
    
    echo -e "${GREEN}[✓] Rust instalado: $(cargo --version)${NC}"
}

# Instalar Rust tools
install_rust_tools() {
    echo -e "\n${BLUE}[*] Instalando ferramentas Rust...${NC}"
    
    check_rust_installation || install_rust
    
    source "$HOME/.cargo/env"
    
    if command -v feroxbuster &>/dev/null; then
        echo -e "${GREEN}[✓] feroxbuster já instalado${NC}"
    else
        echo -e "${BLUE}[*] Instalando feroxbuster...${NC}"
        cargo install feroxbuster
        echo -e "${GREEN}[✓] feroxbuster instalado${NC}"
    fi
}

# Instalar dnsrecon 1.1.3 customizado
install_dnsrecon_custom() {
    echo -e "\n${BLUE}[*] Instalando dnsrecon 1.1.3 (versão customizada)...${NC}"
    
    local DNSRECON_VERSION="1.1.3"
    local DNSRECON_DIR="$OPENPIPES_TOOLS/dnsrecon-${DNSRECON_VERSION}"
    local DNSRECON_URL="https://github.com/darkoperator/dnsrecon/archive/refs/tags/v${DNSRECON_VERSION}.tar.gz"
    
    # Remover versão APT se existir
    if dpkg -l | grep -qw "^ii  python3-dnsrecon"; then
        echo -e "${YELLOW}[!] Removendo dnsrecon do APT...${NC}"
        sudo apt remove -y python3-dnsrecon 2>/dev/null
    fi
    
    # Criar diretório tools
    mkdir -p "$OPENPIPES_TOOLS"
    
    # Baixar e descompactar
    echo -e "${BLUE}[*] Baixando dnsrecon v${DNSRECON_VERSION}...${NC}"
    cd /tmp
    wget -q -O dnsrecon.tar.gz "$DNSRECON_URL"
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}[✗] Falha ao baixar dnsrecon${NC}"
        return 1
    fi
    
    tar -xzf dnsrecon.tar.gz
    mv "dnsrecon-${DNSRECON_VERSION}" "$DNSRECON_DIR"
    rm dnsrecon.tar.gz
    
    # Instalar dependências do dnsrecon no VENV
    if [ -f "$DNSRECON_DIR/requirements.txt" ]; then
        echo -e "${BLUE}[*] Instalando dependências do dnsrecon...${NC}"
        source "$VENV_PATH/bin/activate"
        pip install -q -r "$DNSRECON_DIR/requirements.txt"
        deactivate
    fi
    
    # Criar wrapper executável
    cat > "$OPENPIPES_BIN/dnsrecon" << 'WRAPPER_EOF'
#!/bin/bash
# Wrapper dnsrecon - OpenPipeS v1.1.3

OPENPIPES_DIR="$HOME/.openpipes"
VENV_PATH="$OPENPIPES_DIR/.venv"
DNSRECON_SCRIPT="$OPENPIPES_DIR/tools/dnsrecon-1.1.3/dnsrecon.py"

# Ativar VENV
source "$VENV_PATH/bin/activate"

# Executar dnsrecon
python3 "$DNSRECON_SCRIPT" "$@"

# Desativar VENV
deactivate
WRAPPER_EOF
    
    chmod +x "$OPENPIPES_BIN/dnsrecon"
    
    echo -e "${GREEN}[✓] dnsrecon 1.1.3 instalado em: $DNSRECON_DIR${NC}"
    echo -e "${GREEN}[✓] Wrapper criado em: $OPENPIPES_BIN/dnsrecon${NC}"
}

# Criar wrapper APT
create_apt_wrapper() {
    echo -e "\n${BLUE}[*] Criando wrapper APT para proteção do dnsrecon...${NC}"
    
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
    
    echo -e "${GREEN}[✓] Wrapper APT criado: $APT_WRAPPER${NC}"
    echo -e "${CYAN}[i] Use 'apt-openpipes' em vez de 'apt' para proteger dnsrecon${NC}"
}

# Instalar Python tools (LinkFinder apenas)
install_python_tools() {
    echo -e "\n${BLUE}[*] Instalando ferramentas Python...${NC}"
    
    # LinkFinder (instalação global)
    if command -v linkfinder &>/dev/null; then
        echo -e "${GREEN}[✓] linkfinder já instalado${NC}"
    else
        echo -e "${BLUE}[*] Instalando linkfinder...${NC}"
        pip3 install --user linkfinder 2>/dev/null
        echo -e "${GREEN}[✓] linkfinder instalado${NC}"
    fi
}

# Instalar SecLists
install_seclists() {
    echo -e "\n${BLUE}[*] Instalando SecLists (wordlists)...${NC}"
    
    local SECLISTS_DIR="/usr/share/wordlists/seclists"
    
    if [ -d "$SECLISTS_DIR" ]; then
        echo -e "${GREEN}[✓] SecLists já instalado em: $SECLISTS_DIR${NC}"
        return 0
    fi
    
    sudo mkdir -p /usr/share/wordlists
    
    echo -e "${BLUE}[*] Clonando SecLists (pode demorar alguns minutos)...${NC}"
    sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$SECLISTS_DIR" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓] SecLists instalado em: $SECLISTS_DIR${NC}"
        
        # Processar big.txt (remover comentários e linhas vazias)
        local BIG_TXT="$SECLISTS_DIR/Discovery/Web-Content/dirb/big.txt"
        if [ -f "$BIG_TXT" ]; then
            echo -e "${BLUE}[*] Processando big.txt...${NC}"
            sudo sed -i '/^#/d; /^$/d' "$BIG_TXT"
            echo -e "${GREEN}[✓] big.txt processado ($(wc -l < "$BIG_TXT") linhas)${NC}"
        fi
        
        return 0
    else
        echo -e "${RED}[✗] Falha ao clonar SecLists${NC}"
        echo -e "${YELLOW}[!] Instale manualmente: sudo git clone https://github.com/danielmiessler/SecLists.git $SECLISTS_DIR${NC}"
        return 1
    fi
}

# Criar estrutura de diretórios
create_directories() {
    echo -e "\n${BLUE}[*] Criando estrutura de diretórios...${NC}"
    
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
            echo -e "${GREEN}[✓] Criado: $dir${NC}"
        else
            echo -e "${YELLOW}[!] Já existe: $dir${NC}"
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
    echo -e "\n${BLUE}[*] Configurando PATH...${NC}"
    
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
            echo -e "${YELLOW}[!] Shell não suportado: $SHELL_TYPE${NC}"
            echo -e "${YELLOW}[!] Adicione manualmente ao seu RC file:${NC}"
            echo -e "${CYAN}export PATH=\"\$HOME/.openpipes/bin:\$PATH\"${NC}"
            return 1
            ;;
    esac
    
    # Verificar se já está configurado
    if grep -q "OPENPIPES_DIR" "$RC_FILE" 2>/dev/null; then
        echo -e "${YELLOW}[!] PATH já configurado em $RC_FILE${NC}"
        return 0
    fi
    
    # Adicionar configuração
    cat >> "$RC_FILE" << 'PATH_EOF'

# ========== OpenPipeS Configuration ==========
export OPENPIPES_DIR="$HOME/.openpipes"
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
PATH_EOF
    
    echo -e "${GREEN}[✓] PATH configurado em: $RC_FILE${NC}"
    echo -e "${CYAN}[i] Execute: source $RC_FILE${NC}"
    
    # Carregar configuração na sessão atual
    source "$RC_FILE"
}

# Criar symlinks
create_symlinks() {
    echo -e "\n${BLUE}[*] Criando symlinks...${NC}"
    
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
            echo -e "${GREEN}[✓] Symlink: $link_name -> $source_name${NC}"
        else
            echo -e "${YELLOW}[!] Script não encontrado: $source_name${NC}"
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
            echo -e "${GREEN}[✓] Symlink: $link_name -> $source_name${NC}"
        else
            echo -e "${YELLOW}[!] Script Python não encontrado: $source_name${NC}"
        fi
    done
}

# Criar Python VENV
create_python_venv() {
    echo -e "\n${BLUE}[*] Criando Python virtual environment...${NC}"
    
    if [ -d "$VENV_PATH" ]; then
        echo -e "${YELLOW}[!] VENV já existe em: $VENV_PATH${NC}"
        return 0
    fi
    
    python3 -m venv "$VENV_PATH"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓] VENV criado em: $VENV_PATH${NC}"
    else
        echo -e "${RED}[✗] Falha ao criar VENV${NC}"
        return 1
    fi
}

# Instalar requirements Python
install_python_requirements() {
    echo -e "\n${BLUE}[*] Instalando dependências Python (VENV)...${NC}"
    
    local REQUIREMENTS_FILE="$OPENPIPES_DIR/requirements.txt"
    
    if [ ! -f "$REQUIREMENTS_FILE" ]; then
        echo -e "${YELLOW}[!] requirements.txt não encontrado${NC}"
        echo -e "${YELLOW}[!] Criando requirements.txt básico...${NC}"
        
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

# DNS recon (versão específica)
dnsrecon==1.1.3
REQUIREMENTS_EOF
    fi
    
    source "$VENV_PATH/bin/activate"
    
    pip install --upgrade pip -q
    pip install -r "$REQUIREMENTS_FILE" -q
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓] Dependências Python instaladas${NC}"
        echo -e "${CYAN}[i] Pacotes instalados: $(pip list --format=freeze | wc -l)${NC}"
    else
        echo -e "${RED}[✗] Falha ao instalar dependências Python${NC}"
        deactivate
        return 1
    fi
    
    deactivate
}

# Download cache de vulnerabilidades
download_vuln_cache() {
    echo -e "\n${BLUE}[*] Baixando cache de vulnerabilidades...${NC}"
    
    local CACHE_URL="https://raw.githubusercontent.com/rlSniff3r/openPipes/master/.openpipes_cache/OWASP_WSTG_PwnDoc_pt-br.json"
    local CACHE_FILE="$OPENPIPES_CACHE/OWASP_WSTG_PwnDoc_pt-br.json"
    
    if [ -f "$CACHE_FILE" ]; then
        echo -e "${YELLOW}[!] Cache já existe: $CACHE_FILE${NC}"
        read -p "Sobrescrever? (s/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Ss]$ ]]; then
            echo -e "${YELLOW}[!] Download cancelado${NC}"
            return 0
        fi
    fi
    
    wget -q -O "$CACHE_FILE" "$CACHE_URL"
    
    if [ $? -eq 0 ]; then
        local VULN_COUNT=$(jq '. | length' "$CACHE_FILE" 2>/dev/null || echo "?")
        echo -e "${GREEN}[✓] Cache baixado: $VULN_COUNT templates${NC}"
    else
        echo -e "${YELLOW}[!] Falha no download. Cache será criado no primeiro uso.${NC}"
    fi
}

# Copiar templates
copy_templates() {
    echo -e "\n${BLUE}[*] Copiando templates...${NC}"
    
    local REPO_TEMPLATES="$OPENPIPES_DIR/.templates"
    
    if [ ! -d "$REPO_TEMPLATES" ]; then
        echo -e "${YELLOW}[!] Diretório de templates não encontrado${NC}"
        return 1
    fi
    
    # Copiar todos os templates
    cp -r "$REPO_TEMPLATES"/* "$OPENPIPES_TEMPLATES/" 2>/dev/null
    
    echo -e "${GREEN}[✓] Templates copiados para: $OPENPIPES_TEMPLATES${NC}"
}

# Criar config.sh padrão
create_default_config() {
    echo -e "\n${BLUE}[*] Criando configuração padrão...${NC}"
    
    local CONFIG_FILE="$OPENPIPES_DIR/config.sh"
    
    if [ -f "$CONFIG_FILE" ]; then
        echo -e "${YELLOW}[!] config.sh já existe${NC}"
        return 0
    fi
    
    cat > "$CONFIG_FILE" << 'CONFIG_EOF'
#!/bin/bash

# Diretório base dos projetos
proj_dir="$HOME/Desktop/BugBounty"

# Nome do projeto atual
proj_name="default-project"

# Caminho completo (será construído automaticamente)
proj_path="$proj_dir/$proj_name"

# Diretório do Obsidian (vault)
obsdir="$HOME/.obsidianFixedMount"

# Diretório de templates
tpdir="$OPENPIPES_TEMPLATES"

# Diretório base de varreduras
base_dir="$proj_path/Varreduras/"

# API Keys
securitytrailskey=""
OPENAI_API_KEY=""
HIBP_API_KEY=""
GOOGLE_API_KEY=""
GOOGLE_CX=""
BING_API_KEY=""

# OSINT People - Configurações
OSINT_PEOPLE_AUTH_FILE="$HOME/.openpipes/osint_people_auth.txt"

# Python VENV
OPENPIPES_VENV="$HOME/.openpipes/.venv"
CONFIG_EOF
    
    echo -e "${GREEN}[✓] Configuração criada: $CONFIG_FILE${NC}"
    echo -e "${CYAN}[i] Edite suas API keys em: $CONFIG_FILE${NC}"
}

# Verificar instalação
verify_installation() {
    echo -e "\n${BLUE}[*] Verificando instalação...${NC}"
    
    local ERRORS=0
    
    # Verificar diretórios
    echo -e "\n${CYAN}=== Diretórios ===${NC}"
    for dir in "$OPENPIPES_DIR" "$OPENPIPES_BIN" "$OPENPIPES_SCRIPTS" "$OPENPIPES_TOOLS" "$OPENPIPES_CACHE"; do
        if [ -d "$dir" ]; then
            echo -e "${GREEN}[✓] $dir${NC}"
        else
            echo -e "${RED}[✗] $dir${NC}"
            ((ERRORS++))
        fi
    done
    
    # Verificar comandos essenciais
    echo -e "\n${CYAN}=== Comandos Principais ===${NC}"
    for cmd in openpipes recon nwrapper cria-alvos httpx-runner nuclei-runner; do
        if command -v "$cmd" &>/dev/null; then
            echo -e "${GREEN}[✓] $cmd${NC}"
        else
            echo -e "${RED}[✗] $cmd não encontrado no PATH${NC}"
            ((ERRORS++))
        fi
    done
    
    # Verificar ferramentas Go
    echo -e "\n${CYAN}=== Ferramentas Go ===${NC}"
    for tool in httpx nuclei katana gf amass rdap; do
        if command -v "$tool" &>/dev/null; then
            echo -e "${GREEN}[✓] $tool${NC}"
        else
            echo -e "${YELLOW}[!] $tool não encontrado${NC}"
        fi
    done
    
    # Verificar ferramentas Rust
    echo -e "\n${CYAN}=== Ferramentas Rust ===${NC}"
    if command -v feroxbuster &>/dev/null; then
        echo -e "${GREEN}[✓] feroxbuster${NC}"
    else
        echo -e "${YELLOW}[!] feroxbuster não encontrado${NC}"
    fi
    
    # Verificar dnsrecon customizado
    echo -e "\n${CYAN}=== DNS Recon ===${NC}"
    if [ -f "$OPENPIPES_BIN/dnsrecon" ]; then
        echo -e "${GREEN}[✓] dnsrecon wrapper criado${NC}"
        if [ -d "$OPENPIPES_TOOLS/dnsrecon-1.1.3" ]; then
            echo -e "${GREEN}[✓] dnsrecon 1.1.3 instalado${NC}"
        else
            echo -e "${YELLOW}[!] dnsrecon 1.1.3 não encontrado${NC}"
        fi
    else
        echo -e "${RED}[✗] dnsrecon wrapper não criado${NC}"
        ((ERRORS++))
    fi
    
    # Verificar SecLists
    echo -e "\n${CYAN}=== Wordlists ===${NC}"
    if [ -d "/usr/share/wordlists/seclists" ]; then
        echo -e "${GREEN}[✓] SecLists instalado${NC}"
    else
        echo -e "${YELLOW}[!] SecLists não encontrado${NC}"
    fi
    
    # Verificar Python VENV
    echo -e "\n${CYAN}=== Python Environment ===${NC}"
    if [ -f "$VENV_PATH/bin/activate" ]; then
        echo -e "${GREEN}[✓] Virtual environment criado${NC}"
        
        source "$VENV_PATH/bin/activate"
        local PKG_COUNT=$(pip list --format=freeze 2>/dev/null | wc -l)
        echo -e "${GREEN}[✓] Pacotes Python instalados: $PKG_COUNT${NC}"
        deactivate
    else
        echo -e "${RED}[✗] Virtual environment não criado${NC}"
        ((ERRORS++))
    fi
    
    # Verificar cache
    echo -e "\n${CYAN}=== Cache ===${NC}"
    if [ -f "$OPENPIPES_CACHE/OWASP_WSTG_PwnDoc_pt-br.json" ]; then
        local VULN_COUNT=$(jq '. | length' "$OPENPIPES_CACHE/OWASP_WSTG_PwnDoc_pt-br.json" 2>/dev/null || echo "?")
        echo -e "${GREEN}[✓] Cache de vulnerabilidades: $VULN_COUNT templates${NC}"
    else
        echo -e "${YELLOW}[!] Cache de vulnerabilidades não encontrado${NC}"
    fi
    
    # Resultado final
    echo -e "\n${CYAN}=== Resultado Final ===${NC}"
    if [ $ERRORS -eq 0 ]; then
        echo -e "${GREEN}[✓] Instalação verificada com sucesso!${NC}"
        return 0
    else
        echo -e "${RED}[✗] Instalação incompleta ($ERRORS erros críticos)${NC}"
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
    install_python_tools
    install_seclists
    
    configure_path
    
    create_python_venv || exit 1
    install_python_requirements || exit 1
    
    install_dnsrecon_custom || exit 1
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