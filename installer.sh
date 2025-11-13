#!/bin/bash

# ═══════════════════════════════════════════════════════════════════════════
# OPenPipeS - Instalador Automático
# Autor: Rafael Luís da Silva & Claude A.I.
# Versão: 2.2 - Estratégia VENV correta (PEP 668 compliant)
# ═══════════════════════════════════════════════════════════════════════════

set -euo pipefail

# Cores
source ~/colorCodes.sh

# Diretórios
OPENPIPES_INSTALL_DIR="$(pwd)"
OPENPIPES_HOME="${HOME}/.openpipes"
OPENPIPES_BIN="${OPENPIPES_HOME}/bin"
OPENPIPES_SCRIPTS="${OPENPIPES_HOME}/scripts"
OPENPIPES_TEMPLATES="${OPENPIPES_HOME}/.templates"
OPENPIPES_CACHE="${OPENPIPES_HOME}_cache"
OPENPIPES_CONFIG="${OPENPIPES_HOME}/config.sh"
OPENPIPES_VENV="${OPENPIPES_HOME}/.venv"

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
    echo -e "${GREEN}           INSTALADOR AUTOMÁTICO v2.2${NC}"
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
    
    # ESTRATÉGIA: Instalar via APT sempre que possível
    local packages=(
        nmap
        curl
        wget
        git
        jq
        python3
        python3-pip
        python3-venv
        python3-requests
        python3-yaml
        python3-pil
        python3-bs4
        python3-lxml
        golang-go
        build-essential
        whois
        dnsutils
        exiftool
        yq
    )
    
    log INFO "Atualizando repositórios..."
    sudo apt update
    
    log INFO "Instalando pacotes base..."
    sudo apt install -y "${packages[@]}"
    
    # Fix para hook quebrado do dnsrecon (se existir)
    if dpkg -l | grep -q dnsrecon; then
        log WARN "Detectado dnsrecon via APT (pode causar conflitos)..."
        log INFO "Removendo dnsrecon do APT..."
        sudo apt remove --purge dnsrecon -y 2>/dev/null || true
        sudo rm -f /var/lib/dpkg/info/dnsrecon.* 2>/dev/null || true
        sudo rm -f /usr/share/python3/runtime.d/dnsrecon.rtupdate 2>/dev/null || true
        sudo dpkg --configure -a || true
    fi
    
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

create_openpipes_venv() {
    log STEP "Criando ambiente virtual global do OpenPipeS..."
    
    if [[ ! -d "$OPENPIPES_VENV" ]]; then
        python3 -m venv "$OPENPIPES_VENV"
        log INFO "VENV criado: $OPENPIPES_VENV"
    else
        log INFO "VENV já existe: $OPENPIPES_VENV"
    fi
    
    # Ativar e atualizar pip
    source "$OPENPIPES_VENV/bin/activate"
    pip install --upgrade pip setuptools wheel
    deactivate
    
    log INFO "VENV do OpenPipeS configurado!"
}

install_python_tools() {
    log STEP "Instalando ferramentas Python..."
    
    # ========================================================================
    # ESTRATÉGIA:
    # 1. Pacotes comuns → VENV global do OpenPipeS
    # 2. Ferramentas com conflitos → VENVs isolados
    # ========================================================================
    
    # ========================================================================
    # VENV Global do OpenPipeS
    # ========================================================================
    log INFO "Instalando dependências Python no VENV global..."
    source "$OPENPIPES_VENV/bin/activate"
    
    # Dependências do OSINT People e outras ferramentas
    pip install \
        requests \
        rapidfuzz \
        python-docx \
        openpyxl \
        Pillow \
        pdfminer.six \
        pikepdf \
        ExifRead \
        PyYAML \
        beautifulsoup4 \
        lxml \
        tqdm
    
    deactivate
    log INFO "Dependências instaladas no VENV global!"
    
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
    cat > "$OPENPIPES_BIN/dnsrecon" << 'DNSRECON_WRAPPER'
#!/bin/bash
source "$HOME/.openpipes/.venv/bin/activate"
python "$HOME/.openpipes/bin/dnsrecon-1.1.3/dnsrecon.py" "$@"
deactivate
DNSRECON_WRAPPER
    chmod +x "$OPENPIPES_BIN/dnsrecon"
    
    # Criar symlink para sistema
    sudo ln -sf "$OPENPIPES_BIN/dnsrecon" /usr/local/bin/dnsrecon
    
    log INFO "Ferramentas Python instaladas!"
}

install_python_scripts() {
    log STEP "Instalando scripts Python do OSINT People..."
    
    # Criar wrappers para scripts Python que usam VENV global
    local python_scripts=(
        "osint_people_collector.py"
        "osint_doc_finder.py"
        "osint_people_enricher_v1.0.py"
        "osint_people_parser.py"
    )
    
    for script in "${python_scripts[@]}"; do
        if [[ -f "./.openpipes/scripts/$script" ]]; then
            # Copiar script para OPENPIPES_HOME
            cp "./.openpipes/scripts/$script" "$OPENPIPES_HOME/$script"
            
            # Criar wrapper que ativa VENV antes de executar
            cat > "/usr/local/bin/$script" << SCRIPT_WRAPPER
#!/bin/bash
source "$OPENPIPES_VENV/bin/activate"
python "$OPENPIPES_HOME/$script" "\$@"
deactivate
SCRIPT_WRAPPER
            
            sudo chmod +x "/usr/local/bin/$script"
            log INFO "  → $script instalado com wrapper VENV"
        fi
    done
}

install_additional_tools() {
    log STEP "Instalando ferramentas adicionais..."
    
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
    
    sudo ln -sf "$OPENPIPES_BIN/amass-3.20.0/amass" "$amass_atual"
    
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
        sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/seclists
    fi
    
    # Parse dirb/big.txt
    if [[ -f /usr/share/wordlists/dirb/big.txt ]]; then
        log INFO "Preparando wordlist customizada..."
        grep -v "%" /usr/share/wordlists/dirb/big.txt > /tmp/big-parsed.txt
        sudo mv /tmp/big-parsed.txt /usr/share/wordlists/dirb/big-parsed.txt
    fi
    
    log INFO "Wordlists instaladas!"
}

copy_scripts() {
    log STEP "Copiando scripts para $OPENPIPES_SCRIPTS..."
    
    # Verificar se estamos no diretório do projeto
    if [[ ! -d "$OPENPIPES_INSTALL_DIR/.openpipes/scripts" ]]; then
        log ERROR "Diretório scripts/ não encontrado!"
        log INFO "Execute este instalador a partir do diretório raiz do OPenPipeS"
        exit 1
    fi
    
    # Copiar todos os scripts bash
    cp -r $OPENPIPES_INSTALL_DIR/.openpipes/scripts/* "$OPENPIPES_SCRIPTS/"
    
    # Copiar scripts bash do diretório ./.openpipes/scripts/
    if [[ -d "$OPENPIPES_INSTALL_DIR/.openpipes/scripts" ]]; then
        log INFO "Instalando scripts bash..."
        
        for sh_script in $OPENPIPES_INSTALL_DIR/.openpipes/scripts/*.sh; do
            if [[ -f "$sh_script" ]]; then
                script_name=$(basename "$sh_script")
                cp "$sh_script" "$OPENPIPES_SCRIPTS/"
                ln -sf "$OPENPIPES_SCRIPTS/$script_name" "$OPENPIPES_BIN/$script_name"
                chmod +x "$OPENPIPES_BIN/$script_name"
                log INFO "  → $script_name instalado"
            fi
        done
    fi
    
    # Criar symlinks no bin para scripts principais
    for script in "$OPENPIPES_SCRIPTS"/*.sh; do
        script_name=$(basename "$script")
        ln -sf "$script" "$OPENPIPES_BIN/${script_name}"
        chmod +x "$OPENPIPES_BIN/${script_name}"
    done
    
    log INFO "Scripts copiados e linkados!"
}

copy_templates() {
    log STEP "Copiando templates..."
    
    if [[ -d "$OPENPIPES_INSTALL_DIR/.openpipes/.templates" ]]; then
        cp -r $OPENPIPES_INSTALL_DIR/.openpipes/.templates/* "$OPENPIPES_TEMPLATES/"
        log INFO "Templates copiados!"
    else
        log WARN "Templates não encontrados em $OPENPIPES_INSTALL_DIR/.openpipes/.templates"
    fi
}

copy_cache() {
    log STEP "Copiando cache de vulnerabilidades..."
    
    if [[ -d "$OPENPIPES_INSTALL_DIR/.openpipes_cache" ]]; then
        cp -r $OPENPIPES_INSTALL_DIR/.openpipes_cache/* "$OPENPIPES_CACHE/"
        log INFO "Cache de vulnerabilidades copiado! (${OPENPIPES_CACHE})"
    else
        log WARN "Cache não encontrado em $OPENPIPES_INSTALL_DIR/.openpipes_cache"
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
GITHUB_TOKEN=""
HUNTER_API_KEY=""
HIBP_API_KEY=""
GOOGLE_API_KEY=""
GOOGLE_CX=""
BING_API_KEY=""

# OSINT People - Configurações
OSINT_PEOPLE_AUTH_FILE="$HOME/.openpipes/osint_people_auth.txt"

# Python VENV
OPENPIPES_VENV="$HOME/.openpipes/.venv"
EOF
    
    # Criar arquivo de autorização para OSINT People
    if [[ ! -f "$HOME/.openpipes/osint_people_auth.txt" ]]; then
        cat > "$HOME/.openpipes/osint_people_auth.txt" << 'AUTH_EOF'
# Arquivo de autorização OSINT People
# Use apenas para investigações autorizadas e legais

AUTHORIZED_DOMAINS=example.com,target.com
AUTHORIZED_BY=security-team
AUTHORIZATION_DATE=$(date +%Y-%m-%d)
PURPOSE=defensive-security-assessment
AUTH_EOF
        log INFO "Arquivo de autorização OSINT People criado"
    fi
    
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
        echo "export OPENPIPES_VENV=\"$OPENPIPES_VENV\"" >> ~/.bashrc
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
    echo -e "3. ${YELLOW}Configure autorização OSINT People:${NC}"
    echo -e "   ${BLUE}nano $HOME/.openpipes/osint_people_auth.txt${NC}"
    echo ""
    echo -e "4. ${YELLOW}Execute o orquestrador:${NC}"
    echo -e "   ${BLUE}openpipes${NC}"
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${CYAN}Estratégia Python implementada:${NC}"
    echo -e "  - ${GREEN}VENV Global:${NC} $OPENPIPES_VENV"
    echo -e "  - ${GREEN}VENV LinkFinder:${NC} ~/.venv-jsfinder"
    echo -e "  - ${GREEN}Scripts wrapper:${NC} /usr/local/bin/*.py"
    echo ""
    echo -e "${YELLOW}Compatível com PEP 668 (sem --break-system-packages)${NC}"
    echo ""
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
    create_openpipes_venv
    install_go_tools
    install_rust_tools
    install_python_tools
    install_python_scripts
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