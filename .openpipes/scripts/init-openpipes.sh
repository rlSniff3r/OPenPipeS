#!/usr/bin/env bash
set -euo pipefail

# 
# OPenPipeS v2.1 - Project Initialization
# Responsabilidade: Setup completo (explorador + analista + API keys)
# 

source ~/.bashrc
source $OPENPIPES_CONFIG

OPENPIPES_CONFIG="${HOME}/.openpipes/config.sh"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log() {
    local level=$1
    shift
    case $level in
        INFO)    echo -e "${BLUE}[INFO]${NC} $*" ;;
        SUCCESS) echo -e "${GREEN}[✓]${NC} $*" ;;
        WARN)    echo -e "${YELLOW}[!]${NC} $*" ;;
        ERROR)   echo -e "${RED}[✗]${NC} $*" >&2 ;;
    esac
}

# ─────────────────────────────────────────
# PRÉ-FLIGHT CHECKS
# ─────────────────────────────────────────
preflight_checks() {
    log INFO "Executando verificações pré-flight..."
    
    # 1. Config.sh existe?
    if [[ ! -f "$OPENPIPES_CONFIG" ]]; then
        log ERROR "config.sh não encontrado em $OPENPIPES_CONFIG"
        log ERROR "Execute: make install"
        exit 1
    fi
    
    # 2. Source config
    source "$OPENPIPES_CONFIG"
    
    # 3. Variáveis essenciais definidas?
    for var in proj_name proj_dir obsdir OBSIDIAN_PROJ_PATH; do
        if [[ -z "${!var:-}" ]]; then
            log ERROR "Variável \$$var não definida em config.sh"
            exit 1
        fi
    done
    
    log SUCCESS "Pré-flight OK: config.sh carregado"
}

# ─────────────────────────────────────────
# CRIAR ESTRUTURA EXPLORADOR
# ─────────────────────────────────────────
create_explorer_structure() {
    log INFO "Criando estrutura explorador (Kali)..."
    
    # Diretório principal
    mkdir -p "$proj_path"
    
    # Subdirs
    mkdir -p "$NMAP_DIR" "$RECON_DIR" "$OSINT_DIR" "$LOG_DIR" "SCREENSHOT_DIR"
    
    # domains.txt inicial
    if [[ ! -f "$proj_path/domains.txt" ]]; then
        cat > "$proj_path/domains.txt" << 'EOF'
# Lista de domínios alvo (um por linha)
# Exemplo:
# example.com
# target.org
EOF
        log SUCCESS "domains.txt criado"
    fi
    
    # .gitignore
    cat > "$proj_path/.gitignore" << 'EOF'
*.log
*.tmp
.DS_Store
Logs/
Varreduras/*.xml
EOF
    
    log SUCCESS "Estrutura explorador criada em $proj_path"
}

# ─────────────────────────────────────────
# CRIAR ESTRUTURA OBSIDIAN
# ─────────────────────────────────────────
create_obsidian_structure() {
    log INFO "Criando estrutura Obsidian (Analista)..."
    
    local pentest_root="$OBSIDIAN_PROJ_PATH"
    mkdir -p "$pentest_root/Alvos" "$pentest_root/OSINT"
    
    # Copiar templates
    local templates_dir="${HOME}/.openpipes/.templates"
    
    if [[ -f "$templates_dir/Dashboard_Global.md" ]]; then
        sed "s/{{proj_name}}/$proj_name/g" \
            "$templates_dir/Dashboard_Global.md" \
            > "$pentest_root/Dashboard_Global.md"
    fi
    
    if [[ -f "$templates_dir/Tarefas.md" ]]; then
        cp "$templates_dir/Tarefas.md" "$pentest_root/"
    fi
    
    log SUCCESS "Obsidian vault criado em $pentest_root"
}

# ─────────────────────────────────────────
# VALIDAR API KEYS + TUTORIAL
# ─────────────────────────────────────────
validate_api_keys() {
    log INFO "Verificando API keys..."
    
    local missing_keys=()
    
    [[ -z "${securitytrailskey:-}" ]] && missing_keys+=("SecurityTrails")
    [[ -z "${OPENAI_API_KEY:-}" ]] && missing_keys+=("OpenAI")
    [[ -z "${SERPAPI_KEY:-}" ]] && missing_keys+=("SerpAPI")
    [[ -z "${GOOGLE_API_KEY:-}" ]] && missing_keys+=("Google")
    
    if [[ ${#missing_keys[@]} -eq 0 ]]; then
        log SUCCESS "Todas API keys configuradas!"
        return 0
    fi
    
    log WARN "${#missing_keys[@]} API key(s) não configurada(s):"
    for key in "${missing_keys[@]}"; do
        echo "   ❌ $key"
    done
    
    echo -e "\n${CYAN}Deseja ver tutorial de configuração?${NC}"
    echo "[T] Tutorial completo"
    echo "[P] Pular (continuar sem keys)"
    echo "[C] Configurar agora (abre config.sh)"
    read -rp "Escolha: " choice
    
    case $choice in
        T|t) show_api_tutorial "${missing_keys[@]}" ;;
        C|c) "${EDITOR:-nano}" "$OPENPIPES_CONFIG" ;;
        *) log WARN "Continuando sem API keys (funcionalidade limitada)" ;;
    esac
}

show_api_tutorial() {
    local keys=("$@")
    clear
    echo -e "${CYAN}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║       🔑 TUTORIAL API KEYS                ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════╝${NC}\n"
    
    for key in "${keys[@]}"; do
        case $key in
            SecurityTrails)
                echo -e "${YELLOW}▸ SecurityTrails${NC} (Subdomain Discovery)"
                echo "   URL: https://securitytrails.com/app/account/credentials"
                echo "   Config: securitytrailskey=\"SUA_KEY_AQUI\""
                ;;
            OpenAI)
                echo -e "${YELLOW}▸ OpenAI GPT-4${NC} (Vuln Enrichment)"
                echo "   URL: https://platform.openai.com/api-keys"
                echo "   Config: OPENAI_API_KEY=\"sk-...\""
                ;;
            SerpAPI)
                echo -e "${YELLOW}▸ SerpAPI${NC} (OSINT People)"
                echo "   URL: https://serpapi.com/manage-api-key"
                echo "   Config: SERPAPI_KEY=\"...\""
                ;;
            Google)
                echo -e "${YELLOW}▸ Google Custom Search${NC} (Document Discovery)"
                echo "   URL: https://console.cloud.google.com/apis/credentials"
                echo "   Config: GOOGLE_API_KEY=\"...\" + GOOGLE_CSE_ID=\"...\""
                ;;
        esac
        echo ""
    done
    
    echo -e "${CYAN}Arquivo de configuração:${NC} $OPENPIPES_CONFIG"
    echo -e "Edite com: ${GREEN}openpipes config${NC} ou ${GREEN}nano ~/.openpipes/config.sh${NC}"
    read -rp "Pressione ENTER para continuar..."
}

# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────
main() {
    clear
    echo -e "${CYAN}"
    cat << 'EOF'
   ___  ____                 ____  _                 ____  
 
                                     |_|                    
                     INICIALIZADOR v2.1
EOF
    echo -e "${NC}\n"
    
    preflight_checks
    
    # Checa se projeto existe
    if [[ -d "$proj_path" ]]; then
        log WARN "Projeto '$proj_name' já existe em $proj_path"
        read -rp "Sobrescrever? [s/N]: " overwrite
        [[ ! "$overwrite" =~ ^[Ss]$ ]] && { log INFO "Operação cancelada"; exit 0; }
    fi
    
    log INFO "Inicializando projeto: $proj_name"
    
    create_explorer_structure
    create_obsidian_structure
    validate_api_keys
    
    # Summary
    echo -e "\n${GREEN}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     ✅ PROJETO CRIADO COM SUCESSO!        ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════╝${NC}\n"
    
    echo -e "${CYAN}📁 Estrutura Explorador:${NC}"
    tree -L 2 "$proj_path" 2>/dev/null || ls -lR "$proj_path"
    
    echo -e "\n${CYAN}📝 Obsidian Vault:${NC} $OBSIDIAN_PROJ_PATH"
    
    echo -e "\n${CYAN}🎯 PRÓXIMOS PASSOS:${NC}"
    echo "1. Popule domains.txt: nano $proj_path/domains.txt"
    echo "2. Configure API keys: openpipes config"
    echo "3. Inicie pipeline: openpipes"
}

main "$@"
