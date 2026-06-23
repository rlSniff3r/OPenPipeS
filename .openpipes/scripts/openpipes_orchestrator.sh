#!/usr/bin/env bash

################################################################################
#  OPenPipeS v2.2 - Orchestrador Principal (Versão Clean/Homologada)
################################################################################

set -uo pipefail

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURAÇÃO INICIAL
# ═══════════════════════════════════════════════════════════════════════════

# Detecta diretório do script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Paths críticos
OPENPIPES_HOME="${HOME}/.openpipes"
OPENPIPES_CONFIG="${OPENPIPES_HOME}/config.sh"
OPENPIPES_BIN="${OPENPIPES_HOME}/bin"
OPENPIPES_TEMPLATES="${OPENPIPES_HOME}/.templates"
OPENPIPES_CACHE="${HOME}/.openpipes_cache"

source "$OPENPIPES_CONFIG"

# Cores ANSI
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Variáveis globais (carregadas do config.sh)
proj_dir="${proj_dir:-}"
proj_name="${proj_name:-}"
obsdir="${obsdir:-}"
proj_path="${proj_dir}/${proj_name}"
NMAP_DIR="${proj_path}/Varreduras"
RECON_DIR="${proj_path}/Recon"
OSINT_DIR="${proj_path}/OSINT"
LOG_DIR="${proj_path}/Logs"
SCREENSHOT_DIR="${proj_path}/Screenshots"

# ═══════════════════════════════════════════════════════════════════════════
# FUNÇÕES DE LOGGING
# ═══════════════════════════════════════════════════════════════════════════

log() {
    local level="$1"
    shift
    local message="$*"
    
    case "$level" in
        INFO) echo -e "${BLUE}[INFO]${NC} $message" ;;
        SUCCESS) echo -e "${GREEN}[✓]${NC} $message" ;;
        WARN) echo -e "${YELLOW}[!]${NC} $message" ;;
        ERROR) echo -e "${RED}[✗]${NC} $message" >&2 ;;
        STEP) echo -e "${CYAN}[→]${NC} $message" ;;
    esac
}

# ═══════════════════════════════════════════════════════════════════════════
# EXECUÇÃO DE MÓDULOS
# ═══════════════════════════════════════════════════════════════════════════

validate_module_dependencies() {
    local module="$1"
    # Validações mantidas para as ferramentas que restaram
    return 0
}

run_module() {
    local module_name="$1"
    shift
    local module_script="${OPENPIPES_BIN}/${module_name}"
    local current_dir="$(pwd)"
    
    if [[ ! -x "$module_script" ]]; then
        log ERROR "Módulo não encontrado ou não executável: $module_script"
        return 1
    fi
    
    case "$module_name" in
        recon)
            if [[ ! -f "$proj_path/domains.txt" ]]; then
                log ERROR "Arquivo domains.txt não encontrado: $proj_path/domains.txt"
                return 1
            fi
            cd "$proj_path" || return 1
            ;;
        nwrapper)
            cd "$NMAP_DIR" 2>/dev/null || mkdir -p "$NMAP_DIR" && cd "$NMAP_DIR"
            nwrapper -f targets.txt || return 1
            ;;
        *)
            cd "$proj_path" || return 1
            ;;
    esac
    
    log STEP "Executando módulo: $module_name"
    "$module_script" "$@"
    local exit_code=$?
    
    cd "$current_dir" || true
    
    if [[ $exit_code -eq 0 ]]; then
        log SUCCESS "Módulo $module_name concluído"
    else
        log ERROR "Módulo $module_name falhou (exit code: $exit_code)"
    fi
    return $exit_code
}

# ═══════════════════════════════════════════════════════════════════════════
# PIPELINE COMPLETO
# ═══════════════════════════════════════════════════════════════════════════

run_full_pipeline() {
    log INFO "═══════════════════════════════════════════"
    log INFO "  INICIANDO PIPELINE COMPLETO (CLEAN)"
    log INFO "═══════════════════════════════════════════"
    
    local modules=(
        "recon"
        "nwrapper"
        "cria-alvos"
        "httpx-runner"
        "katana-buster"
        "jsfinder-runner"
        "screenshot-runner"
        "gf-summary"
        "whois-enricher"
    )
    
    local total=${#modules[@]}
    local current=0
    local failed_modules=()
    local current_dir="$(pwd)"
    
    for module in "${modules[@]}"; do
        ((current++))
        echo -e "\n${CYAN}╔════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║ [$current/$total] Executando: $module${NC}"
        echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
        
        if run_module "$module"; then
            log SUCCESS "[$current/$total] $module concluído"
        else
            log ERROR "[$current/$total] $module falhou"
            failed_modules+=("$module")
            read -rp "Continuar pipeline mesmo com falha? [s/N]: " continue_choice
            if [[ ! "$continue_choice" =~ ^[Ss]$ ]]; then
                log ERROR "Pipeline abortado"
                cd "$current_dir"
                return 1
            fi
        fi
        sleep 1
    done
    
    cd "$current_dir"
    echo -e "\n${CYAN}╔════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  PIPELINE COMPLETO - RELATÓRIO FINAL   ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════╝${NC}\n"
    
    if [[ ${#failed_modules[@]} -eq 0 ]]; then
        log SUCCESS "✅ Pipeline concluído com sucesso!"
    else
        log WARN "⚠  Pipeline concluído com ${#failed_modules[@]} falha(s)"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# MENU PRINCIPAL
# ═══════════════════════════════════════════════════════════════════════════

press_enter() {
    read -rp "Pressione ENTER para continuar..." -t 0.1
    read -rp ""
}

show_banner() {
    clear
    cat << 'EOF'
╔════════════════════════════════════════════════════════════════╗
║              ___  ____             ____  _                     ║
║            / _ \|  _ \ ___ _ __  |  _ \(_)_ __   ___           ║
║           | | | | |_) / _ \ '_ \ | |_) | | '_ \ / _ \          ║
║           | |_| |  __/  __/ | | ||  __/| | |_) |  __/          ║
║            \___/|_|   \___|_| |_||_|   |_| .__/ \___|          ║
║                                          |_|                   ║
║         🔍 Obsidian Pentest Pipeline Stack (Homologado)        ║
╚════════════════════════════════════════════════════════════════╝
EOF
}

show_menu() {
    show_banner
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  PROJETO ATIVO: ${YELLOW}$proj_name${NC}${CYAN}                                    ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║  MÓDULOS CORE                                                ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[01]${NC} Reconhecimento (Subdomain Discovery)                   ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[02]${NC} Scanning Nmap (Port Scanning)                          ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[03]${NC} Criar Estrutura Obsidian (Alvos)                       ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[04]${NC} HTTP Probing (HTTPx)                                   ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[05]${NC} Web Crawling (Katana)                                  ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[06]${NC} Fuzzing (Feroxbuster)                                  ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[07]${NC} Katana + Feroxbuster (Combo)                           ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[08]${NC} JSFinder (JavaScript Analysis)                         ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[09]${NC} Screenshots (Smart Dedupe)                             ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[10]${NC} GF Summary (Pattern Matching)                          ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[11]${NC} WHOIS Enrichment                                       ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[12]${NC} Gestão de Vulnerabilidades                             ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║  PIPELINE & UTILITÁRIOS                                      ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[13]${NC} Pipeline Completo (Auto-Run)                           ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[14]${NC} Listar Alvos                                           ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[15]${NC} Editar domains.txt                                     ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[16]${NC} Mostrar Últimos Outputs                                ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[17]${NC} Configuração / Status                                  ║${NC}"
    echo -e "${CYAN}║  ${RED}[00]${NC} Sair                                                   ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}\n"

    read -rp "Escolha uma opção: " choice
    handle_menu_choice "$choice"
}

handle_menu_choice() {
    local choice="$1"
    
    case "$choice" in
        01|1) run_module "recon"; press_enter ;;
        02|2) run_module "nwrapper"; press_enter ;;
        03|3) run_module "cria-alvos"; press_enter ;;
        04|4) run_module "httpx-runner"; press_enter ;;
        05|5) run_module "katana-runner"; press_enter ;;
        06|6) run_module "feroxbuster-runner"; press_enter ;;
        07|7) run_module "katana-buster"; press_enter ;;
        08|8) run_module "jsfinder-runner"; press_enter ;;
        09|9) run_module "screenshot-runner"; press_enter ;;
        10) run_module "gf-summary"; press_enter ;;
        11) run_module "whois-enricher"; press_enter ;;
        12) run_module "cria-vulnerabilidades"; press_enter ;;
        13) run_full_pipeline; press_enter ;;
        14) show_targets_list; press_enter ;;
        15) "${EDITOR:-nano}" "$proj_path/domains.txt"; press_enter ;;
        16) show_recent_outputs; press_enter ;;
        17) "${EDITOR:-nano}" "$OPENPIPES_CONFIG"; press_enter ;;
        00|0) log INFO "Encerrando OPenPipeS..."; exit 0 ;;
        *) log ERROR "Opção inválida: $choice"; press_enter ;;
    esac
}

show_targets_list() {
    clear
    echo -e "${CYAN}📋 ALVOS CONFIGURADOS${NC}"
    if [[ -f "$proj_path/domains.txt" ]]; then
        cat "$proj_path/domains.txt"
    else
        echo "Nenhum alvo (domains.txt ausente)"
    fi
}

show_recent_outputs() {
    clear
    echo -e "${CYAN}📊 OUTPUTS RECENTES${NC}"
    find "$proj_path" -type f \( -name "*.md" -o -name "*.json" \) -printf '%T@ %p\n' 2>/dev/null | \
        sort -rn | head -10 | cut -d' ' -f2- | while read -r file; do
        echo " • $(basename "$file")"
    done
}

main() {
    if [[ -z "$proj_name" ]]; then
        log ERROR "Projeto não configurado no config.sh"
        exit 1
    fi
    while true; do show_menu; done
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi