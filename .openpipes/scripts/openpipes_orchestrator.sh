#!/usr/bin/env bash

################################################################################
#
#  OPenPipeS v2.1 - Orchestrador Principal
#  Framework de Reconhecimento Automatizado com Integração Obsidian MD
#
#  Autor: Rafael Luís da Silva
#  Descrição: Menu interativo para orquestração de módulos de pentest
#  Responsabilidade: APENAS orquestração - setup é responsabilidade do init
#
################################################################################

set -uo pipefail

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURAÇÃO INICIAL
# ═══════════════════════════════════════════════════════════════════════════

source $OPENPIPES_CONFIG

# Detecta diretório do script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Paths críticos
OPENPIPES_HOME="${HOME}/.openpipes"
OPENPIPES_CONFIG="${OPENPIPES_HOME}/config.sh"
OPENPIPES_BIN="${OPENPIPES_HOME}/bin"
OPENPIPES_TEMPLATES="${OPENPIPES_HOME}/.templates"
OPENPIPES_CACHE="${HOME}/.openpipes_cache"

# Cores ANSI
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m'

# Variáveis globais (carregadas do config.sh)
proj_dir=""
proj_name=""
proj_path=""
obsdir=""
NMAP_DIR=""
RECON_DIR=""
OSINT_DIR=""
LOG_DIR=""
SCREENSHOT_DIR=""

# ═══════════════════════════════════════════════════════════════════════════
# FUNÇÕES DE LOGGING
# ═══════════════════════════════════════════════════════════════════════════

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        INFO)
            echo -e "${BLUE}[INFO]${NC} $message"
            ;;
        SUCCESS)
            echo -e "${GREEN}[✓]${NC} $message"
            ;;
        WARN)
            echo -e "${YELLOW}[!]${NC} $message"
            ;;
        ERROR)
            echo -e "${RED}[✗]${NC} $message" >&2
            ;;
        STEP)
            echo -e "${CYAN}[→]${NC} $message"
            ;;
        DEBUG)
            if [[ "${DEBUG:-0}" == "1" ]]; then
                echo -e "${MAGENTA}[DEBUG]${NC} $message"
            fi
            ;;
    esac
}

# ═══════════════════════════════════════════════════════════════════════════
# PRÉ-FLIGHT CHECKS
# ═══════════════════════════════════════════════════════════════════════════

check_config() {
    log INFO "Verificando configuração..."
    
    if [[ ! -f "$OPENPIPES_CONFIG" ]]; then
        log ERROR "config.sh não encontrado em $OPENPIPES_CONFIG"
        log ERROR "Execute: make install"
        return 1
    fi
    
    # Source config.sh
    source "$OPENPIPES_CONFIG" || {
        log ERROR "Erro ao carregar config.sh"
        return 1
    }
    
    # Valida variáveis essenciais
    for var in proj_name proj_dir obsdir; do
        if [[ -z "${!var:-}" ]]; then
            log ERROR "Variável \$$var não definida em config.sh"
            return 1
        fi
    done
    
    # Calcula paths derivados
    proj_path="${proj_dir}/${proj_name}"
    NMAP_DIR="${proj_path}/Varreduras"
    RECON_DIR="${proj_path}/Recon"
    OSINT_DIR="${proj_path}/OSINT"
    LOG_DIR="${proj_path}/Logs"
	SCREENSHOT_DIR="${proj_path}/Screenshots"
    
    log SUCCESS "config.sh carregado com sucesso"
    return 0
}

check_openpipes_structure() {
    log INFO "Verificando estrutura OPenPipeS..."
    
    # Valida diretórios críticos
    if [[ ! -d "$OPENPIPES_HOME" ]]; then
        log ERROR "Diretório OPenPipeS não encontrado: $OPENPIPES_HOME"
        return 1
    fi
    
    if [[ ! -d "$OPENPIPES_BIN" ]]; then
        log ERROR "Diretório bin não encontrado: $OPENPIPES_BIN"
        return 1
    fi
    
    if [[ ! -d "$OPENPIPES_TEMPLATES" ]]; then
        log WARN "Diretório templates não encontrado: $OPENPIPES_TEMPLATES"
    fi
    
    log SUCCESS "Estrutura OPenPipeS OK"
    return 0
}

# ═══════════════════════════════════════════════════════════════════════════
# VALIDAÇÃO DE PROJETO
# ═══════════════════════════════════════════════════════════════════════════

validate_project() {
    log INFO "Validando estrutura do projeto..."
    
    local errors=0
    local pentest_root="${obsdir}/${proj_name}/Pentest"
    
    # 1. Valida diretório principal
    if [[ ! -d "$proj_path" ]]; then
        log ERROR "Diretório do projeto não existe: $proj_path"
        ((errors++))
    else
        log SUCCESS "Diretório do projeto existe"
    fi
    
    # 2. Valida subdirs explorador
    for dir in "$NMAP_DIR" "$RECON_DIR" "$OSINT_DIR" "$LOG_DIR"; do
        if [[ ! -d "$dir" ]]; then
            log WARN "Subdiretório ausente: $dir"
        fi
    done
    
    # 3. Valida domains.txt
    if [[ ! -f "$proj_path/domains.txt" ]]; then
        log ERROR "Arquivo domains.txt não encontrado em $proj_path"
        ((errors++))
    else
        local valid_lines=$(grep -v '^\s*#' "$proj_path/domains.txt" 2>/dev/null | grep -v '^\s*$' | wc -l)
        if [[ $valid_lines -eq 0 ]]; then
            log WARN "domains.txt está vazio ou contém apenas comentários"
            log WARN "Adicione alvos antes de executar reconhecimento"
        else
            log SUCCESS "domains.txt contém $valid_lines alvo(s)"
        fi
    fi
    
    # 4. Valida Obsidian vault
    if [[ ! -d "$obsdir" ]]; then
        log ERROR "Obsidian vault não encontrado: $obsdir"
        ((errors++))
    else
        log SUCCESS "Obsidian vault encontrado"
    fi
    
    # 5. Valida estrutura Obsidian do projeto
    if [[ ! -d "$pentest_root" ]]; then
        log ERROR "Estrutura Obsidian do projeto não existe: $pentest_root"
        ((errors++))
    else
        log SUCCESS "Estrutura Obsidian do projeto existe"
        
        # Valida subdirs Obsidian
        for dir in "$pentest_root/Alvos" "$pentest_root/OSINT"; do
            if [[ ! -d "$dir" ]]; then
                log WARN "Subdiretório Obsidian ausente: $dir"
            fi
        done
    fi
    
    # 6. Resultado final
    if [[ $errors -gt 0 ]]; then
        log ERROR "Validação falhou com $errors erro(s) crítico(s)"
        log ERROR "Execute: init-openpipes"
        return 1
    fi
    
    log SUCCESS "Validação concluída (projeto OK)"
    return 0
}

# ═══════════════════════════════════════════════════════════════════════════
# VALIDAÇÃO DE FERRAMENTAS
# ═══════════════════════════════════════════════════════════════════════════

check_tool_dependency() {
    local tool="$1"
    
    if ! command -v "$tool" &>/dev/null; then
        return 1
    fi
    return 0
}

validate_module_dependencies() {
    local module="$1"
    
    case "$module" in
        recon)
            for tool in dnsrecon amass; do
                if ! check_tool_dependency "$tool"; then
                    log ERROR "Dependência ausente: $tool"
                    return 1
                fi
            done
            ;;
        nwrapper)
            if ! check_tool_dependency nmap; then
                log ERROR "Dependência ausente: nmap"
                return 1
            fi
            ;;
        httpx-runner)
            if ! check_tool_dependency httpx; then
                log ERROR "Dependência ausente: httpx"
                log ERROR "Instale: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
                return 1
            fi
            ;;
        nuclei-runner)
            if ! check_tool_dependency nuclei; then
                log ERROR "Dependência ausente: nuclei"
                return 1
            fi
            ;;
        katana-buster)
            for tool in katana feroxbuster; do
                if ! check_tool_dependency "$tool"; then
                    log ERROR "Dependência ausente: $tool"
                    return 1
                fi
            done
            ;;
        jsfinder-runner)
            if ! check_tool_dependency linkfinder.py; then
                log ERROR "Dependência ausente: linkfinder.py"
                return 1
            fi
            ;;
        gf-summary)
            if ! check_tool_dependency gf; then
                log ERROR "Dependência ausente: gf (GrepFuzzable)"
                return 1
            fi
            ;;
		screenshot-runner)
            if ! check_tool_dependency gf; then
                log ERROR "Dependência ausente: gf (GrepFuzzable)"
                return 1
            fi
            ;;
        osint-runner-people)
            if ! check_tool_dependency python3; then
                log ERROR "Dependência ausente: python3"
                return 1
            fi
            ;;
    esac
    
    return 0
}

# ═══════════════════════════════════════════════════════════════════════════
# EXECUÇÃO DE MÓDULOS
# ═══════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════
# EXECUÇÃO DE MÓDULOS COM PRÉ-FLIGHT CHECKS
# ═══════════════════════════════════════════════════════════════════════════

run_module() {
    local module_name="$1"
    shift  # Remove module_name dos argumentos
    
    local module_script="${OPENPIPES_BIN}/${module_name}"
    local current_dir="$(pwd)"
    
    # 1. Valida script existe e é executável
    if [[ ! -x "$module_script" ]]; then
        log ERROR "Módulo não encontrado ou não executável: $module_script"
        return 1
    fi
    
    # 2. Valida dependências
    if ! validate_module_dependencies "$module_name"; then
        log ERROR "Dependências não atendidas para: $module_name"
        return 1
    fi
    
    # 3. PRÉ-FLIGHT CHECKS específicos por módulo
    case "$module_name" in
        recon)
            # Verifica se DOMAIN_FILE está definido e existe
            if [[ -z "${DOMAIN_FILE:-}" ]]; then
                log ERROR "Variável DOMAIN_FILE não está definida em config.sh"
                return 1
            fi
            
            if [[ ! -f "$DOMAIN_FILE" ]]; then
                log ERROR "Arquivo DOMAIN_FILE não encontrado: $DOMAIN_FILE"
                return 1
            fi
            
            # Valida se tem conteúdo (não vazio, não só comentários)
            if ! grep -qvE '^\s*(#|$)' "$DOMAIN_FILE" 2>/dev/null; then
                log ERROR "DOMAIN_FILE está vazio ou contém apenas comentários: $DOMAIN_FILE"
                return 1
            fi
            
            local domain_count=$(grep -v '^\s*#' "$DOMAIN_FILE" 2>/dev/null | grep -v '^\s*$' | wc -l)
            log SUCCESS "DOMAIN_FILE validado: $domain_count alvo(s)"
            
            # Muda para proj_path (onde recon.sh espera encontrar domains.txt)
            log STEP "Mudando para diretório do projeto: $proj_path"
            cd "$proj_path" || {
                log ERROR "Falha ao mudar para: $proj_path"
                return 1
            }
            ;;
        
        nwrapper)
            # Valida que há outputs de recon
            if [[ ! -d "$RECON_DIR" ]] || [[ -z "$(ls -A "$RECON_DIR" 2>/dev/null)" ]]; then
                log WARN "Nenhum output de reconhecimento encontrado"
                log WARN "Execute [R] Reconhecimento primeiro"
            fi
            (
            cd "$NMAP_DIR" 
            nwrapper -f targets.txt 
            ) || return 1
            ;;
        
        httpx-runner|katana-buster|nuclei-runner|jsfinder-runner|gf-summary)
            # Valida que há outputs de nmap
            if [[ ! -d "$NMAP_DIR" ]] || [[ -z "$(ls -A "$NMAP_DIR" 2>/dev/null)" ]]; then
                log ERROR "Nenhum output de nmap encontrado"
                log ERROR "Execute [S] Scanning primeiro"
                return 1
            fi
            
            cd "$proj_path" || return 1
            ;;
        
        whois-enricher)
            # Valida recon output
            if [[ ! -d "$RECON_DIR" ]] || [[ -z "$(ls -A "$RECON_DIR" 2>/dev/null)" ]]; then
                log ERROR "Nenhum output de reconhecimento encontrado"
                log ERROR "Execute [R] Reconhecimento primeiro"
                return 1
            fi
            ;;
			
       screenshot-runner)
            # Valida recon output
            if [[ ! -d "$RECON_DIR" ]] || [[ -z "$(ls -A "$RECON_DIR" 2>/dev/null)" ]]; then
                log ERROR "Nenhum output de reconhecimento encontrado"
                log ERROR "Execute [R] Reconhecimento primeiro"
                return 1
            fi
            
            cd "$proj_path" || return 1
            ;;
        
        osint-runner-people)
            cd "$proj_path" || return 1
            ;;
        
        cria-alvos)
            # Valida que há outputs de nmap
            if [[ ! -d "$NMAP_DIR" ]] || [[ -z "$(ls -A "$NMAP_DIR" 2>/dev/null)" ]]; then
                log ERROR "Nenhum output de nmap encontrado"
                log ERROR "Execute [S] Scanning primeiro"
                return 1
            fi
            
            cd "$proj_path" || return 1
            ;;
        
        cria-vulnerabilidades)
            cd "$proj_path" || return 1
            ;;

        id-manager)
            cd "$proj_path" || return 1
            echo -e "\n${CYAN}════════════════════════════════════════════════════════════════${NC}"
            echo -e "${BOLD}🔐 Executando Identities Manager...${NC}"
            echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}\n"
            
            # Verifica se o script existe
            if [[ -f "${HOME}/.openpipes/scripts/identities_manager.sh" ]]; then
                bash "${HOME}/.openpipes/scripts/identities_manager.sh"
            else
                echo -e "${RED}❌ ERRO: Script identities_manager.sh não encontrado!${NC}"
                echo -e "Verifique a instalação do OpenPipeS.\n"
            fi
            ;;
            
    esac
    
    # 4. Executa módulo (EXATAMENTE COMO ANTES - SEM ALTERAÇÕES)
    log STEP "Executando módulo: $module_name"
    
    "$module_script" "$@"
    local exit_code=$?
    
    # 5. Volta ao diretório original
    cd "$current_dir" || {
        log WARN "Falha ao voltar para diretório original: $current_dir"
    }
    
    # 6. Feedback
    if [[ $exit_code -eq 0 ]]; then
        log SUCCESS "Módulo $module_name concluído"
    else
        log ERROR "Módulo $module_name falhou (exit code: $exit_code)"
    fi
    
    return $exit_code
}


# ═══════════════════════════════════════════════════════════════════════════
# PIPELINE COMPLETO COM PRÉ-FLIGHT CHECKS
# ═══════════════════════════════════════════════════════════════════════════

run_full_pipeline() {
    log INFO "═══════════════════════════════════════════"
    log INFO "  INICIANDO PIPELINE COMPLETO"
    log INFO "═══════════════════════════════════════════"
    
    # Valida DOMAIN_FILE antes de começar
    if [[ -z "${DOMAIN_FILE:-}" ]]; then
        log ERROR "Variável DOMAIN_FILE não está definida em config.sh"
        return 1
    fi
    
    if [[ ! -f "$DOMAIN_FILE" ]]; then
        log ERROR "Arquivo DOMAIN_FILE não encontrado: $DOMAIN_FILE"
        return 1
    fi
    
    # Valida se tem conteúdo
    if ! grep -qvE '^\s*(#|$)' "$DOMAIN_FILE" 2>/dev/null; then
        log ERROR "DOMAIN_FILE está vazio ou contém apenas comentários"
        log ERROR "Popule com alvos antes de executar pipeline"
        return 1
    fi
    
    local valid_lines=$(grep -v '^\s*#' "$DOMAIN_FILE" 2>/dev/null | grep -v '^\s*$' | wc -l)
    log SUCCESS "Pipeline iniciado com $valid_lines alvo(s)"
    
    # Array de módulos (ordem lógica)
    local modules=(
        "recon"
        "nwrapper"
        "cria-alvos"
        "httpx-runner"
        "katana-buster"
        "nuclei-runner"
        "jsfinder-runner"
        "gf-summary"
        "whois-enricher"
		"screenshot-runner"
        "id-manager"
    )
    
    local total=${#modules[@]}
    local current=0
    local failed_modules=()
    local current_dir="$(pwd)"
    
    # Executa pipeline
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
            
            # Pergunta se continua ou aborta
            read -rp "Continuar pipeline mesmo com falha? [s/N]: " continue_choice
            if [[ ! "$continue_choice" =~ ^[Ss]$ ]]; then
                log ERROR "Pipeline abortado"
                cd "$current_dir"
                return 1
            fi
        fi
        
        sleep 1  # Pequeno delay entre módulos
    done
    
    # Volta ao diretório original
    cd "$current_dir"
    
    # Relatório final
    echo -e "\n${CYAN}╔════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  PIPELINE COMPLETO - RELATÓRIO FINAL   ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════╝${NC}\n"
    
    if [[ ${#failed_modules[@]} -eq 0 ]]; then
        log SUCCESS "✅ Pipeline concluído com sucesso!"
        log SUCCESS "Todos os $total módulos executados"
    else
        log WARN "⚠  Pipeline concluído com ${#failed_modules[@]} falha(s):"
        for failed in "${failed_modules[@]}"; do
            echo "   ❌ $failed"
        done
    fi
    
    echo -e "\n${CYAN}📊 Outputs disponíveis em:${NC}"
    echo "   Explorador: $proj_path"
    echo "   Obsidian: ${obsdir}/${proj_name}/Pentest"
    
    return 0
}


# ═══════════════════════════════════════════════════════════════════════════
# UTILITÁRIOS
# ═══════════════════════════════════════════════════════════════════════════

press_enter() {
    read -rp "Pressione ENTER para continuar..." -t 0.1
    read -rp ""
}

show_banner() {
    clear
    cat << 'EOF'
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║            ___  ____             ____  _                       ║
║          / _ \|  _ \ ___ _ __  |  _ \(_)_ __   ___  ___        ║
║         | | | | |_) / _ \ '_ \ | |_) | | '_ \ / _ \/ __|       ║
║         | |_| |  __/  __/ | | ||  __/| | |_) |  __/\__ \       ║
║          \___/|_|   \___|_| |_||_|   |_| .__/ \___||___/       ║
║                                             |_|                ║
║                                                                ║
║              🔍 Obsidian Pentest Pipeline Stack v2.1           ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
EOF
}

show_status_bar() {
    echo -e "${CYAN}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  PROJETO ATIVO: ${YELLOW}$proj_name${NC}${CYAN}                        ║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════╣${NC}"
    
    # Checa API keys (apenas aviso)
    local keys_configured=0
    local keys_total=5
    
    [[ -n "${securitytrailskey:-}" ]] && ((keys_configured++))
    [[ -n "${OPENAI_API_KEY:-}" ]] && ((keys_configured++))
    [[ -n "${SERPAPI_KEY:-}" ]] && ((keys_configured++))
    [[ -n "${GOOGLE_API_KEY:-}" ]] && ((keys_configured++))
    [[ -n "${GOOGLE_CSE_ID:-}" ]] && ((keys_configured++))
    
    # Status visual
    if [[ $keys_configured -eq 0 ]]; then
        echo -e "${RED}⚠  Nenhuma API Key configurada${NC}"
        echo -e "   ${YELLOW}Funcionalidade limitada!${NC} Configure: ${GREEN}[C]${NC}"
    elif [[ $keys_configured -lt 3 ]]; then
        echo -e "${YELLOW}⚠  API Keys parciais ($keys_configured/$keys_total)${NC}"
        echo -e "   Alguns módulos podem falhar. Configure:    ${GREEN}[C]${NC}"
    else
        echo -e "${GREEN}✓  API Keys: $keys_configured/$keys_total configuradas${NC}"
    fi
    
    echo -e "${CYAN}╚════════════════════════════════════════════════════╝${NC}\n"
}

# ═══════════════════════════════════════════════════════════════════════════
# MENU PRINCIPAL
# ═══════════════════════════════════════════════════════════════════════════

show_menu() {
    show_banner
    show_status_bar
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                   MÓDULOS DISPONÍVEIS                        ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║  RECONHECIMENTO                                              ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[R]${NC} Reconhecimento (Subdomain Discovery)                    ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[S]${NC} Scanning Nmap (Port Scanning)                           ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[W]${NC} WHOIS Enrichment                                        ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║  WEB DISCOVERY (MODULAR)                                     ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[H]${NC} HTTP Probing (HTTPx + Hybrid Targets)                   ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[K]${NC} Web Crawling (Katana)                                   ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[C]${NC} Context Wordlist Builder (Tech-Aware)                   ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[F]${NC} Fuzzing (Feroxbuster + Context Wordlist)                ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[J]${NC} JSFinder (JavaScript Analysis)                          ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[I]${NC} Screenshots (Smart Dedupe)                              ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║  ANÁLISE & VULNERABILIDADES                                  ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[N]${NC} Nuclei Scan (Vulnerability Scanner)                     ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[G]${NC} GF Summary (Pattern Matching)                           ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[O]${NC} OSINT People                                            ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[U]${NC} Identity Manager (Credenciais, Hashes, etc.)            ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║  PIPELINE & GESTÃO                                           ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[P]${NC} Pipeline Completo (R→S→H→K→C→F→N→J→I→G→W)              ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[L]${NC} Pipeline Legacy (katana-buster antigo)                  ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[V]${NC} Criar/editar vulnerabilidades                           ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║  UTILITÁRIOS                                                 ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[T]${NC} Listar Alvos                                            ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[E]${NC} Editar domains.txt                                      ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[M]${NC} Mostrar Últimos Outputs                                 ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[X]${NC} Status de Ferramentas                                   ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[Z]${NC} Configuração                                            ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[A]${NC} Ajuda                                                   ║${NC}"
    echo -e "${CYAN}║  ${GREEN}[Q]${NC} Sair                                                    ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}\n"

    read -rp "Escolha uma opção: " choice
handle_menu_choice "$choice"
}


handle_menu_choice() {
    local choice="$1"
    
    local choice="$1"
    case "$choice" in
        # ... casos existentes ...
        
        [Kk])
            log STEP "Web Crawling (Katana)..."
            run_module "katana-runner"
            press_enter
            ;;
        [Cc])
            log STEP "Context Wordlist Builder..."
            run_module "context-wordlist-builder"
            press_enter
            ;;
        [Ff])
            log STEP "Fuzzing (Feroxbuster)..."
            run_module "feroxbuster-runner"
            press_enter
            ;;
        [Ll])
            log STEP "Pipeline Legacy (katana-buster antigo)..."
            log WARN "DEPRECATED: Este módulo será removido na v3.0"
            run_module "katana-buster"
            press_enter
            ;;

        [Rr])
            log STEP "Reconhecimento (Subdomain Discovery)..."
            run_module "recon"
            press_enter
            ;;
        [Ss])
            log STEP "Scanning Nmap (Port Scanning)..."
            run_module "nwrapper"
            press_enter
            ;;
        [Hh])
            log STEP "HTTP Probing (HTTPx)..."
            run_module "httpx-runner"
            press_enter
            ;;
        [Nn])
            log STEP "Nuclei Scan (Vulnerability Scanner)..."
            run_module "nuclei-runner"
            press_enter
            ;;
        [Jj])
            log STEP "JSFinder (JavaScript Analysis)..."
            run_module "jsfinder-runner"
            press_enter
            ;;
        [Gg])
            log STEP "GF Summary (Pattern Matching)..."
            run_module "gf-summary"
            press_enter
            ;;
        [Uu])
            log STEP "Identities Manager (Creds, E-mails, etc.)..."
            run_module "id-manager"
            press_enter
            ;;
        [Ww])
            log STEP "WHOIS Enrichment..."
            run_module "whois-enricher"
            press_enter
            ;;
        [Oo])
            log STEP "OSINT People..."
            run_module "osint-runner-people"
            press_enter
            ;;
        [Ii])
            log SETOP "Screenshot Module..."
            run_module "screenshot-runner"
            ;;
        [Pp])
            run_full_pipeline
            press_enter
            ;;
        [Vv])
            log STEP "Gestão de Vulnerabilidades..."
            run_module "cria-vulnerabilidades"
            press_enter
            ;;
        [Ee])
            show_edit_domains
            press_enter
            ;;
        [Mm])
            show_recent_outputs
            press_enter
            ;;
        [Tt])
            show_status
            ;;
        [Aa])
            show_help
            ;;
        [Qq])
            log INFO "Encerrando OPenPipeS..."
            exit 0
            ;;
        *)
            log ERROR "Opção inválida: $choice"
            press_enter
            ;;
    esac
}

# ═══════════════════════════════════════════════════════════════════════════
# FUNÇÕES DE UTILITÁRIOS
# ═══════════════════════════════════════════════════════════════════════════

show_targets_list() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              📋 ALVOS CONFIGURADOS                 ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════╝${NC}\n"
    
    if [[ ! -f "$proj_path/domains.txt" ]]; then
        log ERROR "domains.txt não encontrado"
        return
    fi
    
    local count=0
    while IFS= read -r domain; do
        # Ignora comentários e linhas vazias
        [[ "$domain" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$domain" ]] && continue
        
        ((count++))
        echo "   $count. $domain"
    done < "$proj_path/domains.txt"
    
    if [[ $count -eq 0 ]]; then
        log WARN "Nenhum alvo configurado em domains.txt"
    else
        log SUCCESS "Total de $count alvo(s) configurado(s)"
    fi
}

show_edit_domains() {
    log STEP "Editando domains.txt..."
    
    if [[ ! -f "$proj_path/domains.txt" ]]; then
        log ERROR "domains.txt não encontrado em $proj_path"
        return
    fi
    
    "${EDITOR:-nano}" "$proj_path/domains.txt"
    log SUCCESS "domains.txt atualizado"
}

show_recent_outputs() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              📊 OUTPUTS RECENTES                   ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════╝${NC}\n"
    
    echo -e "${YELLOW}▸ Últimos scans Nmap:${NC}"
    find "$NMAP_DIR" -type f -name "*.nmap" -printf '%T@ %p\n' 2>/dev/null | \
        sort -rn | head -5 | cut -d' ' -f2- | while read -r file; do
        echo "   • $(basename "$file")"
    done
    
    echo -e "\n${YELLOW}▸ Últimos relatórios:${NC}"
    find "$proj_path" -type f \( -name "*.md" -o -name "*.json" \) -printf '%T@ %p\n' 2>/dev/null | \
        sort -rn | head -5 | cut -d' ' -f2- | while read -r file; do
        echo "   • $(basename "$file")"
    done
}

show_config() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              ⚙️  CONFIGURAÇÃO                      ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════╝${NC}\n"
    
    echo -e "${YELLOW}Arquivo de configuração:${NC} $OPENPIPES_CONFIG"
    echo -e "${YELLOW}Editor padrão:${NC} ${EDITOR:-nano}\n"
    
    echo -e "${CYAN}Deseja editar config.sh? [s/N]:${NC}"
    read -rp "" edit_choice
    
    if [[ "$edit_choice" =~ ^[Ss]$ ]]; then
        "${EDITOR:-nano}" "$OPENPIPES_CONFIG"
        log SUCCESS "config.sh atualizado"
        
        # Recarrega config
        if check_config; then
            log SUCCESS "Configuração recarregada"
        else
            log ERROR "Erro ao recarregar configuração"
        fi
    fi
}

show_status() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║          🔍 STATUS DO FRAMEWORK                    ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════╝${NC}\n"
    
    # 1. Configuração
    echo -e "${YELLOW}▸ CONFIGURAÇÃO${NC}"
    if [[ -f "$OPENPIPES_CONFIG" ]]; then
        log SUCCESS "config.sh encontrado"
        echo "   proj_name: $proj_name"
        echo "   proj_dir: $proj_dir"
        echo "   obsdir: $obsdir"
    else
        log ERROR "config.sh não encontrado"
    fi
    
    # 2. Estrutura do Projeto
    echo -e "\n${YELLOW}▸ PROJETO ATUAL: $proj_name${NC}"
    if [[ -d "$proj_path" ]]; then
        log SUCCESS "Diretório do projeto existe"
        echo "   Localização: $proj_path"
        
        # Valida subdirs
        for subdir in Recon Varreduras OSINT Logs; do
            if [[ -d "$proj_path/$subdir" ]]; then
                echo "   ✓ $subdir/"
            else
                echo "   ✗ $subdir/ (ausente)"
            fi
        done
        
        # Valida domains.txt
        if [[ -f "$proj_path/domains.txt" ]]; then
             local domain_count=$(grep -v '^\s*#' "$proj_path/domains.txt" 2>/dev/null | grep -v '^\s*$' | wc -l)
            echo "   ✓ domains.txt ($domain_count alvos)"
        else
            echo "   ✗ domains.txt (ausente)"
        fi
    else
        log ERROR "Projeto não inicializado"
        echo "   Execute: init-openpipes"
    fi
    
    # 3. Obsidian Vault
    echo -e "\n${YELLOW}▸ OBSIDIAN VAULT${NC}"
    local pentest_root="${obsdir}/${proj_name}/Pentest"
    if [[ -d "$pentest_root" ]]; then
        log SUCCESS "Vault do projeto existe"
        echo "   Localização: $pentest_root"
        
        # Valida estrutura
        for subdir in Alvos OSINT; do
            if [[ -d "$pentest_root/$subdir" ]]; then
                echo "   ✓ $subdir/"
            else
                echo "   ✗ $subdir/ (ausente)"
            fi
        done
        
        # Valida dashboards
        for file in Dashboard_Global.md Tarefas.md; do
            if [[ -f "$pentest_root/$file" ]]; then
                echo "   ✓ $file"
            else
                echo "   ✗ $file (ausente)"
            fi
        done
    else
        log ERROR "Vault do projeto não encontrado"
    fi
    
    # 4. Ferramentas Instaladas
    echo -e "\n${YELLOW}▸ FERRAMENTAS INSTALADAS${NC}"
    
    local tools=(
        "nmap:Nmap Port Scanner"
        "httpx:HTTPx Prober"
        "nuclei:Nuclei Scanner"
        "katana:Katana Crawler"
        "feroxbuster:Feroxbuster Brute Force"
        "dnsrecon:DNS Recon"
        "amass:Amass OSINT"
        "gf:GrepFuzzable"
        "jq:JSON Processor"
        "curl:HTTP Client"
		"gowitness:Webserver Screenshotter"
    )
    
    for tool_entry in "${tools[@]}"; do
        IFS=':' read -r tool_name tool_desc <<< "$tool_entry"
        
        if command -v "$tool_name" &>/dev/null; then
            local version=$("$tool_name" --version 2>/dev/null | head -1 || echo "instalado")
            log SUCCESS "$tool_desc"
            echo "   └─ $version"
        else
            log ERROR "$tool_desc"
            echo "   └─ Não encontrado"
        fi
    done
    
    # 5. API Keys
    echo -e "\n${YELLOW}▸ API KEYS CONFIGURADAS${NC}"
    
    local keys=(
        "securitytrailskey:SecurityTrails"
        "OPENAI_API_KEY:OpenAI GPT-4"
        "SERPAPI_KEY:SerpAPI"
        "GOOGLE_API_KEY:Google Custom Search"
        "GOOGLE_CSE_ID:Google CSE ID"
    )
    
    local keys_ok=0
    for key_entry in "${keys[@]}"; do
        IFS=':' read -r key_var key_name <<< "$key_entry"
        
        if [[ -n "${!key_var:-}" ]]; then
            log SUCCESS "$key_name"
            ((keys_ok++))
        else
            log ERROR "$key_name"
        fi
    done
    
    echo -e "\n   Total: $keys_ok/${#keys[@]} configuradas"
    
    # 6. Resumo
    echo -e "\n${CYAN}╔════════════════════════════════════════════════════╗${NC}"
    if validate_project &>/dev/null; then
        echo -e "${GREEN}║  ✅ FRAMEWORK PRONTO PARA USO                      ║${NC}"
    else
        echo -e "${YELLOW}║  ⚠  ATENÇÃO: Alguns itens precisam de ajuste       ║${NC}"
    fi
    echo -e "${CYAN}╚════════════════════════════════════════════════════╝${NC}\n"
    
    press_enter
}

show_help() {
    clear
    cat << 'EOF'
╔════════════════════════════════════════════════════════════════╗
║                    📚 AJUDA - OPenPipeS v2.1                   ║
╚════════════════════════════════════════════════════════════════╝

🎯 WORKFLOW RECOMENDADO:

1️⃣  INICIALIZAR PROJETO (primeira vez)
   $ init-openpipes
   → Cria estrutura explorador + Obsidian
   → Valida API keys
   → Popula domains.txt

2️⃣  ABRIR ORCHESTRADOR
   $ openpipes
   → Menu interativo com opções de scan

3️⃣  EXECUTAR MÓDULOS (ordem sugerida)
   [R] Reconhecimento      → Subdomain discovery
   [S] Scanning            → Port scanning (nmap)
   [H] HTTP Probing        → Detecta serviços web
   [K] Web Discovery       → Crawling + bruteforce
   [N] Nuclei Scan         → Vulnerability scanning
   [J] JSFinder            → Extrai endpoints JS
   [G] GF Summary          → Pattern matching
   [W] WHOIS               → Enrichment de dados
   [I] SCREENSHOTS		   → SS de Webservers	
   [U] IDENTITIES MANAGER  → Credenciais, E-mails, etc.

4️⃣  PIPELINE COMPLETO
   [P] Executa todos os módulos em sequência

5️⃣  GESTÃO E ANÁLISE
   [V] Criar/editar vulnerabilidades
   [E] Editar domains.txt  
   [L] Listar alvos
   [E] Editar domains.txt
   [M] Ver outputs recentes
   [T] Status de Ferramentas 
   [C] Configuração
   [A] Ajuda     

═══════════════════════════════════════════════════════════════

📁 ESTRUTURA DE DIRETÓRIOS:

Explorador (Kali):
  ~/Projetos/projeto-alvo/
  ├── domains.txt           ← Adicione alvos aqui
  ├── Recon/                ← Outputs de reconhecimento
  ├── Varreduras/           ← Outputs de nmap
  ├── OSINT/                ← Outputs de OSINT
  ├── Screenshots/          ← Outputs de screenshot-runner  
  └── Logs/                 ← Arquivos de log

Obsidian (Analista):
  ~/.obsidianFixedMount/projeto-alvo/Pentest/
  ├── Alvos/                ← Um .md por alvo
  ├── OSINT/                ← Dados de OSINT
  ├── Dashboard_Global.md   ← Visão agregada
  └── Tarefas.md            ← Task tracking

═══════════════════════════════════════════════════════════════

🔑 API KEYS NECESSÁRIAS:

1. SecurityTrails (Subdomain Discovery)
   URL: https://securitytrails.com/app/account/credentials
   Config: securitytrailskey="sua_key_aqui"

2. OpenAI GPT-4 (Vuln Enrichment)
   URL: https://platform.openai.com/api-keys
   Config: OPENAI_API_KEY="sk-..."

3. SerpAPI (OSINT People)
   URL: https://serpapi.com/manage-api-key
   Config: SERPAPI_KEY="..."

4. Google Custom Search (Document Discovery)
   URL: https://console.cloud.google.com/apis/credentials
   Config: GOOGLE_API_KEY="..." + GOOGLE_CSE_ID="..."

Configure em: ~/.openpipes/config.sh

═══════════════════════════════════════════════════════════════

⚙️  COMANDOS ÚTEIS:

openpipes              ← Abre orchestrador
init-openpipes         ← Inicializa novo projeto
openpipes config       ← Edita configuração
openpipes status       ← Mostra status do framework
make install           ← Instala framework
make update            ← Atualiza framework

═══════════════════════════════════════════════════════════════

💡 DICAS:

• Sempre popule domains.txt ANTES de executar módulos
• Use [P] Pipeline Completo para automatizar tudo
• Verifique [T] Status antes de começar
• Configure todas as API keys para máxima funcionalidade
• Abra Obsidian em paralelo para acompanhar resultados

═══════════════════════════════════════════════════════════════
EOF
    press_enter
}

# ═══════════════════════════════════════════════════════════════════════════
# MAIN - FUNÇÃO PRINCIPAL
# ═══════════════════════════════════════════════════════════════════════════

main() {
        log INFO "═══════════════════════════════════════════════"
    log INFO "  PIPELINE COMPLETO v3.0 (MODULAR)"
    log INFO "═══════════════════════════════════════════════"
    # Validação omitida por brevidade (já existe no código)

    # Nova ordem de módulos
    local modules=(
        "recon"                      # 1. Reconhecimento
        "nwrapper"                   # 2. Port Scan
        "cria-alvos"                 # 3. Criar estrutura Obsidian
        "httpx-runner"               # 4. HTTP Probing (Hybrid)
        "katana-runner"              # 5. Web Crawling
        "context-wordlist-builder"   # 6. Context Wordlist
        "feroxbuster-runner"         # 7. Fuzzing
        "nuclei-runner"              # 8. Nuclei Scan
        "jsfinder-runner"            # 9. JS Analysis
        "screenshot-runner"          # 10. Screenshots
        "gf-summary"                 # 11. GF Summary
        "whois-enricher"             # 12. WHOIS
        "id-manager"                 # 13. Identity Manager
    )
    
    # 1. Pré-flight checks
    if ! check_config; then
        log ERROR "Falha na verificação de configuração"
        exit 1
    fi
    
    if ! check_openpipes_structure; then
        log ERROR "Falha na verificação de estrutura OPenPipeS"
        exit 1
    fi
    
    # 2. Valida projeto inicializado
    if ! validate_project; then
        log ERROR "Projeto não está inicializado corretamente"
        log ERROR "Execute: init-openpipes"
        exit 1
    fi
    
    # 3. Loop do menu
    while true; do
        show_menu
    done
}

# ═══════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

# Executa main se script for executado diretamente (não sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
