#!/usr/bin/env bash
# 
# OPENPIPES CONFIGURATION v2.0
# 

# PROJETO ALVO
proj_name="nasa.gov"

# DIRETÓRIOS BASE
proj_dir="$HOME/Projetos"
proj_path="$proj_dir/$proj_name"
obsdir="$HOME/.obsidianFixedMount"
tpdir="$HOME/.openpipes/.templates"

# PATHS OBSIDIAN (NOVA ESTRUTURA V2)
OBSIDIAN_PROJ_ROOT="$obsdir/$proj_name"
OBSIDIAN_PROJ_PATH="$OBSIDIAN_PROJ_ROOT/Pentest"
TARGETS_DIR="$OBSIDIAN_PROJ_PATH/Alvos"

# PATHS DE TRABALHO
NMAP_DIR="$proj_path/Varreduras"
RECON_DIR="$proj_path/Recon"
OSINT_DIR="$proj_path/OSINT"
base_dir=$NMAP_DIR
SCREENSHOT_DIR="$proj_path/Screenshots"
DOMAIN_FILE="$proj_path/domains.txt"

# API KEYS
securitytrailskey=""
OPENAI_API_KEY=""
GOOGLE_API_KEY=""
GOOGLE_CSE_ID=""
SERPAPI_KEY=""

# TEMPLATES E CACHE
TEMPLATES_DIR="$HOME/.openpipes/.templates"
CACHE_DIR="$HOME/.openpipes_cache"

# WORDLISTS
SECLISTS_DIR="/usr/share/wordlists/seclists"
CUSTOM_WORDLIST="$TEMPLATES_DIR/names.txt"

# CONFIGURAÇÕES DE SCAN
SCAN_PROFILE="normal"

case $SCAN_PROFILE in
    quick)
        NUCLEI_SEVERITY="critical,high"
        FEROX_THREADS=50
        NMAP_TIMING="-T4"
        ;;
    normal)
        NUCLEI_SEVERITY="medium,high,critical"
        FEROX_THREADS=100
        NMAP_TIMING="-T4"
        ;;
    aggressive)
        NUCLEI_SEVERITY="info,low,medium,high,critical"
        FEROX_THREADS=200
        NMAP_TIMING="-T5"
        ;;
esac

# RATE LIMITING
RATE_LIMIT_RPM=60

# LOGGING
LOG_DIR="$proj_path/logs"
LOG_FILE="$LOG_DIR/openpipes_$(date +%Y%m%d).log"

# EXPORT PARA SCRIPTS FILHOS
export proj_name proj_dir proj_path obsdir SCREENSHOT_DIR
export OBSIDIAN_PROJ_ROOT OBSIDIAN_PROJ_PATH TARGETS_DIR
export NMAP_DIR RECON_DIR NUCLEI_DIR HTTPX_DIR KATANA_DIR FEROX_DIR
export securitytrailskey OPENAI_API_KEY GOOGLE_API_KEY GOOGLE_CSE_ID SERPAPI_KEY
export TEMPLATES_DIR CACHE_DIR SECLISTS_DIR CUSTOM_WORDLIST
export SCAN_PROFILE NUCLEI_SEVERITY FEROX_THREADS NMAP_TIMING RATE_LIMIT_RPM
export LOG_DIR LOG_FILE

# FUNÇÕES AUXILIARES
ensure_dirs() {
    mkdir -p "$proj_path" "$NMAP_DIR" "$RECON_DIR" "$LOG_DIR"
}

validate_project() {
    if [[ ! -d "$OBSIDIAN_PROJ_PATH" ]]; then
        echo "[ERRO] Projeto '$proj_name' não inicializado no Obsidian!"
        echo "Execute: init-openpipes"
        return 1
    fi
    return 0
}

log() {
    local level="$1"
    shift
    local message="$*"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" | tee -a "$LOG_FILE"
}

# INICIALIZAÇÃO
ensure_dirs

if [[ -z "$proj_name" ]]; then
    echo "[AVISO] proj_name não definido! Edite ~/.openpipes/config.sh"
fi
