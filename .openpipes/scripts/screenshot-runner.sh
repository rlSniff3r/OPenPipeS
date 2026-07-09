#!/usr/bin/env bash
# screenshot-runner.sh - Visual Reconnaissance Module (Per-Target)
#
# Executa gowitness por alvo, salvando screenshots + JSONL em
# $NMAP_DIR/nmap-$target/Screenshots/

set -euo pipefail

CONFIG_FILE="$HOME/.openpipes/config.sh"
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo -e "\033[1;31m[ERRO]\033[0m Arquivo de configuração não encontrado: $CONFIG_FILE"
    exit 1
fi
source "$CONFIG_FILE"

# Cores (fallback)
RED="\033[1;31m"; GREEN="\033[1;32m"; YELLOW="\033[1;33m"
BLUE="\033[1;34m"; CYAN="\033[1;36m"; RESET="\033[0m"

log() {
    local level="$1"; shift
    local color; case "$level" in
        INFO) color="$GREEN" ;; WARN) color="$YELLOW" ;; ERROR) color="$RED" ;;
        *) color="$RESET" ;;
    esac
    echo -e "${color}[$(date +"%H:%M:%S")] [$level]${RESET} $*"
}

check_deps() {
    if ! command -v gowitness &>/dev/null; then
        log ERROR "gowitness não encontrado. Instale com: go install github.com/sensepost/gowitness@latest"
        exit 1
    fi

    if ! command -v jq &>/dev/null; then
        log ERROR "jq não encontrado. Instale com: sudo apt install jq"
        exit 1
    fi
    log INFO "Dependências OK"
}

process_target() {
    local target_name="$1"
    local nmap_folder="$NMAP_DIR/nmap-$target_name"
    local ss_dir="$nmap_folder/Screenshots"

    # Coleta URLs vivas do httpx JSON (prioridade) ou alive_urls.txt
    local url_list=""

    if [[ -f "$nmap_folder/httpx-dedup.json" ]]; then
        url_list=$(jq -r '.[] | select(.url != null) | .url' "$nmap_folder/httpx-dedup.json" 2>/dev/null)
    fi

    if [[ -z "$url_list" && -f "$nmap_folder/alive_urls.txt" ]]; then
        url_list=$(cat "$nmap_folder/alive_urls.txt")
    fi

    if [[ -z "$url_list" ]]; then
        log WARN "$target_name: Nenhuma URL encontrada. Pulando."
        return 0
    fi

    # Prepara diretório
    mkdir -p "$ss_dir"

    # Escreve lista de URLs para este alvo
    local input_file="/tmp/gowitness_input_${target_name}.txt"
    echo "$url_list" | sort -u > "$input_file"
    local url_count=$(wc -l < "$input_file")
    log INFO "$target_name: $url_count URLs"

    # Executa gowitness (sem --write-db, apenas JSONL + screenshots)
    cd "$ss_dir"
    gowitness scan file \
        -f "$input_file" \
        --screenshot-path "$ss_dir" \
        --write-jsonl \
        --write-jsonl-file "$ss_dir/go_raw.jsonl" \
        --threads 5 \
        --timeout 20 \
        --no-http=false \
        2>&1 | tee "$ss_dir/gowitness.log"

    # Filtra JSONL para campos relevantes
    if [[ -f $ss_dir/go_raw.jsonl ]]; then
        jq -c '{file_name: .file_name, url: .url, final_url: .final_url, status_code: .response_code, content_length: .content_length, title: .title}' $ss_dir/go_raw.jsonl > $ss_dir/go.jsonl
        rm -f "$ss_dir/go_raw.jsonl"
        local shot_count=$(wc -l < $ss_dir/go.jsonl)
        log INFO "$target_name: $shot_count screenshots capturados"
    fi

    rm -f "$input_file"
}

main() {
    echo -e "${BLUE}╔══════════════════════════════════════════╗${RESET}"
    echo -e "${BLUE}║   Screenshot Runner — Per-Target Mode   ║${RESET}"
    echo -e "${BLUE}╚══════════════════════════════════════════╝${RESET}"
    log INFO "Iniciando screenshots para projeto: ${proj_name}"
    check_deps

    for nmap_folder in "$NMAP_DIR"/nmap-*; do
        [[ ! -d "$nmap_folder" ]] && continue
        target_name="${nmap_folder##*/nmap-}"
        process_target "$target_name"
    done

    log INFO "Todos os alvos processados!"
}

trap 'log ERROR "Execução interrompida"; exit 130' SIGINT SIGTERM
main "$@"
