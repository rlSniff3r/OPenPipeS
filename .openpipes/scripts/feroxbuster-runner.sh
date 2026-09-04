#!/bin/bash

# ════════════════════════════════════════════════════════════════════════════
# feroxbuster-runner.sh v1.0 - Fuzzing Inteligente
# Parte do OpenPipeS Framework
# ════════════════════════════════════════════════════════════════════════════
source ~/.openpipes/config.sh
source ~/colorCodes.sh

cat <<Banner
${RED}
███████╗███████╗██████╗  ██████╗ ██╗  ██╗██████╗ ██╗   ██╗███████╗████████╗███████╗██████╗
██╔════╝██╔════╝██╔══██╗██╔═══██╗╚██╗██╔╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗
█████╗  █████╗  ██████╔╝██║   ██║ ╚███╔╝ ██████╔╝██║   ██║███████╗   ██║   █████╗  ██████╔╝
██╔══╝  ██╔══╝  ██╔══██╗██║   ██║ ██╔██╗ ██╔══██╗██║   ██║╚════██║   ██║   ██╔══╝  ██╔══██╗
██║     ███████╗██║  ██║╚██████╔╝██╔╝ ██╗██████╔╝╚██████╔╝███████║   ██║   ███████╗██║  ██║
╚═╝     ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
${NC}
${BLUE}                           Fuzzing com Wordlist Contextualizada
v1.0 - Smart Fuzzing${NC}
Banner

FEROX_THREADS=70
FEROX_DEPTH=2
FEROX_TIMEOUT="6m"
FALLBACK_WL="/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt"

# ════════════════════════════════════════════════════════════════════════════
# PIPELINE POR ALVO
# ════════════════════════════════════════════════════════════════════════════
process_target() {
    local TARGET="$1"

    # === FILTRO OP_TARGETS ===
    if [[ -n "${OP_TARGETS:-}" ]]; then
        # Verifica se o target atual está na lista separada por vírgulas
        if ! echo "$OP_TARGETS" | tr ',' '\n' | grep -Fqx "$TARGET"; then
            return 0 # CORREÇÃO: "return 0" sai da função pulando o alvo!
        fi
        echo "[*] Alvo restrito acionado para: $TARGET"
    fi
    # ==========================

    local WORK_DIR="$NMAP_DIR/nmap-$TARGET"

    if [ ! -d "$WORK_DIR" ]; then
        echo "[!] Diretório não encontrado: $WORK_DIR"
        return 1
    fi

    # ── Input: alive_urls.txt (escrito pelo feeder.py) ──────────────────
    local URLS_FILE="$NMAP_DIR/nmap-$TARGET/ferox_urls.txt"
    if [ ! -s "$URLS_FILE" ]; then
        echo "[!] ferox_urls.txt vazio ou ausente para $TARGET"
        return 1
    fi

    # ── Utiliza os diretórios profundos gerados de forma inteligente pelo feeder.py ──
    local BASE_URLS="$WORK_DIR/base_urls.txt"
    sort -u "$URLS_FILE" > "$BASE_URLS"
    local BASE_COUNT=$(wc -l < "$BASE_URLS")
    echo "[*] $TARGET: $BASE_COUNT diretório(s) profundo(s) para fuzzing"

    # ── Selecionar wordlist ─────────────────────────────────────────────
    local CONTEXT_WL="$WORK_DIR/context_wordlist.txt"
    local WL=""
    if [ -s "$CONTEXT_WL" ]; then
        WL="$CONTEXT_WL"
    elif [ -f "$FALLBACK_WL" ]; then
        WL="$FALLBACK_WL"
    else
        echo "[ERROR] Nenhuma wordlist disponível!"
        return 1
    fi

    # ========================================================
    # MAGIA NINJA: CONVERTER ARGS CUSTOMIZADOS PARA ARRAY
    # ========================================================
    local extra_args=()
    if [[ -n "${OP_TOOL_ARGS:-}" ]]; then
        eval "extra_args=($OP_TOOL_ARGS)"
    fi
    # ========================================================

    # ── Feroxbuster Fuzzing (uma execução por base URL) ─────────────────
    while read -r base_url; do
        local safe_name=$(echo "$base_url" | sed 's/http:\/\///;s/https:\/\///;s/[\/:]/_/g')
        local OUTPUT_FILE="$WORK_DIR/ferox_${safe_name}"
        echo "[*] Fuzzing: $base_url"

        # Olha que espetáculo e limpeza! Adicionamos "${extra_args[@]}" no final!
        feroxbuster -u "$base_url" \
            -w "$WL" \
            --collect-extensions \
            --collect-words \
            -t "$FEROX_THREADS" \
            -d "$FEROX_DEPTH" \
            --time-limit "$FEROX_TIMEOUT" \
            --auto-tune \
            --filter-status 400,401,404,405,500,502,503 \
            --random-agent \
            --no-state \
            --json \
            -o "${OUTPUT_FILE}.jsonl" \
            "${extra_args[@]}"

        jq -r '.url' "${OUTPUT_FILE}.jsonl" > "${OUTPUT_FILE}.txt" 2>/dev/null
    done < "$BASE_URLS"

    # ── Consolida resultados ────────────────────────────────────────────
    local CONSOLIDATED="$WORK_DIR/ferox_consolidated.txt"
    cat "$WORK_DIR"/ferox_*.txt 2>/dev/null | grep "^http" | sort -u > "$CONSOLIDATED"
    local UNIQUE_FOUND=$(wc -l < "$CONSOLIDATED" 2>/dev/null || echo 0)
    echo "[✔] $TARGET: $UNIQUE_FOUND endpoints únicos"
}

# ════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════
if [ -n "$1" ]; then
    process_target "$1"
else
    TARGETS_FILE="$NMAP_DIR/targets.txt"
    if [ ! -f "$TARGETS_FILE" ]; then
        echo "[ERROR] targets.txt não encontrado"
        exit 1
    fi
    mapfile -t TARGETS_ARRAY < "$TARGETS_FILE"
    for TARGET_NAME in "${TARGETS_ARRAY[@]}"; do
        [[ -z "$TARGET_NAME" || "$TARGET_NAME" =~ ^# ]] && continue
        process_target "$TARGET_NAME" || echo "[FAIL] $TARGET_NAME"
    done
fi
echo "[✔] Feroxbuster Runner concluído!"

# Feroxbuster terminou o scan. Antes de dar o exit 0 pro Python, vamos ver se a internet está viva:
if ! ping -c 2 8.8.8.8 &> /dev/null; then
    echo "[!] AVISO: Queda de conexão detectada durante ou após o scan!"
    exit 1  # Força o erro! O Python NÃO vai rodar o parser!
fi

exit 0 # Tudo certo, o Python pode marcar as URLs como lidas!