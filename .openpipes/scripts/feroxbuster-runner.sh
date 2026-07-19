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

    # ── Filtra apenas URLs base para evitar scans redundantes ──────────
    local BASE_URLS="$WORK_DIR/base_urls.txt"
    grep -Eo 'https?://[^/]+' "$URLS_FILE" | sort -u > "$BASE_URLS"
    local BASE_COUNT=$(wc -l < "$BASE_URLS")
    echo "[*] $TARGET: $BASE_COUNT base URL(s)"

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

    # ── Feroxbuster Fuzzing (uma execução por base URL) ─────────────────
    while read -r base_url; do
        local safe_name=$(echo "$base_url" | sed 's/http:\/\///;s/https:\/\///;s/[\/:]/_/g')
        local OUTPUT_FILE="$WORK_DIR/ferox_${safe_name}"
        echo "[*] Fuzzing: $base_url"

        feroxbuster -u "$base_url" \
            -w "$WL" \
            -t "$FEROX_THREADS" \
            -d "$FEROX_DEPTH" \
            --time-limit "$FEROX_TIMEOUT" \
            --auto-tune \
            --filter-status 400,401,404,405,500,502,503 \
            --no-state \
            --json \
            -o "$OUTPUT_FILE.jsonl" \
            --silent 2>/dev/null || true

        jq -r '.url' "$OUTPUT_FILE.jsonl" > "$OUTPUT_FILE.txt" 2>/dev/null
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
