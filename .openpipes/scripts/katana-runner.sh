#!/bin/bash

#════════════════════════════════════════════════════════════════════════════
#katana-runner.sh v1.0 - Deep Crawling
#Parte do OpenPipeS Framework
#════════════════════════════════════════════════════════════════════════════
source ~/.openpipes/config.sh
source ~/colorCodes.sh


cat <<Banner
${MAGENTA}
██╗  ██╗ █████╗ ████████╗ █████╗ ███╗   ██╗ █████╗    ██████╗ ██╗   ██╗███╗   ██╗███╗   ██╗███████╗██████╗
██║ ██╔╝██╔══██╗╚══██╔══╝██╔══██╗████╗  ██║██╔══██╗   ██╔══██╗██║   ██║████╗  ██║████╗  ██║██╔════╝██╔══██╗
█████╔╝ ███████║   ██║   ███████║██╔██╗ ██║███████║   ██████╔╝██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██╔═██╗ ██╔══██║   ██║   ██╔══██║██║╚██╗██║██╔══██║   ██╔══██╗██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║  ██╗██║  ██║   ██║   ██║  ██║██║ ╚████║██║  ██║   ██║  ██║╚██████╔╝██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
${NC}
${BLUE}                          ️  Deep Web Crawling
v1.0 - Extração Pura${NC}
Banner

KATANA_DEPTH=3
KATANA_CONCURRENCY=20

process_target() {
    local TARGET="$1"
    local WORK_DIR="$NMAP_DIR/nmap-$TARGET"
    local INPUT_FILE="$WORK_DIR/katana_urls.txt"

    if [ ! -d "$WORK_DIR" ]; then
        echo "[!] Diretório não encontrado: $WORK_DIR"
        return 1
    fi
    if [ ! -s "$INPUT_FILE" ]; then
        echo "[!] katana_urls.txt vazio ou ausente para $TARGET"
        return 1
    fi

    local URL_COUNT=$(wc -l < "$INPUT_FILE")
    echo "[*] $TARGET: $URL_COUNT URL(s)"

    # Build scope regex from domains.txt
    local DOMAIN_FILE="$proj_path/domains.txt"
    local REGEX_ESCOPO=""
    if [ -f "$DOMAIN_FILE" ]; then
        REGEX_ESCOPO=$(awk 'NF' "$DOMAIN_FILE" | sed 's/\./\\./g' | paste -sd '|' -)
    fi

    katana -list "$INPUT_FILE" \
        -d "$KATANA_DEPTH" \
        -c "$KATANA_CONCURRENCY" \
        -silent \
        -fs "$REGEX_ESCOPO" \
        -cs "$REGEX_ESCOPO" \
        -cos "(facebook|twitter|instagram|linkedin|youtube|google|github|apple|microsoft)" \
        -jc \
        -kf all \
        -or -ob \
        -jsonl \
        -o "$WORK_DIR/crawled_all.jsonl"

    jq -r '.request.endpoint' "$WORK_DIR/crawled_all.jsonl" > "$WORK_DIR/crawled_all.txt" 2>/dev/null
    local CRAWLED_COUNT=$(wc -l < "$WORK_DIR/crawled_all.txt" 2>/dev/null || echo 0)
    echo "[✔] $TARGET: $CRAWLED_COUNT URLs"
}

# Main
if [ -n "$1" ]; then
    process_target "$1"
else
    TARGETS_FILE="$NMAP_DIR/targets.txt"
    [ ! -f "$TARGETS_FILE" ] && echo "[ERROR] targets.txt não encontrado" && exit 1
    mapfile -t TARGETS_ARRAY < "$TARGETS_FILE"
    for TARGET_NAME in "${TARGETS_ARRAY[@]}"; do
        [[ -z "$TARGET_NAME" || "$TARGET_NAME" =~ ^# ]] && continue
        process_target "$TARGET_NAME" || echo "[FAIL] $TARGET_NAME"
    done
fi
echo "[✔] Katana Runner concluído!"
