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

    # ========================================================
    # MAGIA NINJA: CONVERTER ARGS CUSTOMIZADOS PARA ARRAY
    # ========================================================
    local extra_args=()
    if [[ -n "${OP_TOOL_ARGS:-}" ]]; then
        eval "extra_args=($OP_TOOL_ARGS)"
    fi
    # ========================================================

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
        -fx \
        -pc \
        -kb \
        -kb-endpoints \
        -jsonl \
        -o "$WORK_DIR/crawled_all.jsonl" \
        "${extra_args[@]}"

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

# Katana terminou o scan. Antes de dar o exit 0 pro Python, vamos ver se a internet está viva:
if ! ping -c 2 8.8.8.8 &> /dev/null; then
    echo "[!] AVISO: Queda de conexão detectada durante ou após o scan!"
    exit 1  # Força o erro! O Python NÃO vai rodar o parser!
fi

exit 0 # Tudo certo, o Python pode marcar as URLs como lidas!