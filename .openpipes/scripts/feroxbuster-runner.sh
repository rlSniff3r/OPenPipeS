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


# ════════════════════════════════════════════════════════════════════════════
# CONFIGURAÇÃO
#  ════════════════════════════════════════════════════════════════════════════

FEROX_THREADS=50
FEROX_DEPTH=2
FEROX_TIMEOUT="10m"

# Wordlist fallback (se contextualizada não existir)
FALLBACK_WL="/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt"

# ════════════════════════════════════════════════════════════════════════════
# FUNÇÕES AUXILIARES
# ════════════════════════════════════════════════════════════════════════════
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}[ERROR] '$1' não encontrado! ${NC}"
        return 1
    fi
    return 0
}

# ════════════════════════════════════════════════════════════════════════════
# PIPELINE POR ALVO
# ════════════════════════════════════════════════════════════════════════════

process_target() {
        local TARGET="$1"
        echo -e "${BLUE}[*] >>> Processando: ${YELLOW}$TARGET ${NC}"

        # Diretórios
        local WORK_DIR="$NMAP_DIR/nmap-$TARGET"
        local OBSIDIAN_DIR="$TARGETS_DIR/$TARGET"

        if [ ! -d "$WORK_DIR" ]; then
            echo -e "${RED}[!] Diretório Web não encontrado ${NC}"
            echo -e "${YELLOW}    Execute httpx-runner primeiro! ${NC}"
            return 1
        fi

        # ──────────────────────────────────────────────────────────────────────
        # PASSO 1: Validar inputs
        # ──────────────────────────────────────────────────────────────────────

#        local URLS_FILE="$obsdir/$proj_name/Pentest/Alvos/$TARGET/endpoints.md"
        local URLS_FILE="$NMAP_DIR/nmap-$TARGET/alive_urls.txt"

        if [ ! -s "$URLS_FILE" ]; then
            echo -e "${RED}[!] alive_urls.txt não encontrado ou vazio ${NC}"
            return 1
        fi

        local URL_COUNT=$(wc -l < "$URLS_FILE")
        echo -e "${GREEN}[+] Fuzzing em $URL_COUNT URL(s) ${NC}"

        # ──────────────────────────────────────────────────────────────────────
        # PASSO 2: Selecionar wordlist (prioriza contextualizada)
        # ──────────────────────────────────────────────────────────────────────

        local CONTEXT_WL="$WORK_DIR/context_wordlist.txt"
        local WL=""

        if [ -s "$CONTEXT_WL" ]; then
            WL="$CONTEXT_WL"
            local WL_SIZE=$(wc -l < "$WL")
            echo -e "${CYAN}[+] Usando wordlist CONTEXTUALIZADA ($WL_SIZE payloads)${NC}"
        else
            if [ -f "$FALLBACK_WL" ]; then
                WL="$FALLBACK_WL"
                local WL_SIZE=$(wc -l < "$WL")
                echo -e "${YELLOW}[!] Wordlist contextualizada não encontrada${NC}"
                echo -e "${YELLOW}    Usando fallback: common.txt ($WL_SIZE payloads)${NC}"
            else
                echo -e "${RED}[ERROR] Nenhuma wordlist disponível!${NC}"
                return 1
            fi
        fi

        # ──────────────────────────────────────────────────────────────────────
        # PASSO 3: Feroxbuster Fuzzing
        # ──────────────────────────────────────────────────────────────────────

        check_tool "feroxbuster" || return 1

        echo -e "${RED}[+] Executando Feroxbuster...${NC}"
        echo -e "${CYAN}    -> Threads: $FEROX_THREADS | Depth: $FEROX_DEPTH | Timeout: $FEROX_TIMEOUT${NC}"

        local FEROX_COUNT=0
        local TOTAL_FOUND=0

        while read -r url; do
            # Nome seguro para arquivo de saída
            local safe_name=$(echo "$url" | sed 's/http:\/\///;s/https:\/\///;s/[\/:]/_/g')
            local OUTPUT_FILE="$WORK_DIR/ferox_${safe_name}"

            ((FEROX_COUNT++))
            echo -e "${YELLOW}    [$FEROX_COUNT/$URL_COUNT] Fuzzing: $url${NC}"

            # Executa feroxbuster
            feroxbuster -u "$url" \
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

            # Keep text version for backward compatibility
            jq -r '.url' "$OUTPUT_FILE.jsonl" > "$OUTPUT_FILE.txt" 2>/dev/null

            # Conta achados neste URL
#            if [ -f "$OUTPUT_FILE" ]; then
#                local FOUND=$(grep -c "^http" "$OUTPUT_FILE" 2>/dev/null || echo 0)
#                TOTAL_FOUND=$((${TOTAL_FOUND} + ${FOUND}))
#                TOTAL_FOUND=$((${TOTAL_FOUND} + ${FOUND}))
#                echo -e "${GREEN}        -> $FOUND endpoints encontrados${NC}"
#            fi

        done < "$URLS_FILE"

        # ──────────────────────────────────────────────────────────────────────
        # PASSO 4: Consolidação de resultados
        # ──────────────────────────────────────────────────────────────────────

        echo -e "${CYAN}[+] Consolidando resultados...${NC}"

        local CONSOLIDATED="$WORK_DIR/ferox_consolidated.txt"

        cat "$WORK_DIR"/ferox_*.txt 2>/dev/null | \
            grep "^http" | \
            sort -u > "$CONSOLIDATED"

        local UNIQUE_FOUND=$(wc -l < "$CONSOLIDATED" 2>/dev/null || echo 0)

        echo -e "${GREEN}[✔] Fuzzing finalizado!${NC}"
        echo -e "${YELLOW}    -> Total encontrado: $TOTAL_FOUND endpoints${NC}"
        echo -e "${YELLOW}    -> Únicos: $UNIQUE_FOUND endpoints${NC}"

        # Atualiza endpoints.md
        if [ -s "$CONSOLIDATED" ]; then
            local ENDPOINTS_FILE="$OBSIDIAN_DIR/endpoints.md"
            cat "$CONSOLIDATED" >> "$ENDPOINTS_FILE"
            sort -u "$ENDPOINTS_FILE" -o "$ENDPOINTS_FILE"
            echo -e "${CYAN}    -> endpoints.md atualizado${NC}"
        fi

        # ──────────────────────────────────────────────────────────────────────
        # PASSO 5: Gerar Markdown de Relatório
        # ──────────────────────────────────────────────────────────────────────


#         local MD_FILE="$OBSIDIAN_DIR/feroxbuster.md"
#         mkdir -p "$OBSIDIAN_DIR"

#         {
#             echo "#  Feroxbuster Fuzzing - $TARGET"
#             echo ""
#             echo "**Data**: $(date '+%Y-%m-%d %H:%M:%S')"
#             echo "**URLs Base**: $URL_COUNT"
#             echo "**Wordlist**: $(basename "$WL") ($WL_SIZE payloads)"
#             echo "**Threads**: $FEROX_THREADS"
#             echo "**Depth**: $FEROX_DEPTH"
#             echo ""
#             echo "##  Resultados"
#             echo ""
#             echo "| Métrica | Valor |"
#             echo "|---------|-------|"
#             echo "| Endpoints Encontrados | $TOTAL_FOUND |"
#             echo "| Endpoints Únicos | $UNIQUE_FOUND |"
#             echo "| Taxa de Sucesso | $(awk "BEGIN {printf \"%.1f%%\", ($UNIQUE_FOUND/$WL_SIZE)*100}") |"
#             echo "| Taxa de Sucesso | $(awk -v unique="$UNIQUE_FOUND" -v wl="$WL_SIZE" 'BEGIN { if (wl > 0) printf "%.1f%%", (unique/wl)*100; else print "0.0%" }') |"
#             echo ""
#             echo "## Endpoints Descobertos"
#             echo ""
#             cat "$CONSOLIDATED" 2>/dev/null || echo "Nenhum endpoint descoberto"
#             echo ""
#             echo "---"
#         } > "$MD_FILE"

#         echo -e "${CYAN}    -> Markdown: $MD_FILE ${NC}"
}

# ════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════

if [ -n "$1" ]; then
    # Modo manual
    process_target "$1"
else
    # Modo batch
    echo -e "${YELLOW}[*] Modo Batch: Processando todos os alvos... ${NC}"

TARGETS_FILE="$NMAP_DIR/targets.txt"

if [ ! -f "$TARGETS_FILE" ]; then
    echo -e "${RED}[ERROR] targets.txt não encontrado${NC}"
    exit 1
fi

mapfile -t TARGETS_ARRAY < "$TARGETS_FILE"

for TARGET_NAME in "${TARGETS_ARRAY[@]}"; do
    [[ -z "$TARGET_NAME" || "$TARGET_NAME" =~ ^# ]] && continue

    echo -e "${YELLOW}════════════════════════════════════════${NC}"

#    if [ -d "$NMAP_DIR/nmap-$TARGET_NAME/Web" ]; then
        process_target "$TARGET_NAME" || echo -e "${RED}[FAIL] Erro em $TARGET_NAME${NC}"
#    else
#        echo -e "${RED}[!] Web dir não encontrado para $TARGET_NAME${NC}"
#    fi
done
fi

echo -e "${GREEN}[*] Feroxbuster Runner finalizado! ${NC}"
