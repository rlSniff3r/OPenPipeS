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


#════════════════════════════════════════════════════════════════════════════
#CONFIGURAÇÃO
#════════════════════════════════════════════════════════════════════════════
KATANA_DEPTH=3
KATANA_CONCURRENCY=20
KATANA_JS_CRAWL=true
#════════════════════════════════════════════════════════════════════════════
#FUNÇÕES AUXILIARES
#════════════════════════════════════════════════════════════════════════════
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}[ERROR] Ferramenta '$1' não encontrada!${NC}"
        return 1
    fi
    return 0
}

#════════════════════════════════════════════════════════════════════════════
#PIPELINE POR ALVO
#════════════════════════════════════════════════════════════════════════════
process_target() {
    local TARGET="$1"
    echo -e "${BLUE}[*] >>> Processando: ${YELLOW}$TARGET${NC}"

    # Diretórios
    local WORK_DIR="$NMAP_DIR/nmap-$TARGET"
    local OBSIDIAN_DIR="$TARGETS_DIR/$TARGET"

    if [ ! -d "$WORK_DIR" ]; then
        echo -e "${RED}[!] Diretório Web não encontrado. Execute httpx-runner primeiro!${NC}"
        return 1
    fi

    # ──────────────────────────────────────────────────────────────────────
    # PASSO 1: Verificar input (alive_urls.txt)
    # ──────────────────────────────────────────────────────────────────────

#    local INPUT_TMP=$(cat "$OBSIDIAN_DIR/endpoints.md" | sed -E 's/(:80|:443)(\/|$)/\2/g' | sort -u)
    local INPUT_FILE="$OBSIDIAN_DIR/endpoints.md"

    if [ ! -s "$INPUT_FILE" ]; then
        echo -e "${RED}[!] alive_urls.txt não encontrado ou vazio${NC}"
        echo -e "${YELLOW}    Execute httpx-runner.sh primeiro!${NC}"
        return 1
    fi

    local URL_COUNT=$(wc -l < "$INPUT_FILE")
    echo -e "${GREEN}[+] Crawling em $URL_COUNT URL(s)...${NC}"

    # ──────────────────────────────────────────────────────────────────────
    # PASSO 2: Katana Crawling
    # ──────────────────────────────────────────────────────────────────────

    check_tool "katana" || return 1

    local CRAWLED_FILE="$WORK_DIR/crawled_all.txt"

    echo -e "${CYAN}    -> Profundidade: $KATANA_DEPTH | Concorrência: $KATANA_CONCURRENCY${NC}"

    katana -list "$INPUT_FILE" \
        -d "$KATANA_DEPTH" \
        -c "$KATANA_CONCURRENCY" \
        -jc \
        -kf all \
        -fsc 400,401,404,500,501,502,503 \
        -silent \
        -o "$CRAWLED_FILE"

    if [ ! -f "$CRAWLED_FILE" ]; then
        echo -e "${RED}[!] Katana não gerou saída${NC}"
        return 1
    fi

    local CRAWLED_COUNT=$(wc -l < "$CRAWLED_FILE")
    echo -e "${YELLOW}    -> $CRAWLED_COUNT URLs descobertas${NC}"

    # ──────────────────────────────────────────────────────────────────────
    # PASSO 3: Extração de Arquivos JS
    # ──────────────────────────────────────────────────────────────────────

    local JS_FILES="$WORK_DIR/js_files.txt"

    grep -E "\.js(\?|$)" "$CRAWLED_FILE" 2>/dev/null | sort -u > "$JS_FILES"

    local JS_COUNT=$(wc -l < "$JS_FILES" 2>/dev/null || echo 0)

    if [ "$JS_COUNT" -gt 0 ]; then
        echo -e "${GREEN}[+] $JS_COUNT arquivos JS encontrados${NC}"
    else
        echo -e "${YELLOW}[!] Nenhum arquivo JS encontrado${NC}"
    fi

    # ──────────────────────────────────────────────────────────────────────
    # PASSO 4: Consolidação de URLs (Feed pro Context Builder)
    # ──────────────────────────────────────────────────────────────────────

    local CONSOLIDATED="$WORK_DIR/all_discovered_urls.txt"

    cat "$WORK_DIR/alive_urls.txt" \
        "$CRAWLED_FILE" \
        "$JS_FILES" 2>/dev/null | sort -u > "$CONSOLIDATED"

    local TOTAL_URLS=$(wc -l < "$CONSOLIDATED")
    echo -e "${YELLOW}    -> TOTAL consolidado: $TOTAL_URLS URLs únicas${NC}"

    # ──────────────────────────────────────────────────────────────────────
    # PASSO 5: Gerar Markdown para Obsidian
    # ──────────────────────────────────────────────────────────────────────

    cat "$CRAWLED_FILE" "$JS_FILES" "$OBSIDIAN_DIR/endpoints.md" > /tmp/all_endpoints
    cat /tmp/all_endpoints > "$OBSIDIAN_DIR/endpoints.md"

    local MD_FILE="$OBSIDIAN_DIR/katana.md"
    mkdir -p "$OBSIDIAN_DIR"

    {
        echo "# ️ Katana Crawling - $TARGET"
        echo ""
        echo "**Data**: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "**URLs Base**: $URL_COUNT"
        echo "**URLs Descobertas**: $CRAWLED_COUNT"
        echo "**Arquivos JS**: $JS_COUNT"
        echo "**Total Consolidado**: $TOTAL_URLS"
        echo ""
        echo "##  Estatísticas"
        echo ""
        echo "| Tipo | Quantidade |"
        echo "|------|-----------|"
        echo "| URLs Iniciais | $URL_COUNT |"
        echo "| URLs Crawled | $CRAWLED_COUNT |"
        echo "| Arquivos JS | $JS_COUNT |"
        echo "| **Total Único** | **$TOTAL_URLS** |"
        echo ""
        echo "## 🌐 URLs Descobertas"
        echo ""
        cat "$CRAWLED_FILE"
        echo ""
        echo "## 📑 Arquivos JS"
        echo ""
        cat "$JS_FILES" 2>/dev/null || echo "Nenhum arquivo JS encontrado"
        echo ""
        echo "---"
        echo "*Arquivo completo: \`crawled_all.txt\`*"
    } > "$MD_FILE"

    echo -e "${GREEN}[✔] $TARGET finalizado!${NC}"
    echo -e "${CYAN}    -> Markdown: $MD_FILE${NC}"
    echo -e "${CYAN}    -> URLs consolidadas: $CONSOLIDATED${NC}"
}


#════════════════════════════════════════════════════════════════════════════
#MAIN
#════════════════════════════════════════════════════════════════════════════
if [ -n "$1" ]; then
    # Modo manual
    process_target "$1"
else
    # Modo batch
    echo -e "${MAGENTA}[*] Modo Batch: Processando todos os alvos... ${NC}"

TARGETS_FILE="$NMAP_DIR/targets.txt"

if [ ! -f "$TARGETS_FILE" ]; then
    echo -e "${RED}[ERROR] targets.txt não encontrado${NC}"
    exit 1
fi

mapfile -t TARGETS_ARRAY < "$TARGETS_FILE"

for TARGET_NAME in "${TARGETS_ARRAY[@]}"; do
    [[ -z "$TARGET_NAME" || "$TARGET_NAME" =~ ^# ]] && continue
    
    echo -e "${YELLOW}────────────────────────────────────────${NC}"
    
#    if [ -d "$NMAP_DIR/nmap-$TARGET_NAME/Web" ]; then
        process_target "$TARGET_NAME" || echo -e "${RED}[FAIL] Erro em $TARGET_NAME${NC}"
#    else
#        echo -e "${RED}[!] Web dir não encontrado para $TARGET_NAME${NC}"
#    fi
done
fi
echo -e "${GREEN}[★] Katana Runner finalizado! ${NC}"
