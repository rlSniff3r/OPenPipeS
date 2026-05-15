
#!/bin/bash


# ════════════════════════════════════════════════════════════════════════════
# context-wordlist-builder.sh v1.0 - Wordlist Contextualizada
# Parte do OpenPipeS Framework
# ════════════════════════════════════════════════════════════════════════════

source ~/.openpipes/config.sh
source ~/colorCodes.sh


cat <<Banner
${YELLOW}
██████╗ ██████╗ ███╗   ██╗████████╗███████╗██╗  ██╗████████╗    ██╗    ██╗ ██████╗ ██████╗ ██████╗ ██╗     ██╗███████╗████████╗
██╔════╝██╔═══██╗████╗  ██║╚══██╔══╝██╔════╝╚██╗██╔╝╚══██╔══╝    ██║    ██║██╔═══██╗██╔══██╗██╔══██╗██║     ██║██╔════╝╚══██╔══╝
██║     ██║   ██║██╔██╗ ██║   ██║   █████╗   ╚███╔╝    ██║       ██║ █╗ ██║██║   ██║██████╔╝██║  ██║██║     ██║███████╗   ██║
██║     ██║   ██║██║╚██╗██║   ██║   ██╔══╝   ██╔██╗    ██║       ██║███╗██║██║   ██║██╔══██╗██║  ██║██║     ██║╚════██║   ██║
╚██████╗╚██████╔╝██║ ╚████║   ██║   ███████╗██╔╝ ██╗   ██║       ╚███╔███╔╝╚██████╔╝██║  ██║██████╔╝███████╗██║███████║   ██║
╚═════╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝   ╚═╝        ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝╚══════╝   ╚═╝
${NC}
${BLUE}                                   易 Wordlist Inteligente Tech-Aware
v1.0 - Python Powered${NC}
Banner


# ════════════════════════════════════════════════════════════════════════════
# CONFIGURAÇÃO
# ════════════════════════════════════════════════════════════════════════════

FILTERS_SCRIPT="$HOME/.openpipes/scripts/filters.py"

# ════════════════════════════════════════════════════════════════════════════
# FUNÇÕES AUXILIARES
# ════════════════════════════════════════════════════════════════════════════

check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "{RED}[ERROR] '$1' não encontrado!
{NC}"
        return 1
    fi
    return 0
}

check_file() {
    if [ ! -f "$1" ]; then
        echo -e "${RED}[ERROR] Arquivo não encontrado: $1 ${NC}"
        return 1
    fi
    return 0
}

# ════════════════════════════════════════════════════════════════════════════
# PIPELINE POR ALVO
# ════════════════════════════════════════════════════════════════════════════

process_target() {
        local TARGET="$1"
        echo -e "${BLUE}[*] >>> Processando: ${YELLOW}$TARGET${NC}"

        # Diretórios
        local WORK_DIR="$NMAP_DIR/nmap-$TARGET"

        if [ ! -d "$WORK_DIR" ]; then
            echo -e "${RED}[!] Diretório Web não encontrado${NC}"
            echo -e "${YELLOW}    Execute httpx-runner e katana-runner primeiro!${NC}"
            return 1
        fi

        # ──────────────────────────────────────────────────────────────────────
        # PASSO 1: Validar inputs
        # ──────────────────────────────────────────────────────────────────────

        local URLS_FILE="$WORK_DIR/all_discovered_urls.txt"
        local TECH_FILE="$WORK_DIR/technologies.json"
        local OUTPUT_WL="$WORK_DIR/context_wordlist.txt"

        # Fallback se all_discovered_urls.txt não existir
        if [ ! -f "$URLS_FILE" ]; then
            echo -e "${YELLOW}[!] all_discovered_urls.txt não encontrado, criando...${NC}"
            
            cat "$WORK_DIR/alive_urls.txt" \
                "$WORK_DIR/crawled_all.txt" \
                "$WORK_DIR/js_files.txt" 2>/dev/null | sort -u > "$URLS_FILE"
        fi

        check_file "$URLS_FILE" || return 1

        local URL_COUNT=$(wc -l < "$URLS_FILE")
        echo -e "${GREEN}[+] Input: $URL_COUNT URLs para análise${NC}"

        # Tech file é opcional (se não existir, cria vazio)
        if [ ! -f "$TECH_FILE" ]; then
            echo -e "${YELLOW}[!] technologies.json não encontrado (tech detection desabilitado)${NC}"
            echo "[]" > "$TECH_FILE"
        fi

        # ──────────────────────────────────────────────────────────────────────
        # PASSO 2: Executar Python Helper (filters.py)
        # ──────────────────────────────────────────────────────────────────────

        check_tool "python3" || return 1
        check_file "$FILTERS_SCRIPT" || return 1

        echo -e "${CYAN}[+] Gerando wordlist contextualizada...${NC}"

        python3 "$FILTERS_SCRIPT" wordlist \
            --urls "$URLS_FILE" \
            --tech "$TECH_FILE" \
            > "$OUTPUT_WL"

        if [ $? -ne 0 ]; then
            echo -e "${RED}[!] Erro ao executar filters.py${NC}"
            return 1
        fi

        # ──────────────────────────────────────────────────────────────────────
        # PASSO 3: Estatísticas
        # ──────────────────────────────────────────────────────────────────────

        local WL_SIZE=$(wc -l < "$OUTPUT_WL")

        echo -e "${GREEN}[✔] Wordlist gerada com sucesso!${NC}"
        echo -e "${YELLOW}    -> $WL_SIZE payloads contextualizados${NC}"

        # Análise de composição
        local BACKUP_COUNT=$(grep -E '\.(bak|old|swp|orig)$' "$OUTPUT_WL" 2>/dev/null | wc -l)
        local YEAR_COUNT=$(grep -E '_(20[0-9]{2}|20[0-9]{2})$' "$OUTPUT_WL" 2>/dev/null | wc -l)
        local EXT_COUNT=$(grep -E '\.(php|asp|jsp|py|rb)$' "$OUTPUT_WL" 2>/dev/null | wc -l)

        echo -e "${CYAN}[i] Composição da wordlist:${NC}"
        echo -e "    - Payloads de backup: $BACKUP_COUNT"
        echo -e "    - Payloads com ano: $YEAR_COUNT"
        echo -e "    - Payloads tech-aware: $EXT_COUNT"

        # ──────────────────────────────────────────────────────────────────────
        # PASSO 4: Gerar Markdown de Referência
        # ──────────────────────────────────────────────────────────────────────

        local OBSIDIAN_DIR="$TARGETS_DIR/$TARGET"
        local MD_FILE="$OBSIDIAN_DIR/context_wordlist_stats.md"

        mkdir -p "$OBSIDIAN_DIR"

        {
            echo "# 易 Context Wordlist - $TARGET"
            echo ""
            echo "**Data**: $(date '+%Y-%m-%d %H:%M:%S')"
            echo "**URLs Analisadas**: $URL_COUNT"
            echo "**Payloads Gerados**: $WL_SIZE"
            echo ""
            echo "##  Composição"
            echo ""
            echo "| Tipo | Quantidade | Exemplo |"
            echo "|------|-----------|---------|"
            echo "| Backup Extensions | $BACKUP_COUNT | \`admin.bak\`, \`config.old\` |"
            echo "| Year Permutations | $YEAR_COUNT | \`admin_2025\`, \`api2024\` |"
            echo "| Tech-Aware | $EXT_COUNT | \`.php\`, \`.aspx\`, \`.jsp\` |"
            echo "| **Total** | **$WL_SIZE** | - |"
            echo ""
            echo "##  Amostras (Primeiras 30)"
            echo ""
            echo '```'
            head -30 "$OUTPUT_WL"
            echo '```'
            echo ""
            echo "---"
            echo "*Arquivo completo: \`Web/context_wordlist.txt\`*"
        } > "$MD_FILE"

        echo -e "${CYAN}    -> Markdown: $MD_FILE${NC}"
        echo -e "${CYAN}    -> Wordlist: $OUTPUT_WL${NC}"
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
    
    echo -e "${YELLOW}────────────────────────────────────────${NC}"
    
    if [ -d "$NMAP_DIR/nmap-$TARGET_NAME/Web" ]; then
        process_target "$TARGET_NAME" || echo -e "${RED}[FAIL] Erro em $TARGET_NAME${NC}"
    else
        echo -e "${RED}[!] Web dir não encontrado para $TARGET_NAME${NC}"
    fi
done
fi
echo -e "${GREEN}[★] Context Wordlist Builder finalizado! ${NC}"