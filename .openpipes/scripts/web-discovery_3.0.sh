#!/bin/bash
# ==============================================================================
# OPenPipeS Module: Web Discovery 3.0 (Modular & Smart) <- Usa o python script ~/.openpipes/scripts/filters.py e bash script ~/.openpipes/scripts/visual-recon.sh para apoiar
# ==============================================================================

# 1. Carregar Configurações
source ~/.openpipes/config.sh

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[1;35m'
NC='\033[0m'

# Portas para IGNORAR (Infra)
IGNORE_PORTS="21|22|23|25|53|111|135|137|139|445|3306|3389|5432|5900|6379"

# Extensões para IGNORAR no Screenshot (Lixo Visual)
IGNORE_EXT="\.(css|js|map|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|pdf|docx?|xlsx?)$"

# ==============================================================================
# FUNÇÕES AUXILIARES
# ==============================================================================

check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}[ERROR] Ferramenta '$1' não encontrada no PATH!${NC}"
        return 1
    fi
    return 0
}

# ==============================================================================
# NOVA FUNÇÃO DE EXTRAÇÃO HÍBRIDA (NMAP + SUBDOMAINS)
# ==============================================================================
prepare_targets_hybrid() {
    local TGT="$1"
    local GNMAP_FILE="$NMAP_DIR/nmap-${TGT}/nmap.gnmap"
    
    # Define onde buscar a lista de subdomínios (Ajuste se o caminho for diferente)
    # Tenta pegar da pasta do Obsidian (Source of Truth do Recon Passivo)
    local SUBDOMAINS_FILE="$TARGETS_DIR/$TGT/Recon/subdomains_final.txt"
    
    local RAW_TARGETS="$WORK_DIR/raw_combined_targets.txt"
    local FINAL_TARGETS="$WORK_DIR/targets_for_httpx.txt"
    
    echo -e "${GREEN}[+] Passo 0: Preparando Alvos (Modo Híbrido: Scan + Passivo)...${NC}"
    : > "$RAW_TARGETS"

    # 1. Fonte A: Nmap (Portas Específicas)
    if [ -f "$GNMAP_FILE" ]; then
        echo -e "${BLUE}    -> Lendo portas do Nmap...${NC}"
        grep "Ports:" "$GNMAP_FILE" | while read -r line; do
            echo "$line" | grep -oE "[0-9]+/open/tcp//[^/]+/" | while read -r port_block; do
                PORT=$(echo "$port_block" | cut -d/ -f1)
                if [[ "$PORT" =~ ^($IGNORE_PORTS)$ ]]; then continue; fi
                echo "$TGT:$PORT" >> "$RAW_TARGETS"
            done
        done
    else
        echo -e "${YELLOW}    -> Nmap não encontrado. Seguindo apenas com subdomínios.${NC}"
    fi

    # 2. Fonte B: Subdomínios (Recon Passivo/Ativo Anterior)
    if [ -f "$SUBDOMAINS_FILE" ]; then
        echo -e "${BLUE}    -> Injetando subdomínios de $SUBDOMAINS_FILE...${NC}"
        cat "$SUBDOMAINS_FILE" >> "$RAW_TARGETS"
    else
        echo -e "${YELLOW}    -> Lista de subdomínios não encontrada em $SUBDOMAINS_FILE.${NC}"
        # Fallback: Adiciona o próprio alvo se não tiver nada
        echo "$TGT" >> "$RAW_TARGETS"
    fi

    # 3. Consolidação
    # Remove duplicatas. O httpx é esperto: se tiver "alvo.com" e "alvo.com:80", ele trata.
    sort -u "$RAW_TARGETS" > "$FINAL_TARGETS"
    
    TOTAL=$(wc -l < "$FINAL_TARGETS")
    echo -e "${YELLOW}    -> INPUT LIST TURBINADA: $TOTAL alvos potenciais para o HTTPx.${NC}"
}


# ==============================================================================
# PIPELINE POR ALVO
# ==============================================================================

run_pipeline_for_target() {
    local CURRENT_TARGET="$1"
    TARGET="$CURRENT_TARGET"
    WORK_DIR="$NMAP_DIR/nmap-$TARGET/Recon"
    OBSIDIAN_DIR="$TARGETS_DIR/$TARGET/Recon"
    LOG_FILE="$WORK_DIR/web-discovery.log"
    
    mkdir -p "$WORK_DIR/Web/JS" "$WORK_DIR/Evidence"
    echo -e "${BLUE}[*] >>> Pipeline v3.0: ${YELLOW}$TARGET${NC}" | tee -a "$LOG_FILE"

	# PASSO 0: Chama a nova função híbrida
    prepare_targets_hybrid "$TARGET"

    # PASSO 1: HTTPx (Agora com a lista completa)
    echo -e "${GREEN}[+] Passo 1: HTTPx (Scanning Full Scope)...${NC}"
    check_tool "httpx"
    
    # Aponta para o novo arquivo combinado
    INPUT_LIST="$WORK_DIR/targets_for_httpx.txt"
    
    if [ ! -s "$INPUT_LIST" ]; then echo "Sem alvos para testar."; return; fi

    # Flags mantidas (follow redirects, probe)
    httpx -l "$INPUT_LIST" -silent -sc -title -td -ip -cdn \
        -fr -probe \
        -o "$WORK_DIR/Web/alive_hosts.json" -json || true

	# Gera lista de URLs Vivas
    if [ -f "$WORK_DIR/Web/alive_hosts.json" ]; then
        cat "$WORK_DIR/Web/alive_hosts.json" | jq -r .url > "$WORK_DIR/Web/alive_urls.txt"
        # Exporta Techs para um arquivo separado para o Python ler
        cat "$WORK_DIR/Web/alive_hosts.json" > "$WORK_DIR/Web/technologies.json"
    else
        echo "Erro HTTPx JSON."; return
    fi
    
    # --- PASSO 2: Katana ---
    echo -e "${GREEN}[+] Passo 2: Katana (Crawling)...${NC}"
    check_tool "katana"
    katana -list "$WORK_DIR/Web/alive_urls.txt" -d 3 -jc -kf all -c 20 \
        -o "$WORK_DIR/Web/crawled_all.txt" -silent || true

    grep -E "\.js(\?|$)" "$WORK_DIR/Web/crawled_all.txt" 2>/dev/null | sort -u > "$WORK_DIR/Web/js_files.txt"

    # --- PASSO 3: JS Mining ---
    echo -e "${GREEN}[+] Passo 3: LinkFinder (JS Mining)...${NC}"
    if [ -s "$WORK_DIR/Web/js_files.txt" ]; then
        cd "$WORK_DIR/Web/JS" || exit
        cat "$WORK_DIR/Web/js_files.txt" | xargs -n 1 -P 20 wget -q -T 5
        
        if command -v linkfinder.py &> /dev/null; then
             linkfinder.py -i "*.js" -o cli > "$WORK_DIR/Web/js_endpoints_raw.txt" 2>/dev/null || true
        fi
        grep -v "Running against:" "$WORK_DIR/Web/js_endpoints_raw.txt" 2>/dev/null | \
        grep -v "Invalid input" | sort -u > "$WORK_DIR/Web/js_endpoints_clean.txt"
        cd - > /dev/null
    fi

    # PASSO 4: Smart Wordlist (Python Powered)
    echo -e "${GREEN}[+] Passo 4: Smart Wordlist (Python)...${NC}"
    
    # Concatena fontes de URLs para analise
    cat "$WORK_DIR/Web/crawled_all.txt" "$WORK_DIR/Web/js_endpoints_clean.txt" 2>/dev/null > "$WORK_DIR/Web/all_urls_found.txt"
    
    python3 ~/.openpipes/scripts/filters.py wordlist \
        --urls "$WORK_DIR/Web/all_urls_found.txt" \
        --tech "$WORK_DIR/Web/technologies.json" > "$WORK_DIR/Web/context_wordlist.txt"

    WL_SIZE=$(wc -l < "$WORK_DIR/Web/context_wordlist.txt")
    echo -e "${YELLOW}    -> Wordlist Gerada: $WL_SIZE payloads contextuais.${NC}"

    # --- PASSO 5: Feroxbuster ---
    echo -e "${GREEN}[+] Passo 5: Feroxbuster (Fuzzing)...${NC}"
    check_tool "feroxbuster"
	OUT_WL="$WORK_DIR/Web/context_wordlist.txt"
    [ -s "$OUT_WL" ] && WL="$OUT_WL" || WL="/usr/share/seclists/Discovery/Web-Content/common.txt"
    
    for url in $(cat "$WORK_DIR/Web/alive_urls.txt"); do
        safe_name=$(echo "$url" | sed 's/http:\/\///;s/https:\/\///;s/[\/:]/_/g')
        feroxbuster -u "$url" -w "$WL" -t 50 -d 2 --time-limit 10m --no-state \
            -o "$WORK_DIR/Web/ferox_${safe_name}.txt" --silent || true
    done
	
    # PASSO 6: Visual Recon (Módulo Externo)
    echo -e "${GREEN}[+] Passo 6: Visual Recon (Smart Screenshot)...${NC}"
    
    # Consolida URLs (Raw)
    cat "$WORK_DIR/Web/crawled_all.txt" "$WORK_DIR/Web/js_endpoints_clean.txt" "$WORK_DIR/Web/ferox_*.txt" 2>/dev/null | \
    grep "^http" | sort -u > "$WORK_DIR/Web/raw_urls_for_visual.txt"
    
    # Chama o script modular
    bash ~/.openpipes/scripts/visual-recon.sh \
        "$WORK_DIR/Web/raw_urls_for_visual.txt" \
        "$WORK_DIR/Evidence" \
        "$WORK_DIR/Web"

    # PASSO 7: Sync Obsidian (Igual v2.2)
    echo -e "${MAGENTA}[Sync] Sincronizando...${NC}"
    # ... (Código de cp e geração de Galeria MD mantido da v2.2) ...
}


# ==============================================================================
# MAIN (LÓGICA BLINDADA)
# ==============================================================================

if [ -n "$1" ]; then
    # MODO MANUAL
    run_pipeline_for_target "$1"
else
    # MODO BATCH (ARRAY METHOD)
    echo -e "${MAGENTA}[*] Iniciando Modo Batch...${NC}"
    TARGETS_FILE="$NMAP_DIR/targets.txt"
    
    if [ ! -f "$TARGETS_FILE" ]; then
        echo -e "${RED}[ERROR] targets.txt ausente!${NC}"; exit 1
    fi

    # Carrega todo o arquivo para um array em memória (Evita roubo de stdin)
    mapfile -t TARGETS_ARRAY < "$TARGETS_FILE"
    
    echo -e "${YELLOW}[i] Carregados ${#TARGETS_ARRAY[@]} alvos para processamento.${NC}"

    # Loop for sobre o array (Seguro)
    for TARGET_NAME in "${TARGETS_ARRAY[@]}"; do
        # Limpeza de strings vazias ou comentários
        [[ -z "$TARGET_NAME" || "$TARGET_NAME" =~ ^# ]] && continue
        
        echo -e "${YELLOW}----------------------------------------${NC}"
        echo -e "${YELLOW}[?] Processando: $TARGET_NAME${NC}"
        
        if [ -d "$NMAP_DIR/nmap-$TARGET_NAME" ]; then
            # Executa com proteção || true para garantir o próximo loop
            run_pipeline_for_target "$TARGET_NAME" || echo -e "${RED}[FAIL] Erro crítico em $TARGET_NAME${NC}"
        else
            echo -e "${RED}[!] Scan não encontrado para $TARGET_NAME ($NMAP_DIR/nmap-$TARGET_NAME).${NC}"
        fi
    done
fi