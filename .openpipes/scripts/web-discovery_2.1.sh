#!/bin/bash
# ==============================================================================
# OPenPipeS Module: Web Discovery 2.1 (Stable & Local Buffer)
# Funcionalidade: Pipeline unificado Web. Processa localmente (ext4) e sincroniza com Obsidian.
# Estrutura: Lê NMAP_DIR/targets.txt -> Processa em NMAP_DIR -> Copia para TARGETS_DIR
# Autor: Rafael & Gemini (Sócio)
# ==============================================================================

# 1. Carregar Configurações e Cores
source ~/.openpipes/config.sh

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[1;35m'
NC='\033[0m'

# Portas para IGNORAR (Infraestrutura / Não-Web)
IGNORE_PORTS="21|22|23|25|53|111|135|137|139|445|3306|3389|5432|5900|6379"

# ==============================================================================
# FUNÇÕES AUXILIARES
# ==============================================================================

check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}[ERROR] Ferramenta '$1' não encontrada no PATH!${NC}"
        # Não damos exit aqui para não matar o batch inteiro, mas o passo vai falhar.
        return 1
    fi
    return 0
}

# ==============================================================================
# 1. EXTRAÇÃO INTELIGENTE (SNI SAFE)
# ==============================================================================

extract_targets_from_gnmap() {
    local TGT="$1"
    # GNMAP sempre fica na pasta de scan local
    local GNMAP_FILE="$NMAP_DIR/nmap-${TGT}/nmap.gnmap"
    
    # Arquivos de trabalho (WORK_DIR)
    local RAW_TARGETS="$WORK_DIR/raw_nmap_targets.txt"
    local CLEAN_TARGETS="$WORK_DIR/nmap_targets_filtered.txt"
    
    echo -e "${GREEN}[+] Passo 0: Analisando portas em $GNMAP_FILE...${NC}"

    if [ ! -f "$GNMAP_FILE" ]; then
        echo -e "${RED}[!] GNMAP não encontrado. Fallback para host puro.${NC}"
        echo "$TGT" > "$CLEAN_TARGETS"
        return
    fi

    : > "$RAW_TARGETS"

    # Parsing do GNMAP
    grep "Ports:" "$GNMAP_FILE" | while read -r line; do
        echo "$line" | grep -oE "[0-9]+/open/tcp//[^/]+/" | while read -r port_block; do
            PORT=$(echo "$port_block" | cut -d/ -f1)
            
            # Blacklist de portas
            if [[ "$PORT" =~ ^($IGNORE_PORTS)$ ]]; then
                continue
            fi
            
            # SNI Fix: Usa o NOME DO ALVO ($TGT) + Porta
            echo "$TGT:$PORT" >> "$RAW_TARGETS"
        done
    done

    sort -u "$RAW_TARGETS" > "$CLEAN_TARGETS"
    
    COUNT=$(wc -l < "$CLEAN_TARGETS")
    echo -e "${YELLOW}    -> $COUNT serviços (Host:Port) prontos para análise.${NC}"
}

# ==============================================================================
# PIPELINE POR ALVO
# ==============================================================================

run_pipeline_for_target() {
    local CURRENT_TARGET="$1"
    
    # DEFINIÇÃO DE AMBIENTE
    TARGET="$CURRENT_TARGET"
    
    # WORK_DIR: Onde o Kali bate (Rápido/Local/Ext4)
    # Ex: .../Varreduras/nmap-alvo.com/Recon
    WORK_DIR="$NMAP_DIR/nmap-$TARGET/Recon"
    
    # OBSIDIAN_DIR: Onde o usuário lê (Lento/Mount)
    # Ex: .../Pentest/Alvos/alvo.com/Recon
    OBSIDIAN_DIR="$TARGETS_DIR/$TARGET/Recon"
    
    LOG_FILE="$WORK_DIR/web-discovery.log"
    
    # Garante estrutura LOCAL
    mkdir -p "$WORK_DIR/Web/JS" "$WORK_DIR/Evidence"
    
    echo -e "${BLUE}[*] >>> Iniciando Pipeline Web para: ${YELLOW}$TARGET${NC}" | tee -a "$LOG_FILE"
    echo -e "${BLUE}    Workspace: $WORK_DIR${NC}"

    # --- PASSO 0: Extração ---
    extract_targets_from_gnmap "$TARGET"

    # --- PASSO 1: HTTPx ---
    echo -e "${GREEN}[+] Passo 1: Validando Serviços Web (HTTPx)...${NC}"
    check_tool "httpx"
    
    INPUT_LIST="$WORK_DIR/nmap_targets_filtered.txt"
    
    if [ ! -s "$INPUT_LIST" ]; then
        echo -e "${RED}[!] Nenhuma porta web válida encontrada para $TARGET. Abortando este alvo.${NC}" | tee -a "$LOG_FILE"
        return
    fi

    httpx -l "$INPUT_LIST" \
        -silent -sc -title -td -ip -cdn \
        -o "$WORK_DIR/Web/alive_hosts.json" -json || echo -e "${RED}[!] Erro no HTTPx${NC}"

    # Gera lista de URLs vivas
    if [ -f "$WORK_DIR/Web/alive_hosts.json" ]; then
        cat "$WORK_DIR/Web/alive_hosts.json" | jq -r .url > "$WORK_DIR/Web/alive_urls.txt"
    else
        echo -e "${RED}[!] HTTPx não gerou saída JSON.${NC}"
        return
    fi
    
    WEB_COUNT=$(wc -l < "$WORK_DIR/Web/alive_urls.txt")
    echo -e "${YELLOW}    -> $WEB_COUNT serviços WEB confirmados e vivos.${NC}"

    if [ "$WEB_COUNT" -eq 0 ]; then
        echo -e "${YELLOW}[!] Nenhum serviço respondeu HTTP. Pulando.${NC}"
        return
    fi

    # --- PASSO 2: Katana ---
    echo -e "${GREEN}[+] Passo 2: Deep Crawling (Katana)...${NC}"
    check_tool "katana"
    
    katana -list "$WORK_DIR/Web/alive_urls.txt" \
        -d 3 -jc -kf all -c 20 \
        -o "$WORK_DIR/Web/crawled_all.txt" -silent || echo -e "${RED}[!] Erro no Katana${NC}"

    grep -E "\.js(\?|$)" "$WORK_DIR/Web/crawled_all.txt" 2>/dev/null | sort -u > "$WORK_DIR/Web/js_files.txt"

    # --- PASSO 3: JS Mining ---
    echo -e "${GREEN}[+] Passo 3: Mineração JS (LinkFinder)...${NC}"
    if [ -s "$WORK_DIR/Web/js_files.txt" ]; then
        cd "$WORK_DIR/Web/JS" || exit
        # Download local rápido
        cat "$WORK_DIR/Web/js_files.txt" | xargs -n 1 -P 20 wget -q -T 5
        
        if command -v linkfinder.py &> /dev/null; then
             linkfinder.py -i "*.js" -o cli > "$WORK_DIR/Web/js_endpoints_raw.txt" 2>/dev/null || true
        else
             echo -e "${RED}[!] linkfinder.py não encontrado no PATH.${NC}"
        fi
        
        grep -v "Running against:" "$WORK_DIR/Web/js_endpoints_raw.txt" 2>/dev/null | \
        grep -v "Invalid input" | sort -u > "$WORK_DIR/Web/js_endpoints_clean.txt"
        
        # Volta para raiz antes de continuar
        cd - > /dev/null
    fi

    # --- PASSO 4: Profiling ---
    echo -e "${GREEN}[+] Passo 4: Wordlist Contextual...${NC}"
    OUT_WL="$WORK_DIR/Web/context_wordlist.txt"
    TEMP_WL="$OUT_WL.temp"
    
    cat "$WORK_DIR/Web/crawled_all.txt" "$WORK_DIR/Web/js_endpoints_clean.txt" 2>/dev/null | \
    awk -F/ '{print $NF}' | cut -d? -f1 > "$TEMP_WL"
    
    YEAR=$(date +%Y); LAST_YEAR=$((YEAR - 1))
    grep -E "admin|login|portal|api|dashboard|config" "$TEMP_WL" 2>/dev/null | while read word; do
        echo "${word}_${YEAR}" >> "$TEMP_WL"
        echo "${word}${YEAR}" >> "$TEMP_WL"
        echo "${word}.bak" >> "$TEMP_WL"
    done
    cat "$TEMP_WL" 2>/dev/null | sort -u | grep -E "^.{3,25}$" > "$OUT_WL"
    rm "$TEMP_WL" 2>/dev/null

    # --- PASSO 5: Feroxbuster ---
    echo -e "${GREEN}[+] Passo 5: Fuzzing (Feroxbuster)...${NC}"
    check_tool "feroxbuster"
    [ -s "$OUT_WL" ] && WL="$OUT_WL" || WL="/usr/share/seclists/Discovery/Web-Content/common.txt"
    
    for url in $(cat "$WORK_DIR/Web/alive_urls.txt"); do
        # Extrai nome do arquivo seguro para salvar
        safe_name=$(echo "$url" | sed 's/http:\/\///;s/https:\/\///;s/[\/:]/_/g')
        
        feroxbuster -u "$url" -w "$WL" -t 50 -d 2 --time-limit 10m --no-state \
            -o "$WORK_DIR/Web/ferox_${safe_name}.txt" --silent || echo -e "${RED}[!] Erro ao fuzzer $url (continuando...)${NC}"
    done

    # --- PASSO 6: Evidence (GoWitness v3) ---
    echo -e "${GREEN}[+] Passo 6: Screenshots (GoWitness v3)...${NC}"
    check_tool "gowitness"
    
    # Consolida URLs
    cat "$WORK_DIR/Web/crawled_all.txt" "$WORK_DIR/Web/js_endpoints_clean.txt" "$WORK_DIR/Web/ferox_*.txt" 2>/dev/null | \
    grep "^http" | sort -u > "$WORK_DIR/Web/final_urls_to_scan.txt"
    
    INPUT_FILE="$WORK_DIR/Web/final_urls_to_scan.txt"
    EVIDENCE_DIR="$WORK_DIR/Evidence"
    
    if [ -s "$INPUT_FILE" ]; then
        # Sintaxe v3 corrigida: scan file
        gowitness scan file -f "$INPUT_FILE" \
            --screenshot-path "$EVIDENCE_DIR" \
            --threads 10 --timeout 15 2>/dev/null || echo -e "${RED}[!] Erro no GoWitness (continuando...)${NC}"
    else
        echo -e "${YELLOW}    -> Nenhuma URL final para printar.${NC}"
    fi

    # --- PASSO 7: Sincronização Final (Ext4 -> Obsidian) ---
    echo -e "${MAGENTA}[Sync] Sincronizando resultados com o Obsidian...${NC}"
    
    # Cria diretório no Obsidian se não existir
    mkdir -p "$OBSIDIAN_DIR/Web/JS" "$OBSIDIAN_DIR/Evidence"
    
    # Cópia Inteligente (apenas arquivos relevantes)
    cp -r "$WORK_DIR/Web/"* "$OBSIDIAN_DIR/Web/" 2>/dev/null
    cp -r "$WORK_DIR/Evidence/"* "$OBSIDIAN_DIR/Evidence/" 2>/dev/null
    cp "$LOG_FILE" "$OBSIDIAN_DIR/" 2>/dev/null
    
    # Gera Markdown de Galeria no Obsidian (para visualização)
    GALLERY_MD="$OBSIDIAN_DIR/Web_Gallery.md"
    echo "# Galeria de Evidências - $TARGET" > "$GALLERY_MD"
    echo "Gerado em: $(date)" >> "$GALLERY_MD"
    echo "" >> "$GALLERY_MD"
    
    for img in "$OBSIDIAN_DIR/Evidence"/*.png; do
        [ ! -f "$img" ] && continue
        filename=$(basename "$img")
        url_name=$(echo "$filename" | sed 's/http_//;s/https_//;s/.png//')
        echo "### $url_name" >> "$GALLERY_MD"
        # Link relativo do Obsidian
        echo "![$url_name](Recon/Evidence/$filename)" >> "$GALLERY_MD"
        echo "" >> "$GALLERY_MD"
    done

    echo -e "${GREEN}[★] Alvo $TARGET finalizado! Dados sincronizados.${NC}" | tee -a "$LOG_FILE"
}

# ==============================================================================
# MAIN
# ==============================================================================

if [ -n "$1" ]; then
    # MODO MANUAL
    run_pipeline_for_target "$1"
else
    # MODO BATCH
    echo -e "${MAGENTA}[*] Iniciando Modo Batch (Fonte: $NMAP_DIR/targets.txt)${NC}"
    
    TARGETS_FILE="$NMAP_DIR/targets.txt"
    
    if [ ! -f "$TARGETS_FILE" ]; then
        echo -e "${RED}[ERROR] targets.txt não encontrado!${NC}"
        exit 1
    fi

    while read -r TARGET_NAME; do
        [[ -z "$TARGET_NAME" || "$TARGET_NAME" =~ ^# ]] && continue
        
        echo -e "${YELLOW}----------------------------------------${NC}"
        echo -e "${YELLOW}[?] Processando: $TARGET_NAME${NC}"
        
        # Verifica diretório de scan
        if [ -d "$NMAP_DIR/nmap-$TARGET_NAME" ]; then
            # Executa pipeline protegido contra falhas fatais
            run_pipeline_for_target "$TARGET_NAME" || echo -e "${RED}[CRITICAL] Falha não tratada ao processar $TARGET_NAME. Pulando...${NC}"
        else
            echo -e "${RED}[!] Scan não encontrado para $TARGET_NAME. Pule.${NC}"
        fi
        
    done < "$TARGETS_FILE"
fi