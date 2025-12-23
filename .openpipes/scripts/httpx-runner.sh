!#/bin/bash

════════════════════════════════════════════════════════════════════════════
httpx-runner.sh v2.0 - HTTP Probing com Hybrid Target Preparation
Parte do OpenPipeS Framework
════════════════════════════════════════════════════════════════════════════


source ~/.openpipes/config.sh
source ~/colorCodes.sh


cat <<Banner
${CYAN}
██╗  ██╗████████╗████████╗██████╗ ██╗  ██╗   ██████╗ ██╗   ██╗███╗   ██╗███╗   ██╗███████╗██████╗
██║  ██║╚══██╔══╝╚══██╔══╝██╔══██╗╚██╗██╔╝   ██╔══██╗██║   ██║████╗  ██║████╗  ██║██╔════╝██╔══██╗
███████║   ██║      ██║   ██████╔╝ ╚███╔╝    ██████╔╝██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██╔══██║   ██║      ██║   ██╔═══╝  ██╔██╗    ██╔══██╗██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║  ██║   ██║      ██║   ██║     ██╔╝ ██╗   ██║  ██║╚██████╔╝██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝     ╚═╝  ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
${NC}
${BLUE}                      HTTP Probing com Tech Detection
v2.0 - Hybrid Target Preparation${NC}
Banner


════════════════════════════════════════════════════════════════════════════
CONFIGURAÇÃO
════════════════════════════════════════════════════════════════════════════
export NO_COLOR=1
COMMON_HTTP_PORTS=(80 443 8000 8080 8443 10443 4443 3000 5000 8888 9000)
IGNORE_PORTS="21|22|23|25|53|111|135|137|139|445|3306|3389|5432|5900|6379"
════════════════════════════════════════════════════════════════════════════
FUNÇÕES AUXILIARES
════════════════════════════════════════════════════════════════════════════

check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "{RED}[ERROR] Ferramenta '$1' não encontrada! {NC}"
        return 1
    fi
    return 0
}

════════════════════════════════════════════════════════════════════════════
HYBRID TARGET PREPARATION
Combina portas do Nmap + subdomínios do Recon
════════════════════════════════════════════════════════════════════════════
prepare_hybrid_targets() {
    local TGT="$1"
    local WORK_DIR="$2"
    echo -e "${GREEN}[+] Preparando alvos (Modo Híbrido: Nmap + Recon)...${NC}"

    local GNMAP_FILE="$NMAP_DIR/nmap-${TGT}/nmap.gnmap"
    local SUBDOMAINS_FILE="$TARGETS_DIR/$TGT/Recon/subdomains_final.txt"

    local RAW_TARGETS="$WORK_DIR/raw_targets.txt"
    local FINAL_TARGETS="$WORK_DIR/targets_for_httpx.txt"

    : > "$RAW_TARGETS"

    # ──────────────────────────────────────────────────────────────────────
    # FONTE 1: Portas do Nmap (Host:Port específicas)
    # ──────────────────────────────────────────────────────────────────────
    if [ -f "$GNMAP_FILE" ]; then
        echo -e "${BLUE}    -> Extraindo portas do Nmap...${NC}"
        
        grep "Ports:" "$GNMAP_FILE" | while read -r line; do
            echo "$line" | grep -oE "[0-9]+/open/tcp" | while read -r port_block; do
                PORT=$(echo "$port_block" | cut -d/ -f1)
                
                # Ignora portas de infraestrutura
                if [[ "$PORT" =~ ^($IGNORE_PORTS)$ ]]; then
                    continue
                fi
                
                # Adiciona target:port
                echo "$TGT:$PORT" >> "$RAW_TARGETS"
            done
        done
    else
        echo -e "${YELLOW}    -> Nmap não encontrado, seguindo apenas com subdomínios.${NC}"
    fi

    # ──────────────────────────────────────────────────────────────────────
    # FONTE 2: Subdomínios do Recon (com portas comuns)
    # ──────────────────────────────────────────────────────────────────────
    if [ -f "$SUBDOMAINS_FILE" ]; then
        echo -e "${BLUE}    -> Injetando subdomínios do Recon...${NC}"
        
        # Adiciona subdomínios puros (HTTPx vai testar 80/443 automaticamente)
        cat "$SUBDOMAINS_FILE" >> "$RAW_TARGETS"
        
        # Se temos portas do Nmap, testa subdomínios nessas portas também!
        if [ -f "$GNMAP_FILE" ]; then
            local DISCOVERED_PORTS=($(grep "Ports:" "$GNMAP_FILE" | grep -oE "[0-9]+/open/tcp" | cut -d/ -f1 | sort -u))
            
            # Testa cada subdomínio nas portas descobertas
            while read -r subdomain; do
                for port in "${DISCOVERED_PORTS[@]}"; do
                    # Pula portas de infraestrutura
                    if [[ "$port" =~ ^($IGNORE_PORTS)$ ]]; then
                        continue
                    fi
                    
                    # Adiciona subdomain:port
                    echo "$subdomain:$port" >> "$RAW_TARGETS"
                done
            done < "$SUBDOMAINS_FILE"
        fi
    else
        echo -e "${YELLOW}    -> Lista de subdomínios não encontrada em $SUBDOMAINS_FILE${NC}"
        # Fallback: adiciona o próprio target
        echo "$TGT" >> "$RAW_TARGETS"
    fi

    # ──────────────────────────────────────────────────────────────────────
    # FONTE 3: Portas comuns (fallback se não achou nada)
    # ──────────────────────────────────────────────────────────────────────
    if [ ! -s "$RAW_TARGETS" ]; then
        echo -e "${YELLOW}    -> Nenhum alvo encontrado, usando portas comuns...${NC}"
        for port in "${COMMON_HTTP_PORTS[@]}"; do
            echo "$TGT:$port" >> "$RAW_TARGETS"
        done
    fi

    # ──────────────────────────────────────────────────────────────────────
    # Consolidação e Deduplicação
    # ──────────────────────────────────────────────────────────────────────
    sort -u "$RAW_TARGETS" > "$FINAL_TARGETS"

    local TOTAL=$(wc -l < "$FINAL_TARGETS")
    echo -e "${YELLOW}    -> INPUT LIST TURBINADA: $TOTAL alvos para o HTTPx${NC}"

    # Retorna o arquivo final
    echo "$FINAL_TARGETS"
}


════════════════════════════════════════════════════════════════════════════
PIPELINE POR ALVO
════════════════════════════════════════════════════════════════════════════
process_target() {
    local TARGET="$1"
    echo -e "${BLUE}[*] >>> Processando: ${YELLOW}$TARGET${NC}"

    # Diretórios
    local WORK_DIR="$NMAP_DIR/nmap-$TARGET/Web"
    local OBSIDIAN_DIR="$TARGETS_DIR/$TARGET"

    mkdir -p "$WORK_DIR"

    # ──────────────────────────────────────────────────────────────────────
    # PASSO 1: Preparar alvos (Hybrid)
    # ──────────────────────────────────────────────────────────────────────
    local INPUT_FILE=$(prepare_hybrid_targets "$TARGET" "$WORK_DIR")

    if [ ! -s "$INPUT_FILE" ]; then
        echo -e "${RED}[!] Nenhum alvo válido para $TARGET. Abortando.${NC}"
        return 1
    fi

    # ──────────────────────────────────────────────────────────────────────
    # PASSO 2: HTTPx Probing
    # ──────────────────────────────────────────────────────────────────────
    echo -e "${GREEN}[+] Executando HTTPx...${NC}"
    check_tool "httpx" || return 1

    local JSON_OUT="$WORK_DIR/alive_hosts.json"
    local URLS_OUT="$WORK_DIR/alive_urls.txt"

    httpx -l "$INPUT_FILE" \
        -silent -sc -title -td -ip -cdn -tech-detect -server \
        -fr -probe \
        -json -o "$JSON_OUT"

    if [ ! -f "$JSON_OUT" ]; then
        echo -e "${RED}[!] HTTPx não gerou saída JSON${NC}"
        return 1
    fi

    # ──────────────────────────────────────────────────────────────────────
    # PASSO 3: Processar resultados
    # ──────────────────────────────────────────────────────────────────────

    # Extrai URLs vivas
    jq -r '.url' "$JSON_OUT" 2>/dev/null | sort -u > "$URLS_OUT"

    # Extrai tecnologias (feed pro context builder)
    cp "$JSON_OUT" "$WORK_DIR/technologies.json"

    local WEB_COUNT=$(wc -l < "$URLS_OUT")
    echo -e "${YELLOW}    -> $WEB_COUNT serviços WEB confirmados${NC}"

    if [ "$WEB_COUNT" -eq 0 ]; then
        echo -e "${YELLOW}[!] Nenhum serviço HTTP respondeu${NC}"
        return 0
    fi

    # ──────────────────────────────────────────────────────────────────────
    # PASSO 4: Gerar Markdown para Obsidian
    # ──────────────────────────────────────────────────────────────────────

    local MD_FILE="$OBSIDIAN_DIR/httpx.md"
    mkdir -p "$OBSIDIAN_DIR"

    echo "#  HTTPX - $TARGET" > "$MD_FILE"
    echo "" >> "$MD_FILE"
    echo "| Method | URL | IP | Port | Status | Title | Tecnologias | Servidor |" >> "$MD_FILE"
    echo "|--------|-----|----|------|--------|-------|-------------|----------|" >> "$MD_FILE"

    jq -r '
        sort_by(.method, .url) |
        .[] |
        [
            .method,
            (.final_url // .url // "-"),
            (.host // "-"),
            (.port|tostring // "-"),
            ((.status_code|tostring) + " " + (.status_line // "-")),
            ((.title // "-") | gsub("\\|"; "-")),
            ((.tech // ["-"] | join(",")) | gsub("\\|"; "-")),
            ((.webserver // "-") | gsub("\\|"; "-"))
        ] | "| " + join(" | ") + " |"
    ' "$JSON_OUT" >> "$MD_FILE" 2>/dev/null

    # Gera endpoints.md (URLs com status 200-299)
    local ENDPOINTS_FILE="$OBSIDIAN_DIR/endpoints.md"
    jq -r '.[] | select(.status_code >= 200 and .status_code < 300) | .url' "$JSON_OUT" 2>/dev/null | sort -u > "$ENDPOINTS_FILE"

    echo -e "${GREEN}[✔] $TARGET finalizado!${NC}"
    echo -e "${CYAN}    -> Markdown: $MD_FILE${NC}"
    echo -e "${CYAN}    -> Endpoints: $ENDPOINTS_FILE${NC}"
}


════════════════════════════════════════════════════════════════════════════
MAIN
════════════════════════════════════════════════════════════════════════════
if [ -n "$1" ]; then
    # Modo manual: target específico
    process_target "$1"
else
    # Modo batch: processa todos os targets
    echo -e "MAGENTA[∗]ModoBatch:Processandotodososalvos...{MAGENTA}[*] Modo Batch: Processando todos os alvos...
MAGENTA[∗]ModoBatch:Processandotodososalvos...{NC}"
fi

TARGETS_FILE="$NMAP_DIR/targets.txt"

if [ ! -f "$TARGETS_FILE" ]; then
    echo -e "${RED}[ERROR] targets.txt não encontrado em $NMAP_DIR${NC}"
    exit 1
fi

# Carrega targets em array (evita roubo de stdin)
mapfile -t TARGETS_ARRAY < "$TARGETS_FILE"

echo -e "${YELLOW}[i] Carregados ${#TARGETS_ARRAY[@]} alvos${NC}"

for TARGET_NAME in "${TARGETS_ARRAY[@]}"; do
    # Ignora comentários e linhas vazias
    [[ -z "$TARGET_NAME" || "$TARGET_NAME" =~ ^# ]] && continue
    
    echo -e "${YELLOW}────────────────────────────────────────${NC}"
    
    if [ -d "$NMAP_DIR/nmap-$TARGET_NAME" ]; then
        process_target "$TARGET_NAME" || echo -e "${RED}[FAIL] Erro ao processar $TARGET_NAME${NC}"
    else
        echo -e "${RED}[!] Scan não encontrado para $TARGET_NAME${NC}"
    fi
done

echo -e "GREEN[★]HTTPxRunnerfinalizado!{GREEN}[★] HTTPx Runner finalizado!
GREEN[★]HTTPxRunnerfinalizado!{NC}"

