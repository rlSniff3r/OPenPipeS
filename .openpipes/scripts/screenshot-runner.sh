#!/usr/bin/env bash
# 
# screenshot-runner.sh - Visual Reconnaissance Module
# 
# Descrição: Captura screenshots de URLs vivas usando gowitness
# Input: results/httpx_live_probes.txt
# Output: results/screenshots/ (HTML report + imagens)
# Dependências: gowitness
# 

set -euo pipefail

# 
# CONFIGURAÇÃO E VALIDAÇÃO
# 

# Carrega configuração central
CONFIG_FILE="$HOME/.openpipes/config.sh"
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo -e "\033[1;31m[ERRO]\033[0m Arquivo de configuração não encontrado: $CONFIG_FILE"
    exit 1
fi
source "$CONFIG_FILE"

# Carrega códigos de cor
COLOR_FILE="$HOME/.openpipes/colorCodes.sh"
if [[ -f "$COLOR_FILE" ]]; then
    source "$COLOR_FILE"
else
    # Fallback se colorCodes.sh não existir
    RED="\033[1;31m"
    GREEN="\033[1;32m"
    YELLOW="\033[1;33m"
    BLUE="\033[1;34m"
    MAGENTA="\033[1;35m"
    CYAN="\033[1;36m"
    RESET="\033[0m"
fi

# 
# VARIÁVEIS GLOBAIS
# 

SCRIPT_NAME="screenshot-runner"
INPUT_FILE="${proj_dir}/${proj_name}/results/httpx_live_probes.txt"
OUTPUT_DIR="${proj_dir}/${proj_name}/results/screenshots"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="${OUTPUT_DIR}/gowitness_${TIMESTAMP}.html"
DB_FILE="${OUTPUT_DIR}/gowitness.sqlite3"

# 
# FUNÇÕES AUXILIARES
# 

# Função de logging (reusa padrão do config.sh se disponível)
log_msg() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    case "$level" in
        INFO)  echo -e "${CYAN}[${timestamp}]${RESET} ${GREEN}[INFO]${RESET} $message" ;;
        WARN)  echo -e "${CYAN}[${timestamp}]${RESET} ${YELLOW}[WARN]${RESET} $message" ;;
        ERROR) echo -e "${CYAN}[${timestamp}]${RESET} ${RED}[ERRO]${RESET} $message" ;;
        *)     echo -e "${CYAN}[${timestamp}]${RESET} $message" ;;
    esac
    
    # Log para arquivo se LOG_FILE estiver definido
    if [[ -n "${LOG_FILE:-}" ]]; then
        echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    fi
}

# Valida dependências
check_dependencies() {
    log_msg INFO "Validando dependências..."
    
    if ! command -v gowitness &>/dev/null; then
        log_msg ERROR "gowitness não encontrado. Instale com: go install github.com/sensepost/gowitness@latest"
        exit 1
    fi
    
    log_msg INFO "Dependências OK: gowitness $(gowitness version 2>&1 | head -n1 || echo 'instalado')"
}

# Valida arquivo de entrada
validate_input() {
    log_msg INFO "Validando arquivo de entrada: $INPUT_FILE"
    
    if [[ ! -f "$INPUT_FILE" ]]; then
        log_msg ERROR "Arquivo de entrada não encontrado: $INPUT_FILE"
        log_msg WARN "Execute httpx-runner.sh antes de rodar este módulo"
        exit 1
    fi
    
    local line_count=$(wc -l &lt; "$INPUT_FILE" | tr -d ' ')
    if [[ "$line_count" -eq 0 ]]; then
        log_msg ERROR "Arquivo de entrada está vazio: $INPUT_FILE"
        exit 1
    fi
    
    log_msg INFO "Arquivo válido: $line_count URLs encontradas"
}

# Cria estrutura de diretórios
setup_directories() {
    log_msg INFO "Configurando estrutura de diretórios..."
    
    if [[ ! -d "$OUTPUT_DIR" ]]; then
        mkdir -p "$OUTPUT_DIR"
        log_msg INFO "Criado: $OUTPUT_DIR"
    else
        log_msg WARN "Diretório já existe: $OUTPUT_DIR"
    fi
}

# 
# EXECUÇÃO PRINCIPAL
# 

run_gowitness() {
    log_msg INFO "Iniciando captura de screenshots com gowitness..."
    log_msg INFO "Input: $INPUT_FILE"
    log_msg INFO "Output: $OUTPUT_DIR"
    
    # Ajusta parâmetros baseado no SCAN_PROFILE (se definido)
    local threads=10
    local timeout=15
    
    case "${SCAN_PROFILE:-normal}" in
        quick)
            threads=5
            timeout=10
            ;;
        aggressive)
            threads=20
            timeout=20
            ;;
        *)
            threads=10
            timeout=15
            ;;
    esac
    
    log_msg INFO "Perfil de scan: ${SCAN_PROFILE:-normal} (threads=$threads, timeout=${timeout}s)"
    
    # Executa gowitness
    # Flags:
    # --chrome-path: deixa gowitness usar o chromium instalado
    # --screenshot-path: diretório para salvar screenshots
    # --db-path: banco SQLite para metadados
    # --threads: paralelização
    # --timeout: timeout por URL
    # --no-http: desabilita fallback HTTP (já temos URLs completas do httpx)
    
    cd "$OUTPUT_DIR" || exit 1
    
    gowitness file \
        --file "$INPUT_FILE" \
        --screenshot-path "$OUTPUT_DIR" \
        --db-path "$DB_FILE" \
        --threads "$threads" \
        --timeout "${timeout}s" \
        --write-db \
        --write-screenshots \
        2>&1 | tee "${OUTPUT_DIR}/gowitness_${TIMESTAMP}.log"
    
    local exit_code=${PIPESTATUS[0]}
    
    if [[ $exit_code -eq 0 ]]; then
        log_msg INFO "Captura concluída com sucesso"
    else
        log_msg WARN "gowitness retornou código de saída: $exit_code"
    fi
    
    # Gera relatório HTML
    log_msg INFO "Gerando relatório HTML..."
    gowitness report server \
        --db-path "$DB_FILE" \
        --addr "127.0.0.1:7171" \
        --open=false &
    
    local server_pid=$!
    sleep 2
    
    # Salva referência ao servidor (para stop manual se necessário)
    echo "$server_pid" > "${OUTPUT_DIR}/gowitness_server.pid"
    log_msg INFO "Servidor gowitness disponível em: http://127.0.0.1:7171"
    log_msg INFO "PID do servidor: $server_pid (kill com: kill $server_pid)"
}

# Gera resumo para Obsidian
generate_obsidian_summary() {
    log_msg INFO "Gerando resumo para Obsidian..."
    
    local summary_file="${OUTPUT_DIR}/summary.md"
    local screenshot_count=$(ls -1 "${OUTPUT_DIR}"/*.png 2>/dev/null | wc -l)
    
    cat > "$summary_file" &lt;<EOF
# Screenshot Reconnaissance - Summary

**Data**: $(date +"%Y-%m-%d %H:%M:%S")
**Projeto**: ${proj_name}
**Input**: \`$(basename "$INPUT_FILE")\`
**Output**: \`$(basename "$OUTPUT_DIR")\`

---

## Estatísticas

- **URLs processadas**: $(wc -l &lt; "$INPUT_FILE" | tr -d ' ')
- **Screenshots capturados**: $screenshot_count
- **Banco de dados**: \`$(basename "$DB_FILE")\`
- **Log**: \`gowitness_${TIMESTAMP}.log\`

---

## Visualização

Para visualizar o relatório interativo:

\`\`\`bash
gowitness report server --db-path "$DB_FILE" --addr 127.0.0.1:7171
\`\`\`

Acesse: [http://127.0.0.1:7171](http://127.0.0.1:7171)

---

## Screenshots Capturados

$(ls -1 "${OUTPUT_DIR}"/*.png 2>/dev/null | head -20 | while read -r img; do
    echo "- \`$(basename "$img")\`"
done)

$(if [[ $screenshot_count -gt 20 ]]; then
    echo ""
    echo "> **Nota**: Exibindo apenas os primeiros 20 de $screenshot_count screenshots."
fi)

---

## Próximos Passos

- [ ] Revisar screenshots manualmente
- [ ] Identificar interfaces de admin/login
- [ ] Mapear tecnologias via análise visual
- [ ] Correlacionar com resultados do Nuclei

EOF
    
    log_msg INFO "Resumo salvo: $summary_file"
    
    # Copia resumo para diretório Obsidian se definido
    if [[ -n "${OBSIDIAN_PROJ_PATH:-}" ]] && [[ -d "${OBSIDIAN_PROJ_PATH}" ]]; then
        local obsidian_summary="${OBSIDIAN_PROJ_PATH}/screenshots_$(date +%Y%m%d).md"
        cp "$summary_file" "$obsidian_summary"
        log_msg INFO "Resumo copiado para Obsidian: $obsidian_summary"
    fi
}

# Banner inicial
display_banner() {
    echo -e "${MAGENTA}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║         📸 OPenPipeS Screenshot Runner v1.0              ║"
    echo "║         Visual Reconnaissance with gowitness             ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
}

# 
# FLUXO PRINCIPAL
# 

main() {
    display_banner
    
    log_msg INFO "Iniciando $SCRIPT_NAME para projeto: ${proj_name}"
    
    check_dependencies
    validate_input
    setup_directories
    run_gowitness
    generate_obsidian_summary
    
    echo ""
    log_msg INFO "${GREEN}✓ Execução concluída com sucesso!${RESET}"
    log_msg INFO "Resultados disponíveis em: $OUTPUT_DIR"
    echo ""
}

# Trap para cleanup em caso de interrupção
trap 'log_msg ERROR "Execução interrompida pelo usuário"; exit 130' SIGINT SIGTERM

# Execução
main "$@"
