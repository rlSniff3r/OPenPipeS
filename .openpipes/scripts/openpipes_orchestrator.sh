#!/bin/bash

# ============================================================================
# OPenPipeS - Obsidian Pentest Pipeline Stack
# Orquestrador Principal v2.1
# Author: Rafael Luís da Silva & Claude Beast A.I.
# ============================================================================

set -euo pipefail

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Diretórios
OPENPIPES_HOME="${OPENPIPES_DIR:-$HOME/.openpipes}"
OPENPIPES_BIN="$OPENPIPES_HOME/bin"
OPENPIPES_SCRIPTS="$OPENPIPES_HOME/scripts"
OPENPIPES_TEMPLATES="$OPENPIPES_HOME/.templates"
OPENPIPES_CACHE="${OPENPIPES_CACHE:-$HOME/.openpipes_cache}"
OPENPIPES_CONFIG="$OPENPIPES_HOME/config.sh"

# Variáveis globais do projeto (carregadas do config.sh)
proj_dir=""
proj_name=""
proj_path=""
obsdir=""

# ============================================================================
# FUNÇÕES DE UTILIDADE
# ============================================================================

show_banner() {
    clear
    echo -e "${BLUE}"
    cat << "EOF"
   ___  ____                 ____  _                ____  
  / _ \|  _ \ ___ _ __  _ __|  _ \(_)_ __   ___  / ___| 
 | | | | |_) / _ | '_ \| '__| |_) | | '_ \ / _ \ \___ \ 
 | |_| |  __/  __| | | | |  |  __/| | |_) |  __/  ___) |
  \___/|_|   \___|_| |_|_|  |_|   |_| .__/ \___| |____/ 
                                     |_|                  
            Obsidian Pentest Pipeline Stack v2.1
EOF
    echo -e "${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        INFO)
            echo -e "${BLUE}[*]${NC} $message"
            ;;
        SUCCESS)
            echo -e "${GREEN}[✓]${NC} $message"
            ;;
        WARNING)
            echo -e "${YELLOW}[!]${NC} $message"
            ;;
        ERROR)
            echo -e "${RED}[✗]${NC} $message"
            ;;
        STEP)
            echo -e "\n${MAGENTA}▶${NC} ${CYAN}$message${NC}\n"
            ;;
        QUESTION)
            echo -e "${YELLOW}[?]${NC} $message"
            ;;
    esac
}

press_enter() {
    echo ""
    read -p "Pressione ENTER para continuar..."
}

# ============================================================================
# VALIDAÇÃO E CONFIGURAÇÃO
# ============================================================================

check_root() {
    if [[ $EUID -eq 0 ]]; then
        log ERROR "Este script não deve ser executado como root!"
        log WARNING "Execute como usuário normal. Sudo será solicitado quando necessário."
        exit 1
    fi
}

check_config() {
    if [[ ! -f "$OPENPIPES_CONFIG" ]]; then
        log ERROR "Arquivo de configuração não encontrado!"
        log INFO "Esperado em: $OPENPIPES_CONFIG"
        log INFO "Execute o instalador primeiro: installer.sh"
        exit 1
    fi
    
    source "$OPENPIPES_CONFIG"
    
    # Validar variáveis obrigatórias
    local required_vars=(
        "proj_dir"
        "proj_name"
        "obsdir"
    )
    
    local missing_vars=()
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var}" ]]; then
            missing_vars+=("$var")
        fi
    done
    
    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        log ERROR "Variáveis não configuradas em config.sh:"
        for var in "${missing_vars[@]}"; do
            echo "  - $var"
        done
        log INFO "Configure usando a opção [C] do menu"
    fi
    
    # Construir caminho completo do projeto
    proj_path="$proj_dir/$proj_name"
}

# ============================================================================
# NOVA FUNÇÃO: VALIDAÇÃO COMPLETA DO PROJETO
# ============================================================================

validate_project() {
    local errors=0
    local warnings=0
    
    log STEP "Validando estrutura do projeto..."
    
    # 1. Verificar se diretório do projeto existe
    if [[ ! -d "$proj_path" ]]; then
        log ERROR "Diretório do projeto não existe: $proj_path"
        ((errors++))
    else
        log SUCCESS "Diretório do projeto existe"
    fi
    
    # 2. Verificar se domains.txt existe
    if [[ ! -f "$proj_path/Recon/domains.txt" ]]; then
        log ERROR "Arquivo domains.txt não encontrado: $proj_path/Recon/domains.txt"
        ((errors++))
    else
        log SUCCESS "Arquivo domains.txt existe"
        
        # 3. Verificar se domains.txt tem conteúdo
        if [[ ! -s "$proj_path/Recon/domains.txt" ]]; then
            log WARNING "domains.txt está vazio!"
            ((warnings++))
        else
            local domain_count=$(grep -v '^#' "$proj_path/Recon/domains.txt" | grep -v '^$' | wc -l)
            if [[ $domain_count -eq 0 ]]; then
                log WARNING "domains.txt não possui domínios válidos (apenas comentários/linhas vazias)"
                ((warnings++))
            else
                log SUCCESS "domains.txt contém $domain_count domínio(s)"
            fi
        fi
    fi
    
    # 4. Verificar subdiretórios essenciais
    local required_dirs=(
        "Recon"
        "Varreduras"
    )
    
    for dir in "${required_dirs[@]}"; do
        if [[ ! -d "$proj_path/$dir" ]]; then
            log WARNING "Diretório $dir não existe (será criado quando necessário)"
            ((warnings++))
        else
            log SUCCESS "Diretório $dir existe"
        fi
    done
    
    # 5. Verificar Obsidian vault
    if [[ ! -d "$obsdir" ]]; then
        log WARNING "Obsidian vault não existe: $obsdir"
        ((warnings++))
    else
        log SUCCESS "Obsidian vault configurado"
    fi
    
    echo ""
    
    # Resultado da validação
    if [[ $errors -gt 0 ]]; then
        log ERROR "Validação falhou: $errors erro(s), $warnings aviso(s)"
        log QUESTION "Deseja inicializar a estrutura do projeto agora?"
        read -p "$(echo -e ${YELLOW}[S/n]:${NC} )" -n 1 -r
        echo
        if [[ $REPLY =~ ^[Ss]$ ]] || [[ -z $REPLY ]]; then
            setup_project_structure
            return 0
        else
            log WARNING "Execute a opção [I] do menu para inicializar o projeto"
            return 1
        fi
    elif [[ $warnings -gt 0 ]]; then
        log WARNING "Validação concluída com $warnings aviso(s)"
        return 0
    else
        log SUCCESS "Validação concluída! Projeto pronto para uso."
        return 0
    fi
}

# ============================================================================
# NOVA FUNÇÃO: CRIAR ESTRUTURA DO PROJETO
# ============================================================================

setup_project_structure() {
    log STEP "Inicializando estrutura do projeto..."
    
    # 1. Criar diretório principal do projeto
    if [[ ! -d "$proj_path" ]]; then
        log INFO "Criando diretório do projeto: $proj_path"
        mkdir -p "$proj_path"
        log SUCCESS "Diretório criado"
    else
        log SUCCESS "Diretório do projeto já existe"
    fi
    
    # 2. Criar subdiretórios
    local project_dirs=(
        "Recon"
        "Varreduras"
        "OSINT"
        "Logs"
    )
    
    log INFO "Criando estrutura de diretórios..."
    for dir in "${project_dirs[@]}"; do
        if [[ ! -d "$proj_path/$dir" ]]; then
            mkdir -p "$proj_path/$dir"
            log SUCCESS "  ✓ $dir/"
        else
            echo -e "${CYAN}  - $dir/ ${YELLOW}(já existe)${NC}"
        fi
    done
    
    # 3. Criar domains.txt (se não existir)
    if [[ ! -f "$proj_path/Recon/domains.txt" ]]; then
        log INFO "Criando domains.txt..."
        
        cat > "$proj_path/Recon/domains.txt" << 'DOMAINS_EOF'
# ============================================================================
# domains.txt - Lista de Domínios para Reconhecimento
# ============================================================================
# 
# Instruções:
# - Adicione um domínio por linha (SLDs apenas, sem subdomínios)
# - Linhas começando com # são ignoradas
# - Linhas vazias são ignoradas
#
# Exemplos:
# example.com
# target.com.br
# test-domain.org
#
# ============================================================================

DOMAINS_EOF
        
        log SUCCESS "domains.txt criado"
        log WARNING "Arquivo está vazio! Adicione domínios antes de executar o pipeline."
        
        # Perguntar se quer adicionar domínios agora
        echo ""
        log QUESTION "Deseja adicionar domínios agora?"
        read -p "$(echo -e ${YELLOW}[s/N]:${NC} )" -n 1 -r
        echo
        
        if [[ $REPLY =~ ^[Ss]$ ]]; then
            ${EDITOR:-nano} "$proj_path/Recon/domains.txt"
            
            # Validar se foram adicionados domínios
            local domain_count=$(grep -v '^#' "$proj_path/Recon/domains.txt" | grep -v '^$' | wc -l)
            if [[ $domain_count -gt 0 ]]; then
                log SUCCESS "$domain_count domínio(s) adicionado(s)"
            else
                log WARNING "Nenhum domínio adicionado. Lembre-se de adicionar antes de executar módulos."
            fi
        fi
    else
        log SUCCESS "domains.txt já existe"
        
        # Mostrar quantos domínios existem
        local domain_count=$(grep -v '^#' "$proj_path/Recon/domains.txt" | grep -v '^$' | wc -l)
        if [[ $domain_count -gt 0 ]]; then
            log INFO "Domínios configurados: $domain_count"
        else
            log WARNING "domains.txt existe mas está vazio!"
        fi
    fi
    
    # 4. Criar .gitignore (se não existir)
    if [[ ! -f "$proj_path/.gitignore" ]]; then
        log INFO "Criando .gitignore..."
        
        cat > "$proj_path/.gitignore" << 'GITIGNORE_EOF'
# OPenPipeS - GitIgnore
*.log
*.tmp
.DS_Store
Thumbs.db
GITIGNORE_EOF
        
        log SUCCESS ".gitignore criado"
    fi
    
    # 5. Criar Obsidian vault (se não existir)
    if [[ ! -d "$obsdir" ]]; then
        log INFO "Criando Obsidian vault: $obsdir"
        mkdir -p "$obsdir/$proj_name/Pentest"
        mkdir -p "$obsdir/$proj_name/Pentest/Alvos"
        log SUCCESS "Obsidian vault criado"
    else
        log SUCCESS "Obsidian vault já existe"
    fi
    
    # 6. Criar README do projeto
    if [[ ! -f "$proj_path/README.md" ]]; then
        log INFO "Criando README.md..."
        
        cat > "$proj_path/README.md" << EOF
# Projeto: $proj_name

**Criado em:** $(date '+%Y-%m-%d %H:%M:%S')  
**Framework:** OPenPipeS v2.1

---

## 📁 Estrutura de Diretórios

\`\`\`
$proj_name/
├── Varreduras/          # Scans Nmap
├── OSINT/               # OSINT People
├── Logs/                # Execution logs
├── README.md            # Informações do Projeto
└── Recon/               # Reconhecimento DNS
     └── domains.txt          # Lista de domínios alvo
\`\`\`

---

## 🚀 Comandos Rápidos

\`\`\`bash
# Executar orchestrador
openpipes

# Módulos individuais
recon                  # Reconhecimento
nwrapper               # Nmap scan
httpx-runner           # HTTP probing
nuclei-runner          # Vulnerability scan
\`\`\`

---

## 📊 Obsidian Vault

**Localização:** \`$obsdir/$proj_name\`

Acesse os dashboards gerados em:
- Dashboard Global: \`Pentest/Dashboard_Global.md\`
- Alvos individuais: \`Pentest/Alvos/<target>/\`

---

Gerado automaticamente por OPenPipeS
EOF
        
        log SUCCESS "README.md criado"
    fi
    
    echo ""
    log SUCCESS "Estrutura do projeto inicializada com sucesso!"
    log INFO "Diretório: $proj_path"
    
    # Mostrar resumo
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}✓${NC} Diretórios criados"
    echo -e "${GREEN}✓${NC} domains.txt configurado"
    echo -e "${GREEN}✓${NC} README.md gerado"
    
    local domain_count=$(grep -v '^#' "$proj_path/Recon/domains.txt" | grep -v '^$' | wc -l)
    if [[ $domain_count -gt 0 ]]; then
        echo -e "${GREEN}✓${NC} $domain_count domínio(s) configurado(s)"
    else
        echo -e "${YELLOW}!${NC} domains.txt vazio (adicione domínios antes de executar)"
    fi
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# ============================================================================
# MENU PRINCIPAL
# ============================================================================

show_menu() {
    show_banner
    
    # Mostrar configuração atual
    echo -e "${CYAN}Projeto atual:${NC} ${GREEN}$proj_name${NC}"
    echo -e "${CYAN}Diretório:${NC} $proj_path"
    
    # Verificar se domains.txt existe e mostrar status
    if [[ -f "$proj_path/Recon/domains.txt" ]]; then
        local domain_count=$(grep -v '^#' "$proj_path/Recon/domains.txt" | grep -v '^$' | wc -l)
        if [[ $domain_count -gt 0 ]]; then
            echo -e "${CYAN}Domínios:${NC} ${GREEN}$domain_count configurado(s)${NC}"
        else
            echo -e "${CYAN}Domínios:${NC} ${YELLOW}0 (domains.txt vazio!)${NC}"
        fi
    else
        echo -e "${CYAN}Domínios:${NC} ${RED}domains.txt não encontrado!${NC}"
    fi
    
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    echo -e "${GREEN}[I]${NC} Inicializar Projeto     ${CYAN}(Criar estrutura e domains.txt)${NC}"
    echo -e "${GREEN}[R]${NC} Reconhecimento          ${CYAN}(dnsrecon, amass, SecurityTrails)${NC}"
    echo -e "${GREEN}[S]${NC} Scanning                ${CYAN}(nmap wrapper)${NC}"
    echo -e "${GREEN}[O]${NC} Setup Obsidian          ${CYAN}(cria estrutura de alvos)${NC}"
    echo -e "${GREEN}[H]${NC} HTTPx Runner            ${CYAN}(HTTP probing)${NC}"
    echo -e "${GREEN}[K]${NC} Katana + Feroxbuster    ${CYAN}(web discovery)${NC}"
    echo -e "${GREEN}[N]${NC} Nuclei Scan             ${CYAN}(vulnerability scanning)${NC}"
    echo -e "${GREEN}[J]${NC} JSFinder                ${CYAN}(JavaScript analysis)${NC}"
    echo -e "${GREEN}[G]${NC} GF Summary              ${CYAN}(pattern matching)${NC}"
    echo -e "${GREEN}[W]${NC} WHOIS Enricher          ${CYAN}(WHOIS data)${NC}"
    echo -e "${GREEN}[Y]${NC} OSINT People            ${CYAN}(people reconnaissance)${NC}"
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${MAGENTA}[P]${NC} Pipeline Completo       ${CYAN}(executa todos os módulos)${NC}"
    echo -e "${MAGENTA}[V]${NC} Vulnerabilidades        ${CYAN}(gerenciar vulnerabilidades)${NC}"
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${YELLOW}[C]${NC} Configuração            ${CYAN}(editar config.sh)${NC}"
    echo -e "${YELLOW}[T]${NC} Status                  ${CYAN}(verificar ferramentas)${NC}"
    echo -e "${YELLOW}[?]${NC} Ajuda"
    echo -e "${YELLOW}[Q]${NC} Sair"
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}


# ============================================================================
# PIPELINE COMPLETO
# ============================================================================

run_module() {
    local module=$1
    local script=""
    local description=""

    case $module in
        recon)
            script="$OPENPIPES_BIN/recon"
            description="Reconhecimento DNS"
            
            # PRÉ-VALIDAÇÕES ESPECÍFICAS DO RECON
            if [[ ! -f "$proj_path/Recon/domains.txt" ]]; then
                log ERROR "domains.txt não encontrado em $proj_path/Recon/"
                log INFO "Execute [I] Inicializar Projeto para criar a estrutura"
                return 1
            fi
            
            local domain_count=$(grep -v '^#' "$proj_path/Recon/domains.txt" 2>/dev/null | grep -v '^$' | wc -l)
            if [[ $domain_count -eq 0 ]]; then
                log ERROR "domains.txt está vazio ou contém apenas comentários"
                log INFO "Adicione domínios em: $proj_path/Recon/domains.txt"
                return 2
            fi
            
            log INFO "Encontrados $domain_count domínio(s) para processar"
            ;;
            

         nwrapper)
             script="$OPENPIPES_BIN/nwrapper"
             description="Scanning (Nmap)"
        
            # PRÉ-VALIDAÇÃO: targets.txt existe?
             if [[ ! -f "$proj_path/Varreduras/targets.txt" ]]; then
                 log ERROR "targets.txt não encontrado em $proj_path/Varreduras/"
                 log INFO "Execute [R] Recon primeiro para gerar os targets"
                 return 1
             fi
        
             local target_count=$(grep -v '^#' "$proj_path/Varreduras/targets.txt" 2>/dev/null | grep -v '^$' | wc -l)
             if [[ $target_count -eq 0 ]]; then
                 log ERROR "targets.txt está vazio"
                 return 2
             fi
        
             log INFO "Encontrados $target_count alvo(s) para varredura"
             ;;

#        nwrapper)
#            script="$OPENPIPES_BIN/nwrapper"
#            description="Scanning (Nmap)"
#            ;;
            
        cria-alvos)
            script="$OPENPIPES_BIN/cria-alvos"
            description="Setup Obsidian"
            ;;
            
        httpx)
            script="$OPENPIPES_BIN/httpx-runner"
            description="HTTPx Runner"
            ;;
            
        katana)
            script="$OPENPIPES_BIN/katana-buster"
            description="Katana + Feroxbuster"
            ;;
            
        nuclei)
            script="$OPENPIPES_BIN/nuclei-runner"
            description="Nuclei Scan"
            ;;
            
        jsfinder)
            script="$OPENPIPES_BIN/jsfinder-runner"
            description="JSFinder"
            ;;
            
        gf)
            script="$OPENPIPES_BIN/gf-summary"
            description="GF Summary"
            ;;
            
        whois)
            script="$OPENPIPES_BIN/whois-enricher"
            description="WHOIS Enricher"
            ;;
            
        osint)
            script="$OPENPIPES_BIN/osint-people"
            description="OSINT People"
            ;;
            
        *)
            log ERROR "Módulo desconhecido: $module"
            return 1
            ;;
    esac

    if [[ ! -f "$script" ]]; then
        log ERROR "Script não encontrado: $script"
        return 1
    fi

    log STEP "Executando: $description"

    # EXECUTA todos os módulos no contexto correto
    (
        cd "$proj_path" || {
            log ERROR "Não foi possível acessar $proj_path"
            return 1
        }
        
        # Para recon e nwraper passa arquivos de consumo.
        if [[ "$module" == "recon" ]]; then
            bash "$script" -d "$proj_path/Recon/domains.txt"
        elif [[ "$module" == "nwrapper" ]]; then
            (
                cd "$proj_path/Varreduras" || {
                    log ERROR "Não foi possível acessar $proj_path/Varreduras"
                    return 1
                }
                bash "$script" -f "$proj_path/Varreduras/targets.txt"
            )
        elif [[ "$module" == "cria-alvos" ]]; then
            (
                cd "$proj_path/Varreduras" || {
                    log ERROR "Não foi possível acessar $proj_path/Varreduras"
                    return 1
                }
                bash "$script"
            )
        else
            bash "$script"
        fi
)
 
    local exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log SUCCESS "$description concluído"
        return 0
    else
        log ERROR "$description falhou (exit code: $exit_code)"
        return 1
    fi
}

# ============================================================================
# MENU DE VULNERABILIDADES
# ============================================================================

vulnerabilities_menu() {
    while true; do
        show_banner
        echo -e "${CYAN}━━━ GERENCIAMENTO DE VULNERABILIDADES ━━━${NC}"
        echo ""
        echo -e "${GREEN}[1]${NC} Criar Nova Vulnerabilidade"
        echo -e "${GREEN}[2]${NC} Enriquecer Vulnerabilidade (OpenAI)"
        echo -e "${GREEN}[3]${NC} Listar Cache de Vulnerabilidades"
        echo -e "${GREEN}[4]${NC} Voltar ao Menu Principal"
        echo ""
        
        read -p "$(echo -e ${YELLOW}Escolha uma opção:${NC} )" choice
        
        case $choice in
            1)
                cria_vulnerabilidades
                ;;
            2)
                enriquecer_vulnerabilidade
                ;;
            3)
                listar_cache
                ;;
            4)
                break
                ;;
            *)
                log ERROR "Opção inválida"
                press_enter
                ;;
        esac
    done
}

cria_vulnerabilidades() {
    log STEP "Criando Nova Vulnerabilidade"
    
    local script="$OPENPIPES_BIN/cria-vulns"
    
    if [[ ! -f "$script" ]]; then
        log ERROR "Script cria-vulns não encontrado"
        press_enter
        return 1
    fi
    
    bash "$script"
    press_enter
}

enriquecer_vulnerabilidade() {
    log STEP "Enriquecimento de Vulnerabilidade"
    
    # Verificar se OpenAI API key está configurada
    if [[ -z "${OPENAI_API_KEY:-}" ]]; then
        log ERROR "OPENAI_API_KEY não configurada!"
        log INFO "Configure em: $OPENPIPES_CONFIG"
        press_enter
        return 1
    fi
    
    local script="$OPENPIPES_BIN/vuln-enricher"
    
    if [[ ! -f "$script" ]]; then
        log ERROR "Script vuln-enricher não encontrado"
        press_enter
        return 1
    fi
    
    bash "$script"
    press_enter
}

listar_cache() {
    log STEP "Cache de Vulnerabilidades"
    
    if [[ ! -d "$OPENPIPES_CACHE" ]]; then
        log ERROR "Cache não encontrado: $OPENPIPES_CACHE"
        press_enter
        return 1
    fi
    
    local vuln_files=$(find "$OPENPIPES_CACHE" -type f -name "*.json" | wc -l)
    
    if [[ $vuln_files -eq 0 ]]; then
        log WARNING "Nenhum arquivo de vulnerabilidade encontrado no cache"
    else
        log SUCCESS "Vulnerabilidades em cache: $vuln_files"
        echo ""
        
        find "$OPENPIPES_CACHE" -type f -name "*.json" -exec basename {} \; | sort | nl
    fi
    
    press_enter
}

# ============================================================================
# CONFIGURAÇÃO E STATUS
# ============================================================================

show_config() {
    show_banner
    log STEP "Configuração Atual"
    echo ""
    
    cat "$OPENPIPES_CONFIG"
    
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    read -p "$(echo -e ${YELLOW}Deseja editar a configuração? [s/N]:${NC} )" -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Ss]$ ]]; then
        ${EDITOR:-nano} "$OPENPIPES_CONFIG"
        
        # Recarregar configuração
        source "$OPENPIPES_CONFIG"
        proj_path="$proj_dir/$proj_name"
        
        log SUCCESS "Configuração atualizada!"
        echo ""
        
        # Perguntar se quer criar estrutura
        log QUESTION "Deseja verificar/criar a estrutura do projeto agora?"
        read -p "$(echo -e ${YELLOW}[S/n]:${NC} )" -n 1 -r
        echo
        
        if [[ $REPLY =~ ^[Ss]$ ]] || [[ -z $REPLY ]]; then
            if [[ -d "$proj_path" ]] && [[ -f "$proj_path/Recon/domains.txt" ]]; then
                validate_project
            else
                setup_project_structure
            fi
        fi
    fi
    
    press_enter
}

show_status() {
    show_banner
    log STEP "Status da Instalação"
    echo ""
    
    local tools=(
        "nmap:Nmap"
        "httpx:HTTPx"
        "nuclei:Nuclei"
        "katana:Katana"
        "feroxbuster:Feroxbuster"
        "gf:GF"
        "amass:Amass"
        "dnsrecon:DNSRecon"
        "jq:jq"
        "curl:curl"
        "linkfinder.py:LinkFinder"
    )
    
    local installed=0
    local missing=0
    
    for tool_pair in "${tools[@]}"; do
        local cmd="${tool_pair%%:*}"
        local name="${tool_pair##*:}"
        
        if command -v "$cmd" &>/dev/null; then
            echo -e "${GREEN}[✓]${NC} $name"
            ((installed++))
        else
            echo -e "${RED}[✗]${NC} $name ${YELLOW}(não instalado)${NC}"
            ((missing++))
        fi
    done
    
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}Instaladas:${NC} $installed/${#tools[@]}"
    
    if [[ $missing -gt 0 ]]; then
        echo -e "${YELLOW}Faltando:${NC} $missing"
        echo ""
        log WARNING "Execute o instalador para instalar ferramentas faltantes"
    fi
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    press_enter
}

show_help() {
    show_banner
    log STEP "Ajuda do OPenPipeS"
    echo ""
    
    cat << 'HELP_EOF'
OPenPipeS - Obsidian Pentest Pipeline Stack

FLUXO DE TRABALHO:
  1. [I] Inicializar Projeto       - Criar estrutura e configurar domains.txt
  2. [C] Configuração               - Editar configurações (API keys, paths)
  3. Adicionar domínios             - Editar domains.txt manualmente
  4. [P] Pipeline Completo          - Executar todos os módulos automaticamente
     OU executar módulos individuais:
       [R] Reconhecimento
       [S] Scanning (Nmap)
       [O] Setup Obsidian
       [H] HTTPx
       [K] Katana/Ferox
       [N] Nuclei
       [J] JSFinder
       [G] GF Summary
       [W] WHOIS
  5. [V] Vulnerabilidades           - Documentar e enriquecer vulnerabilidades

ESTRUTURA DE DIRETÓRIOS:
  ~/.openpipes/               - Instalação do framework
  ~/Desktop/BugBounty/        - Projetos (configurável)
  ~/.obsidianFixedMount/      - Vault Obsidian

ARQUIVOS IMPORTANTES:
  config.sh                   - Configuração global
  domains.txt                 - Lista de domínios alvo
  
COMANDOS RÁPIDOS:
  openpipes                   - Menu principal
  recon                       - Módulo reconhecimento
  nwrapper                    - Módulo nmap
  nuclei-runner               - Módulo nuclei
  
DOCUMENTAÇÃO COMPLETA:
  https://github.com/rlSniff3r/openPipes

HELP_EOF
    
    press_enter
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    check_root
    check_config
    
    while true; do
        show_menu
        
        read -p "$(echo -e ${YELLOW}Escolha uma opção:${NC} )" choice
        
        case $choice in
            [Ii])
                setup_project_structure
                press_enter
                ;;
            [Rr])
                run_module "recon"
                press_enter
                ;;
            [Ss])
                run_module "nwrapper"
                press_enter
                ;;
            [Oo])
                run_module "cria-alvos"
                press_enter
                ;;
            [Hh])
                run_module "httpx"
                press_enter
                ;;
            [Kk])
                run_module "katana"
                press_enter
                ;;
            [Nn])
                run_module "nuclei"
                press_enter
                ;;
            [Jj])
                run_module "jsfinder"
                press_enter
                ;;
            [Gg])
                run_module "gf"
                press_enter
                ;;
            [Ww])
                run_module "whois"
                press_enter
                ;;
            [Yy])
                run_module "osint"
                press_enter
                ;;
            [Pp])
                run_full_pipeline
                press_enter
                ;;
            [Vv])
                vulnerabilities_menu
                ;;
            [Cc])
                show_config
                ;;
            [Tt])
                show_status
                ;;
            [\?])
                show_help
                ;;
            [Qq])
                log SUCCESS "Até logo!"
                exit 0
                ;;
            *)
                log ERROR "Opção inválida: $choice"
                press_enter
                ;;
        esac
    done
}

# Executar
main "$@"
