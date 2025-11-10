#!/bin/bash

# ═══════════════════════════════════════════════════════════════════════════
# OPenPipeS - Obsidian Pentest Pipeline Stack
# Orquestrador Principal v2.0
# Autor: Rafael Luís da Silva
# ═══════════════════════════════════════════════════════════════════════════

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
OPENPIPES_HOME="${HOME}/.openpipes"
OPENPIPES_BIN="${OPENPIPES_HOME}/bin"
OPENPIPES_TEMPLATES="${OPENPIPES_HOME}/.templates"
OPENPIPES_CACHE="${OPENPIPES_HOME}_cache"
OPENPIPES_CONFIG="${OPENPIPES_HOME}/config.sh"

# Banner
show_banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
   ___  ____            ____  _            ____  
  / _ \|  _ \ ___ _ __ |  _ \(_)_ __   ___/ ___| 
 | | | | |_) / _ \ '_ \| |_) | | '_ \ / _ \___ \ 
 | |_| |  __/  __/ | | |  __/| | |_) |  __/___) |
  \___/|_|   \___|_| |_|_|   |_| .__/ \___|____/ 
                                |_|               
EOF
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}    Obsidian Pentest Pipeline Stack - Orquestrador v2.0${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Função de log
log() {
    local level=$1
    shift
    local msg="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        INFO)  echo -e "${GREEN}[+]${NC} $msg" ;;
        WARN)  echo -e "${YELLOW}[!]${NC} $msg" ;;
        ERROR) echo -e "${RED}[-]${NC} $msg" ;;
        STEP)  echo -e "${CYAN}[*]${NC} $msg" ;;
    esac
}

# Verificar se rodando como root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log ERROR "Não execute este script como root!"
        log INFO "Execute como usuário normal. Sudo será solicitado quando necessário."
        exit 1
    fi
}

# Verificar configuração
check_config() {
    if [[ ! -f "$OPENPIPES_CONFIG" ]]; then
        log ERROR "Arquivo de configuração não encontrado: $OPENPIPES_CONFIG"
        log INFO "Execute primeiro: openpipes-install"
        exit 1
    fi
    
    source "$OPENPIPES_CONFIG"
    
    if [[ -z "$proj_dir" ]] || [[ -z "$proj_name" ]]; then
        log ERROR "Configuração incompleta! Configure proj_dir e proj_name em:"
        log INFO "$OPENPIPES_CONFIG"
        exit 1
    fi
    
    if [[ -z "$obsdir" ]]; then
        log ERROR "Diretório do Obsidian não configurado!"
        exit 1
    fi
}

# Menu principal
show_menu() {
    echo ""
    echo -e "${MAGENTA}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║              MENU PRINCIPAL - OPenPipeS                    ║${NC}"
    echo -e "${MAGENTA}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}[1]${NC} 🔍 Reconhecimento Completo (recon.sh)"
    echo -e "${CYAN}[2]${NC} 🎯 Scan de Portas/Serviços (nwrapper.sh)"
    echo -e "${CYAN}[3]${NC} 📦 Criar Estrutura no Obsidian (cria_Alvos_Obsidian.sh)"
    echo -e "${CYAN}[4]${NC} 🌐 HTTPX Runner (httpx-runner.sh)"
    echo -e "${CYAN}[5]${NC} 🔗 Katana + Feroxbuster (katana-buster.sh)"
    echo -e "${CYAN}[6]${NC} 🧪 Nuclei Scanner (nuclei-runner.sh)"
    echo -e "${CYAN}[7]${NC} 📜 JSFinder (jsfinder-runner.sh)"
    echo -e "${CYAN}[8]${NC} 🧬 GF Summary (gf-summary.sh)"
    echo -e "${CYAN}[9]${NC} 🏷️  WHOIS Enricher (whois-enricher.sh)"
    echo ""
    echo -e "${YELLOW}[V]${NC} 💥 Gerenciar Vulnerabilidades"
    echo -e "${YELLOW}[P]${NC} 🔄 Pipeline Completo (Todos os módulos)"
    echo ""
    echo -e "${GREEN}[C]${NC} ⚙️  Configuração"
    echo -e "${GREEN}[S]${NC} 📊 Status do Sistema"
    echo -e "${GREEN}[H]${NC} 📖 Help/Documentação"
    echo ""
    echo -e "${RED}[0]${NC} 🚪 Sair"
    echo ""
    echo -ne "${CYAN}Escolha uma opção:${NC} "
}

# Submenu de vulnerabilidades
vulnerabilities_menu() {
    while true; do
        clear
        show_banner
        echo -e "${MAGENTA}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${MAGENTA}║           GERENCIAMENTO DE VULNERABILIDADES               ║${NC}"
        echo -e "${MAGENTA}╚════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${CYAN}[1]${NC} ➕ Criar Nova Vulnerabilidade"
        echo -e "${CYAN}[2]${NC} ✨ Enriquecer Vulnerabilidade (OpenAI)"
        echo -e "${CYAN}[3]${NC} 📋 Listar Cache de Vulnerabilidades"
        echo ""
        echo -e "${RED}[0]${NC} ⬅️  Voltar ao Menu Principal"
        echo ""
        echo -ne "${CYAN}Escolha uma opção:${NC} "
        
        read -r vuln_choice
        
        case $vuln_choice in
            1) cria_vulnerabilidades ;;
            2) enriquecer_vulnerabilidade ;;
            3) listar_cache ;;
            0) break ;;
            *) log WARN "Opção inválida!" ; sleep 2 ;;
        esac
    done
}

# Executar reconhecimento
run_recon() {
    log STEP "Iniciando Reconhecimento..."
    
    if [[ ! -f "${OPENPIPES_BIN}/recon.sh" ]]; then
        log ERROR "Script recon.sh não encontrado!"
        return 1
    fi
    
    cd "$proj_path" || exit 1
    bash "${OPENPIPES_BIN}/recon.sh" "$@"
}

# Executar nmap wrapper
run_nmap() {
    log STEP "Iniciando Scan de Portas..."
    
    cd "${proj_path}/Varreduras" || exit 1
    bash "${OPENPIPES_BIN}/nwrapper.sh" "$@"
}

# Criar alvos no Obsidian
criar_alvos_obsidian() {
    log STEP "Criando estrutura de alvos no Obsidian..."
    
    cd "${proj_path}/Varreduras" || exit 1
    bash "${OPENPIPES_BIN}/cria_Alvos_Obsidian.sh"
    
    log INFO "Estrutura criada com sucesso!"
    sleep 2
}

# HTTPX Runner
run_httpx() {
    log STEP "Executando HTTPX..."
    
    cd "${proj_path}/Varreduras" || exit 1
    bash "${OPENPIPES_BIN}/httpx-runner.sh"
}

# Katana + Feroxbuster
run_katana_ferox() {
    log STEP "Executando Katana + Feroxbuster..."
    
    echo -ne "${CYAN}Deseja usar --dns-only ou --ip-only? [d/i/N]:${NC} "
    read -r choice
    
    cd "${proj_path}/Varreduras" || exit 1
    
    case $choice in
        d|D) bash "${OPENPIPES_BIN}/katana-buster.sh" --dns-only ;;
        i|I) bash "${OPENPIPES_BIN}/katana-buster.sh" --ip-only ;;
        *) bash "${OPENPIPES_BIN}/katana-buster.sh" ;;
    esac
}

# Nuclei Runner
run_nuclei() {
    log STEP "Executando Nuclei Scanner..."
    
    cd "${proj_path}/Varreduras" || exit 1
    bash "${OPENPIPES_BIN}/nuclei-runner.sh"
}

# JSFinder
run_jsfinder() {
    log STEP "Executando JSFinder..."
    
    echo -ne "${CYAN}Forçar re-análise? [s/N]:${NC} "
    read -r force
    
    cd "${proj_path}/Varreduras" || exit 1
    
    if [[ "$force" =~ ^[sS]$ ]]; then
        bash "${OPENPIPES_BIN}/jsfinder-runner.sh" --force
    else
        bash "${OPENPIPES_BIN}/jsfinder-runner.sh"
    fi
}

# GF Summary
run_gf_summary() {
    log STEP "Gerando GF Summary..."
    
    cd "${proj_path}/Varreduras" || exit 1
    bash "${OPENPIPES_BIN}/gf-summary.sh"
}

# WHOIS Enricher
run_whois_enricher() {
    log STEP "Enriquecendo informações WHOIS..."
    
    cd "${proj_path}/Varreduras" || exit 1
    bash "${OPENPIPES_BIN}/whois-enricher.sh"
}

# Criar vulnerabilidade
cria_vulnerabilidades() {
    log STEP "Criando nova vulnerabilidade..."
    bash "${OPENPIPES_BIN}/cria_Vulnerabilidades.sh"
}

# Enriquecer vulnerabilidade
enriquecer_vulnerabilidade() {
    log STEP "Enriquecendo vulnerabilidade com OpenAI..."
    bash "${OPENPIPES_BIN}/vuln-enricher.sh"
}

# Listar cache
listar_cache() {
    log INFO "Cache de vulnerabilidades disponível:"
    echo ""
    
    if [[ -d "$OPENPIPES_CACHE" ]]; then
        ls -1 "$OPENPIPES_CACHE"/*.json 2>/dev/null | while read -r f; do
            echo -e "${GREEN}  →${NC} $(basename "$f" .json)"
        done
    else
        log WARN "Nenhum cache encontrado em $OPENPIPES_CACHE"
    fi
    
    echo ""
    read -p "Pressione Enter para continuar..."
}

# Pipeline completo
run_full_pipeline() {
    log INFO "Executando pipeline completo..."
    echo ""
    
    log STEP "Etapa 1/9: Reconhecimento"
    run_recon || { log ERROR "Falha no reconhecimento"; return 1; }
    
    log STEP "Etapa 2/9: Scan de Portas"
    run_nmap -f "${proj_path}/Varreduras/targets.txt" || { log ERROR "Falha no scan"; return 1; }
    
    log STEP "Etapa 3/9: Criando Alvos no Obsidian"
    criar_alvos_obsidian || { log ERROR "Falha ao criar alvos"; return 1; }
    
    log STEP "Etapa 4/9: HTTPX"
    run_httpx || { log ERROR "Falha no HTTPX"; return 1; }
    
    log STEP "Etapa 5/9: Katana + Feroxbuster"
    run_katana_ferox || { log ERROR "Falha no Katana/Ferox"; return 1; }
    
    log STEP "Etapa 6/9: Nuclei"
    run_nuclei || { log ERROR "Falha no Nuclei"; return 1; }
    
    log STEP "Etapa 7/9: JSFinder"
    run_jsfinder || { log ERROR "Falha no JSFinder"; return 1; }
    
    log STEP "Etapa 8/9: GF Summary"
    run_gf_summary || { log ERROR "Falha no GF Summary"; return 1; }
    
    log STEP "Etapa 9/9: WHOIS Enricher"
    run_whois_enricher || { log ERROR "Falha no WHOIS Enricher"; return 1; }
    
    log INFO "Pipeline completo executado com sucesso!"
    echo ""
    read -p "Pressione Enter para continuar..."
}

# Configuração
show_config() {
    clear
    show_banner
    echo -e "${CYAN}Configuração Atual:${NC}"
    echo ""
    
    source "$OPENPIPES_CONFIG"
    
    echo -e "${YELLOW}Diretório do Projeto:${NC} $proj_dir"
    echo -e "${YELLOW}Nome do Projeto:${NC} $proj_name"
    echo -e "${YELLOW}Caminho Completo:${NC} $proj_path"
    echo -e "${YELLOW}Diretório Obsidian:${NC} $obsdir"
    echo -e "${YELLOW}SecurityTrails Key:${NC} ${securitytrailskey:-[não configurada]}"
    echo -e "${YELLOW}OpenAI Key:${NC} ${OPENAI_API_KEY:-[não configurada]}"
    echo ""
    echo -ne "${CYAN}Deseja editar? [s/N]:${NC} "
    read -r edit
    
    if [[ "$edit" =~ ^[sS]$ ]]; then
        ${EDITOR:-nano} "$OPENPIPES_CONFIG"
    fi
}

# Status do sistema
show_status() {
    clear
    show_banner
    echo -e "${CYAN}Status do Sistema:${NC}"
    echo ""
    
    # Verificar ferramentas
    local tools=("nmap" "httpx" "nuclei" "katana" "feroxbuster" "amass" "dnsrecon" "jq" "curl")
    
    for tool in "${tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            echo -e "${GREEN}✓${NC} $tool: $(command -v "$tool")"
        else
            echo -e "${RED}✗${NC} $tool: não instalado"
        fi
    done
    
    echo ""
    read -p "Pressione Enter para continuar..."
}

# Help
show_help() {
    clear
    show_banner
    cat << EOF
${CYAN}═══════════════════════════════════════════════════════════${NC}
${GREEN}DOCUMENTAÇÃO - OPenPipeS${NC}
${CYAN}═══════════════════════════════════════════════════════════${NC}

${YELLOW}Fluxo de Trabalho Recomendado:${NC}

1️⃣  ${CYAN}Reconhecimento${NC}
   → Descobre subdomínios, IPs, WHOIS
   → Gera arquivo targets.txt

2️⃣  ${CYAN}Scan de Portas${NC}
   → Executa nmap em todos os targets
   → Identifica portas e serviços

3️⃣  ${CYAN}Criar Estrutura Obsidian${NC}
   → Organiza dados no Obsidian MD
   → Cria dashboards e tabelas

4️⃣  ${CYAN}HTTPX${NC}
   → Identifica web servers
   → Detecta tecnologias

5️⃣  ${CYAN}Katana + Feroxbuster${NC}
   → Descobre endpoints
   → Mapeia superfície de ataque

6️⃣  ${CYAN}Nuclei${NC}
   → Busca vulnerabilidades conhecidas
   → Classifica por severidade

7️⃣  ${CYAN}JSFinder${NC}
   → Analisa arquivos JavaScript
   → Extrai endpoints ocultos

8️⃣  ${CYAN}GF Summary${NC}
   → Agrupa endpoints por padrões
   → Facilita análise manual

9️⃣  ${CYAN}WHOIS Enricher${NC}
   → Enriquece informações de ownership
   → Atualiza dashboards

${YELLOW}Gerenciamento de Vulnerabilidades:${NC}

→ Criar vulnerabilidades manualmente
→ Enriquecer com OpenAI (descrições técnicas)
→ Usar cache de templates prontos

${YELLOW}Arquivos Importantes:${NC}

→ ${OPENPIPES_CONFIG}
→ ${OPENPIPES_CACHE}
→ ${OPENPIPES_TEMPLATES}

${CYAN}═══════════════════════════════════════════════════════════${NC}
EOF
    
    echo ""
    read -p "Pressione Enter para continuar..."
}

# Main
main() {
    check_root
    check_config
    
    while true; do
        show_banner
        show_menu
        read -r choice
        
        case $choice in
            1) run_recon ;;
            2) run_nmap ;;
            3) criar_alvos_obsidian ;;
            4) run_httpx ;;
            5) run_katana_ferox ;;
            6) run_nuclei ;;
            7) run_jsfinder ;;
            8) run_gf_summary ;;
            9) run_whois_enricher ;;
            [Vv]) vulnerabilities_menu ;;
            [Pp]) run_full_pipeline ;;
            [Cc]) show_config ;;
            [Ss]) show_status ;;
            [Hh]) show_help ;;
            0) 
                log INFO "Até logo!"
                exit 0
                ;;
            *)
                log WARN "Opção inválida!"
                sleep 2
                ;;
        esac
    done
}

main "$@"