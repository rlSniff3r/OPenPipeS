#!/usr/bin/env bash
set -euo pipefail

source ~/.openpipes/config.sh

: "${proj_name:?ERRO: proj_name não definido}"
: "${obsdir:?ERRO: obsdir não definido}"
: "${OBSIDIAN_PROJ_PATH:?ERRO: OBSIDIAN_PROJ_PATH não definido}"

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
CYAN="\033[0;36m"
BOLD="\033[1m"
NC="\033[0m"

clear
echo -e "${CYAN}${BOLD}"
cat << 'BANNER'
╔═══════════════════════════════════════════════════════╗
║   OPenPipeS v2.0 - Project Initializer               ║
║   Estrutura Hierárquica com $proj_name               ║
╚═══════════════════════════════════════════════════════╝
BANNER
echo -e "${NC}"

echo -e "${YELLOW}${BOLD}[*] Inicializando projeto...${NC}"
echo -e "${BLUE}    Projeto:${NC} ${GREEN}${proj_name}${NC}"
echo -e "${BLUE}    Obsidian Vault:${NC} ${obsdir}"
echo -e "${BLUE}    Path Completo:${NC} ${OBSIDIAN_PROJ_PATH}"
echo ""

if [[ -d "$OBSIDIAN_PROJ_PATH" ]]; then
    echo -e "${YELLOW}[!] Projeto '$proj_name' já existe!${NC}"
    read -p "Deseja recriar a estrutura? (s/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Ss]$ ]]; then
        echo -e "${RED}[x] Operação cancelada${NC}"
        exit 0
    fi
fi

echo -e "${GREEN}[+] Criando estrutura de diretórios...${NC}"

PENTEST_ROOT="$OBSIDIAN_PROJ_PATH"
ALVOS_DIR="$PENTEST_ROOT/Alvos"
OSINT_DIR="$PENTEST_ROOT/OSINT"

mkdir -p "$PENTEST_ROOT"
mkdir -p "$ALVOS_DIR"
mkdir -p "$OSINT_DIR"
mkdir -p "$proj_path"
mkdir -p "$NMAP_DIR"
mkdir -p "$RECON_DIR"
mkdir -p "$LOG_DIR"

echo -e "${GREEN}    ✓ Diretórios criados${NC}"
echo ""

echo -e "${GREEN}[+] Copiando templates...${NC}"

TEMPLATES_DIR="$HOME/.openpipes/.templates"

if [[ ! -f "$TEMPLATES_DIR/Dashboard_Global.md" ]]; then
    echo -e "${RED}[ERRO] Template Dashboard_Global.md não encontrado!${NC}"
    exit 1
fi

if [[ ! -f "$TEMPLATES_DIR/Tarefas.md" ]]; then
    echo -e "${RED}[ERRO] Template Tarefas.md não encontrado!${NC}"
    exit 1
fi

cp "$TEMPLATES_DIR/Dashboard_Global.md" "$PENTEST_ROOT/Dashboard_Global.md"
sed -i "s/{{proj_name}}/$proj_name/g" "$PENTEST_ROOT/Dashboard_Global.md"

echo -e "${GREEN}    ✓ Dashboard_Global.md${NC}"

cp "$TEMPLATES_DIR/Tarefas.md" "$PENTEST_ROOT/Tarefas.md"
sed -i "s/{{proj_name}}/$proj_name/g" "$PENTEST_ROOT/Tarefas.md"

echo -e "${GREEN}    ✓ Tarefas.md${NC}"

if [[ -f "$TEMPLATES_DIR/README.md" ]]; then
    cp "$TEMPLATES_DIR/README.md" "$OBSIDIAN_PROJ_ROOT/README.md"
    sed -i "s/{{proj_name}}/$proj_name/g" "$OBSIDIAN_PROJ_ROOT/README.md"
    echo -e "${GREEN}    ✓ README.md${NC}"
fi

if [[ -f "$TEMPLATES_DIR/.gitignore" ]]; then
    cp "$TEMPLATES_DIR/.gitignore" "$OBSIDIAN_PROJ_ROOT/.gitignore"
    echo -e "${GREEN}    ✓ .gitignore${NC}"
fi

if [[ ! -f "$proj_path/domains.txt" ]]; then
    cat > "$proj_path/domains.txt" << 'DOM_EOF'
# Domínios para reconhecimento
# Adicione um por linha (SLD apenas, sem www)

DOM_EOF
    echo -e "${GREEN}    ✓ domains.txt${NC}"
fi

echo ""
echo -e "${GREEN}${BOLD}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║  ✓ Projeto inicializado com sucesso!             ║${NC}"
echo -e "${GREEN}${BOLD}╚════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}📁 Estrutura criada em:${NC}"
echo -e "   ${BLUE}Obsidian:${NC} $OBSIDIAN_PROJ_PATH"
echo -e "   ${BLUE}Trabalho:${NC} $proj_path"
echo ""
echo -e "${CYAN}📊 Arquivos copiados:${NC}"
echo -e "   ${GREEN}✓${NC} Dashboard_Global.md (com DataviewJS)"
echo -e "   ${GREEN}✓${NC} Tarefas.md (original)"
echo -e "   ${GREEN}✓${NC} README.md"
echo -e "   ${GREEN}✓${NC} .gitignore"
echo -e "   ${GREEN}✓{{NC}} domains.txt"
echo ""
echo -e "${YELLOW}${BOLD}🚀 Próximos passos:{{NC}}"
echo -e "   ${CYAN}1.{{NC}} Adicione domínios em: ${BLUE}$proj_path/domains.txt{{NC}}"
echo -e "   ${CYAN}2.{{NC}} Execute reconhecimento: ${GREEN}recon.sh <domain>{{NC}}"
echo -e "   ${CYAN}3.{{NC}} Execute port scan: ${GREEN}nwrapper.sh <domain>{{NC}}"
echo -e "   ${CYAN}4.{{NC}} Crie estrutura Obsidian: ${GREEN}cria-alvos{{NC}}"
echo ""
