#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# 🚀 OPenPipeS - Project Initializer v3.0
# Responsável por criar a estrutura do projeto, validar segurança e templates.
# ==============================================================================

CONFIG_FILE="$HOME/.openpipes/config.sh"
SECRETS_FILE="$HOME/.openpipes/secrets.conf"

# Cores para Output
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "   ___  ____            ____  _            ____ "
echo "  / _ \|  _ \ ___ _ __ |  _ \(_)_ __   ___/ ___|"
echo " | | | | |_) / _ \ '_ \| |_) | | '_ \ / _ \___ \\"
echo " | |_| |  __/  __/ | | |  __/| | |_) |  __/___) |"
echo "  \___/|_|   \___|_| |_|_|   |_| .__/ \___|____/ "
echo "                               |_|               "
echo -e "${NC}"
echo -e "${BLUE}[*] Project Initializer v3.0${NC}\n"

# ------------------------------------------------------------------------------
# 1. Input do Projeto e Atualização do Config
# ------------------------------------------------------------------------------
if [ -z "${1:-}" ]; then
    read -p "Nome do Projeto (Ex: cliente-xyz): " PROJ_NAME_INPUT
else
    PROJ_NAME_INPUT="$1"
fi

if [[ -z "$PROJ_NAME_INPUT" ]]; then
    echo -e "${RED}[ERRO] O nome do projeto não pode ser vazio.${NC}"
    exit 1
fi

echo -e "${YELLOW}[*] Atualizando projeto ativo em config.sh...${NC}"

# Atualiza a variável proj_name no config.sh usando Regex seguro
if grep -q "proj_name=" "$CONFIG_FILE"; then
    sed -i "s|proj_name=\".*\"|proj_name=\"$PROJ_NAME_INPUT\"|" "$CONFIG_FILE"
else
    echo "proj_name=\"$PROJ_NAME_INPUT\"" >> "$CONFIG_FILE"
fi

# ------------------------------------------------------------------------------
# 2. Carregar Configurações (Agora com o nome correto)
# ------------------------------------------------------------------------------
source "$CONFIG_FILE"

# Validação de Variáveis Críticas do Config
if [[ -z "${proj_dir:-}" ]] || [[ -z "${obsdir:-}" ]] || [[ -z "${tpdir:-}" ]]; then
    echo -e "${RED}[ERRO] Variáveis base (proj_dir, obsdir, tpdir) não definidas no config.sh!${NC}"
    exit 1
fi

# Definir caminhos baseados no config carregado
# Nota: Usamos as variáveis que você definiu no config.sh (OBSIDIAN_PROJ_PATH, etc)
# Se elas não estiverem exportadas lá, montamos aqui por garantia:
OBS_PATH="${OBSIDIAN_PROJ_PATH:-$obsdir/$proj_name/Pentest}"
SCANS_PATH="${NMAP_DIR:-$proj_dir/$proj_name/Varreduras}"

echo -e "${BLUE}[>] Projeto define: $proj_name${NC}"
echo -e "${BLUE}[>] Obsidian Path:  $OBS_PATH${NC}"
echo -e "${BLUE}[>] Work Path:      $SCANS_PATH${NC}"

# ------------------------------------------------------------------------------
# 3. Auditoria de Segurança (Secrets & Keys)
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[*] Realizando Auditoria de Segurança...${NC}"

if [[ ! -f "$SECRETS_FILE" ]]; then
    echo -e "${RED}[PERIGO] Arquivo secrets.conf não encontrado!${NC}"
    echo "Por favor, crie-o a partir do secrets.conf.example"
    exit 1
fi

# Check de Permissões (Deve ser 600)
PERM=$(stat -c "%a" "$SECRETS_FILE")
if [[ "$PERM" != "600" ]]; then
    echo -e "${RED}[ALERTA] Permissões inseguras ($PERM) em secrets.conf. Corrigindo para 600...${NC}"
    chmod 600 "$SECRETS_FILE"
    echo -e "${GREEN}[OK] Permissões blindadas.${NC}"
else
    echo -e "${GREEN}[OK] Permissões do arquivo de segredos seguras (600).${NC}"
fi

# Carregar Segredos para validar se estão preenchidos
source "$SECRETS_FILE"

MISSING_KEYS=0
if [[ -z "${securitytrailskey:-}" ]]; then
    echo -e "${YELLOW}[AVISO] SecurityTrails Key não configurada. O Recon será limitado.${NC}"
    ((MISSING_KEYS++))
fi
if [[ -z "${OPENAI_API_KEY:-}" ]]; then
    echo -e "${YELLOW}[AVISO] OpenAI Key não configurada. Análise de IA desativada.${NC}"
    ((MISSING_KEYS++))
fi

if [[ $MISSING_KEYS -eq 0 ]]; then
    echo -e "${GREEN}[OK] Todas as chaves principais detectadas.${NC}"
fi

# ------------------------------------------------------------------------------
# 4. Criação de Estrutura de Diretórios
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[*] Criando estrutura de pastas...${NC}"

# Pastas Físicas (Onde as ferramentas rodam)
mkdir -p "$proj_path"/{Recon,OSINT,Screenshots,Varreduras}

# Pastas Lógicas (Obsidian - Onde os links simbólicos ou sync ocorrem)
mkdir -p "$OBS_PATH/Alvos"
mkdir -p "$OBSIDIAN_PROJ_ROOT/OSINT"

echo -e "${GREEN}[OK] Estrutura criada.${NC}"

# ------------------------------------------------------------------------------
# 5. Instalação de Templates (Dashboards & Loots)
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[*] Gerando Dashboards e Arquivos Mestre...${NC}"

# Função auxiliar para copiar e processar templates
# Uso: install_template "template_origem" "arquivo_destino"
install_template() {
    local tpl_name="$1"
    local dest_path="$2"

    if [[ -f "$tpdir/$tpl_name" ]]; then
        if [[ -f "$dest_path" ]]; then
            echo -e "    ${YELLOW}[SKIP] $tpl_name já existe no destino.${NC}"
        else
            cp "$tpdir/$tpl_name" "$dest_path"
            # Substituição de Variáveis Globais (Usando pipe | como delimitador)
            sed -i "s|{{proj_name}}|$proj_name|g" "$dest_path"
            sed -i "s|{{date}}|$(date +%Y-%m-%d)|g" "$dest_path"
            echo -e "    ${GREEN}[+] $tpl_name instalado com sucesso.${NC}"
        fi
    else
        echo -e "    ${RED}[ERRO] Template $tpl_name não encontrado na pasta .templates!${NC}"
    fi
}

# 5.1 Dashboard Global
install_template "Dashboard_Global.md" "$OBS_PATH/Dashboard_Global.md"

# 5.2 Dashboard de Loots (NOVO)
install_template "Dashboard_Loots.md" "$OBS_PATH/Dashboard_Loots.md"

# 5.3 Tarefas / Todo List
install_template "Tarefas.md" "$OBS_PATH/Tarefas.md"

# ------------------------------------------------------------------------------
# 6. Finalização
# ------------------------------------------------------------------------------
echo -e "\n${GREEN}==============================================${NC}"
echo -e "${GREEN}   PROJETO '$proj_name' INICIALIZADO! 🚀${NC}"
echo -e "${GREEN}==============================================${NC}"
echo -e "Próximos passos:"
echo -e "1. Adicione domínios em: ${BLUE}$proj_path/domains.txt${NC}"
echo -e "2. Execute o Recon:      ${BLUE}openpipes recon${NC}"
echo -e "3. Visualize no Obsidian:${BLUE} $OBSIDIAN_PROJ_ROOT${NC}"