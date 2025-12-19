#!/bin/bash

# ════════════════════════════════════════════════════════════════════════════
# Script: identities_manager.sh
# Descrição: Módulo de gerenciamento de identidades (loot) para o OpenPipeS
# Autor: Rafael (OpenPipeS Framework)
# Versão: 1.0
# ════════════════════════════════════════════════════════════════════════════

# ════════════════════════════════════════════════════════════════════════════
# IMPORTAÇÃO DE CONFIGURAÇÕES
# ════════════════════════════════════════════════════════════════════════════

# Localiza e importa o arquivo de configuração central
OPENPIPES_CONFIG="${HOME}/.openpipes/config.sh"

if [[ ! -f "$OPENPIPES_CONFIG" ]]; then
    echo -e "\n❌ ERRO: Arquivo de configuração não encontrado em $OPENPIPES_CONFIG"
    echo -e "Execute o instalador do OpenPipeS primeiro.\n"
    exit 1
fi

source "$OPENPIPES_CONFIG"

# Importa o esquema de cores (se disponível)
if [[ -f "${HOME}/.openpipes/colorCodes.sh" ]]; then
    source "${HOME}/.openpipes/colorCodes.sh"
else
    # Fallback: define cores básicas caso o arquivo não exista
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    NC='\033[0m' # No Color
    BOLD='\033[1m'
fi

# ════════════════════════════════════════════════════════════════════════════
# VALIDAÇÕES INICIAIS
# ════════════════════════════════════════════════════════════════════════════

# Verifica se o diretório do Obsidian existe
if [[ ! -d "$obsdir" ]]; then
    echo -e "\n${RED}❌ ERRO:${NC} Diretório do Obsidian não encontrado: ${BOLD}$obsdir${NC}"
    echo -e "Verifique a variável \$obsdir no arquivo config.sh\n"
    exit 1
fi

# Verifica se o projeto está configurado
if [[ -z "$proj_name" ]]; then
    echo -e "\n${RED}❌ ERRO:${NC} Nome do projeto não configurado."
    echo -e "Defina a variável ${BOLD}\$proj_name${NC} no arquivo config.sh\n"
    exit 1
fi

# Define o caminho base dos alvos no Obsidian
ALVOS_DIR="${obsdir}/${proj_name}/Pentest/Alvos"

if [[ ! -d "$ALVOS_DIR" ]]; then
    echo -e "\n${RED}❌ ERRO:${NC} Diretório de alvos não encontrado: ${BOLD}$ALVOS_DIR${NC}"
    echo -e "Execute o módulo ${BOLD}cria_Alvos_Obsidian.sh${NC} primeiro para criar a estrutura.\n"
    exit 1
fi

# ════════════════════════════════════════════════════════════════════════════
# FUNÇÕES AUXILIARES
# ════════════════════════════════════════════════════════════════════════════

# Função para exibir o banner do módulo
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "════════════════════════════════════════════════════════════════"
    echo "           🔐 IDENTITIES MANAGER - OpenPipeS v1.0"
    echo "════════════════════════════════════════════════════════════════"
    echo -e "${NC}"
    echo -e "${BOLD}Projeto:${NC} $proj_name"
    echo -e "${BOLD}Alvos disponíveis:${NC} $(ls -1 "$ALVOS_DIR" 2>/dev/null | wc -l)"
    echo ""
}

# Função para listar alvos disponíveis e permitir seleção
select_target() {
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}📍 SELEÇÃO DE ALVO${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}\n"
    
    # Lista os diretórios de alvos disponíveis
    local targets=($(ls -1 "$ALVOS_DIR" 2>/dev/null))
    
    if [[ ${#targets[@]} -eq 0 ]]; then
        echo -e "${RED}❌ Nenhum alvo encontrado em $ALVOS_DIR${NC}\n"
        exit 1
    fi
    
    echo -e "${YELLOW}Alvos disponíveis:${NC}\n"
    
    local i=1
    for target in "${targets[@]}"; do
        echo -e "  ${BOLD}[$i]${NC} $target"
        ((i++))
    done
    
    echo ""
    read -p "$(echo -e ${BOLD}Selecione o número do alvo:${NC} )" target_choice
    
    # Valida a escolha
    if [[ ! "$target_choice" =~ ^[0-9]+$ ]] || [[ "$target_choice" -lt 1 ]] || [[ "$target_choice" -gt ${#targets[@]} ]]; then
        echo -e "\n${RED}❌ Seleção inválida!${NC}\n"
        exit 1
    fi
    
    # Retorna o nome do alvo selecionado (array é 0-indexed)
    SELECTED_TARGET="${targets[$((target_choice - 1))]}"
    TARGET_DIR="${ALVOS_DIR}/${SELECTED_TARGET}"
    IDENTITIES_FILE="${TARGET_DIR}/identities.md"
    
    echo -e "\n${GREEN}✅ Alvo selecionado:${NC} ${BOLD}$SELECTED_TARGET${NC}\n"
}

# Função para exibir o menu de tipos de identidade
show_identity_menu() {
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}🔑 TIPO DE IDENTIDADE${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}\n"
    
    echo -e "  ${BOLD}[1]${NC} 🔐 Credencial (usuário + senha)"
    echo -e "  ${BOLD}[2]${NC} 🔒 Hash (hash de senha)"
    echo -e "  ${BOLD}[3]${NC} 📧 E-mail"
    echo -e "  ${BOLD}[4]${NC} 👤 Usuário"
    echo -e "  ${BOLD}[0]${NC} ❌ Cancelar\n"
    
    read -p "$(echo -e ${BOLD}Selecione o tipo:${NC} )" identity_type
}

# Função para adicionar uma credencial
add_credential() {
    echo -e "\n${YELLOW}═══ Adicionando Credencial ═══${NC}\n"
    
    read -p "$(echo -e ${BOLD}Usuário:${NC} )" username
    read -sp "$(echo -e ${BOLD}Senha:${NC} )" password
    echo ""
    read -p "$(echo -e ${BOLD}Fonte (ex: manual, mimikatz, secretsdump):${NC} )" source
    read -p "$(echo -e ${BOLD}Endereço/Serviço (opcional):${NC} )" address
    
    # Valida campos obrigatórios
    if [[ -z "$username" ]] || [[ -z "$password" ]] || [[ -z "$source" ]]; then
        echo -e "\n${RED}❌ Campos obrigatórios não preenchidos!${NC}\n"
        return 1
    fi
    
    # Monta a linha no formato Dataview Inline Fields
    local identity_line="[type:: credential] [user:: $username] [password:: $password] [source:: $source] [target:: $SELECTED_TARGET]"
    
    # Adiciona o endereço se fornecido
    if [[ -n "$address" ]]; then
        identity_line="$identity_line [address:: $address]"
    fi
    
    # Adiciona ao arquivo identities.md
    echo "$identity_line" >> "$IDENTITIES_FILE"
    
    echo -e "\n${GREEN}✅ Credencial adicionada com sucesso!${NC}\n"
}

# Função para adicionar um hash
add_hash() {
    echo -e "\n${YELLOW}═══ Adicionando Hash ═══${NC}\n"
    
    read -p "$(echo -e ${BOLD}Usuário (opcional):${NC} )" username
    read -p "$(echo -e ${BOLD}Hash:${NC} )" hash_value
    read -p "$(echo -e ${BOLD}Formato (ex: NTLM, MD5, SHA256):${NC} )" hash_format
    read -p "$(echo -e ${BOLD}Fonte (ex: manual, mimikatz, secretsdump):${NC} )" source
    read -p "$(echo -e ${BOLD}Endereço/Serviço (opcional):${NC} )" address
    
    # Valida campos obrigatórios
    if [[ -z "$hash_value" ]] || [[ -z "$hash_format" ]] || [[ -z "$source" ]]; then
        echo -e "\n${RED}❌ Campos obrigatórios não preenchidos!${NC}\n"
        return 1
    fi
    
    # Monta a linha no formato Dataview Inline Fields
    local identity_line="[type:: hash] [hash:: $hash_value] [format:: $hash_format] [source:: $source] [target:: $SELECTED_TARGET]"
    
    # Adiciona o usuário se fornecido
    if [[ -n "$username" ]]; then
        identity_line="$identity_line [user:: $username]"
    fi
    
    # Adiciona o endereço se fornecido
    if [[ -n "$address" ]]; then
        identity_line="$identity_line [address:: $address]"
    fi
    
    # Adiciona ao arquivo identities.md
    echo "$identity_line" >> "$IDENTITIES_FILE"
    
    echo -e "\n${GREEN}✅ Hash adicionado com sucesso!${NC}\n"
}

# Função para adicionar um e-mail
add_email() {
    echo -e "\n${YELLOW}═══ Adicionando E-mail ═══${NC}\n"
    
    read -p "$(echo -e ${BOLD}E-mail:${NC} )" email_value
    read -p "$(echo -e ${BOLD}Fonte (ex: manual, hunter.io, theHarvester):${NC} )" source
    read -p "$(echo -e ${BOLD}Observações (opcional):${NC} )" notes
    
    # Valida campos obrigatórios
    if [[ -z "$email_value" ]] || [[ -z "$source" ]]; then
        echo -e "\n${RED}❌ Campos obrigatórios não preenchidos!${NC}\n"
        return 1
    fi
    
    # Monta a linha no formato Dataview Inline Fields
    local identity_line="[type:: email] [address:: $email_value] [source:: $source] [target:: $SELECTED_TARGET]"
    
    # Adiciona observações se fornecidas
    if [[ -n "$notes" ]]; then
        identity_line="$identity_line [notes:: $notes]"
    fi
    
    # Adiciona ao arquivo identities.md
    echo "$identity_line" >> "$IDENTITIES_FILE"
    
    echo -e "\n${GREEN}✅ E-mail adicionado com sucesso!${NC}\n"
}

# Função para adicionar um usuário
add_user() {
    echo -e "\n${YELLOW}═══ Adicionando Usuário ═══${NC}\n"
    
    read -p "$(echo -e ${BOLD}Usuário:${NC} )" username
    read -p "$(echo -e ${BOLD}Fonte (ex: manual, enum4linux, ldapsearch):${NC} )" source
    read -p "$(echo -e ${BOLD}Endereço/Serviço (opcional):${NC} )" address
    read -p "$(echo -e ${BOLD}Observações (opcional):${NC} )" notes
    
    # Valida campos obrigatórios
    if [[ -z "$username" ]] || [[ -z "$source" ]]; then
        echo -e "\n${RED}❌ Campos obrigatórios não preenchidos!${NC}\n"
        return 1
    fi
    
    # Monta a linha no formato Dataview Inline Fields
    local identity_line="[type:: user] [user:: $username] [source:: $source] [target:: $SELECTED_TARGET]"
    
    # Adiciona o endereço se fornecido
    if [[ -n "$address" ]]; then
        identity_line="$identity_line [address:: $address]"
    fi
    
    # Adiciona observações se fornecidas
    if [[ -n "$notes" ]]; then
        identity_line="$identity_line [notes:: $notes]"
    fi
    
    # Adiciona ao arquivo identities.md
    echo "$identity_line" >> "$IDENTITIES_FILE"
    
    echo -e "\n${GREEN}✅ Usuário adicionado com sucesso!${NC}\n"
}

# Função para criar o arquivo identities.md se não existir
ensure_identities_file() {
    if [[ ! -f "$IDENTITIES_FILE" ]]; then
        echo -e "${YELLOW}⚠️  Arquivo identities.md não encontrado. Criando...${NC}\n"
        
        # Cria o arquivo com um cabeçalho
        cat > "$IDENTITIES_FILE" << 'EOF'
---
tipo: identities
targetName: PLACEHOLDER
---

# 🔐 Identidades Coletadas

> [!info] Sobre este arquivo
> Este arquivo armazena todas as identidades (credenciais, hashes, e-mails, usuários) coletadas durante o pentest deste alvo. Cada linha representa uma identidade usando o formato de Inline Fields do Dataview.

## 📋 Identidades

EOF
        
        # Substitui o placeholder pelo nome do alvo
        sed -i "s/PLACEHOLDER/$SELECTED_TARGET/g" "$IDENTITIES_FILE"
        
        echo -e "${GREEN}✅ Arquivo criado: $IDENTITIES_FILE${NC}\n"
    fi
}

# ════════════════════════════════════════════════════════════════════════════
# FLUXO PRINCIPAL
# ════════════════════════════════════════════════════════════════════════════

main() {
    # Exibe o banner
    show_banner
    
    # Seleciona o alvo
    select_target
    
    # Garante que o arquivo identities.md existe
    ensure_identities_file
    
    # Loop principal para adicionar múltiplas identidades
    while true; do
        # Exibe o menu de tipos
        show_identity_menu
        
        # Processa a escolha
        case "$identity_type" in
            1)
                add_credential
                ;;
            2)
                add_hash
                ;;
            3)
                add_email
                ;;
            4)
                add_user
                ;;
            0)
                echo -e "\n${YELLOW}👋 Encerrando o Identities Manager...${NC}\n"
                exit 0
                ;;
            *)
                echo -e "\n${RED}❌ Opção inválida!${NC}\n"
                ;;
        esac
        
        # Pergunta se deseja adicionar outra identidade
        echo ""
        read -p "$(echo -e ${BOLD}Adicionar outra identidade? [S/n]:${NC} )" continue_choice
        
        if [[ "$continue_choice" =~ ^[Nn]$ ]]; then
            echo -e "\n${GREEN}✅ Identidades salvas em:${NC} ${BOLD}$IDENTITIES_FILE${NC}"
            echo -e "${YELLOW}💡 Visualize os dados nas dashboards do Obsidian!${NC}\n"
            exit 0
        fi
        
        echo ""
    done
}

# Executa o fluxo principal
main