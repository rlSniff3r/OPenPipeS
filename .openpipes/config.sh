# ------------------------------------------------------------------
# ⚙️ OPenPipeS Global Configuration
# Arquivo seguro para versionamento (Sem senhas aqui!)
# ------------------------------------------------------------------

# Caminhos do Projeto

# NOME DO PROJETO
proj_name="PROJECT_NAME_HERE"

# DIRETÓRIOS BASE
proj_dir="$HOME/Projetos"
proj_path="$proj_dir/$proj_name"
obsdir="$HOME/.obsidianFixedMount"
tpdir="$HOME/.openpipes/.templates"

# PATHS OBSIDIAN (NOVA ESTRUTURA V2)
OBSIDIAN_PROJ_ROOT="$obsdir/$proj_name"
OBSIDIAN_PROJ_PATH="$OBSIDIAN_PROJ_ROOT/Pentest"
TARGETS_DIR="$OBSIDIAN_PROJ_PATH/Alvos"

# PATHS DE TRABALHO
NMAP_DIR="$proj_path/Varreduras"
RECON_DIR="$proj_path/Recon"
OSINT_DIR="$proj_path/OSINT"
base_dir=$NMAP_DIR
SCREENSHOT_DIR="$proj_path/Screenshots"
DOMAIN_FILE="$proj_path/domains.txt"


# Definições de Ambiente
export TARGETS_DIR="$obsdir/$proj_name/Pentest/Alvos/"

# ------------------------------------------------------------------
# 🛡️ Carregamento Seguro de Segredos
# ------------------------------------------------------------------
SECRETS_PATH="$HOME/.openpipes/secrets.conf"

if [[ -f "$SECRETS_PATH" ]]; then
    # Verifica permissões: Stat retorna direitos em octal
    PERM=$(stat -c "%a" "$SECRETS_PATH")
    
    if [[ "$PERM" != "600" ]]; then
        echo -e "\033[0;31m[PERIGO] Permissões inseguras detectadas em secrets.conf ($PERM)!\033[0m"
        echo "Execute: chmod 600 $SECRETS_PATH"
        # Em modo paranoico, poderíamos dar exit 1 aqui. 
        # Por enquanto apenas avisamos e carregamos.
    fi
    
    source "$SECRETS_PATH"
else
    echo -e "\033[0;33m[AVISO] Arquivo secrets.conf não encontrado. Alguns módulos falharão.\033[0m"
fi
