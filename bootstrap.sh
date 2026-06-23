#!/bin/bash
# OPenPipeS - Minimal Bootstrap
set -e

echo -e "\033[0;34m[*] Iniciando Bootstrap do OPenPipeS...\033[0m"

# 1. Verifica dependências básicas de sistema para o Python assumir
for pkg in python3 python3-venv python3-pip sudo wget unzip; do
    if ! dpkg -l | grep -qw "^ii  $pkg"; then
        echo -e "\033[1;33m[!] Instalando pacote base faltante: $pkg\033[0m"
        sudo apt-get update -qq && sudo apt-get install -y -qq $pkg
    fi
done

# 2. Cria o VENV isolado estritamente para o "Core/Instalador" do OPenPipeS
CORE_VENV="$HOME/.openpipes/.venv-core"
if [ ! -d "$CORE_VENV" ]; then
    echo "[*] Criando ambiente virtual do Core em $CORE_VENV..."
    mkdir -p "$HOME/.openpipes"
    python3 -m venv "$CORE_VENV"
fi

# 3. Instala a biblioteca visual (rich) e chama o cérebro
"$CORE_VENV/bin/pip" install --upgrade pip -q
"$CORE_VENV/bin/pip" install rich requests -q

echo -e "\033[0;32m[✓] Bootstrap concluído. Passando controle para o Python...\033[0m\n"
"$CORE_VENV/bin/python" installer.py