#!/usr/bin/env bash
#
# osint-runner-people.sh — integra o módulo Python osint_people_enricher_v1.0.py ao fluxo OpenPipeS
# Autor: Rafael + GPT-5
# Versão: v1.0
#

set -euo pipefail

### CONFIGURAÇÕES INICIAIS ###
targetName="$1"
if [ -z "$targetName" ]; then
    echo "[!] Uso: osint-runner-people.sh <targetName>"
    exit 1
fi

# Diretórios principais da Vault e templates
obsdir="${OBSIDIAN_VAULT_DIR:-$HOME/ObsidianVault}"
targetDir="$obsdir/Pentest/Alvos/$targetName"
osintDir="$targetDir/OSINT"
peopleDir="$osintDir/Pessoas"
logDir="$osintDir/logs"

# Criação das pastas
mkdir -p "$peopleDir" "$logDir" "$osintDir/files_raw"

echo "[+] Iniciando OSINT de pessoas para alvo: $targetName"
echo "[+] Diretório base: $osintDir"

### CHAMADA DO MÓDULO PYTHON ###
# O script Python deve estar no PATH (instalado via OpenPipeS installer)
timestamp=$(date +"%Y%m%d_%H%M%S")
logfile="$logDir/osint_people_${timestamp}.log"

osint_people_enricher_v1.0.py \
  --target "$targetName" \
  --obsdir "$obsdir" \
  --outdir "$osintDir" \
  --log "$logfile" \
  --mode defensive \
  --mask emails \
  2>&1 | tee -a "$logfile"

if [ $? -eq 0 ]; then
    echo "[+] Coleta de pessoas concluída com sucesso!"
    echo "    → JSON: $osintDir/osint_people.json"
    echo "    → Notas Markdown: $peopleDir/*.md"
else
    echo "[!] Falha durante execução do osint_people_enricher_v1.0.py"
    echo "    Verifique o log em: $logfile"
    exit 2
fi

### SINCRONIZAÇÃO E DASHBOARD ###
# Atualiza a dashboard do alvo com link para o sumário global
dashboard="$targetDir/Dashboard_${targetName}.md"
summaryLink="[[OSINT/Sumário_Global|Sumário OSINT de Pessoas]]"

if ! grep -q "$summaryLink" "$dashboard" 2>/dev/null; then
    echo -e "\n## 🔎 OSINT de Pessoas\n- $summaryLink\n" >> "$dashboard"
    echo "[+] Link de sumário adicionado à Dashboard_${targetName}.md"
fi

echo "[✓] Execução finalizada. Dados integrados ao Obsidian."
