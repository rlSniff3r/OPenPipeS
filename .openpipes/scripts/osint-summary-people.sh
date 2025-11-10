#!/usr/bin/env bash
# =============================================================================
# Script: osint-summary-people.sh
# Descrição: Gera a dashboard de colaboradores (OSINT People Summary)
# Autor: OPenPipeS Stack
# =============================================================================

targetName="$1"
obsdir="${OBSIDIAN_VAULT_DIR:-$HOME/ObsidianVault}"
peopleDir="$obsdir/Pentest/Alvos/$targetName/OSINT/People"
summaryFile="$peopleDir/osint_people_summary.md"
tpldir="$HOME/.openpipes/.templates/osint"

# Cria tabela dinâmica
table=""

for personFile in "$peopleDir"/people_*.md; do
    [[ ! -f "$personFile" ]] && continue

    name=$(grep '^name:' "$personFile" | cut -d'"' -f2)
    role=$(grep '^role:' "$personFile" | cut -d'"' -f2)
    email=$(grep '^email:' "$personFile" | cut -d'"' -f2)
    photo=$(grep '^photo:' "$personFile" | cut -d'"' -f2)
    source=$(grep '^source:' "$personFile" | cut -d'"' -f2)
    personBase=$(basename "$personFile")

    table+="| ![]($photo){width=40} | [$name]($personBase) | $role | $email | $source |\n"
done

# Gera arquivo final baseado no stub
sed "s|{{TARGET}}|$targetName|g" "$tpldir/osint_people_summary.stub.md" \
  | sed "s|{{DATE}}|$(date '+%Y-%m-%d %H:%M:%S')|g" \
  | sed "s|{{TABLE}}|$table|g" > "$summaryFile"

echo "[✔] OSINT People Summary gerado em: $summaryFile"
