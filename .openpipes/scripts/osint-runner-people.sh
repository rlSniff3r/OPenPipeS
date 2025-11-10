#!/usr/bin/env bash
# =============================================================================
# Script: osint-runner-people.sh
# Descrição: Executa coleta OSINT sobre colaboradores da organização
# Autor: OPenPipeS Stack
# =============================================================================

targetName="$1"
obsdir="${OBSIDIAN_VAULT_DIR:-$HOME/ObsidianVault}"
tpldir="$HOME/.openpipes/.templates/osint"
peopleDir="$obsdir/Pentest/Alvos/$targetName/OSINT/People"

mkdir -p "$peopleDir"

echo "[INFO] Iniciando OSINT People Runner para: $targetName"

# 1. Busca básica de colaboradores (DuckDuckGo, Google, LinkedIn, GitHub)
python3 /usr/local/bin/osint_people_collector.py "$targetName" "$peopleDir/raw_people.json"

# 2. Parser para criar perfis individuais
python3 /usr/local/bin/osint_people_parser.py "$peopleDir/raw_people.json" "$peopleDir"

# 3. Coleta e análise de metadados de documentos públicos
echo "[INFO] Executando análise de metadados e busca de documentos..."
python3 /usr/local/bin/osint_doc_finder.py "$targetName" "$peopleDir/evidences/"

# 4. Geração dos perfis individuais com base no template
for row in $(jq -r '.people[] | @base64' "$peopleDir/raw_people.json"); do
    _jq() { echo "${row}" | base64 --decode | jq -r "${1}"; }

    name=$(_jq '.name')
    email=$(_jq '.email')
    role=$(_jq '.role')
    photo=$(_jq '.photo')
    github=$(_jq '.github')
    linkedin=$(_jq '.linkedin')
    source=$(_jq '.source')

    cat "$tpldir/osint_person.stub.md" | \
      sed "s|{{NAME}}|$name|g" | \
      sed "s|{{EMAIL}}|$email|g" | \
      sed "s|{{ROLE}}|$role|g" | \
      sed "s|{{PHOTO}}|$photo|g" | \
      sed "s|{{GITHUB}}|$github|g" | \
      sed "s|{{LINKEDIN}}|$linkedin|g" | \
      sed "s|{{SOURCE}}|$source|g" \
      > "$peopleDir/people_${name// /_}.md"
done

# 5. Cria evidências no final dos perfis
for f in "$peopleDir"/people_*.md; do
    echo -e "\n## 📂 Evidências Encontradas" >> "$f"
    find "$peopleDir/evidences" -type f -iname "*${f##*/}*" -printf "- %p\n" 2>/dev/null || true
done

# 6. Geração automática do resumo global
echo "[INFO] Gerando summary global..."
osint-summary-people.sh "$targetName"

echo "[✔] OSINT People Runner finalizado para: $targetName"
