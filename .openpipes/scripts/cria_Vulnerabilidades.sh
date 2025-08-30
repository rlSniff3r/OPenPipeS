#!/bin/bash

# Configs
source $HOME/.openpipes/config.sh

CACHE_DIR="$HOME/.openpipes_cache"

# Seleciona alvo
echo "[*] Selecione o alvo:"
targetName=$(find "$obsdir/Pentest/Alvos" -mindepth 1 -maxdepth 1 -type d | sed 's|.*/||' | fzf --prompt="Alvo: ")
[[ -z "$targetName" ]] && echo "[!] Nenhum alvo selecionado." && exit 1

# Pega IP do alvo
target_file="$obsdir/Pentest/Alvos/$targetName/$targetName.md"
t_IP=$(grep '^t_IP:' "$target_file" | cut -d ':' -f2- | xargs)

# Seleciona vulnerabilidade do cache
echo "[*] Selecione a vulnerabilidade do cache:"
vulnFile=$(find "$CACHE_DIR" -type f -name "*.json" | fzf --prompt="Vuln: ")
[[ -z "$vulnFile" ]] && echo "[!] Nenhuma vulnerabilidade selecionada." && exit 1

# Extrai dados do JSON
title=$(jq -r '.title' "$vulnFile" | sed 's,/, ,g')
cvss_v=$(jq -r '.cvssv3' "$vulnFile")
description=$(jq -r '.description' "$vulnFile")
observation=$(jq -r '.observation' "$vulnFile")
remediation=$(jq -r '.remediation' "$vulnFile")
references=$(jq -r '.references | join("\n- ")' "$vulnFile")

# Calcula score e severidade via cvss_calculator
cvss_json=$(cvss_calculator -3jv "$cvss_v" | tail -n +8)
cvss_float=$(echo "$cvss_json" | jq -r '."baseScore"')
severity_en=$(echo "$cvss_json" | jq -r '."baseSeverity"')

# Tradução severidade + emoji
case "$severity_en" in
  "LOW")    severidade="Baixa";  emoji="🟢" ;;
  "MEDIUM") severidade="Média";  emoji="🟡" ;;
  "HIGH")   severidade="Alta";   emoji="🟠" ;;
  "CRITICAL") severidade="Crítica"; emoji="🔴" ;;
  *) severidade="Desconhecida"; emoji="⚪" ;;
esac

# Cria arquivo markdown com timestamp
timestamp=$(date +%Y%m%d%H%M%S)
filename="${timestamp}_${title}.md"
vulnDir="$obsdir/Pentest/Alvos/$targetName/Vulnerabilidades"
mkdir -p "$vulnDir"

cp "$tpdir/vuln.stub.md" "$vulnDir/$filename"

# Atualiza frontmatter
sed -i "s/^targetName:.*/targetName: $targetName/" "$vulnDir/$filename"
sed -i "s/^t_IP:.*/t_IP: $t_IP/" "$vulnDir/$filename"
sed -i "s/^Tipo:.*/Tipo: $title/" "$vulnDir/$filename"
sed -i "s/^Severidade:.*/Severidade: $severidade/" "$vulnDir/$filename"
sed -i "s/^CVSS:.*/CVSS: $cvss_float/" "$vulnDir/$filename"
sed -i "s,^cvss_v:.*,cvss_v: ${cvss_v}," "$vulnDir/$filename"

# Substitui seções do corpo
sed -i "s/^title.*/# $emoji $title/" "$vulnDir/$filename"

# Descrição
sed -i "0,/^description/{s|^description.*|$description|}" "$vulnDir/$filename"
# Impacto
sed -i "0,/^observation/{s|^observation.*|$observation|}" "$vulnDir/$filename"
# Recomendação
sed -i "0,/^remediation/{s|^remediation.*|$remediation|}" "$vulnDir/$filename"
# Referências (prefixa cada uma com "- ")
#sed -i "0,/^references/{s|^references.*|- $references|}" "$vulnDir/$filename"
awk -v r="$references" 'c==0 && /^references/ { print "- " r; c=1; next } { print }' "$vulnDir/$filename" > tmp && mv tmp "$vulnDir/$filename"

echo "[✔] Vulnerabilidade criada com sucesso: $filename"

