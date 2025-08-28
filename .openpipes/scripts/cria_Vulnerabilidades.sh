#!/bin/bash

# Configs
source $HOME/.openpipes/config.sh

# Prompt para escolher o alvo (nome do host)
echo "[*] Selecione o alvo:"
targetName=$(find "$obsdir/Pentest/Alvos" -mindepth 1 -maxdepth 1 -type d | sed 's|.*/||' | fzf --prompt="Alvo: ")
[[ -z "$targetName" ]] && echo "[!] Nenhum alvo selecionado." && exit 1

# Caminho da nota de alvo (para extrair IP)
target_file="$obsdir/Pentest/Alvos/$targetName/$targetName.md"
t_IP=$(grep '^t_IP:' "$target_file" | cut -d ':' -f2- | xargs)

# Prompts adicionais
read -p "[?] Nome da Vulnerabilidade (Tipo): " vulnTipo
read -p "[?] CVSS (ex: 9.1): " cvss

# Cálculo automático da severidade com base em CVSS v3
cvss_float=$(printf "%.1f" "$cvss")
if (( $(echo "$cvss_float >= 9.0" | bc -l) )); then
  severidade="Crítica"
  emoji="🔴"
elif (( $(echo "$cvss_float >= 7.0" | bc -l) )); then
  severidade="Alta"
  emoji="🟠"
elif (( $(echo "$cvss_float >= 4.0" | bc -l) )); then
  severidade="Média"
  emoji="🟡"
else
  severidade="Baixa"
  emoji="🟢"
fi

# Cria nome do arquivo com timestamp para ordenação
timestamp=$(date +%Y%m%d%H%M%S)
filename="${timestamp}_${vulnTipo// /_}.md"
vulnDir="$obsdir/Pentest/Alvos/$targetName/Vulnerabilidades"
mkdir -p "$vulnDir"

# Copia template
cp "$tpdir/vuln.stub.md" "$vulnDir/$filename"

# Atualiza frontmatter
sed -i "s/^targetName:.*/targetName: $targetName/" "$vulnDir/$filename"
sed -i "s/^t_IP:.*/t_IP: $t_IP/" "$vulnDir/$filename"
sed -i "s/^Tipo:.*/Tipo: $vulnTipo/" "$vulnDir/$filename"
sed -i "s/^Severidade:.*/Severidade: $severidade/" "$vulnDir/$filename"
sed -i "s/^CVSS:.*/CVSS: $cvss_float/" "$vulnDir/$filename"

# Insere título com emoji após bloco YAML
line=$(grep -n '^---$' "$vulnDir/$filename" | tail -n1 | cut -d':' -f1)
insert_line=$((line + 1))
sed -i "${insert_line}i# $emoji $vulnTipo\n" "$vulnDir/$filename"

echo "[✔] Vulnerabilidade criada com sucesso: $filename"

