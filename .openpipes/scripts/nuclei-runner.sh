#!/bin/bash

# Configs
source $HOME/.openpipes/config.sh

base_dir="$PWD"
templates_dir="$HOME/nuclei.openpipes/.templates"  # Var declarada mas não utilizada
output_dir="nuclei-output"

mkdir -p "$output_dir"

# Verifica dependências
command -v nuclei >/dev/null 2>&1 || { echo >&2 "[!] nuclei não encontrado no PATH."; exit 1; }
command -v jq >/dev/null 2>&1 || { echo >&2 "[!] jq não instalado."; exit 1; }

# Itera sobre os diretórios nmap-*
for dir in "$base_dir"/nmap-*; do
  [[ ! -d "$dir" ]] && continue
  target_name="${dir##*/nmap-}"

  echo "[*] Processando alvo: $target_name"

  # Arquivo com endpoints já processados
  endpoints_file="$obsdir/Pentest/Alvos/$target_name/endpoints.md"
  [[ ! -f "$endpoints_file" ]] && echo "[!] endpoints.md ausente para $target_name. Pulando..." && continue

  cat "$endpoints_file" | sort -u > urls_file

  # Executa nuclei
  nuclei_json="$output_dir/$target_name-nuclei.json"
  nuclei -l urls_file -severity low,medium,high,critical -je "$nuclei_json"

  # Gera nuclei.md no Obsidian
  obs_nuclei_file="$obsdir/Pentest/Alvos/$target_name/nuclei.md"
  mkdir -p "$(dirname "$obs_nuclei_file")"

  echo "---" > "$obs_nuclei_file"
  echo "tipo: nuclei" >> "$obs_nuclei_file"
  echo "targetName: $target_name" >> "$obs_nuclei_file"
  echo "data: $(date +%Y-%m-%d)" >> "$obs_nuclei_file"
  echo "---" >> "$obs_nuclei_file"
  echo -e "\n# 📦 Resultados do Nuclei\n" >> "$obs_nuclei_file"
  echo "| Nome | Severidade | URL | Dados Extraídos | Descrição |" >> "$obs_nuclei_file"
  echo "|------|------------|-----|------------------|------------|" >> "$obs_nuclei_file"

  jq -r '
    .[] |
    "| \(.info.name // "-") | \(.info.severity // "-") | \(.["matched-at"] // "-") | \((.["extracted-results"] // ["-"]) | join(", ")) | \(.info.description // "-" | gsub("\n"; " ")) |"
  ' "$nuclei_json" >> "$obs_nuclei_file"

  echo "[✔] nuclei.md gerado para $target_name"
done

echo "[✓] Execução do nuclei-runner.sh finalizada com sucesso!"
