#!/bin/bash

# === CONFIG ===
source $HOME/.openpipes/config.sh
gf_dir="$HOME/.openpipes/.gf"
gf_filters=(xss sqli lfi rce idor redirect debug_logic interestingparams)  # personalizável
exts=("php" "json" "js" "bak" "zip" "env" "txt" "log" "conf")

# === VERIFICA DEPENDÊNCIAS ===
for bin in gf awk grep cut sort uniq sed; do
  if ! command -v "$bin" &>/dev/null; then
    echo "[!] Dependência ausente: $bin"
    exit 1
  fi
done

# === LOOP EM TODOS OS ALVOS COM endpoints.md ===
for endpoint_file in "$obsdir"/Pentest/Alvos/*/endpoints.md; do
  [[ ! -f "$endpoint_file" ]] && continue

  target_dir=$(dirname "$endpoint_file")
  target_name=$(basename "$target_dir")
  output="$target_dir/gf-summary.md"

  echo "# 🧬 GF Summary - $target_name" > "$output"
  echo "" >> "$output"

  urls=$(cat "$endpoint_file")

  # === Agrupamento por extensão ===
  echo "## 📂 Extensões encontradas" >> "$output"
  for ext in "${exts[@]}"; do
    count=$(echo "$urls" | grep -Ei "\.${ext}(\?|$|/)" | wc -l)
    if [[ "$count" -gt 0 ]]; then
      echo "- .$ext: $count ocorrências" >> "$output"
    fi
  done
  echo "" >> "$output"

  # === Filtros GF ===
  for filter in "${gf_filters[@]}"; do
    echo "## 🧪 gf: $filter" >> "$output"
    echo '```' >> "$output"
    echo "$urls" | gf "$filter" | sort -u >> "$output"
    echo '```' >> "$output"
    echo "" >> "$output"
  done

  # === Agrupamento por arquivos sensíveis (sem filtros gf) ===
  echo "## 🧪 Arquivos sensíveis (extensões)" >> "$output"
  echo '```' >> "$output"
  echo "$urls" | grep -E '\.(bak|zip|env|conf|log|sql|tar|gz|rar)(\?|$|/)' | sort -u >> "$output"
  echo '```' >> "$output"

  echo "[✔] gf-summary.md gerado para: $target_name"
done
