#!/bin/bash

# Configs
source $HOME/.openpipes/config.sh

for dir in $(ls -d $NMAP_DIR/nmap-* 2>/dev/null); do
  [[ ! -d "$dir" ]] && continue
  
  targetName=$(basename "$dir" | sed 's/^nmap-//')
  targetDash="$obsdir/$proj_name/Pentest/Alvos/$targetName/Dashboard_${targetName}.md"
  
  if [[ ! -f "$targetDash" ]]; then
    echo "[SKIP] Dashboard não encontrada: $targetDash"
    continue
  fi
  
  echo "[*] Processando: $targetName"
  
  # Procura arquivo .nmap
  nmap_file=$(find "$dir" -name "*.nmap" | head -n1)
  
  if [[ ! -f "$nmap_file" ]]; then
    echo "[ERROR] Arquivo .nmap não encontrado em $dir"
    continue
  fi
  
  # Extrai IP
  ip=$(grep "Nmap scan report for" "$nmap_file" | sed 's/Nmap scan report for //g' | cut -d "(" -f2 | cut -d ")" -f1)
  
  if [[ -z "$ip" ]]; then
    echo "[WARN] IP não encontrado para $targetName"
    continue
  fi
  
  # Cria arquivo WHOIS (não variável string!)
  whois_block_file="$dir/whois_block.txt"
  
  {
    echo "|$targetName|$ip|"
    echo "|--------|--|"
    cat $NMAP_DIR/nmap-$targetName/initial | grep -A 7 " whois" | tail -n +2 | sed 's/:/|/g' | sed 's/$/|/g' | sed 's/|_/| /g'
  } > "$whois_block_file"
  
  # Encontra linha para inserir
  line=$(grep -n "Dashboard" "$targetDash" | tail -n1 | cut -d ":" -f1)
  insert_line=$((line + 2))
  
  # ✅ AWK CORRETO
  awk -v insert_line="$insert_line" -v whois_file="$whois_block_file" '
    NR == insert_line {
      while ((getline < whois_file) > 0) {
        print $0
      }
      print ""
    }
    { print }
  ' "$targetDash" > "$targetDash.tmp" && mv "$targetDash.tmp" "$targetDash"
  
  echo "[OK] $targetName atualizado"
done

echo "[SUCCESS] WHOIS enrichment concluído"
