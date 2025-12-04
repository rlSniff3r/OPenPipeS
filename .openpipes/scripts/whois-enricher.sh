#!/bin/bash

# Configs
source $HOME/.openpipes/config.sh

for dir in $(ls -l $NMAP_DIR | grep nmap- | rev | cut -d " " -f1 | rev); do
  targetName=${dir#nmap-}
  targetDash="$obsdir/$proj_name/Pentest/Alvos/$targetName/Dashboard_${targetName}.md"
#  echo $targetName
  ip=$(grep "Nmap scan report for" $NMAP_DIR/$dir/initial | sed 's/Nmap scan report for //g' |cut -d "(" -f2 | cut -d ")" -f1 | cut -d ":" -f2)
  echo -e "|$targetName|$ip|\n|--------|--|"> $NMAP_DIR/$dir/whois_block.txt
  cat $NMAP_DIR/$dir/initial | grep -A 7 " whois" | tail -n +2 | sed 's/:/|/g' | sed 's/$/|/g' | sed 's/|_/| /g'>> $NMAP_DIR/$dir/whois_block.txt
  cat $NMAP_DIR/$dir/whois_block.txt
  whois_block=$(cat $NMAP_DIR/$dir/whois_block.txt)


# === Inserir bloco WHOIS na linha abaixo da última ocorrência de "Dashboard"
line=$(grep -n "Dashboard" "$targetDash" | tail -n1 | cut -d ":" -f1)
insert_line=$((line + 2))

# Cria um arquivo temporário com a nova versão da dashboard
awk -v insert="$insert_line" -v file="$whois_block" '
  NR==insert {
    while ((getline line < file) > 0) {
      print line
    }
  }
  { print }
' "$targetDash" > "$targetDash.tmp" && mv "$targetDash.tmp" "$targetDash"

done
