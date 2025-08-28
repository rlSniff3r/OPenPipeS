#!/bin/bash

# Configs
source $HOME/.openpipes/config.sh

for dir in $(ls -l | grep nmap- | rev | cut -d " " -f1 | rev); do
  targetName=${dir#nmap-}
  targetDash="$obsdir/Pentest/Alvos/$targetName/Dashboard_${targetName}.md"
#  echo $targetName
  ip=$(grep "Nmap scan report for" $dir/initial | sed 's/Nmap scan report for //g' |cut -d "(" -f2 | cut -d ")" -f1 | cut -d ":" -f2)
  echo -e "|$targetName|$ip|\n|--------|--|"> $dir/whois_block.txt
  cat $dir/initial | grep -A 7 " whois" | tail -n +2 | sed 's/:/|/g' | sed 's/$/|/g' | sed 's/|_/| /g'>> $dir/whois_block.txt
  cat $dir/whois_block.txt
  whois_block=$(cat $dir/whois_block.txt)


# === Inserir bloco WHOIS na linha abaixo da última ocorrência de "Dashboard"
line=$(grep -n "Dashboard" "$targetDash" | tail -n1 | cut -d ":" -f1)
insert_line=$((line + 2))

# Cria um arquivo temporário com a nova versão da dashboard
awk -v insert="$insert_line" -v file="$dir/whois_block.txt" '
  NR==insert {
    while ((getline line < file) > 0) {
      print line
    }
  }
  { print }
' "$targetDash" > "$targetDash.tmp" && mv "$targetDash.tmp" "$targetDash"

done
