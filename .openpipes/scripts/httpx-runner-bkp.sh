#!/bin/bash

# Updating...

# Configs
source $HOME/.openpipes/config.sh

base_dir=$NMAP_DIR
recon_dir="$base_dir/../Recon"
domains_file="$base_dir/../domains.txt"
common_http_ports=(80 443 8000 8080 8443 10443 4443)
export NO_COLOR=1

regex_domains=$(paste -sd"|" "$domains_file")

# Mapeia domínios a IPs
mapfile -t ip_mappings < <(grep -hE "has address" $recon_dir/*/hosts-allsubs | grep -E "$regex_domains")
declare -A ip_to_domains
for line in "${ip_mappings[@]}"; do
  domain=$(echo "$line" | awk '{print $1}')
  ip=$(echo "$line" | awk '{print $NF}')
  [[ "$ip" =~ : ]] && continue
  ip_to_domains[$ip]="${ip_to_domains[$ip]} $domain"
done

# Complementa com JSON do allsubs.httpx.json
for json in $recon_dir/*/allsubs.httpx.json; do
  [[ ! -f "$json" ]] && continue
  jq -r 'select(.input and .host) | [.input, .host] | @tsv' "$json" | while IFS=$'\t' read -r domain ip; do
    [[ "$ip" =~ : ]] && continue
    ip_to_domains[$ip]="${ip_to_domains[$ip]} $domain"
  done
done

# Processa cada alvo
for dir in "$base_dir"/nmap-*; do
  [[ ! -d "$dir" ]] && continue
  targetName="${dir##*/nmap-}"

  # Verifica se o relatório já existe
  md_file="$obsdir/$proj_name/Pentest/Alvos/$targetName/httpx.md"
  if [[ -f "$md_file" ]]; then
    echo "[*] Relatório para $targetName já existe. Pulando."
    continue
  fi

  ip=$(grep "Nmap scan report for" $dir/initial | sed 's/Nmap scan report for //g' |cut -d "(" -f2 | cut -d ")" -f1 | cut -d ":" -f2)
#  ip=$(grep "Nmap scan report for" "$dir/nmap.nmap" | head -n1 | cut -d "(" -f2 | cut -d ")" -f1)

  [[ -z "$ip" ]] && echo "[!] IP não encontrado para $targetName" && continue

  echo "[*] Processando alvo: $targetName com IP $ip"

  mapfile -t all_ports < <(grep "/tcp" "$dir"/*.nmap 2>/dev/null | grep open | cut -d"/" -f1 | sort -nu)
  http_ports=()
  for port in "${all_ports[@]}"; do
    service_line=$(grep "^$port/tcp" "$dir"/*.nmap | head -n1)
    service=$(echo "$service_line" | awk '{print $3}')
    if [[ "$service" =~ ^(http|https|ssl|proxy|ajp|sun-answerbook|webmin|zabbix|grafana|http.*|.*http)$ ]]; then
      http_ports+=("$port")
    fi
  done

  for p in "${common_http_ports[@]}"; do
    if [[ ! " ${http_ports[*]} " =~ " $p " ]]; then
      http_ports+=("$p")
    fi
  done
  ports=$(IFS=','; echo "${http_ports[*]}")

  target_list="httpx_targets.txt"
  > "$HTTPX_DIR/$target_list"
  seen=()
  for domain in ${ip_to_domains[$ip]}; do
    [[ " ${seen[*]} " =~ " $domain " ]] && continue
    seen+=("$domain")
    echo "http://$domain" >> "$target_list"
    echo "https://$domain" >> "$target_list"
  done

  # Garantir que o hostname (nome do diretório / nmap-<host>) também seja testado
  if [[ ! " ${seen[*]} " =~ " $targetName " ]]; then
    seen+=("$targetName")
    echo "http://$targetName" >> "$target_list"
    echo "https://$targetName" >> "$target_list"
  fi

  # Sempre mantenha os IPs como fallback
  echo "http://$ip" >> "$target_list"
  echo "https://$ip" >> "$target_list"

  timestamp=$(date +%Y%m%d-%H%M%S)
  json_out="$dir/httpx-$timestamp.json"
  url_list="$dir/httpx-$timestamp.list"
  echo "[*] Executando httpx para $targetName → $json_out"

  httpx -l "$target_list" -p "$ports" -x GET,POST,OPTIONS,HEAD \
    -title -tech-detect -server -sc -fr -ip -json -o "$json_out"

  jq -r '.url' "$json_out" | sort -u > "$url_list"

  json_files=("$dir"/httpx-*.json)
  combined_httpx="$dir/httpx-combined.json"
  jq -s '[.[] | select(type=="object" and has("status_code"))]' "${json_files[@]}" > "$combined_httpx"

  dedup_json="$dir/httpx-dedup.json"
  jq 'unique_by(.url, .method, .final_url)' "$combined_httpx" > "$dedup_json"

  # Markdown: httpx.md
  md_file="$obsdir/$proj_name/Pentest/Alvos/$targetName/httpx.md"
  mkdir -p "$(dirname "$md_file")"
  echo "# 🌐 HTTPX - $targetName" > "$md_file"
  echo "" >> "$md_file"
  echo "| Method | URL | IP | Port | Status | Title | Tecnologias | Servidor |" >> "$md_file"
  echo "|--------|-----|----|------|--------|-------|-------------|----------|" >> "$md_file"

  if [[ -f "$dedup_json" ]]; then
  jq -r '
    sort_by(.method, .url, .final_url) |
    .[] |
    . as $h |
    [
      $h.method,
      ($h.final_url // $h.url // "-"),
      ($h.host // "-"),
      ($h.port|tostring // "-"),
      (
        ($h.status_code|tostring + " " + ($h.status_line // "-")) +
        (if $h.chain_status_codes then
          " (" + ($h.chain_status_codes | map(tostring) | join("→")) + ")"
        else
          ""
        end)
      ),
      (($h.title // "-") | gsub("\\|"; "-")),
      (($h.tech // ["-"] | join(",") | gsub("\\|"; "-"))),
      (($h.webserver // "-") | gsub("\\|"; "-"))
#      ($h.title // "-"),
#      ($h.tech // ["-"] | join(",")),
#      ($h.webserver // "-")
    ] | "| " + join(" | ") + " |"
  ' "$dedup_json" >> "$md_file"
  else
    echo "| - | - | - | - | - | - | - | - |" >> "$md_file"
  fi

  # endpoints.md
  endpoints_file="$obsdir/$proj_name/Pentest/Alvos/$targetName/endpoints.md"
  jq -r '.[] | select(.status_code >= 200 and .status_code < 300) | .url' "$dedup_json" | sort -u >> "$endpoints_file"

  (head -n4 "$md_file"; tail -n +5 "$md_file" | sort -u | egrep -v "400 |406 ") > $md_file.txt
  mv "$md_file.txt" "$md_file"

  echo "[✔] $targetName finalizado."
done

echo -e "\n[🏁] httpx-runner.v3.sh finalizado com sucesso!"

# HTTPx terminou o scan. Antes de dar o exit 0 pro Python, vamos ver se a internet está viva:
if ! ping -c 2 8.8.8.8 &> /dev/null; then
    echo "[!] AVISO: Queda de conexão detectada durante ou após o scan!"
    exit 1  # Força o erro! O Python NÃO vai rodar o parser!
fi

exit 0 # Tudo certo, o Python pode marcar as URLs como lidas!