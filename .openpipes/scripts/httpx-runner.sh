#!/bin/bash
source $HOME/.openpipes/config.sh

for dir in "$NMAP_DIR"/nmap-*; do
    [[ ! -d "$dir" ]] && continue
    targetName="${dir##*/nmap-}"
    target_list="$dir/httpx_targets.txt"
    ports_file="$dir/httpx_ports.txt"

    if [[ ! -f "$target_list" || ! -f "$ports_file" ]]; then
        echo "[SKIP] $targetName: inputs não encontrados. Execute 'openpipes-core feed' primeiro."
        continue
    fi

    ports=$(cat "$ports_file")
    [[ -z "$ports" ]] && echo "[SKIP] $targetName: sem portas." && continue

    echo "[*] Processando: $targetName (portas: $ports)"

    timestamp=$(date +%Y%m%d-%H%M%S)
    json_out="$dir/httpx-$timestamp.json"
    url_list="$dir/httpx-$timestamp.list"

    httpx -l "$target_list" -p "$ports" -x GET,POST,OPTIONS,HEAD \
        -random-agent \
        -title -tech-detect -server -sc -fr -ip \
        -json -o "$json_out"

    jq -r '.url' "$json_out" | sort -u > "$url_list"
    jq -r 'select(.status_code != null) | .url' "$json_out" | sort -u > "$dir/alive_urls.txt"

    echo "[✔] $targetName finalizado."
done

# Consolidate all httpx JSONs into one file for the parser
jq -s -c '.[]' "$NMAP_DIR"/nmap-*/httpx-*.json > "$NMAP_DIR/httpx_output.json" 2>/dev/null
echo "[✔] httpx-runner concluído."
