#!/bin/bash
source $HOME/.openpipes/config.sh

for dir in "$NMAP_DIR"/nmap-*; do
    [[ ! -d "$dir" ]] && continue
    target_name="${dir##*/nmap-}"
    input_file="$dir/alive_urls.txt"

    if [[ ! -s "$input_file" ]]; then
        echo "[SKIP] $target_name: alive_urls.txt vazio ou ausente."
        continue
    fi

    echo "[*] Processando: $target_name"
    nuclei_json="$dir/nuclei_output.json"

    nuclei -l "$input_file" \
        -severity low,medium,high,critical \
        -json \
        -o "$nuclei_json"

    echo "[✔] $target_name finalizado."
done
echo "[✔] nuclei-runner concluído."
