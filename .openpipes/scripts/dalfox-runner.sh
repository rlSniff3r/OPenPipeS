#!/bin/bash
source ~/.openpipes/config.sh

echo -e "\n\e[34m[+]\e[0m Iniciando varredura XSS com Dalfox (Remote Payloads + Deep DOM)..."

TIMESTAMP=$(date +%Y%m%d_%H%M%S)

for d in "$NMAP_DIR"/nmap-*/; do
    [ -d "$d" ] || continue
    TARGET_FILE="${d}dalfox_targets.txt"
    OUT_FILE="${d}dalfox_output_${TIMESTAMP}.json"

    if [ -s "$TARGET_FILE" ]; then
        target_name=$(basename "$d" | sed 's/nmap-//')
        echo "  → Analisando $target_name..."

        while IFS= read -r url || [ -n "$url" ]; do
            [ -z "$url" ] && continue
            echo "    ↳ $url"
            dalfox url "$url" \
                --worker 150 \
                --remote-payloads portswigger,payloadbox \
                --deep-domxss \
                --format json \
                >> "$OUT_FILE"
        done < "$TARGET_FILE"
    fi
done

echo -e "\e[32m[✔]\e[0m Dalfox finalizado."
