#!/bin/bash
source ~/.openpipes/config.sh

echo -e "\n\e[34m[+]\e[0m Iniciando varredura XSS com Dalfox (Throttled)..."

for d in "$NMAP_DIR"/nmap-*/; do
    [ -d "$d" ] || continue
    TARGET_FILE="${d}dalfox_targets.txt"
    OUT_FILE="${d}dalfox_output.json"

    if [ -s "$TARGET_FILE" ]; then
        target_name=$(basename "$d" | sed 's/nmap-//')
        echo "  → Analisando $target_name..."
        dalfox file "$TARGET_FILE" \
            --worker 30 \
            --delay 300 \
            --timeout 10 \
            --only-poc \
            --format json \
            -o "$OUT_FILE"
    fi
done

echo -e "\e[32m[✔]\e[0m Dalfox finalizado."
