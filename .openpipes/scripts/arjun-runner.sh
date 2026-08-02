#!/bin/bash
source ~/.openpipes/config.sh

echo -e "\n\e[34m[+]\e[0m Iniciando descoberta de parâmetros ocultos com Arjun..."

TIMESTAMP=$(date +%Y%m%d_%H%M%S)

for d in "$NMAP_DIR"/nmap-*/; do
    [ -d "$d" ] || continue
    TARGET_FILE="${d}arjun_targets.txt"
    OUT_FILE="${d}arjun_output_${TIMESTAMP}.json"

    if [ -s "$TARGET_FILE" ]; then
        target_name=$(basename "$d" | sed 's/nmap-//')
        echo "  → Analisando $target_name..."
        arjun -i "$TARGET_FILE" \
            -t 10 \
            -d 1 \
            -m GET,POST,HEADER \
            -oJ "$OUT_FILE"
    fi
done

echo -e "\e[32m[✔]\e[0m Arjun finalizado."
