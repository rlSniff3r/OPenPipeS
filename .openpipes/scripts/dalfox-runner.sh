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

        # Native file mode: dalfox reads all URLs from the file in one pass
        dalfox scan "$TARGET_FILE" \
            --follow-redirects \
            --stream-findings \
            --max-targets-per-host 200 \
            --ignore-return 302,403,404 \
            --workers 150 \
            --remote-payloads portswigger,payloadbox \
            --format json \
            -o "$OUT_FILE"
    fi
done

echo -e "\e[32m[✔]\e[0m Dalfox finalizado."
