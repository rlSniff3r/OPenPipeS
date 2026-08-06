#!/bin/bash
source ~/.openpipes/config.sh
echo -e "\n\e[34m[+]\e[0m Iniciando SQLMap (injetáveis)..."
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

for d in "$NMAP_DIR"/nmap-*/; do
    [ -d "$d" ] || continue
    GET_FILE="${d}sqlmap_get.txt"
    POST_FILE="${d}sqlmap_post.txt"
    OUT_FILE="${d}sqlmap_output_${TIMESTAMP}.json"

    if [ -s "$GET_FILE" ]; then
        target_name=$(basename "$d" | sed 's/nmap-//')
        echo "  → (GET) $target_name..."
        sqlmap -m "$GET_FILE" --batch --threads 5 --level 2 --risk 2 \
            --smart --flush-session \
            --json --output-dir="$d"
    fi

    if [ -s "$POST_FILE" ]; then
        echo "  → (POST) $target_name..."
        while IFS='|' read -r url data; do
            [ -z "$url" ] && continue
            sqlmap -u "$url" --data "$data" --batch --threads 5 \
                --level 2 --risk 2 --flush-session \
                --report-json $OUT_FILE
        done < "$POST_FILE"
    fi
done
echo -e "\e[32m[✔]\e[0m SQLMap finalizado."
