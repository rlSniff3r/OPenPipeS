#!/bin/bash
source ~/.openpipes/config.sh

echo -e "\n\e[34m[+]\e[0m Iniciando descoberta de parâmetros ocultos com Arjun..."

TIMESTAMP=$(date +%Y%m%d_%H%M%S)

for d in "$NMAP_DIR"/nmap-*/; do
    [ -d "$d" ] || continue
    target_name=$(basename "$d" | sed 's/nmap-//')
    TARGET_FILE="${d}arjun_targets.txt"
    OUT_FILE="${d}arjun_output_${TIMESTAMP}.json"

    # ── Scope guard: skip out-of-scope hosts ──
    in_scope=$(sqlite3 "$proj_path/.openpipes.db" \
        "SELECT in_scope FROM hosts WHERE host='$target_name' AND is_alive=1" 2>/dev/null)
    if [ "$in_scope" != "1" ]; then
        echo "  → Pulando $target_name (fora do escopo)"
        continue
    fi

    if [ -s "$TARGET_FILE" ]; then
        echo "  → Analisando $target_name..."
        arjun -i "$TARGET_FILE" \
            -t 10 \
            -d 1 \
            -m GET,POST,HEADER \
            -oJ "$OUT_FILE"
    fi
done

echo -e "\e[32m[✔]\e[0m Arjun finalizado."
