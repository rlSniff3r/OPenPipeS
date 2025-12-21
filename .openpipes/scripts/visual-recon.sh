#!/bin/bash
# Wrapper para Screenshot Inteligente com GoWitness

INPUT_LIST="$1"
OUTPUT_DIR="$2"
WORK_DIR="$3"

if [ -z "$WORK_DIR" ]; then
    echo "Uso: visual-recon.sh <lista_urls> <output_dir> <work_dir>"
    exit 1
fi

echo -e "\033[0;34m[Visual] Enriquecendo alvos para deduplicação...\033[0m"

# 1. Httpx Enrichment (Pega Títulos e Status para o Python analisar)
# -json gerando linhas individuais, jq -s agrupa num array único pro Python ler fácil
httpx -l "$INPUT_LIST" \
    -silent -title -sc -cl -json \
    | jq -s '.' > "$WORK_DIR/enrichment_for_visual.json"

# 2. Filtragem Python
echo -e "\033[0;34m[Visual] Filtrando duplicatas (Title/Path logic)...\033[0m"
python3 ~/.openpipes/scripts/filters.py dedupe \
    --json "$WORK_DIR/enrichment_for_visual.json" > "$WORK_DIR/final_screens_clean.txt"

COUNT=$(wc -l < "$WORK_DIR/final_screens_clean.txt")
ORIGINAL=$(wc -l < "$INPUT_LIST")

echo -e "\033[0;33m[Visual] Otimização: $ORIGINAL -> $COUNT URLs para printar.\033[0m"

# 3. GoWitness
if [ "$COUNT" -gt 0 ]; then
    # --delay 2 e --threads 4 para não travar a VM
    gowitness scan file -f "$WORK_DIR/final_screens_clean.txt" \
        --screenshot-path "$OUTPUT_DIR" \
        --threads 4 --delay 2 --timeout 20 \
        --write-db-uri "sqlite://$WORK_DIR/gowitness.sqlite3" 2>/dev/null
else
    echo "Nenhuma URL relevante encontrada."
fi
