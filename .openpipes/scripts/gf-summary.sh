#!/bin/bash
# === CONFIG ===
source $HOME/.openpipes/config.sh
gf_dir="$HOME/.openpipes/.gf"
gf_filters=(xss sqli lfi rce idor redirect debug_logic interestingparams)
exts=("php" "json" "js" "bak" "zip" "env" "txt" "log" "conf")

# === VERIFICA DEPENDÊNCIAS ===
for bin in gf awk grep cut sort uniq sed; do
    if ! command -v "$bin" &>/dev/null; then
        echo "[!] Dependência ausente: $bin"
        exit 1
    fi
done

# === LOOP EM TODOS OS ALVOS ===
for nmap_folder in "$NMAP_DIR"/nmap-*; do
    [[ ! -d "$nmap_folder" ]] && continue
    target_name="${nmap_folder##*/nmap-}"

    # Collect URLs from httpx JSON files
    urls=""
    if [[ -f "$nmap_folder/httpx-dedup.json" ]]; then
        urls=$(jq -r '.[] | select(.url != null) | .url' "$nmap_folder/httpx-dedup.json" 2>/dev/null)
    fi
    for json in "$nmap_folder"/httpx-*.json; do
        [[ ! -f "$json" ]] && continue
        urls+=$'\n'"$(jq -r 'select(.url != null) | .url' "$json" 2>/dev/null)"
    done

    # Also add URLs from katana and ferox outputs
    if [[ -f "$nmap_folder/crawled_all.txt" ]]; then
        urls+=$'\n'"$(cat "$nmap_folder/crawled_all.txt")"
    fi
    if [[ -f "$nmap_folder/ferox_consolidated.txt" ]]; then
        urls+=$'\n'"$(cat "$nmap_folder/ferox_consolidated.txt")"
    fi
    if [[ -f "$nmap_folder/alive_urls.txt" ]]; then
        urls+=$'\n'"$(cat "$nmap_folder/alive_urls.txt")"
    fi

    # Re-deduplicate after adding all sources
    urls=$(echo "$urls" | sort -u)

    [[ -z "$urls" ]] && echo "[!] Nenhuma URL encontrada para $target_name" && continue

    # === Agrupamento por extensão ===
    ext_data="{}"
    for ext in "${exts[@]}"; do
        count=$(echo "$urls" | grep -cEi "\\.${ext}(\\?|$|/)")
        [[ "$count" -gt 0 ]] && ext_data=$(echo "$ext_data" | jq --arg ext "$ext" --argjson cnt "$count" '. + {($ext): $cnt}')
    done

    # === Filtros GF ===
    gf_data="{}"
    for filter in "${gf_filters[@]}"; do
        matches=$(echo "$urls" | gf "$filter" | sort -u | jq -R -s 'split("\n") | map(select(length > 0))')
        gf_data=$(echo "$gf_data" | jq --arg f "$filter" --argjson m "$matches" '. + {($f): $m}')
    done

    # === Arquivos sensíveis ===
    sensitive=$(echo "$urls" | grep -E '\.(bak|zip|env|conf|log|sql|tar|gz|rar)(\?|$|/)' | sort -u | jq -R -s 'split("\n") | map(select(length > 0))')

    # === Output: JSON (FIXED: --argjson gf instead of --arg json gf) ===
    json_output="$nmap_folder/gf-summary.json"
    jq -n \
        --arg target "$target_name" \
        --argjson exts "$ext_data" \
        --argjson gf "$gf_data" \
        --argjson sensitive "$sensitive" \
        '{target: $target, generated_at: now, extension_summary: $exts, gf_patterns: $gf, sensitive_files: $sensitive}' \
        > "$json_output"

    echo "[✔] gf-summary.json gerado para: $target_name → $json_output"
done

# GF-Summary terminou o scan. Antes de dar o exit 0 pro Python, vamos ver se a internet está viva:
if ! ping -c 2 8.8.8.8 &> /dev/null; then
    echo "[!] AVISO: Queda de conexão detectada durante ou após o scan!"
    exit 1  # Força o erro! O Python NÃO vai rodar o parser!
fi

exit 0 # Tudo certo, o Python pode marcar as URLs como lidas!