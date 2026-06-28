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
# Changed: iterate over nmap directories instead of Obsidian vault
for nmap_folder in "$NMAP_DIR"/nmap-*; do
    [[ ! -d "$nmap_folder" ]] && continue
    target_name="${nmap_folder##*/nmap-}"

    # Collect URLs from httpx JSON files in this target's nmap directory
    # (Fallback: still tries endpoints.md if it exists)
    urls=""
    if [[ -f "$nmap_folder/httpx-dedup.json" ]]; then
        urls=$(jq -r '.[] | select(.url != null) | .url' "$nmap_folder/httpx-dedup.json" 2>/dev/null)
    fi
    # Also try individual httpx JSONs
    for json in "$nmap_folder"/httpx-*.json; do
        [[ ! -f "$json" ]] && continue
        urls+=$'\n'"$(jq -r 'select(.url != null) | .url' "$json" 2>/dev/null)"
    done
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

    # === Output: JSON ===
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
