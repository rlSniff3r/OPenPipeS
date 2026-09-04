#!/bin/bash
source $HOME/.openpipes/config.sh

# ========================================================
# MAGIA NINJA: CONVERTER ARGS CUSTOMIZADOS PARA ARRAY
# (Fora do loop para performance e SEM a palavra 'local')
# ========================================================
extra_args=()
if [[ -n "${OP_TOOL_ARGS:-}" ]]; then
    eval "extra_args=($OP_TOOL_ARGS)"
fi
# ========================================================

for dir in "$NMAP_DIR"/nmap-*; do
    [[ ! -d "$dir" ]] && continue
    targetName="${dir##*/nmap-}"

    # === FILTRO OP_TARGETS ===
    if [[ -n "${OP_TARGETS:-}" ]]; then
        # Verifica se o target atual está na lista separada por vírgulas
        if ! echo "$OP_TARGETS" | tr ',' '\n' | grep -Fqx "$targetName"; then
            continue # Pula se não estiver na lista!
        fi
        echo "[*] Alvo restrito acionado para: $targetName"
    fi
    # ==========================

    target_list="$dir/httpx_targets.txt"
    ports_file="$dir/httpx_ports.txt"

    if [[ ! -f "$target_list" || ! -f "$ports_file" ]]; then
        echo "[SKIP] $targetName: inputs não encontrados. Execute 'openpipes-core feed' primeiro."
        continue
    fi

    ports=$(cat "$ports_file")
    [[ -z "$ports" ]] && echo "[SKIP] $targetName: sem portas." && continue

    echo "[*] Processando: $targetName (portas: $ports)"

    timestamp=$(date +%Y%m%d-%H%M%S)
    json_out="$dir/httpx-$timestamp.json"
    url_list="$dir/httpx-$timestamp.list"

    httpx -l "$target_list" -p "$ports" -x GET,POST,OPTIONS,HEAD \
        -random-agent \
        -title -tech-detect -server -sc -fr -ip \
        -json -o "$json_out" \
        "${extra_args[@]}"

    jq -r '.url' "$json_out" | sort -u > "$url_list"
    jq -r 'select(.status_code != null) | .url' "$json_out" | sort -u > "$dir/alive_urls.txt"

    echo "[✔] $targetName finalizado."
done

# Consolidate all httpx JSONs into one file for the parser
jq -s -c '.[]' "$NMAP_DIR"/nmap-*/httpx-*.json > "$NMAP_DIR/httpx_output.json" 2>/dev/null
echo "[✔] httpx-runner concluído."

# HTTPx terminou o scan. Antes de dar o exit 0 pro Python, vamos ver se a internet está viva:
if ! ping -c 2 8.8.8.8 &> /dev/null; then
    echo "[!] AVISO: Queda de conexão detectada durante ou após o scan!"
    exit 1  # Força o erro! O Python NÃO vai rodar o parser!
fi

exit 0 # Tudo certo, o Python pode marcar as URLs como lidas!