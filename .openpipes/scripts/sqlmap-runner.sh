#!/bin/bash
source ~/.openpipes/config.sh
echo -e "\n\e[34m[+]\e[0m Iniciando SQLMap (injetáveis)..."

# ========================================================
# MAGIA NINJA: CONVERTER ARGS CUSTOMIZADOS PARA ARRAY
# ========================================================
extra_args=()
if [[ -n "${OP_TOOL_ARGS:-}" ]]; then
    eval "extra_args=($OP_TOOL_ARGS)"
fi
# ========================================================

# RAIO-X: Mostra o que diabos o Bash entendeu!
if [ ${#extra_args[@]} -gt 0 ]; then
    echo -e " [DEBUG] Argumentos recebidos do Python:"
    for i in "${!extra_args[@]}"; do
        echo "   [$i] -> ${extra_args[$i]}"
    done
fi

for d in "$NMAP_DIR"/nmap-*/; do
    [ -d "$d" ] || continue
    
    target_name=$(basename "$d" | sed 's/nmap-//')

    # === FILTRO OP_TARGETS ===
    if [[ -n "${OP_TARGETS:-}" ]]; then
        # Verifica se o target atual está na lista separada por vírgulas
        if ! echo "$OP_TARGETS" | tr ',' '\n' | grep -Fqx "$target_name"; then
            continue # Aqui o 'continue' é perfeito, pois estamos num 'for' limpo!
        fi
        echo "[*] Alvo restrito acionado para: $target_name"
    fi
    # ==========================

    GET_FILE="${d}sqlmap_get.txt"
    POST_FILE="${d}sqlmap_post.txt"

    # Gera um hash único para a URL atual (ex: 8b1a9953c4611296a827abf8c47804d7)
    URL_HASH=$(echo -n "$url" | md5sum | awk '{print $1}')

    # Define o arquivo de saída com o hash no nome
    OUT_JSON="$NMAP_DIR/nmap-${target_name}/sqlmap_${URL_HASH}.json"

    if [ -s "$GET_FILE" ]; then
        echo "  → (GET) $target_name..."
        sqlmap -m "$GET_FILE" --batch --threads 5 --level 2 --risk 2 \
            --flush-session \
            --random-agent \
            "${extra_args[@]}" \
            --report-json "$OUT_JSON"
    fi

    if [ -s "$POST_FILE" ]; then
        echo "  → (POST) $target_name..."
        while IFS='|' read -r url data; do
            [ -z "$url" ] && continue
            sqlmap -u "$url" --data "$data" --batch --threads 5 \
                --level 2 --risk 2 --flush-session \
                --random-agent \
                "${extra_args[@]}" \
                --report-json "$OUT_JSON"
        done < "$POST_FILE"
    fi
done
echo -e "\e[32m[✔]\e[0m SQLMap finalizado."

# SQLMap terminou o scan. Antes de dar o exit 0 pro Python, vamos ver se a internet está viva:
if ! ping -c 2 8.8.8.8 &> /dev/null; then
    echo "[!] AVISO: Queda de conexão detectada durante ou após o scan!"
    exit 1  # Força o erro! O Python NÃO vai rodar o parser!
fi

exit 0 # Tudo certo, o Python pode marcar as URLs como lidas!